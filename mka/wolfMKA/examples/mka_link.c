/* mka_link.c - run wolfMKA over a real Linux AF_PACKET raw socket.
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of wolfMKA.
 *
 * wolfMKA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfMKA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Carries EAPOL-MKA frames (EtherType 0x888E) to the PAE group address
 * 01:80:C2:00:00:03 on a chosen interface, driving a live MKA participant with
 * a pre-shared CAK/CKN. This is the concrete counterpart to the abstract
 * send/receive interface: the only integration glue most deployments must
 * write themselves.
 *
 * Linux-only; needs CAP_NET_RAW (run as root). The data plane here is a logging
 * shim - a real deployment would wire the SecY callbacks to a MACsec device.
 *
 * Usage:   sudo ./mka_link <ifname> <priority> <cak-hex> <ckn-hex>
 * Example: two veth ends sharing one CAK/CKN, different priorities:
 *   sudo ./mka_link veth0 10 cacacacacacacacacacacacacacacaca 0011223344
 *   sudo ./mka_link veth1 20 cacacacacacacacacacacacacacacaca 0011223344
 */
#if !defined(__linux__)
    #include <stdio.h>
int main(void)
{
    printf("mka_link requires Linux AF_PACKET; see the source header.\n");
    return 1;
}
#else

    #ifndef _GNU_SOURCE /* g++ predefines it; avoid a redefinition warning */
        #define _GNU_SOURCE
    #endif
    #include <errno.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdint.h>
    #include <time.h>
    #include <poll.h>
    #include <unistd.h>
    #include <signal.h>
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <net/if_arp.h>
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>

    #include "wolfmka/mka_kay.h"
    #include "wolfmka/mka_crypto.h"

    #define EAPOL_TYPE  0x888E
    #define ETH_HDR_LEN 14
    #define MAX_FRAME   1600

/* Set by SIGINT so the run loop exits and releases its resources (Ctrl-C is the
 * documented way to stop the daemon); without this the loop never returns and
 * the socket close at the end is unreachable. */
static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

static const uint8_t PAE_GROUP[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x03};

typedef struct {
    int fd;
    int ifindex;
    uint8_t src_mac[6];
} Link;

/* ------------------------------------------------------------------ time -- */
static uint32_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000U +
                      (uint64_t)ts.tv_nsec / 1000000U);
}

/* ------------------------------------------------------------------ util -- */
static void hexline(const char* tag, const uint8_t* p, size_t n)
{
    size_t i;
    printf("%s", tag);
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

static size_t parse_hex(const char* s, uint8_t* out, size_t cap)
{
    size_t n = 0;
    while ((s[0] != '\0') && (s[1] != '\0') && (n < cap)) {
        unsigned int v;
        if (sscanf(s, "%2x", &v) != 1) {
            break;
        }
        out[n] = (uint8_t)v;
        n++;
        s += 2;
    }
    return n;
}

/* ------------------------------------------------------------------ SecY -- */
static int sc_noop(void* c, const uint8_t* sci)
{
    (void)c;
    (void)sci;
    return 0;
}

static int sa_tx(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
    const uint8_t* sak, size_t len)
{
    (void)c;
    (void)sci;
    printf("[SecY] install TX SA an=%u kn=%u\n", (unsigned)an, (unsigned)kn);
    hexline("       SAK = ", sak, len);
    return 0;
}

static int sa_rx(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
    const uint8_t* sak, size_t len)
{
    (void)c;
    (void)sci;
    (void)kn;
    printf("[SecY] install RX SA an=%u\n", (unsigned)an);
    hexline("       SAK = ", sak, len);
    return 0;
}

static int en_tx(void* c, uint8_t an, bool e)
{
    (void)c;
    printf("[SecY] transmit an=%u %s\n", (unsigned)an, e ? "ENABLED" : "off");
    return 0;
}

static int en_rx(void* c, const uint8_t* s, uint8_t an, bool e)
{
    (void)c;
    (void)s;
    (void)an;
    (void)e;
    return 0;
}

/* ----------------------------------------------------------- transport ---- */
/* Transmit callback: prepend an Ethernet header and send the EAPOL frame. */
static int link_send(void* ctx, const uint8_t* frame, size_t len)
{
    Link* lk = (Link*)ctx;
    uint8_t buf[MAX_FRAME];
    struct sockaddr_ll sa;
    size_t total = ETH_HDR_LEN + len;

    if (total > sizeof buf) {
        return -1;
    }
    memcpy(&buf[0], PAE_GROUP, 6);
    memcpy(&buf[6], lk->src_mac, 6);
    buf[12] = 0x88;
    buf[13] = 0x8E;
    memcpy(&buf[ETH_HDR_LEN], frame, len);

    memset(&sa, 0, sizeof sa);
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = lk->ifindex;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, PAE_GROUP, 6);

    if (sendto(lk->fd, buf, total, 0, (struct sockaddr*)&sa, sizeof sa) < 0) {
        return -1;
    }
    return 0;
}

/* Open and bind a raw EAPOL socket, joining the PAE group multicast. */
static int link_open(Link* lk, const char* ifname)
{
    struct ifreq ifr;
    struct sockaddr_ll sa;
    struct packet_mreq mreq;

    lk->fd = socket(AF_PACKET, SOCK_RAW, htons(EAPOL_TYPE));
    if (lk->fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1U);
    if (ioctl(lk->fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ifindex");
        goto fail;
    }
    lk->ifindex = ifr.ifr_ifindex;
    if (ioctl(lk->fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("hwaddr");
        goto fail;
    }
    /* The SCI is seeded from the hardware address, so insist on an Ethernet
     * interface; a loopback/tunnel hwaddr would otherwise seed a garbage SCI.
     */
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        fprintf(stderr, "interface '%s' is not Ethernet\n", ifname);
        goto fail;
    }
    memcpy(lk->src_mac, ifr.ifr_hwaddr.sa_data, 6);

    memset(&sa, 0, sizeof sa);
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(EAPOL_TYPE);
    sa.sll_ifindex = lk->ifindex;
    if (bind(lk->fd, (struct sockaddr*)&sa, sizeof sa) < 0) {
        perror("bind");
        goto fail;
    }

    memset(&mreq, 0, sizeof mreq);
    mreq.mr_ifindex = lk->ifindex;
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = 6;
    memcpy(mreq.mr_address, PAE_GROUP, 6);
    (void)setsockopt(lk->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
        sizeof mreq);
    return 0;

fail:
    (void)close(lk->fd);
    lk->fd = -1;
    return -1;
}

/* ------------------------------------------------------------------ main -- */
static MkaSecyOps make_secy(void)
{
    MkaSecyOps o;
    memset(&o, 0, sizeof o);
    o.create_tx_sc = sc_noop;
    o.create_rx_sc = sc_noop;
    o.install_tx_sa = sa_tx;
    o.install_rx_sa = sa_rx;
    o.enable_transmit = en_tx;
    o.enable_receive = en_rx;
    return o;
}

int main(int argc, char** argv)
{
    Link lk;
    MkaParticipantConfig cfg;
    MkaParticipant p;
    MkaCmacCtx* cmac;
    MkaRandom* rng;
    uint8_t cak[MKA_MAX_CAK_LEN];
    uint8_t ckn[MKA_MAX_CKN_LEN];
    size_t cak_len, ckn_len;
    int pri;
    int prev_ks = -1, prev_live = -1, prev_sak = -1;

    /* Line-buffer stdout. These examples are driven by the interop scripts with
     * stdout redirected to a file, where stdio defaults to full buffering: the
     * short status lines below would sit in a 4 KB buffer for the whole run, so
     * the log a script polls stays empty however well the protocol is going. */
    (void)setvbuf(stdout, NULL, _IOLBF, 0);

    if ((argc != 5) && (argc != 6)) {
        printf("usage: %s <ifname> <priority> <cak-hex> <ckn-hex> "
               "[sak-octets]\n",
            argv[0]);
        return 1;
    }
    pri = atoi(argv[2]);
    cak_len = parse_hex(argv[3], cak, sizeof cak);
    ckn_len = parse_hex(argv[4], ckn, sizeof ckn);
    if (((cak_len != 16U) && (cak_len != 32U)) || (ckn_len == 0U)) {
        printf("CAK must be 16 or 32 octets; CKN 1..32 octets.\n");
        return 1;
    }
    if (link_open(&lk, argv[1]) != 0) {
        return 1;
    }
    cmac = wm_Crypto_CmacInit(); /* required workspace (ICV + key derivation) */
    if (cmac == NULL) {
        printf("cmac init failed\n");
        (void)close(lk.fd);
        return 1;
    }
    rng = wm_Crypto_RandomInit(); /* required workspace (MIs and SAKs) */
    if (rng == NULL) {
        printf("rng init failed\n");
        wm_Crypto_CmacFree(cmac);
        (void)close(lk.fd);
        return 1;
    }

    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.cak.cak, cak, cak_len);
    cfg.cak.cak_len = cak_len;
    memcpy(cfg.cak.ckn, ckn, ckn_len);
    cfg.cak.ckn_len = ckn_len;
    memcpy(cfg.sci, lk.src_mac, 6); /* SCI = MAC || port 1 */
    cfg.sci[6] = 0x00;
    cfg.sci[7] = 0x01;
    cfg.priority = (uint8_t)pri;
    cfg.macsec_desired = 1;
    cfg.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    cfg.confidentiality_offset = MKA_CONF_OFFSET_0;
    cfg.key_server_capable = 1;
    /* SAK length selects the cipher suite: 16 -> GCM-AES-128 (the default, left
     * as 0 so the Distributed SAK parameter set omits the suite), 32 ->
     * GCM-AES-256, which is named explicitly on the wire. The interop harness
     * uses this to exercise both against wpa_supplicant's macsec_csindex. */
    cfg.sak_len = (argc == 6) ? (size_t)atoi(argv[5]) : 16U;
    if (cfg.sak_len == 32U) {
        cfg.cipher_suite = MKA_CIPHER_GCM_AES_256;
    }
    cfg.secy = make_secy();
    cfg.send = link_send;
    cfg.send_ctx = &lk;
    cfg.cmac = cmac;
    cfg.rng = rng;

    if (wm_Participant_Init(&p, &cfg) != MKA_OK) {
        printf("participant init failed\n");
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        (void)close(lk.fd);
        return 1;
    }
    printf("MKA running on %s (priority %d). Ctrl-C to stop.\n", argv[1], pri);
    (void)signal(SIGINT, on_sigint);

    while (!g_stop) {
        struct pollfd pfd;
        uint32_t t;
        int live, ks, sak;

        pfd.fd = lk.fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 1000) < 0) {
            /* A signal is the normal way SIGINT arrives; re-check g_stop
             * rather than treating it as a fatal poll error. */
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }
        t = now_ms();

        if ((pfd.revents & POLLIN) != 0) {
            uint8_t buf[MAX_FRAME];
            struct sockaddr_ll sa;
            socklen_t sl = sizeof sa;
            ssize_t n =
                recvfrom(lk.fd, buf, sizeof buf, 0, (struct sockaddr*)&sa, &sl);
            /* Skip our own outgoing copies; strip the Ethernet header. */
            if ((n > ETH_HDR_LEN) && (sa.sll_pkttype != PACKET_OUTGOING)) {
                (void)wm_Participant_Receive(&p, &buf[ETH_HDR_LEN],
                    (size_t)n - ETH_HDR_LEN, t);
            }
        }

        (void)wm_Participant_Run(&p, t, NULL);

        live = (int)wm_Participant_LivePeerCount(&p);
        ks = wm_Participant_IsKeyServer(&p) ? 1 : 0;
        sak = wm_Participant_HasSak(&p) ? 1 : 0;
        if ((live != prev_live) || (ks != prev_ks) || (sak != prev_sak)) {
            printf("state: live=%d key_server=%d sak=%d\n", live, ks, sak);
            prev_live = live;
            prev_ks = ks;
            prev_sak = sak;
        }
    }
    wm_Participant_Free(&p);
    wm_Crypto_RandomFree(rng);
    wm_Crypto_CmacFree(cmac);
    (void)close(lk.fd);
    return 0;
}

#endif /* __linux__ */
