/* mka_macsec.c - live wolfMKA over a Linux raw EAPOL socket AND the kernel
 * MACsec data plane, in one process.
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
 * This consolidates the two reference shims into the binary a real deployment
 * actually ships: it carries EAPOL-MKA control frames over an AF_PACKET socket
 * on the physical interface (as mka_link.c does) and wires the SecY callbacks
 * to the kernel `macsec` netdevice over generic netlink (as secy_macsec_linux.c
 * does), so an agreed SAK is programmed into the kernel and real traffic on the
 * macsec interface is protected. It is the wolfMKA peer used by the data-plane
 * interoperability harness (test/interop/).
 *
 * EAPOL is always sent in the clear on the PHYSICAL interface; protected data
 * rides the macsec child device layered on top of it. So two interfaces are
 * given: <eth> for control (the raw socket) and <macsec> for the data plane
 * (netlink). The macsec device is created out of band, e.g.:
 *
 *     sudo ip link add link veth0 macsec0 type macsec encrypt on
 *     sudo ip link set macsec0 up && sudo ip addr add 10.0.0.1/24 dev macsec0
 *
 * Linux-only; needs CAP_NET_RAW + CAP_NET_ADMIN (run as root).
 *
 * Usage:  sudo ./mka_macsec <eth> <macsec> <priority> <cak-hex> <ckn-hex> \
 *                           [rekey-ms]
 * SIGUSR1 forces a rekey (Key Server only); the optional rekey-ms arg arms the
 * automatic Key Server rekey timer instead.
 */
#if !defined(__linux__)
    #include <stdio.h>
int main(void)
{
    printf("mka_macsec requires Linux AF_PACKET + MACsec; see the header.\n");
    return 1;
}
#else

    #ifndef _GNU_SOURCE
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
    #include <linux/genetlink.h>
    #include <linux/if_macsec.h>
    #include <linux/netlink.h>

    #include "wolfmka/mka_kay.h"
    #include "wolfmka/mka_crypto.h"

    #define EAPOL_TYPE  0x888E
    #define ETH_HDR_LEN 14
    #define MAX_FRAME   1600
    #define SECY_BUF    2048

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_rekey = 0;
static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}
static void on_sigusr1(int sig)
{
    (void)sig;
    g_rekey = 1;
}

static const uint8_t PAE_GROUP[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x03};

/* ===================================================================== EAPOL
 * transport (physical interface) - see mka_link.c. */
typedef struct {
    int fd;
    int ifindex;
    uint8_t src_mac[6];
} Link;

static uint32_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000U +
                      (uint64_t)ts.tv_nsec / 1000000U);
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

static int link_open(Link* lk, const char* ifname)
{
    struct ifreq ifr;
    struct sockaddr_ll sa;
    struct packet_mreq mreq;

    lk->fd = socket(AF_PACKET, SOCK_RAW, htons(EAPOL_TYPE));
    if (lk->fd < 0) {
        perror("socket(AF_PACKET)");
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

/* =============================================================== MACsec SecY
 * (kernel netdevice over genetlink) - see secy_macsec_linux.c. */
typedef struct {
    int fd;
    int family;
    unsigned int seq;
    unsigned int ifindex;
    uint32_t ssci;
} SecyMacsec;

    #define NL_TAIL(n)                                                         \
        ((struct nlattr*)((char*)(n) + NLMSG_ALIGN((n)->nlmsg_len)))

static int nl_put(struct nlmsghdr* n, int cap, uint16_t type, const void* data,
    int len)
{
    struct nlattr* nla;
    int alen = (int)NLA_HDRLEN + len;

    if (((int)NLMSG_ALIGN(n->nlmsg_len) + NLA_ALIGN(alen)) > cap) {
        return -1;
    }
    nla = NL_TAIL(n);
    nla->nla_type = type;
    nla->nla_len = (uint16_t)alen;
    if (len > 0) {
        (void)memcpy((char*)nla + NLA_HDRLEN, data, (size_t)len);
    }
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + (unsigned int)NLA_ALIGN(alen);
    return 0;
}

static struct nlattr* nl_nest(struct nlmsghdr* n, int cap, uint16_t type)
{
    struct nlattr* nest = NL_TAIL(n);
    if (nl_put(n, cap, (uint16_t)(type | NLA_F_NESTED), NULL, 0) < 0) {
        return NULL;
    }
    return nest;
}

static void nl_nest_end(struct nlmsghdr* n, struct nlattr* nest)
{
    nest->nla_len = (uint16_t)((char*)NL_TAIL(n) - (char*)nest);
}

static struct nlmsghdr* nl_msg(void* buf, int family, uint8_t cmd,
    unsigned int seq)
{
    struct nlmsghdr* n = (struct nlmsghdr*)buf;
    struct genlmsghdr* g;

    n->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    n->nlmsg_type = (uint16_t)family;
    n->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | NLM_F_ACK);
    n->nlmsg_seq = seq;
    g = (struct genlmsghdr*)NLMSG_DATA(n);
    g->cmd = cmd;
    g->version = 1U;
    return n;
}

static int nl_send_ack(SecyMacsec* s, struct nlmsghdr* n)
{
    union {
        struct nlmsghdr n;
        char b[SECY_BUF];
    } r;
    struct nlmsghdr* h;
    ssize_t len;

    if (send(s->fd, n, n->nlmsg_len, 0) < 0) {
        return -errno;
    }
    len = recv(s->fd, &r, sizeof r, 0);
    if (len < 0) {
        return -errno;
    }
    {
        int rem = (int)len;
        for (h = &r.n; NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)) {
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr* e =
                    (const struct nlmsgerr*)NLMSG_DATA(h);
                return e->error;
            }
        }
    }
    return 0;
}

static int nl_resolve(SecyMacsec* s, const char* name)
{
    union {
        struct nlmsghdr n;
        char b[SECY_BUF];
    } u, r;
    struct nlmsghdr* n;
    struct nlmsghdr* h;
    ssize_t len;

    (void)memset(&u, 0, sizeof u);
    n = nl_msg(&u, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, ++s->seq);
    if (nl_put(n, (int)sizeof u, CTRL_ATTR_FAMILY_NAME, name,
            (int)strlen(name) + 1) < 0) {
        return -1;
    }
    if (send(s->fd, n, n->nlmsg_len, 0) < 0) {
        return -errno;
    }
    len = recv(s->fd, &r, sizeof r, 0);
    if (len < 0) {
        return -errno;
    }
    {
        int nlrem = (int)len;
        for (h = &r.n; NLMSG_OK(h, nlrem); h = NLMSG_NEXT(h, nlrem)) {
            const struct nlattr* a =
                (const struct nlattr*)((const char*)NLMSG_DATA(h) +
                                       GENL_HDRLEN);
            int rem = (int)h->nlmsg_len - (int)NLMSG_LENGTH(GENL_HDRLEN);
            if (h->nlmsg_type == NLMSG_ERROR) {
                return -1;
            }
            while ((rem >= (int)NLA_HDRLEN) && (a->nla_len >= NLA_HDRLEN) &&
                   (rem >= (int)a->nla_len)) {
                if (a->nla_type == CTRL_ATTR_FAMILY_ID) {
                    uint16_t id;
                    if (a->nla_len < NLA_HDRLEN + sizeof id) {
                        return -1;
                    }
                    (void)memcpy(&id, (const char*)a + NLA_HDRLEN, sizeof id);
                    return (int)id;
                }
                rem -= NLA_ALIGN(a->nla_len);
                a = (const struct nlattr*)((const char*)a +
                                           NLA_ALIGN(a->nla_len));
            }
        }
    }
    return -1;
}

static void secy_keyid(uint8_t kid[MACSEC_KEYID_LEN], uint32_t kn)
{
    (void)memset(kid, 0, MACSEC_KEYID_LEN);
    kid[12] = (uint8_t)(kn >> 24);
    kid[13] = (uint8_t)(kn >> 16);
    kid[14] = (uint8_t)(kn >> 8);
    kid[15] = (uint8_t)kn;
}

static uint64_t secy_sci64(const uint8_t sci[MKA_SCI_LEN])
{
    uint64_t v;
    (void)memcpy(&v, sci, sizeof v);
    return v;
}

static int secy_add_sa(SecyMacsec* s, const uint8_t* sci, uint8_t an,
    uint32_t kn, const uint8_t* sak, size_t sak_len)
{
    union {
        struct nlmsghdr n;
        char b[SECY_BUF];
    } u;
    struct nlmsghdr* n;
    struct nlattr* sa;
    uint32_t ifx = s->ifindex;
    uint32_t pn = 1U;
    uint8_t active = 0U;
    uint8_t keyid[MACSEC_KEYID_LEN];

    (void)memset(&u, 0, sizeof u);
    n = nl_msg(&u, s->family,
        (uint8_t)((sci == NULL) ? MACSEC_CMD_ADD_TXSA : MACSEC_CMD_ADD_RXSA),
        ++s->seq);
    (void)nl_put(n, (int)sizeof u, MACSEC_ATTR_IFINDEX, &ifx, (int)sizeof ifx);
    if (sci != NULL) {
        struct nlattr* rxsc =
            nl_nest(n, (int)sizeof u, MACSEC_ATTR_RXSC_CONFIG);
        uint64_t sci64 = secy_sci64(sci);
        (void)nl_put(n, (int)sizeof u, MACSEC_RXSC_ATTR_SCI, &sci64,
            (int)sizeof sci64);
        nl_nest_end(n, rxsc);
    }
    sa = nl_nest(n, (int)sizeof u, MACSEC_ATTR_SA_CONFIG);
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_AN, &an, (int)sizeof an);
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_PN, &pn, (int)sizeof pn);
    secy_keyid(keyid, kn);
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_KEYID, keyid,
        (int)sizeof keyid);
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_KEY, sak, (int)sak_len);
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_ACTIVE, &active,
        (int)sizeof active);
    nl_nest_end(n, sa);
    return nl_send_ack(s, n);
}

static int secy_set_active(SecyMacsec* s, const uint8_t* sci, uint8_t an,
    bool enable)
{
    union {
        struct nlmsghdr n;
        char b[SECY_BUF];
    } u;
    struct nlmsghdr* n;
    struct nlattr* sa;
    uint32_t ifx = s->ifindex;
    uint8_t active = (uint8_t)((enable != 0) ? 1 : 0);

    (void)memset(&u, 0, sizeof u);
    n = nl_msg(&u, s->family,
        (uint8_t)((sci == NULL) ? MACSEC_CMD_UPD_TXSA : MACSEC_CMD_UPD_RXSA),
        ++s->seq);
    (void)nl_put(n, (int)sizeof u, MACSEC_ATTR_IFINDEX, &ifx, (int)sizeof ifx);
    if (sci != NULL) {
        struct nlattr* rxsc =
            nl_nest(n, (int)sizeof u, MACSEC_ATTR_RXSC_CONFIG);
        uint64_t sci64 = secy_sci64(sci);
        (void)nl_put(n, (int)sizeof u, MACSEC_RXSC_ATTR_SCI, &sci64,
            (int)sizeof sci64);
        nl_nest_end(n, rxsc);
    }
    sa = nl_nest(n, (int)sizeof u, MACSEC_ATTR_SA_CONFIG);
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_AN, &an, (int)sizeof an);
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_ACTIVE, &active,
        (int)sizeof active);
    nl_nest_end(n, sa);
    return nl_send_ack(s, n);
}

static int secy_create_tx_sc(void* ctx, const uint8_t* sci)
{
    (void)ctx;
    (void)sci;
    return 0;
}

static int secy_create_rx_sc(void* ctx, const uint8_t* sci)
{
    SecyMacsec* s = (SecyMacsec*)ctx;
    union {
        struct nlmsghdr n;
        char b[SECY_BUF];
    } u;
    struct nlmsghdr* n;
    struct nlattr* rxsc;
    uint32_t ifx = s->ifindex;
    uint64_t sci64 = secy_sci64(sci);

    (void)memset(&u, 0, sizeof u);
    n = nl_msg(&u, s->family, MACSEC_CMD_ADD_RXSC, ++s->seq);
    (void)nl_put(n, (int)sizeof u, MACSEC_ATTR_IFINDEX, &ifx, (int)sizeof ifx);
    rxsc = nl_nest(n, (int)sizeof u, MACSEC_ATTR_RXSC_CONFIG);
    (void)nl_put(n, (int)sizeof u, MACSEC_RXSC_ATTR_SCI, &sci64,
        (int)sizeof sci64);
    nl_nest_end(n, rxsc);
    return nl_send_ack(s, n);
}

static int secy_install_tx_sa(void* ctx, const uint8_t* sci, uint8_t an,
    uint32_t kn, const uint8_t* sak, size_t sak_len)
{
    (void)sci;
    return secy_add_sa((SecyMacsec*)ctx, NULL, an, kn, sak, sak_len);
}

static int secy_install_rx_sa(void* ctx, const uint8_t* sci, uint8_t an,
    uint32_t kn, const uint8_t* sak, size_t sak_len)
{
    return secy_add_sa((SecyMacsec*)ctx, sci, an, kn, sak, sak_len);
}

static int secy_enable_transmit(void* ctx, uint8_t an, bool enable)
{
    return secy_set_active((SecyMacsec*)ctx, NULL, an, enable);
}

static int secy_enable_receive(void* ctx, const uint8_t* sci, uint8_t an,
    bool enable)
{
    return secy_set_active((SecyMacsec*)ctx, sci, an, enable);
}

static int secy_delete_sa(void* ctx, const uint8_t* sci, uint8_t an)
{
    SecyMacsec* s = (SecyMacsec*)ctx;
    union {
        struct nlmsghdr n;
        char b[SECY_BUF];
    } u;
    struct nlmsghdr* n;
    struct nlattr* sa;
    uint32_t ifx = s->ifindex;

    (void)memset(&u, 0, sizeof u);
    n = nl_msg(&u, s->family,
        (uint8_t)((sci == NULL) ? MACSEC_CMD_DEL_TXSA : MACSEC_CMD_DEL_RXSA),
        ++s->seq);
    (void)nl_put(n, (int)sizeof u, MACSEC_ATTR_IFINDEX, &ifx, (int)sizeof ifx);
    if (sci != NULL) {
        struct nlattr* rxsc =
            nl_nest(n, (int)sizeof u, MACSEC_ATTR_RXSC_CONFIG);
        uint64_t sci64 = secy_sci64(sci);
        (void)nl_put(n, (int)sizeof u, MACSEC_RXSC_ATTR_SCI, &sci64,
            (int)sizeof sci64);
        nl_nest_end(n, rxsc);
    }
    sa = nl_nest(n, (int)sizeof u, MACSEC_ATTR_SA_CONFIG);
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_AN, &an, (int)sizeof an);
    nl_nest_end(n, sa);
    return nl_send_ack(s, n);
}

static MkaSecyOps secy_macsec_ops(SecyMacsec* s)
{
    MkaSecyOps ops;
    (void)memset(&ops, 0, sizeof ops);
    ops.create_tx_sc = secy_create_tx_sc;
    ops.create_rx_sc = secy_create_rx_sc;
    ops.install_tx_sa = secy_install_tx_sa;
    ops.install_rx_sa = secy_install_rx_sa;
    ops.enable_transmit = secy_enable_transmit;
    ops.enable_receive = secy_enable_receive;
    ops.delete_sa = secy_delete_sa;
    ops.ctx = s;
    return ops;
}

static int secy_macsec_init(SecyMacsec* s, const char* ifname)
{
    struct sockaddr_nl sa;

    (void)memset(s, 0, sizeof *s);
    s->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (s->fd < 0) {
        perror("socket(NETLINK_GENERIC)");
        return -1;
    }
    (void)memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (bind(s->fd, (struct sockaddr*)&sa, sizeof sa) < 0) {
        perror("bind(netlink)");
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }
    s->family = nl_resolve(s, "macsec");
    if (s->family < 0) {
        fprintf(stderr, "macsec genl family not found (module loaded?)\n");
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }
    s->ifindex = if_nametoindex(ifname);
    if (s->ifindex == 0U) {
        fprintf(stderr, "macsec interface '%s' not found\n", ifname);
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }
    return 0;
}

static void secy_macsec_free(SecyMacsec* s)
{
    if (s->fd >= 0) {
        (void)close(s->fd);
        s->fd = -1;
    }
}

/* ====================================================================== main
 */
int main(int argc, char** argv)
{
    Link lk;
    SecyMacsec secy;
    MkaParticipantConfig cfg;
    MkaParticipant p;
    MkaCmacCtx* cmac;
    MkaRandom* rng;
    uint8_t cak[MKA_MAX_CAK_LEN];
    uint8_t ckn[MKA_MAX_CKN_LEN];
    size_t cak_len, ckn_len;
    int pri;
    int prev_ks = -1, prev_live = -1, prev_sak = -1;
    uint32_t prev_kn = 0;

    if ((argc != 6) && (argc != 7)) {
        printf("usage: %s <eth> <macsec> <priority> <cak-hex> <ckn-hex> "
               "[rekey-ms]\n",
            argv[0]);
        return 1;
    }
    pri = atoi(argv[3]);
    cak_len = parse_hex(argv[4], cak, sizeof cak);
    ckn_len = parse_hex(argv[5], ckn, sizeof ckn);
    if (((cak_len != 16U) && (cak_len != 32U)) || (ckn_len == 0U)) {
        printf("CAK must be 16 or 32 octets; CKN 1..32 octets.\n");
        return 1;
    }
    if (link_open(&lk, argv[1]) != 0) {
        return 1;
    }
    if (secy_macsec_init(&secy, argv[2]) != 0) {
        (void)close(lk.fd);
        return 1;
    }
    cmac = wm_Crypto_CmacInit();
    if (cmac == NULL) {
        printf("cmac init failed\n");
        secy_macsec_free(&secy);
        (void)close(lk.fd);
        return 1;
    }
    rng = wm_Crypto_RandomInit();
    if (rng == NULL) {
        fprintf(stderr, "could not acquire RNG workspace\n");
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }

    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.cak.cak, cak, cak_len);
    cfg.cak.cak_len = cak_len;
    memcpy(cfg.cak.ckn, ckn, ckn_len);
    cfg.cak.ckn_len = ckn_len;
    memcpy(cfg.sci, lk.src_mac,
        6); /* SCI = MAC || port 1 (matches macsec dev) */
    cfg.sci[6] = 0x00;
    cfg.sci[7] = 0x01;
    cfg.priority = (uint8_t)pri;
    cfg.macsec_desired = 1;
    cfg.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    cfg.key_server_capable = 1;
    cfg.sak_len = 16;
    if (argc == 7) {
        cfg.sak_rekey_time_ms = (uint32_t)strtoul(argv[6], NULL, 10);
    }
    cfg.secy = secy_macsec_ops(&secy);
    cfg.send = link_send;
    cfg.send_ctx = &lk;
    cfg.cmac = cmac;
    cfg.rng = rng;

    if (wm_Participant_Init(&p, &cfg) != MKA_OK) {
        printf("participant init failed\n");
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        secy_macsec_free(&secy);
        (void)close(lk.fd);
        return 1;
    }
    printf("MKA+MACsec on %s/%s (priority %d). SIGUSR1 rekeys; Ctrl-C stops.\n",
        argv[1], argv[2], pri);
    (void)signal(SIGINT, on_sigint);
    (void)signal(SIGUSR1, on_sigusr1);

    while (!g_stop) {
        struct pollfd pfd;
        uint32_t t;
        int live, ks, sak;

        pfd.fd = lk.fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 1000) < 0) {
            break; /* EINTR from a signal: re-check g_stop / g_rekey */
        }
        t = now_ms();

        if ((pfd.revents & POLLIN) != 0) {
            uint8_t buf[MAX_FRAME];
            struct sockaddr_ll sa;
            socklen_t sl = sizeof sa;
            ssize_t n =
                recvfrom(lk.fd, buf, sizeof buf, 0, (struct sockaddr*)&sa, &sl);
            if ((n > ETH_HDR_LEN) && (sa.sll_pkttype != PACKET_OUTGOING)) {
                (void)wm_Participant_Receive(&p, &buf[ETH_HDR_LEN],
                    (size_t)n - ETH_HDR_LEN, t);
            }
        }

        if (g_rekey != 0) {
            g_rekey = 0;
            if (wm_Participant_Rekey(&p) == MKA_OK) {
                printf("rekey requested\n");
            }
            else {
                printf("rekey ignored (not Key Server)\n");
            }
        }

        (void)wm_Participant_Run(&p, t, NULL);

        live = (int)wm_Participant_LivePeerCount(&p);
        ks = wm_Participant_IsKeyServer(&p) ? 1 : 0;
        sak = wm_Participant_HasSak(&p) ? 1 : 0;
        if ((live != prev_live) || (ks != prev_ks) || (sak != prev_sak) ||
            (p.latest.kn != prev_kn)) {
            printf("state: live=%d key_server=%d sak=%d kn=%u\n", live, ks, sak,
                p.latest.kn);
            prev_live = live;
            prev_ks = ks;
            prev_sak = sak;
            prev_kn = p.latest.kn;
        }
    }
    wm_Participant_Free(&p);
    wm_Crypto_RandomFree(rng);
    wm_Crypto_CmacFree(cmac);
    secy_macsec_free(&secy);
    (void)close(lk.fd);
    return 0;
}

#endif /* __linux__ */
