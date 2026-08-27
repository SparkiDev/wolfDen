/* Headless libmka peer for wolfMKA Tier 5 interop.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libmka (Intrepid Control Systems) ships one example, examples/external, and
 * it cannot be used here: it prompts for an interface on stdin, is built around
 * Npcap, and does not compile - `if((ics_mka_has_response(&state)) {` has
 * unbalanced parentheses. This is the equivalent driver, taking its parameters
 * on the command line and running on an AF_PACKET socket.
 *
 * libmka is a control-plane implementation: it hands the agreed SAK to an
 * sa_installer callback and has no MACsec data plane, so this driver prints
 * what it was given rather than programming a device. That is what Tier 5
 * checks - that a third implementation of the MKPDU format, the ICV and the
 * key hierarchy agrees with wolfMKA on the key, not that frames flow.
 *
 * Everything printed here is test scaffolding for a throwaway CA on a veth
 * pair. It prints the SAK, which no production tool should ever do; comparing
 * the key both stacks derived is the entire point of the tier.
 *
 * Build: see run-interop-libmka.sh (needs libmka's headers and libics-mka.a).
 */

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "ics/mka/mka.h"

#define MAX_FRAME 1600

/* Hex string -> bytes; returns the byte count, or 0 on a malformed input. */
static size_t parse_hex(const char* in, unsigned char* out, size_t max)
{
    size_t n = strlen(in);
    size_t i;

    if (((n & 1U) != 0U) || ((n / 2U) > max)) {
        return 0;
    }
    for (i = 0; i < n; i += 2) {
        char b[3];
        char* end;
        long v;
        b[0] = in[i];
        b[1] = in[i + 1];
        b[2] = '\0';
        v = strtol(b, &end, 16);
        if (*end != '\0') {
            return 0;
        }
        out[i / 2] = (unsigned char)v;
    }
    return n / 2;
}

static void print_hex(const char* label, const unsigned char* p, size_t n)
{
    size_t i;
    printf("%s", label);
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

/* libmka reports the agreed key here. The Key Identifier is the Key Server's
 * Member Identifier followed by the Key Number, which is what the peer's SecY
 * labels the SA with - so printing both lets the harness match the two ends
 * without either of them trusting the other's account of it.
 *
 * sa->key_server names a *peer*, so it is NULL when this end is the Key Server
 * itself and the Member Identifier to report is our own. That is not a guess:
 * libmka's own salt derivation makes the same substitution,
 * `key_server ? &key_server->id : &state->id`. Without it the round where
 * libmka holds the role has no Key Identifier to compare and falls back to the
 * weaker "each end has a key" claim. */
static void sa_installer(const mka_new_sa_t* sa, void* user_data)
{
    const mka_state_t* state = (const mka_state_t*)user_data;

    printf("SAK installed: kn=%u an=%u len=%u\n", (unsigned)sa->key_number,
        (unsigned)sa->an, (unsigned)sa->sak_length);
    print_hex("  sak=", sa->sak, sa->sak_length);
    print_hex("  salt=", sa->salt, MKA_SALT_LENGTH);
    if (sa->key_server != NULL) {
        print_hex("  ks_mi=", sa->key_server->id, MKA_ACTOR_ID_LENGTH);
    }
    else if (state != NULL) {
        print_hex("  ks_mi=", state->id, MKA_ACTOR_ID_LENGTH);
        printf("  (this end is the Key Server)\n");
    }
    else {
        printf("  ks_mi=unavailable\n");
    }
    fflush(stdout);
}

int main(int argc, char** argv)
{
    unsigned char cak[32];
    unsigned char ckn[32];
    size_t cak_len;
    size_t ckn_len;
    mka_state_t state;
    mka_settings_t settings;
    mka_result_t res;
    struct sockaddr_ll ll;
    struct ifreq ifr;
    int fd;
    int pri;
    int ifindex;
    const char* ifname;

    if (argc < 5) {
        printf("usage: %s <iface> <priority> <cak-hex> <ckn-hex> [xpn]\n",
            argv[0]);
        return 1;
    }
    ifname = argv[1];
    pri = atoi(argv[2]);
    cak_len = parse_hex(argv[3], cak, sizeof cak);
    ckn_len = parse_hex(argv[4], ckn, sizeof ckn);
    if ((cak_len == 0U) || (ckn_len == 0U)) {
        printf("bad CAK or CKN hex\n");
        return 1;
    }

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(fd);
        return 1;
    }
    ifindex = ifr.ifr_ifindex;
    memset(&ll, 0, sizeof ll);
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr*)&ll, sizeof ll) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(fd);
        return 1;
    }

    memset(&state, 0, sizeof state);
    memset(&settings, 0, sizeof settings);
    ics_mka_settings_init(&settings);
    settings.plain_rx = false;
    settings.plain_tx = false;
    /* Table 11-6 selector 1: confidentiality from octet 0. libmka names the
     * values the same way the standard does. */
    settings.confidentiality_offset = MKA_CONFIDENTIALITY_NO_OFFSET;
    settings.macsec_desired = true;
    settings.cipher_suite = ((argc >= 6) && (atoi(argv[5]) != 0))
        ? MKA_GCM_AES_XPN_128
        : MKA_GCM_AES_128;
    settings.key_server_priority = (u8)pri;
    settings.port_id = 0x01;
    settings.sa_installer = sa_installer;
    /* So the callback can fall back to our own Member Identifier when this end
     * is the Key Server; see sa_installer. */
    settings.user_data = &state;
    settings.version = MKA_VERSION_3;
    settings.capability = MKA_MACSEC_INTEGRITY_AND_CONFIDENTIALITY_OFFSET;
    memcpy(settings.mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    ics_mka_add_cak(&settings, cak, (u8)cak_len, ckn, (u8)ckn_len);

    res = ics_mka_init(&state, &settings);
    if (res != MKA_SUCCESS) {
        printf("ics_mka_init failed: %d\n", (int)res);
        close(fd);
        return 1;
    }
    print_hex("libmka peer up, mac=", (unsigned char*)settings.mac_addr, 6);
    printf("priority=%d cipher=%s\n", pri,
        (settings.cipher_suite == MKA_GCM_AES_128) ? "GCM_AES_128"
                                                   : "GCM_AES_XPN_128");
    fflush(stdout);

    for (;;) {
        unsigned char in[MAX_FRAME];
        unsigned char out[MAX_FRAME];
        u16 out_size = 0;
        struct timeval tv;
        fd_set rfds;
        int rc;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        /* Short enough that the periodic transmit below stays near libmka's
         * own hello timing without this driver having to model it. */
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if ((rc > 0) && FD_ISSET(fd, &rfds)) {
            ssize_t n = recv(fd, in, sizeof in, 0);
            if (n > 0) {
                /* libmka filters by EtherType itself; a non-MKA frame comes
                 * back as an error that is not worth reporting, since this
                 * socket sees all traffic on the link. */
                (void)ics_mka_process_message(&state, in, (u16)n);
            }
        }
        /* Read as a boolean, not as a result code. ics_mka_has_response is
         * declared mka_result_t but returns the value of a || expression: 1
         * when there *is* something to send - which is MKA_ERROR in that
         * enumeration - and 0, MKA_SUCCESS, when there is not. Comparing it
         * against MKA_SUCCESS transmits exactly when there is nothing to say,
         * and the peer never hears anything. */
        if (ics_mka_has_response(&state)) {
            /* The last parameter is the next packet number, not a timestamp.
             * libmka drives no data plane here, so nothing consumes it beyond
             * the Lowest Acceptable PN it advertises; 1 is the honest value
             * for an end that has transmitted no protected frames. */
            res = ics_mka_next_pdu(&state, out, &out_size, 1U);
            if (res == MKA_SUCCESS) {
                if (send(fd, out, out_size, 0) < 0) {
                    perror("send");
                }
            }
            else {
                printf("ics_mka_next_pdu failed: %d\n", (int)res);
                fflush(stdout);
            }
        }
    }
}
