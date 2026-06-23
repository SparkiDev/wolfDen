/* clang-format off */
/* secy_macsec_linux.c - reference SecY (data-plane) driver for wolfMKA on
 * Linux.
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
 * Implements the wolfMKA MkaSecyOps hooks against the Linux kernel's native
 * MACsec device (the `macsec` generic-netlink family, drivers/net/macsec.c).
 * It is the concrete counterpart to the abstract SecY interface and the rough
 * equivalent of hostapd's driver_macsec_linux.c - the glue most deployments
 * must otherwise write themselves. Raw netlink is used (no libnl dependency) so
 * the mapping from each hook to its netlink command is visible in one file:
 *
 *   MkaSecyOps hook   Linux MACsec netlink
 *   ---------------   --------------------------------------------------------
 *   create_tx_sc      (implicit: the device IS the transmit SC) - no-op
 *   create_rx_sc      MACSEC_CMD_ADD_RXSC  (RXSC_CONFIG{SCI})
 *   install_tx_sa     MACSEC_CMD_ADD_TXSA  (SA_CONFIG{AN,PN,KEYID,KEY})
 *   install_rx_sa     MACSEC_CMD_ADD_RXSA  (RXSC_CONFIG{SCI} + SA_CONFIG{...})
 *   enable_transmit   MACSEC_CMD_UPD_TXSA  (SA_CONFIG{AN,ACTIVE})
 *   enable_receive    MACSEC_CMD_UPD_RXSA  (RXSC_CONFIG{SCI} + SA_CONFIG{...})
 *   delete_sa         MACSEC_CMD_DEL_TXSA / MACSEC_CMD_DEL_RXSA
 *   set_cipher_suite  (device cipher is fixed at creation) - validated/logged
 *
 * The SAK bytes are delivered to the kernel in the MACSEC_SA_ATTR_KEY attribute
 * when an SA is created; from there the kernel macsec module performs the
 * GCM-AES itself, or pushes the key to the NIC/PHY if offload is enabled.
 *
 * Prerequisites: the macsec netdevice is created out of band, e.g. with
 * iproute2 -
 *
 *     sudo ip link add link eth0 macsec0 type macsec encrypt on
 *     sudo ip link set macsec0 up
 *
 * then run (needs CAP_NET_ADMIN):
 *
 *     sudo ./secy_macsec_linux macsec0 [peer-sci-hex-16]
 *
 * The main() below is a smoke test: it drives the hooks exactly as wolfMKA's
 * KaY would (create RX SC, install RX/TX SAs with dummy keys, enable, delete),
 * printing each netlink result, so the file doubles as copy-paste glue.
 *
 * Caveats vs the full IEEE model:
 *   - Confidentiality offset (0/30/50): the Linux genl API has no attribute for
 *     it (only encrypt on/off), so set_cipher_suite logs but cannot program it.
 *   - The Key Identifier MKA uses is MI||KN; the SecY hook does not pass the MI,
 *     so a deterministic KEYID is synthesised from the Key Number here.
 *   - PN is seeded to 1 as a u32 (GCM-AES, non-XPN). An XPN device needs a u64
 *     PN plus MACSEC_SA_ATTR_SSCI / _SALT - sketched in install_*_sa comments.
 */
/* clang-format on */
#if !defined(__linux__)
    #include <stdio.h>
int main(void)
{
    printf("secy_macsec_linux requires Linux MACsec; see the source header.\n");
    return 1;
}
#else

    #include <errno.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <net/if.h>
    #include <sys/socket.h>
    #include <linux/genetlink.h>
    #include <linux/if_macsec.h>
    #include <linux/netlink.h>

    #include "wolfmka/mka_kay.h"

    #define SECY_BUF 2048

/* Per-port SecY context: the genetlink socket, the resolved family id and the
 * macsec netdevice this SecY drives. */
typedef struct {
    int fd;
    int family;
    unsigned int seq;
    unsigned int ifindex;
    uint32_t ssci; /* last SSCI seen via set_cipher_suite (XPN) */
} SecyMacsec;

/* ------------------------------------------------------------ netlink core -
 */
    #define NL_TAIL(n)                                                         \
        ((struct nlattr*)((char*)(n) + NLMSG_ALIGN((n)->nlmsg_len)))

/* Append one attribute to a request, growing nlmsg_len. */
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

/* Open a nested attribute; close it with nl_nest_end once members are added. */
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

/* Initialise a request buffer (must be zeroed) with the genl header. */
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

/* Send a request and wait for its ACK; returns 0 or a negative errno. */
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
    /* Walk with a SIGNED remaining count: NLMSG_NEXT subtracts the kernel-
     * supplied nlmsg_len, which can exceed what is left; NLMSG_OK's signed
     * length test then stops the walk instead of a cast-to-unsigned reading
     * past the buffer. len <= sizeof r, so it fits an int. */
    {
        int rem = (int)len;
        for (h = &r.n; NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)) {
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr* e =
                    (const struct nlmsgerr*)NLMSG_DATA(h);
                return e->error; /* 0 == success ACK */
            }
        }
    }
    return 0;
}

/* Resolve a generic-netlink family id by name (CTRL_CMD_GETFAMILY). */
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
        int nlrem = (int)len; /* signed walk; see nl_send_ack */
        for (h = &r.n; NLMSG_OK(h, nlrem); h = NLMSG_NEXT(h, nlrem)) {
            const struct nlattr* a =
                (const struct nlattr*)((const char*)NLMSG_DATA(h) +
                                       GENL_HDRLEN);
            int rem = (int)h->nlmsg_len - (int)NLMSG_LENGTH(GENL_HDRLEN);
            if (h->nlmsg_type == NLMSG_ERROR) {
                return -1;
            }
            /* Require a full attribute header AND that nla_len covers it, so a
             * zero/short nla_len cannot spin (NLA_ALIGN(0)==0) or under-read.
             */
            while ((rem >= (int)NLA_HDRLEN) && (a->nla_len >= NLA_HDRLEN) &&
                   (rem >= (int)a->nla_len)) {
                if (a->nla_type == CTRL_ATTR_FAMILY_ID) {
                    uint16_t id;
                    /* Confirm the attribute actually carries the 2 payload
                     * octets before copying them out. */
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

/* ----------------------------------------------------- MACsec SA programming
 */

/* Synthesise a 16-octet KEYID from the Key Number (real MKA uses MI||KN, but
 * the SecY hook does not carry the MI). */
static void secy_keyid(uint8_t kid[MACSEC_KEYID_LEN], uint32_t kn)
{
    (void)memset(kid, 0, MACSEC_KEYID_LEN);
    kid[12] = (uint8_t)(kn >> 24);
    kid[13] = (uint8_t)(kn >> 16);
    kid[14] = (uint8_t)(kn >> 8);
    kid[15] = (uint8_t)kn;
}

/* The kernel takes the SCI as a u64 whose octets are the 8 SCI octets in wire
 * order, so a plain memcpy round-trips it. */
static uint64_t secy_sci64(const uint8_t sci[MKA_SCI_LEN])
{
    uint64_t v;
    (void)memcpy(&v, sci, sizeof v);
    return v;
}

/* Add an SA (transmit when sci == NULL, else a receive SA on the peer SC),
 * delivering the SAK in MACSEC_SA_ATTR_KEY. */
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
    uint32_t pn = 1U;    /* initial packet number (u64 for an XPN device) */
    uint8_t active = 0U; /* gated: enable_{transmit,receive} flips this */
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
    /* XPN device: also add MACSEC_SA_ATTR_SSCI (s->ssci) and
     * MACSEC_SA_ATTR_SALT (12 octets derived from the SAK), and send PN as a
     * u64. */
    (void)nl_put(n, (int)sizeof u, MACSEC_SA_ATTR_ACTIVE, &active,
        (int)sizeof active);
    nl_nest_end(n, sa);

    return nl_send_ack(s, n);
}

/* Set an SA's ACTIVE flag (transmit when sci == NULL, else a receive SA). */
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

/* ----------------------------------------------------------- MkaSecyOps hooks
 */

/* The macsec netdevice already is the transmit Secure Channel. */
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
    (void)sci; /* the transmit SC is the device itself */
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

/* The kernel device's cipher suite is fixed at creation and the confidentiality
 * offset is not exposed by the genl API; record the SSCI for XPN SA setup and
 * warn on a mismatch the integrator must resolve at `ip link add` time. */
static int secy_set_cipher_suite(void* ctx, const uint8_t* sci, uint64_t cs,
    uint32_t ssci, uint8_t conf_offset)
{
    SecyMacsec* s = (SecyMacsec*)ctx;
    (void)sci;
    s->ssci = ssci;
    if (conf_offset != 0U) {
        printf("[secy] note: confidentiality offset %u not programmable on "
               "Linux macsec (ignored)\n",
            (unsigned int)conf_offset);
    }
    if ((cs != MACSEC_CIPHER_ID_GCM_AES_128) &&
        (cs != MACSEC_DEFAULT_CIPHER_ID)) {
        /* Print the 64-bit cipher ID as two 32-bit halves: C89 has no portable
         * 64-bit printf length modifier (no 'll'). */
        printf("[secy] note: device must have been created with cipher "
               "0x%08lx%08lx\n",
            (unsigned long)(cs >> 32), (unsigned long)(cs & 0xFFFFFFFFU));
    }
    return 0;
}

/* Fill an MkaSecyOps wired to this driver. The PN/XPN read-back hooks are left
 * NULL (a full driver would implement them via MACSEC_CMD_GET_TXSC). */
static MkaSecyOps secy_macsec_linux_ops(SecyMacsec* s)
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
    ops.set_cipher_suite = secy_set_cipher_suite;
    ops.ctx = s;
    return ops;
}

/* Open the genetlink socket, resolve the macsec family and the netdevice. */
static int secy_macsec_linux_init(SecyMacsec* s, const char* ifname)
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
        perror("bind");
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }
    s->family = nl_resolve(s, "macsec");
    if (s->family < 0) {
        fprintf(stderr,
            "macsec genl family not found (is the module loaded?)\n");
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }
    s->ifindex = if_nametoindex(ifname);
    if (s->ifindex == 0U) {
        fprintf(stderr, "interface '%s' not found\n", ifname);
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }
    return 0;
}

static void secy_macsec_linux_free(SecyMacsec* s)
{
    if (s->fd >= 0) {
        (void)close(s->fd);
        s->fd = -1;
    }
}

/* ------------------------------------------------------------------ demo ----
 */
static int parse_sci(const char* hex, uint8_t out[MKA_SCI_LEN])
{
    size_t i;
    for (i = 0U; i < MKA_SCI_LEN; i++) {
        unsigned int v;
        if (sscanf(&hex[i * 2U], "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char** argv)
{
    SecyMacsec s;
    MkaSecyOps ops;
    uint8_t peer_sci[MKA_SCI_LEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00,
        0x01};
    uint8_t rx_key[16];
    uint8_t tx_key[16];
    int rc = 0;

    if (argc < 2) {
        printf("usage: %s <macsec-ifname> [peer-sci-hex-16]\n", argv[0]);
        return 1;
    }
    if ((argc >= 3) && (parse_sci(argv[2], peer_sci) != 0)) {
        printf("peer SCI must be 16 hex digits (8 octets)\n");
        return 1;
    }
    (void)memset(rx_key, 0x11, sizeof rx_key);
    (void)memset(tx_key, 0x22, sizeof tx_key);

    if (secy_macsec_linux_init(&s, argv[1]) != 0) {
        return 1;
    }
    ops = secy_macsec_linux_ops(&s);
    printf("driving SecY hooks on %s (ifindex %u)\n", argv[1], s.ifindex);

    /* Exercise the hooks exactly as wolfMKA's KaY would on a fresh SAK. */
    #define STEP(call, what)                                                   \
        do {                                                                   \
            int e = (call);                                                    \
            printf("  %-24s -> %d%s\n", (what), e, (e == 0) ? " (ok)" : "");   \
            if (e != 0) {                                                      \
                rc = 1;                                                        \
            }                                                                  \
        } while (0)

    STEP(ops.create_rx_sc(ops.ctx, peer_sci), "create_rx_sc(peer)");
    STEP(
        ops.set_cipher_suite(ops.ctx, peer_sci, MKA_CIPHER_GCM_AES_128, 0U, 0U),
        "set_cipher_suite");
    STEP(ops.install_rx_sa(ops.ctx, peer_sci, 0U, 1U, rx_key, sizeof rx_key),
        "install_rx_sa");
    STEP(ops.enable_receive(ops.ctx, peer_sci, 0U, true), "enable_receive");
    STEP(ops.install_tx_sa(ops.ctx, peer_sci, 0U, 1U, tx_key, sizeof tx_key),
        "install_tx_sa");
    STEP(ops.enable_transmit(ops.ctx, 0U, true), "enable_transmit");

    /* Tear the SAs down again (rekey / shutdown path). */
    STEP(ops.delete_sa(ops.ctx, peer_sci, 0U), "delete_sa(rx)");
    STEP(ops.delete_sa(ops.ctx, NULL, 0U), "delete_sa(tx)");

    #undef STEP
    secy_macsec_linux_free(&s);
    printf("%s\n", (rc == 0) ? "all SecY operations succeeded"
                             : "some operations failed (see results above)");
    return rc;
}

#endif /* __linux__ */
