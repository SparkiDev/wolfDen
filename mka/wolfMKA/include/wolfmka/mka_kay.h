/* mka_kay.h
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
 * The KaY (Key Agreement Entity) - the MKA protocol engine of IEEE Std
 * 802.1X-2010, Clause 9. A participant runs MKA for a single Connectivity
 * Association (one CKN/CAK) on one port. It:
 *
 *   - discovers peers and tracks liveness (9.4.3),
 *   - elects a Key Server (9.5),
 *   - when Key Server, generates and distributes SAKs (9.8),
 *   - installs agreed SAKs into the SecY data plane (Clause 10),
 *   - emits MKPDUs - periodically, and (with immediate_response configured) as
 *     soon as it has new information to report - and processes received ones.
 *
 * Time is supplied by the caller as a monotonic millisecond clock so the engine
 * has no platform dependencies. Outbound MKPDUs go through a send callback;
 * inbound frames are fed in via wm_Participant_Receive().
 */

#ifndef WOLFMKA_KAY_H
#define WOLFMKA_KAY_H

#include "mka_types.h"
#include "mka_pdu.h"
#include "mka_secy.h"
#include "mka_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WOLFMKA_SUSPENSION) && defined(WOLFMKA_NO_XPN)
    #error                                                                     \
        "WOLFMKA_SUSPENSION requires XPN: the MKA Suspension Time is carried \
in the XPN parameter set, so do not combine it with WOLFMKA_NO_XPN."
#endif

#if defined(WOLFMKA_CIPHER_NEGOTIATION) && defined(WOLFMKA_NO_ANNOUNCEMENTS)
    #error                                                                     \
        "WOLFMKA_CIPHER_NEGOTIATION requires the Announcement parameter set, \
which carries the peers' cipher suites; do not combine it with \
WOLFMKA_NO_ANNOUNCEMENTS."
#endif

#if defined(WOLFMKA_CIPHER_NEGOTIATION) && defined(WOLFMKA_AUTOMOTIVE_PROFILE)
    #error                                                                     \
        "WOLFMKA_AUTOMOTIVE_PROFILE removes Secure Announcements and cipher- \
suite negotiation (OPEN Alliance AutoMKA-11001); do not combine it with \
WOLFMKA_CIPHER_NEGOTIATION."
#endif

/* Default MKA timers (IEEE Std 802.1X-2010, 9.16 / Table 9-3). Each may be
 * overridden at build time (e.g. -DMKA_HELLO_TIME_MS=1000); keep the Life Time
 * at roughly three Hello Times so a peer is not expired prematurely. */
#ifndef MKA_HELLO_TIME_MS
    /* MKA Hello Time */
    #define MKA_HELLO_TIME_MS 2000u
#endif
#ifndef MKA_LIFE_TIME_MS
    /* MKA Life Time (3 x hello) */
    #define MKA_LIFE_TIME_MS 6000u
#endif
#ifndef MKA_BOUNDED_HELLO_TIME_MS
    /* used when delay protection is on */
    #define MKA_BOUNDED_HELLO_TIME_MS 500u
#endif
/* Key Server priority values the OPEN Alliance profile makes absolute
 * (AutoMKA-03007): 0 always serves, 255 never does. 0 needs no special handling
 * - it is the lowest value, so the ordinary "lowest priority wins" comparison
 * of IEEE Std 802.1X-2010 9.5 already makes it win - but 255 does, since the
 * base standard treats it as merely the least preferred. Honoured only under
 * WOLFMKA_AUTOMOTIVE_PROFILE; elsewhere 255 stays an ordinary low preference
 * and `key_server_capable` is how a participant declines the role. */
#define MKA_PRIORITY_ALWAYS_KS 0U
#define MKA_PRIORITY_NEVER_KS  255U

#ifndef MKA_MN_RECENT_WINDOW
    /* How many of the most recently emitted Message Numbers count as
     * "acceptably recent" when a peer echoes one back to prove liveness
     * (IEEE Std 802.1X-2010, 9.4.3). The standard leaves the depth open; the
     * OPEN Alliance profile fixes it at the last three MKPDUs emitted
     * (AutoMKA-03005), which is the default here. A window of 1 accepts only
     * the newest emitted MN and is the strictest useful setting. */
    #define MKA_MN_RECENT_WINDOW 3U
#endif
#ifndef MKA_AUTOMOTIVE_RETRY_BASE_MS
    /* First step of the startup ramp wm_Participant_AutomotiveDefaults()
     * installs; it doubles from here to MKA_HELLO_TIME_MS (OPEN Alliance
     * AutoMKA-03004 proposes 10, 20, 40 ms ... 2 s). */
    #define MKA_AUTOMOTIVE_RETRY_BASE_MS 10u
#endif

/* Scratch buffer size for an outgoing MKPDU. Override at build time if needed
 * (e.g. to fit a larger MKA_MAX_PEERS); wm_Pdu_Encode returns
 * MKA_ERR_BUFFER if the frame to encode exceeds this. */
#ifndef MKA_MKPDU_MAX_LEN
    #define MKA_MKPDU_MAX_LEN 516U
#endif

/* Transmit callback: hand a complete EAPOL-MKA frame to the network.
 * Returns 0 on success. */
typedef int (*MkaSendFn)(void* ctx, const uint8_t* frame, size_t len);

/* One known peer in the Connectivity Association. Fields are ordered by
 * descending alignment to minimise padding. */
typedef struct {
    /* last Message Number seen */
    uint32_t mn;
    uint32_t last_seen_ms;
    /* KN this peer reports installed */
    uint32_t latest_kn;
    /* peer's reported lowest accept PN */
    uint32_t latest_lpn;
    /* XPN: MSBs of that PN (11.11.6) */
    uint32_t latest_lpn_msb;
#ifdef WOLFMKA_CIPHER_NEGOTIATION
    /* cipher suites this peer last announced (Announcement set); adv_count 0
     * means the peer sent no Announcement, so it constrains no suite. */
    uint64_t adv_suites[MKA_MAX_CIPHER_SUITES];
    uint8_t adv_count;
#endif
    uint8_t mi[MKA_MI_LEN];
    uint8_t sci[MKA_SCI_LEN];
    /* advertised Key Server priority */
    uint8_t priority;
    uint8_t macsec_capability;
    bool valid;
    /* in our Live Peer List vs Potential */
    bool live;
    /* advertised Key Server flag */
    bool key_server;
    bool macsec_desired;
    /* mn holds an accepted value yet */
    bool mn_seen;
    /* peer is receiving on its latest key */
    bool sak_rx;
    /* peer is transmitting on it */
    bool sak_tx;
    /* this peer has reported using the SAK now in force; if it later stops,
     * the key is gone at its end and the Key Server rekeys */
    bool sak_use_seen;
#ifdef WOLFMKA_SUSPENSION
    /* MKA Suspension Time this peer last advertised (s) */
    uint8_t suspend_for;
#endif
} MkaPeer;

/*
 * Key Server role selection. MKA_ROLE_AUTO runs the dynamic election of IEEE
 * Std 802.1X-2010 (9.5). The fixed roles bypass election and pin the outcome,
 * as required by AUTOSAR CP (CP_SWS_Mka_00011): the Key Server is configured,
 * not negotiated.
 */
typedef enum {
    /* dynamic election (default) */
    MKA_ROLE_AUTO = 0,
    /* fixed Key Server */
    MKA_ROLE_KEY_SERVER = 1,
    /* fixed non-Key-Server */
    MKA_ROLE_PEER = 2
} MkaRole;

/**
 * Optional asynchronous event notifications (management / observability).
 *
 * Every hook is optional - leave it NULL to ignore that event. Hooks fire
 * synchronously from within wm_Participant_Run / wm_Participant_Receive
 * the moment the state changes, so a handler MUST NOT re-enter the same
 * participant (i.e. must not call any wm_Participant_* / wm_Kay_* on it).
 * The data plane is driven separately through MkaSecyOps; these hooks are for
 * logging, status reporting and controlled-port policy, not key installation.
 */
typedef struct MkaEventOps {
    /** A new peer was added to the table (first MKPDU seen from its MI). */
    void (*peer_added)(void* ctx, const uint8_t mi[MKA_MI_LEN],
        const uint8_t sci[MKA_SCI_LEN]);
    /** A peer became live - bidirectional connectivity proven (9.4.3). */
    void (*peer_live)(void* ctx, const uint8_t mi[MKA_MI_LEN]);
    /** A peer was removed; was_live is true if it had been live. */
    void (*peer_lost)(void* ctx, const uint8_t mi[MKA_MI_LEN], bool was_live);
    /** The elected Key Server changed; is_self is true when it is us. */
    void (*key_server_elected)(void* ctx, const uint8_t sci[MKA_SCI_LEN],
        bool is_self);
    /** A SAK became the participant's Latest key (initial key or rekey).
     * Raised when the key is adopted, which is not necessarily when the SecY
     * has it: under distribute_before_install the data plane is programmed
     * afterwards, and a SecY that returns MKA_SECY_PENDING finishes later
     * still. Use macsec_up for the point at which protection is running. */
    void (*sak_installed)(void* ctx, uint32_t kn, uint8_t an,
        uint64_t cipher_suite);
    /** Transmit protection was enabled on the Latest key. */
    void (*macsec_up)(void* ctx, uint32_t kn, uint8_t an);
    /** A received MKPDU failed ICV verification. */
    void (*auth_fail)(void* ctx);
#ifdef WOLFMKA_DISTRIBUTED_CAK
    /** A group CAK was distributed to us by the Key Server and unwrapped
     * (Distributed CAK, parameter set type 5). cak/ckn are the plaintext group
     * CAK and its name; the integrator typically starts a new CA for it with
     * wm_Kay_AddParticipant. The pointers are valid only for this call. */
    void (*cak_received)(void* ctx, const uint8_t* cak, size_t cak_len,
        const uint8_t* ckn, size_t ckn_len);
#endif
    /** Opaque context passed to every event callback. */
    void* ctx;
} MkaEventOps;

/* Fields are ordered by descending alignment to minimise padding. */
typedef struct {
    /* CAK / CKN for this CA */
    MkaCakPair cak;
    /* 0 => GCM-AES-128; or MKA_CIPHER_* */
    uint64_t cipher_suite;
#ifdef WOLFMKA_CIPHER_NEGOTIATION
    /* Optional Key Server cipher-suite preference list, most preferred first
     * (caller-owned, up to MKA_MAX_CIPHER_SUITES entries). When
     * cipher_pref_count is non-zero, the Key Server selects the first suite
     * every live peer accepts (a peer accepts a suite it announced, or any
     * suite when it sends no Announcement); the choice drives the SAK length.
     * When 0, cipher_suite / sak_len are used unchanged. */
    const uint64_t* cipher_prefs;
#endif
    /* data-plane hooks (any may be NULL) */
    MkaSecyOps secy;
    /* async event hooks (any may be NULL) */
    MkaEventOps events;
    /* transmit callback */
    MkaSendFn send;
    void* send_ctx;
    /* RNG from wm_Crypto_RandomInit; NULL seeds one per use */
    MkaRandom* rng;
    /* CMAC workspace from wm_Crypto_CmacInit; keeps the wolfSSL Cmac off the
     * stack and out of any allocation. Required (non-NULL): the participant
     * uses it for ICV and key derivation, and wolfMKA never falls back to a
     * stack or heap context. */
    MkaCmacCtx* cmac;

    /* AUTO (elect) or a fixed role */
    MkaRole role;
    /* Key Server auto-rekey period; 0 off */
    uint32_t sak_rekey_time_ms;
#ifndef WOLFMKA_NO_RETRY
    /* MKA retry base delay; 0 disables */
    uint32_t retry_base_ms;
    /* retry back-off ceiling */
    uint32_t retry_cyclic_ms;
#endif

    /* our SCI (MAC || port) */
    uint8_t sci[MKA_SCI_LEN];
    /* our Key Server priority */
    uint8_t priority;
    /* MkaMacsecCapability */
    uint8_t macsec_capability;
    /* SAK size to generate (16 or 32) */
    uint8_t sak_len;
    /* MkaConfidentialityOffset advertised in the Distributed SAK (Key Server)
     */
    uint8_t confidentiality_offset;
#ifdef WOLFMKA_CIPHER_NEGOTIATION
    /* number of entries in cipher_prefs (0 disables negotiation) */
    uint8_t cipher_pref_count;
#endif
    bool macsec_desired;
    /* may we become Key Server? */
    bool key_server_capable;
    /* enable MACsec delay protection */
    bool delay_protect;
    /* Transmit on the next wm_Participant_Run() when this participant has new
     * information to report, instead of waiting out the Hello Time - the
     * newInfo behaviour of IEEE Std 802.1X-2010, 9.4 (OPEN Alliance
     * AutoMKA-03003). New information is any of:
     *   - a peer entering the Potential Peer List, becoming live, or expiring;
     *   - a SAK installed (the MACsec SAK Use set now names a different key);
     *   - the transmit gate releasing onto the Latest key.
     * The last two are what let a CA finish the SAK Use handshake without a
     * Hello Time between each step, so both ends bring MACsec up promptly.
     * Off by default, leaving the transmit cadence purely periodic; the
     * automotive profile turns it on (see wm_Participant_AutomotiveDefaults).
     */
    bool immediate_response;
    /* Put a newly adopted SAK on the wire before programming it into the SecY,
     * so both ends start installing at the same moment instead of one after the
     * other (OPEN Alliance AutoMKA-03010). Worth setting when the SecY is slow
     * to program - an external PHY behind a narrow management interface - and
     * immaterial otherwise. Off by default, which programs first; the
     * automotive profile defaults turn it on.
     *
     * Only the Key Server defers: a member has nothing to distribute early, and
     * a member that held its data plane back would stop reporting itself as
     * receiving, which the Key Server reads as a lost key (AutoMKA-03011).
     *
     * Safe either way: while programming is outstanding the MACsec SAK Use does
     * not report this participant as receiving on the key, so no peer takes it
     * as leave to send protected frames the data plane could not yet decrypt.
     */
    bool distribute_before_install;
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    /* emit Announcement set (type 7) */
    bool announce_cipher_suites;
#endif
#ifdef WOLFMKA_KMD
    /* Key Management Domain to advertise (KS) */
    uint8_t kmd[MKA_MAX_KMD_LEN];
    /* 0 => do not advertise a KMD */
    size_t kmd_len;
#endif
} MkaParticipantConfig;

/* One installed Secure Association Key. During a rekey both a Latest and an Old
 * key are installed at once (make-before-break, IEEE Std 802.1X-2010, 9.x). */
typedef struct {
    size_t sak_len;
    /* Key Number */
    uint32_t kn;
    uint8_t sak[MKA_MAX_CAK_LEN];
    /* Association Number */
    uint8_t an;
    bool valid;
    /* transmitting on this key */
    bool tx;
} MkaSak;

/* Read-only snapshot of a tracked peer, returned by wm_Participant_GetPeer.
 */
typedef struct {
    /* peer Member Identifier */
    uint8_t mi[MKA_MI_LEN];
    /* peer Secure Channel Identifier */
    uint8_t sci[MKA_SCI_LEN];
    /* last Message Number seen from the peer */
    uint32_t mn;
    /* advertised Key Server priority */
    uint8_t priority;
    /* in our Live Peer List (proven bidirectional) */
    bool live;
    /* advertises the Key Server flag */
    bool key_server;
    /* advertises MACsec Desired */
    bool macsec_desired;
} MkaPeerInfo;

/* Read-only snapshot of the in-force SAK, returned by wm_Participant_GetSak.
 */
typedef struct {
    /* a Latest SAK is installed */
    bool valid;
    /* Latest Key Number */
    uint32_t kn;
    /* Latest Association Number */
    uint8_t an;
    /* SAK length in octets */
    size_t sak_len;
    /* transmitting on the Latest key */
    bool tx;
    /* cipher suite in force (MKA_CIPHER_*) */
    uint64_t cipher_suite;
} MkaSakInfo;

/**
 * Overall state of one participant, as reported by wm_Participant_GetPaeStatus.
 *
 * These are the states of the OPEN Alliance management interface
 * (AutoMKA-07008), which is why the set is coarser than the internal state the
 * accessors expose individually.
 */
typedef enum {
    /* MACsec and/or MKA is not in use on this participant */
    MKA_PAE_UNDEFINED = 0,
    /* Waiting for the underlying link. Never reported by wolfMKA, which has no
     * view of link state; an integrator that gates on link up reports it. */
    MKA_PAE_WAITING_FOR_LINK_UP = 1,
    /* No peer has been heard from yet */
    MKA_PAE_WAITING_FOR_PEER = 2,
    /* A peer is known; discovery, election or key agreement is under way */
    MKA_PAE_IN_PROGRESS = 3,
    /* A SAK is agreed and MACsec is transmitting */
    MKA_PAE_RUNNING = 4,
    /* MKPDUs are arriving but failing ICV verification: the peer holds a
     * different CAK, so no peer can be established */
    MKA_PAE_AUTH_FAIL_UNKNOWN_PEER = 5
} MkaPaeState;

/* Participant status, returned by wm_Participant_GetPaeStatus. */
typedef struct {
    /* the CAK Name this participant runs */
    uint8_t ckn[MKA_MAX_CKN_LEN];
    size_t ckn_len;
    /* cipher suite in force; 0 unless the state is MKA_PAE_RUNNING */
    uint64_t cipher_suite;
    /* the peer's SCI, or all zero when there is no peer */
    uint8_t peer_sci[MKA_SCI_LEN];
    MkaPaeState state;
} MkaPaeStatus;

/* MKA protocol counters, returned by wm_Participant_GetCounters. */
typedef struct {
    /* MKPDUs received that passed ICV verification */
    uint32_t mkpdu_in;
    /* MKPDUs built for transmission */
    uint32_t mkpdu_out;
    /* received MKPDUs that failed ICV verification */
    uint32_t icv_failures;
    /* SAKs adopted as the Latest key (initial key + rekeys) */
    uint32_t sak_installs;
} MkaCounters;

/* Fields are ordered by descending alignment to minimise padding. The SAK
 * state (latest/old) is the in-use key and, during a rekey, the key being
 * retired. */
typedef struct {
    MkaParticipantConfig cfg;
    /* derived KEK / ICK */
    MkaDerivedKeys keys;
    MkaSak latest;
    MkaSak old;
    /* cipher suite in force for the SAK */
    uint64_t sak_cipher_suite;
    /* MKA protocol counters */
    MkaCounters counters;
    size_t peer_count;
    /* confidentiality offset in force for the SAK */
    uint8_t sak_conf_offset;
#ifdef WOLFMKA_CIPHER_NEGOTIATION
    /* the SAK is used integrity-only: a member of the CA cannot do
     * confidentiality (its MACsec Capability is below INTEGRITY_CONF). */
    bool sak_integrity_only;
#endif

    MkaPeer peers[MKA_MAX_PEERS];
    /* our Message Number */
    uint32_t actor_mn;
    /* when we last sent an MKPDU */
    uint32_t last_tx_ms;
    /* when the Latest SAK was generated */
    uint32_t last_rekey_ms;
#ifndef WOLFMKA_NO_RETRY
    /* current MKA retry back-off interval */
    uint32_t retry_delay_ms;
#endif

    /* our Member Identifier */
    uint8_t actor_mi[MKA_MI_LEN];
    /* elected Key Server's SCI */
    uint8_t ks_sci[MKA_SCI_LEN];
    /* held silent because another CA on this KaY has MACsec up
     * (wm_Kay_SetQuiesceOthers); set by wm_Kay_Run, never by the participant */
    bool quiesced;
    /* a peer that was using the SAK has stopped reporting it, so the Key
     * Server rekeys to bring it back (see mka_note_sak_use) */
    bool sak_lost;
    /* the Latest key is adopted but not yet programmed into the SecY: it goes
     * out on the wire first (cfg.distribute_before_install) */
    bool sak_program_pending;
    /* something worth announcing has happened since the last MKPDU (a peer
     * list changed, a SAK was installed, or the transmit gate released). With
     * cfg.immediate_response the next wm_Participant_Run() transmits rather
     * than waiting for the interval; cleared by that transmit. */
    bool new_info;
    /* election has produced a result */
    bool elected;
    /* are we the elected Key Server? */
    bool is_key_server;
    bool started;
    /* count of SecY ops awaiting async completion */
    unsigned secy_pending;
#ifdef WOLFMKA_DISTRIBUTED_CAK
    /* group CAK staged for distribution */
    uint8_t dist_cak[MKA_MAX_CAK_LEN];
    /* its CAK Name */
    uint8_t dist_ckn[MKA_MAX_CKN_LEN];
    /* 0 => nothing staged to distribute */
    size_t dist_cak_len;
    size_t dist_ckn_len;
#endif
#ifdef WOLFMKA_KMD
    /* last Key Management Domain received */
    uint8_t rx_kmd[MKA_MAX_KMD_LEN];
    /* 0 => none received */
    size_t rx_kmd_len;
#endif
#ifdef WOLFMKA_SUSPENSION
    /* MKA suspended (announce, then go quiet) */
    bool suspended;
    /* a suspension announcement is still pending */
    bool suspend_announce;
    /* MKA Suspension Time we advertise (s) */
    uint8_t suspend_for;
#endif

#if defined(WOLFMKA_SMALL_STACK) && defined(WOLFMKA_NO_MALLOC)
    /* Off-stack scratch storage for the small-stack, no-malloc build: the large
     * MKPDU working set lives in the participant object instead of on the stack
     * or the heap. */
    MkaPdu ws_pdu;
    uint8_t ws_frame[MKA_MKPDU_MAX_LEN];
#endif
} MkaParticipant;

/**
 * Initialise a participant from its configuration.
 *
 * Derives KEK/ICK from the CAK, generates a random actor MI, and sets MN to 1.
 *
 * @param[out] p    The participant to initialise.
 * @param[in]  cfg  The configuration (CAK/CKN, SCI, priority, SecY hooks, ...).
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p or cfg is NULL, cfg->sak_len is not 16 or 32, or
 *         cfg->cipher_suite is unsupported or inconsistent with sak_len;
 *         MKA_ERR_CRYPTO if key derivation or MI generation fails.
 */
MkaStatus wm_Participant_Init(MkaParticipant* p,
    const MkaParticipantConfig* cfg);

/**
 * Apply the OPEN Alliance TC17 Automotive MKA timing defaults to a config.
 *
 * Sets the fields the profile fixes and leaves everything else (CAK/CKN, SCI,
 * priority, SecY hooks, ...) untouched, so it is called on a partly filled
 * configuration before wm_Participant_Init():
 *
 *   - immediate_response = true, so new information (a peer-list change, a
 *     newly installed SAK, or the transmit gate releasing) is announced at
 *     once rather than at the next Hello Time (AutoMKA-03003, AutoMKA-01015);
 *   - retry_base_ms / retry_cyclic_ms = 10 ms / the Hello Time, giving the
 *     doubling 10, 20, 40 ms ... ramp up to the nominal rate (AutoMKA-03004).
 *     Omitted in a WOLFMKA_NO_RETRY build, which has no ramp;
 *   - distribute_before_install = true, so a new SAK reaches the peer before
 *     this end programs it and both install together (AutoMKA-03010).
 *
 * Together these are what bring link establishment under the profile's startup
 * budget; the rest of the profile is either compiled in by
 * WOLFMKA_AUTOMOTIVE_PROFILE or is the integrator's to supply (see
 * OPEN-ALLIANCE.md). Available in every build - the profile macro is not
 * required to use these settings.
 *
 * @param[in,out] cfg  the configuration to update.
 * @return MKA_OK, or MKA_ERR_BAD_ARG if cfg is NULL.
 */
MkaStatus wm_Participant_AutomotiveDefaults(MkaParticipantConfig* cfg);

/**
 * Summarise the participant's state for a management or diagnostics interface.
 *
 * Collapses what the individual accessors expose into the single status the
 * OPEN Alliance profile asks for (AutoMKA-07008): the state, the peer's SCI,
 * the CKN in use, and the cipher suite once running.
 * MKA_PAE_WAITING_FOR_LINK_UP is never returned - wolfMKA has no view of link
 * state, so an integrator that gates MKA on the link reports that itself.
 * @param[in]  p    The participant.
 * @param[out] out  Receives the status.
 * @return MKA_OK on success, or MKA_ERR_BAD_ARG if p or out is NULL.
 */
MkaStatus wm_Participant_GetPaeStatus(const MkaParticipant* p,
    MkaPaeStatus* out);

/**
 * Read the port's MACsec statistics from the SecY.
 *
 * wolfMKA keeps no MACsec counters of its own - they belong to the data plane -
 * so this simply drives MkaSecyOps.get_secy_stats. It exists so a management or
 * diagnostics interface can reach them through the same object it already holds
 * (OPEN Alliance AutoMKA-07009). For wolfMKA's own protocol counters, see
 * wm_Participant_GetCounters().
 * @param[in]  p    The participant.
 * @param[out] out  Receives the statistics.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p or out is NULL;
 *         MKA_ERR_STATE if no get_secy_stats hook is configured;
 *         MKA_ERR_INTERNAL if the hook reports failure.
 */
MkaStatus wm_Participant_GetSecyStats(const MkaParticipant* p,
    MkaSecyStats* out);

/**
 * Read the statistics of our transmit Secure Channel.
 * @param[in]  p    The participant (its SCI identifies the channel).
 * @param[out] out  Receives the statistics.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p or out is NULL;
 *         MKA_ERR_STATE if no get_tx_sc_stats hook is configured;
 *         MKA_ERR_INTERNAL if the hook reports failure.
 */
MkaStatus wm_Participant_GetTxScStats(const MkaParticipant* p,
    MkaTxScStats* out);

/**
 * Read the statistics of one peer's receive Secure Channel.
 *
 * Peers are indexed as by wm_Participant_GetPeer(), so an enumeration walks
 * both with the same index.
 * @param[in]  p      The participant.
 * @param[in]  index  Zero-based peer index.
 * @param[out] out    Receives the statistics.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p or out is NULL;
 *         MKA_ERR_NO_PEER if index is past the last peer;
 *         MKA_ERR_STATE if no get_rx_sc_stats hook is configured;
 *         MKA_ERR_INTERNAL if the hook reports failure.
 */
MkaStatus wm_Participant_GetRxScStats(const MkaParticipant* p, size_t index,
    MkaRxScStats* out);

/**
 * Tear down a participant when it is no longer needed.
 *
 * Deletes any installed SecY SAs so the data plane keeps no SAK, then securely
 * zeroes all key material (CAK, derived KEK/ICK, SAKs) held in the object.
 * @param[in,out] p  The participant to free (may be NULL).
 */
void wm_Participant_Free(MkaParticipant* p);

/**
 * Process a received EAPOL-MKA frame.
 *
 * Verifies the ICV, updates peer liveness, and acts on any distributed SAK.
 * Frames for a different CKN, replays, or bad ICVs are rejected.
 *
 * @param[in,out] p       The participant.
 * @param[in]     frame   The received frame.
 * @param[in]     len     Length of the frame in octets.
 * @param[in]     now_ms  Current monotonic time in milliseconds.
 * @return MKA_OK on success or for an ignored loopback/foreign-CKN frame;
 *         MKA_ERR_BAD_ARG if p or frame is NULL;
 *         MKA_ERR_INTERNAL if the working buffer cannot be allocated;
 *         MKA_ERR_PARSE or MKA_ERR_VERSION for a malformed/unsupported frame;
 *         MKA_ERR_ICV if ICV verification fails;
 *         MKA_ERR_REPLAY for a stale/duplicate Message Number;
 *         MKA_ERR_NO_PEER for a foreign CKN, MKA_ERR_FULL if the peer table is
 *         full, or MKA_ERR_CRYPTO if installing a distributed SAK fails.
 */
MkaStatus wm_Participant_Receive(MkaParticipant* p, const uint8_t* frame,
    size_t len, uint32_t now_ms);

/**
 * Periodic engine step.
 *
 * Expires dead peers, runs Key Server election, generates and distributes a SAK
 * when Key Server, and transmits an MKPDU on the first call and then once per
 * transmit interval - the Hello Time, the Bounded Hello Time under delay
 * protection, or the retry back-off while no peer is live. With
 * MkaParticipantConfig.immediate_response set, it also transmits as soon as
 * there is new information to report, without waiting for that interval.
 *
 * Call it regularly (the loop's tick); it is cheap when nothing is due.
 *
 * @param[in,out] p       The participant.
 * @param[in]     now_ms  Current monotonic time in milliseconds.
 * @param[out]    sent    Optional; set to true if an MKPDU was transmitted,
 *                        else false.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p is NULL;
 *         MKA_ERR_CRYPTO if SAK generation or MKPDU building fails;
 *         MKA_ERR_INTERNAL if a working buffer cannot be allocated.
 */
MkaStatus wm_Participant_Run(MkaParticipant* p, uint32_t now_ms, bool* sent);

/**
 * Report completion of an asynchronous SecY operation.
 *
 * A SecY backend that programs the data plane asynchronously returns
 * MKA_SECY_PENDING from a callback and later calls this once per pending
 * operation. While any operation is outstanding the KaY holds back enabling
 * transmit protection; the final completion releases that gate. A purely
 * synchronous backend never returns MKA_SECY_PENDING and need not call this.
 *
 * No result is taken: like the synchronous path, the engine does not react to a
 * failed install (it has no recovery path), so the operation is simply cleared
 * as no-longer-outstanding. The integrator's SecY hooks must be fail-safe in
 * themselves - see FMEA.md FM-06. (Propagating SecY failures into the engine
 * remains a deliberate future enhancement, not dead API surface here.)
 *
 * @param[in,out] p  The participant the operation was issued for.
 * @return MKA_OK, or MKA_ERR_BAD_ARG if p is NULL.
 */
MkaStatus wm_Participant_SecyComplete(MkaParticipant* p);

/**
 * Request a SAK rekey (Key Server only).
 *
 * Generates a fresh SAK and begins a make-before-break handover: the current
 * key becomes the Old key and stays installed for in-flight traffic until every
 * peer has moved to the new Latest key. Call e.g. when the SecY reports the
 * transmit packet number nearing exhaustion.
 *
 * The new key is programmed into the SecY before it is distributed, unless
 * distribute_before_install reverses that; either way it returns as soon as the
 * key is generated, and the handover completes over the following runs.
 *
 * @param[in,out] p  The participant.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p is NULL;
 *         MKA_ERR_NOT_KS if the participant is not the Key Server;
 *         MKA_ERR_CRYPTO if SAK generation fails.
 */
MkaStatus wm_Participant_Rekey(MkaParticipant* p);

#ifdef WOLFMKA_SUSPENSION
/**
 * Suspend MKA for a planned brief interruption (802.1Xbx-2014), without tearing
 * down the Connectivity Association or its Secure Associations.
 *
 * The participant advertises the suspension time once (in the XPN parameter
 * set's MKA Suspension Time field), then stops transmitting MKPDUs. Peers that
 * receive the announcement hold this participant's state - they do not expire
 * it for `seconds` beyond the normal Life Time - so keys survive the gap.
 * Effective only while an XPN cipher suite and an installed SAK provide the XPN
 * set that carries the time; otherwise the announcement does not reach peers.
 *
 * @param[in,out] p        the participant.
 * @param[in]     seconds  the suspension time to advertise (0..255).
 * @return MKA_OK, or MKA_ERR_BAD_ARG if p is NULL.
 */
MkaStatus wm_Participant_Suspend(MkaParticipant* p, uint8_t seconds);

/**
 * Resume MKA after a suspension: clear the suspended state and the advertised
 * suspension time, so periodic transmission and normal expiry resume.
 * @param[in,out] p  the participant.
 * @return MKA_OK, or MKA_ERR_BAD_ARG if p is NULL.
 */
MkaStatus wm_Participant_Resume(MkaParticipant* p);
#endif /* WOLFMKA_SUSPENSION */

#ifdef WOLFMKA_DISTRIBUTED_CAK
/**
 * Stage a group CAK to distribute to this CA's members (Key Server only).
 *
 * While staged, the CAK is AES-Key-Wrapped with this CA's KEK and emitted as a
 * Distributed CAK parameter set (type 5) in every MKPDU the Key Server builds,
 * until a different CAK is staged. Each member that receives it unwraps the CAK
 * and reports it through the `cak_received` event; the member's integrator then
 * decides whether to start a new CA (group CA) for it. Only the elected Key
 * Server actually emits the set.
 *
 * @param[in,out] p        The participant (must be/become this CA's Key
 * Server).
 * @param[in]     cak      The group CAK to distribute (16 or 32 octets).
 * @param[in]     cak_len  CAK length in octets (16 or 32).
 * @param[in]     ckn      The CAK Name of the group CAK.
 * @param[in]     ckn_len  CKN length in octets (1..MKA_MAX_CKN_LEN).
 * @return MKA_OK, or MKA_ERR_BAD_ARG on a NULL pointer or invalid length.
 */
MkaStatus wm_Participant_DistributeCak(MkaParticipant* p, const uint8_t* cak,
    size_t cak_len, const uint8_t* ckn, size_t ckn_len);
#endif /* WOLFMKA_DISTRIBUTED_CAK */

/**
 * Build (but do not send) the current MKPDU into out.
 *
 * Increments the actor Message Number on success.
 *
 * @param[in,out] p        The participant.
 * @param[out]    out      Output buffer.
 * @param[in]     cap      Capacity of out in octets.
 * @param[out]    out_len  Receives the number of octets written.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p, out or out_len is NULL;
 *         MKA_ERR_INTERNAL if the working buffer cannot be allocated;
 *         MKA_ERR_BUFFER if out is too small;
 *         MKA_ERR_CRYPTO if SAK wrapping or ICV computation fails.
 */
MkaStatus wm_Participant_BuildMkpdu(MkaParticipant* p, uint8_t* out, size_t cap,
    size_t* out_len);

/**
 * Number of live peers in the Connectivity Association.
 * @param[in] p  The participant (may be NULL).
 * @return The number of peers in the Live Peer List; 0 if p is NULL.
 */
size_t wm_Participant_LivePeerCount(const MkaParticipant* p);

/**
 * True if this participant is the elected Key Server.
 * @param[in] p  The participant (may be NULL).
 * @return true if elected Key Server; false otherwise (including p == NULL).
 */
bool wm_Participant_IsKeyServer(const MkaParticipant* p);

/**
 * True if a SAK has been installed.
 * @param[in] p  The participant (may be NULL).
 * @return true if a SAK is installed; false otherwise (including p == NULL).
 */
bool wm_Participant_HasSak(const MkaParticipant* p);

/**
 * Number of peers currently tracked (Live plus Potential).
 * @param[in] p  The participant (may be NULL).
 * @return The tracked peer count; 0 if p is NULL.
 */
size_t wm_Participant_PeerCount(const MkaParticipant* p);

/**
 * Read a read-only snapshot of one tracked peer by index.
 *
 * @p index runs 0 .. wm_Participant_PeerCount()-1 over the tracked peers in
 * an unspecified but stable order (until the peer set changes).
 * @param[in]  p      The participant.
 * @param[in]  index  Zero-based index of the peer to read.
 * @param[out] out    Receives the peer snapshot.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p or out is NULL;
 *         MKA_ERR_NO_PEER if index is past the tracked peer count.
 */
MkaStatus wm_Participant_GetPeer(const MkaParticipant* p, size_t index,
    MkaPeerInfo* out);

/**
 * Read the in-force Secure Association Key metadata (no key bytes).
 * @param[in]  p     The participant.
 * @param[out] info  Receives the SAK snapshot; info->valid is false when no SAK
 *                   is installed.
 * @return MKA_OK on success; MKA_ERR_BAD_ARG if p or info is NULL.
 */
MkaStatus wm_Participant_GetSak(const MkaParticipant* p, MkaSakInfo* info);

/**
 * Copy the elected Key Server's SCI.
 * @param[in]  p    The participant.
 * @param[out] sci  Receives the Key Server's SCI (MKA_SCI_LEN octets).
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p or sci is NULL;
 *         MKA_ERR_STATE if no Key Server has been elected yet.
 */
MkaStatus wm_Participant_GetKeyServerSci(const MkaParticipant* p,
    uint8_t sci[MKA_SCI_LEN]);

#ifdef WOLFMKA_KMD
/**
 * Copy the most recently received Key Management Domain (parameter set type 6).
 *
 * The KMD is an informational octet-string name the Key Server advertises; it
 * is authenticated by the MKPDU ICV but otherwise unprocessed by the library -
 * the integrator interprets it (e.g. for domain/connectivity policy).
 * @param[in]  p        the participant.
 * @param[out] kmd      receives the KMD octets.
 * @param[in]  cap      capacity of @p kmd in octets.
 * @param[out] kmd_len  receives the KMD length in octets (0 if none received).
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if p, kmd or kmd_len is NULL;
 *         MKA_ERR_BUFFER if cap is smaller than the received KMD.
 */
MkaStatus wm_Participant_GetKmd(const MkaParticipant* p, uint8_t* kmd,
    size_t cap, size_t* kmd_len);
#endif /* WOLFMKA_KMD */

/**
 * Copy the MKA protocol counters.
 * @param[in]  p    The participant.
 * @param[out] out  Receives the counters.
 * @return MKA_OK on success; MKA_ERR_BAD_ARG if p or out is NULL.
 */
MkaStatus wm_Participant_GetCounters(const MkaParticipant* p, MkaCounters* out);

/* ------------------------------------------------------------------------- */
/* KaY manager: multiple Connectivity Associations on one port               */
/* ------------------------------------------------------------------------- */

/* Maximum number of Connectivity Associations (distinct CKNs) a single KaY
 * runs concurrently on one port. Override at build time if needed. */
#ifndef MKA_MAX_PARTICIPANTS
    #define MKA_MAX_PARTICIPANTS 4U
#endif

/**
 * The KaY of a port. It owns one MKA participant per Connectivity Association
 * (one CAK/CKN each) and demultiplexes inbound MKPDUs to the participant whose
 * CKN they carry, so several CAs can coexist on the same physical port
 * (IEEE Std 802.1X-2010, 9.6 / 12.5).
 */
typedef struct {
    MkaParticipant parts[MKA_MAX_PARTICIPANTS];
    size_t count;
    /* once one CA has MACsec up, hold the others silent (see
     * wm_Kay_SetQuiesceOthers) */
    bool quiesce_others;
} MkaKay;

/**
 * Initialise an empty KaY (no participants).
 * @param[out] kay  The KaY to initialise.
 * @return MKA_OK on success; MKA_ERR_BAD_ARG if kay is NULL.
 */
MkaStatus wm_Kay_Init(MkaKay* kay);

/**
 * Tear down a KaY when it is no longer needed.
 *
 * Securely frees every participant (wiping its key material) and resets the
 * KaY to empty.
 * @param[in,out] kay  The KaY to free (may be NULL).
 */
void wm_Kay_Free(MkaKay* kay);

/**
 * Create and start a participant for one Connectivity Association.
 *
 * Initialises a fresh participant from cfg in the next free slot.
 *
 * @param[in,out] kay  The KaY.
 * @param[in]     cfg  Participant configuration; its CKN must be unique within
 *                     kay.
 * @param[out]    out  Optional; receives a pointer to the created participant.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if kay or cfg is NULL;
 *         MKA_ERR_FULL if the participant table is full;
 *         MKA_ERR_STATE if a participant with the same CKN already exists;
 *         MKA_ERR_CRYPTO if participant initialisation fails.
 */
MkaStatus wm_Kay_AddParticipant(MkaKay* kay, const MkaParticipantConfig* cfg,
    MkaParticipant** out);

/**
 * Find the participant that owns a given CKN.
 * @param[in] kay      The KaY (may be NULL).
 * @param[in] ckn      The CAK Name to match (may be NULL).
 * @param[in] ckn_len  Length of ckn in octets.
 * @return A pointer to the owning participant, or NULL if kay or ckn is NULL or
 *         no Connectivity Association matches.
 */
MkaParticipant* wm_Kay_Find(MkaKay* kay, const uint8_t* ckn, size_t ckn_len);

/**
 * Remove the participant for a given CKN, stopping MKA for that Connectivity
 * Association.
 *
 * Tears down the participant's SecY SAs and securely wipes its key material
 * (via wm_Participant_Free), then compacts the participant table so the
 * remaining Connectivity Associations stay contiguous. Any pointer previously
 * returned by wm_Kay_Find / wm_Kay_AddParticipant for this KaY is
 * invalidated by the compaction and must not be reused.
 *
 * @param[in,out] kay      The KaY.
 * @param[in]     ckn      The CAK Name identifying the participant to remove.
 * @param[in]     ckn_len  Length of ckn in octets.
 * @return MKA_OK if a participant was removed;
 *         MKA_ERR_BAD_ARG if kay or ckn is NULL;
 *         MKA_ERR_NO_PEER if no Connectivity Association owns the CKN.
 */
MkaStatus wm_Kay_RemoveParticipant(MkaKay* kay, const uint8_t* ckn,
    size_t ckn_len);

/**
 * Step every participant once (see wm_Participant_Run).
 * @param[in,out] kay     The KaY.
 * @param[in]     now_ms  Current monotonic time in milliseconds.
 * @return MKA_OK if all participants succeed;
 *         MKA_ERR_BAD_ARG if kay is NULL;
 *         otherwise the status of the first participant that reported an error.
 */
MkaStatus wm_Kay_Run(MkaKay* kay, uint32_t now_ms);

/**
 * Route a received EAPOL-MKA frame to the participant for its CKN.
 *
 * Peeks the Basic Parameter Set to read the CKN, then dispatches to the owning
 * participant. Frames for an unknown CKN are dropped (MKA_ERR_NO_PEER).
 *
 * @param[in,out] kay     The KaY.
 * @param[in]     frame   The received frame.
 * @param[in]     len     Length of the frame in octets.
 * @param[in]     now_ms  Current monotonic time in milliseconds.
 * @return The owning participant's status (see wm_Participant_Receive);
 *         MKA_ERR_BAD_ARG if kay or frame is NULL;
 *         MKA_ERR_PARSE or MKA_ERR_VERSION if the Basic Parameter Set is
 *         malformed or unsupported;
 *         MKA_ERR_NO_PEER if no Connectivity Association owns the CKN.
 */
MkaStatus wm_Kay_Receive(MkaKay* kay, const uint8_t* frame, size_t len,
    uint32_t now_ms);

/**
 * Stop the losing Connectivity Associations transmitting once one wins.
 *
 * A port may run several participants, each with its own CAK/CKN, to find one
 * the far end also holds. Once any of them establishes MACsec, the rest have
 * nobody left to negotiate with - on a point-to-point link no other peer can
 * appear - so keeping them transmitting only spends bandwidth and airtime.
 * With this enabled, wm_Kay_Run() holds every other participant silent for as
 * long as one has MACsec up, and releases them all again the moment it drops,
 * so a link that comes back re-runs the full search (OPEN Alliance
 * AutoMKA-09001, AutoMKA-09002).
 *
 * Off by default: a deployment that deliberately runs several CAs at once
 * (rather than as alternatives) needs them all to keep running.
 * @param[in,out] kay     The KaY.
 * @param[in]     enable  true to quiesce the losers.
 * @return MKA_OK, or MKA_ERR_BAD_ARG if kay is NULL.
 */
MkaStatus wm_Kay_SetQuiesceOthers(MkaKay* kay, bool enable);

/**
 * Number of participants (Connectivity Associations) on this KaY.
 * @param[in] kay  The KaY (may be NULL).
 * @return The participant count; 0 if kay is NULL.
 */
size_t wm_Kay_ParticipantCount(const MkaKay* kay);

#ifdef __cplusplus
}
#endif

#endif /* WOLFMKA_KAY_H */
