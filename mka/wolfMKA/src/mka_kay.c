/* mka_kay.c  -  MKA Key Agreement Entity (IEEE Std 802.1X-2010, Clause 9).
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
 * Written to conform to MISRA C:2012 (see MISRA.md for the deviation record).
 */

#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_crypto.h"
#include "wolfmka/mka_mem.h"

#define MKA_AN_MASK 0x3U

/* ------------------------------------------------------------------------- */
/* Event dispatch (optional MkaEventOps hooks; each skipped when NULL)        */
/* ------------------------------------------------------------------------- */

/** Notify that a new peer was added to the table. */
static void mka_ev_peer_added(const MkaParticipant* p,
    const uint8_t mi[MKA_MI_LEN], const uint8_t sci[MKA_SCI_LEN])
{
    if (p->cfg.events.peer_added != NULL) {
        p->cfg.events.peer_added(p->cfg.events.ctx, mi, sci);
    }
}

/** Notify that a peer became live. */
static void mka_ev_peer_live(const MkaParticipant* p,
    const uint8_t mi[MKA_MI_LEN])
{
    if (p->cfg.events.peer_live != NULL) {
        p->cfg.events.peer_live(p->cfg.events.ctx, mi);
    }
}

/** Notify that a peer was removed (was_live flags a previously-live peer). */
static void mka_ev_peer_lost(const MkaParticipant* p,
    const uint8_t mi[MKA_MI_LEN], bool was_live)
{
    if (p->cfg.events.peer_lost != NULL) {
        p->cfg.events.peer_lost(p->cfg.events.ctx, mi, was_live);
    }
}

/** Notify that the elected Key Server changed (is_self: we are the KS). */
static void mka_ev_key_server(const MkaParticipant* p,
    const uint8_t sci[MKA_SCI_LEN], bool is_self)
{
    if (p->cfg.events.key_server_elected != NULL) {
        p->cfg.events.key_server_elected(p->cfg.events.ctx, sci, is_self);
    }
}

/** Notify that a SAK was installed as the Latest key. */
static void mka_ev_sak_installed(const MkaParticipant* p, uint32_t kn,
    uint8_t an, uint64_t cipher_suite)
{
    if (p->cfg.events.sak_installed != NULL) {
        p->cfg.events.sak_installed(p->cfg.events.ctx, kn, an, cipher_suite);
    }
}

/** Notify that transmit protection was enabled on the Latest key. */
static void mka_ev_macsec_up(const MkaParticipant* p, uint32_t kn, uint8_t an)
{
    if (p->cfg.events.macsec_up != NULL) {
        p->cfg.events.macsec_up(p->cfg.events.ctx, kn, an);
    }
}

/** Notify that a received MKPDU failed ICV verification. */
static void mka_ev_auth_fail(const MkaParticipant* p)
{
    if (p->cfg.events.auth_fail != NULL) {
        p->cfg.events.auth_fail(p->cfg.events.ctx);
    }
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
/** Notify that a group CAK was distributed to us and unwrapped. */
static void mka_ev_cak_received(const MkaParticipant* p, const uint8_t* cak,
    size_t cak_len, const uint8_t* ckn, size_t ckn_len)
{
    if (p->cfg.events.cak_received != NULL) {
        p->cfg.events.cak_received(p->cfg.events.ctx, cak, cak_len, ckn,
            ckn_len);
    }
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

/* ------------------------------------------------------------------------- */
/* Peer table helpers                                                        */
/* ------------------------------------------------------------------------- */

/**
 * Find a peer in the table by Member Identifier.
 * @param[in] p   the participant whose peer table is searched.
 * @param[in] mi  the Member Identifier to match (MKA_MI_LEN octets).
 * @return a pointer to the matching peer, or NULL if not present.
 */
static MkaPeer* mka_find_peer(MkaParticipant* p, const uint8_t mi[MKA_MI_LEN])
{
    MkaPeer* result = NULL;
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        if (p->peers[i].valid &&
            (WOLFMKA_MEMCMP(p->peers[i].mi, mi, MKA_MI_LEN) == 0)) {
            result = &p->peers[i];
            break;
        }
    }
    return result;
}

/**
 * Allocate and initialise a new peer slot for a Member Identifier.
 * @param[in,out] p   the participant whose peer table receives the new entry.
 * @param[in]     mi  the new peer's Member Identifier (MKA_MI_LEN octets).
 * @return a pointer to the new peer, or NULL if the peer table is full.
 */
static MkaPeer* mka_add_peer(MkaParticipant* p, const uint8_t mi[MKA_MI_LEN])
{
    MkaPeer* result = NULL;
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        if (!p->peers[i].valid) {
            result = &p->peers[i];
            (void)WOLFMKA_MEMSET(result, 0, sizeof(*result));
            result->valid = true;
            (void)WOLFMKA_MEMCPY(result->mi, mi, MKA_MI_LEN);
            p->peer_count++;
            /* newInfo: the Potential Peer List changed. */
            p->new_info = true;
            break;
        }
    }
    return result;
}

/**
 * Record the outcome of a data-plane (SecY) call.
 *
 * A backend that programs the SecY asynchronously returns MKA_SECY_PENDING; we
 * count the outstanding operation so the transmit-enable handover defers until
 * it is reported complete via wm_Participant_SecyComplete(). A synchronous
 * backend returns 0 (or a negative error) and nothing is deferred - preserving
 * the original fire-and-forget behaviour exactly.
 * @param[in,out] p   the participant the call was issued for.
 * @param[in]     rc  the value the SecY callback returned.
 */
static void mka_secy_track(MkaParticipant* p, int rc)
{
    if (rc == MKA_SECY_PENDING) {
        p->secy_pending++;
    }
}

/**
 * Remove a peer and tear down its receive SAs in the SecY.
 * @param[in,out] p   the participant owning the peer table.
 * @param[in,out] pe  the peer entry to remove.
 */
static void mka_drop_peer(MkaParticipant* p, MkaPeer* pe)
{
    const MkaSecyOps* s = &p->cfg.secy;

    if (s->delete_sa != NULL) {
        if (p->latest.valid) {
            mka_secy_track(p, s->delete_sa(s->ctx, pe->sci, p->latest.an));
        }
        if (p->old.valid) {
            mka_secy_track(p, s->delete_sa(s->ctx, pe->sci, p->old.an));
        }
    }
    mka_ev_peer_lost(p, pe->mi, pe->live);
    /* newInfo: a peer left the Potential or Live Peer List. */
    p->new_info = true;
    (void)WOLFMKA_MEMSET(pe, 0, sizeof(*pe));
    /* mka_drop_peer is only ever called for a tracked peer, so peer_count > 0.
     * Check the invariant in debug builds; release builds just decrement. */
    WOLFMKA_ASSERT(p->peer_count != 0U);
    p->peer_count--;
}

/* Counts valid && live entries; tolerates a NULL participant. */
size_t wm_Participant_LivePeerCount(const MkaParticipant* p)
{
    size_t i;
    size_t n = 0U;

    if (p == NULL) {
        return 0U;
    }
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        if (p->peers[i].valid && p->peers[i].live) {
            n++;
        }
    }
    return n;
}

/* The tracked peer count is maintained as peers are added and dropped. */
size_t wm_Participant_PeerCount(const MkaParticipant* p)
{
    return (p != NULL) ? p->peer_count : 0U;
}

bool wm_Participant_IsKeyServer(const MkaParticipant* p)
{
    return (p != NULL) && p->is_key_server;
}

bool wm_Participant_HasSak(const MkaParticipant* p)
{
    return (p != NULL) && p->latest.valid;
}

/* Map the caller's index onto the index-th valid slot, then copy a read-only
 * view of that peer (no internal SAK/PN bookkeeping is exposed). */
MkaStatus wm_Participant_GetPeer(const MkaParticipant* p, size_t index,
    MkaPeerInfo* out)
{
    size_t i;
    size_t seen = 0U;

    if ((p == NULL) || (out == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (!pe->valid) {
            continue;
        }
        if (seen == index) {
            (void)WOLFMKA_MEMCPY(out->mi, pe->mi, MKA_MI_LEN);
            (void)WOLFMKA_MEMCPY(out->sci, pe->sci, MKA_SCI_LEN);
            out->mn = pe->mn;
            out->priority = pe->priority;
            out->live = pe->live;
            out->key_server = pe->key_server;
            out->macsec_desired = pe->macsec_desired;
            return MKA_OK;
        }
        seen++;
    }
    return MKA_ERR_NO_PEER;
}

/* Snapshot the Latest key's metadata and the cipher suite in force; the SAK
 * octets themselves are never exposed. */
MkaStatus wm_Participant_GetSak(const MkaParticipant* p, MkaSakInfo* info)
{
    if ((p == NULL) || (info == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    info->valid = p->latest.valid;
    info->kn = p->latest.kn;
    info->an = p->latest.an;
    info->sak_len = p->latest.sak_len;
    info->tx = p->latest.tx;
    info->cipher_suite = p->sak_cipher_suite;
    return MKA_OK;
}

/* The elected Key Server's SCI is only meaningful once an election has run. */
MkaStatus wm_Participant_GetKeyServerSci(const MkaParticipant* p,
    uint8_t sci[MKA_SCI_LEN])
{
    if ((p == NULL) || (sci == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!p->elected) {
        return MKA_ERR_STATE;
    }
    (void)WOLFMKA_MEMCPY(sci, p->ks_sci, MKA_SCI_LEN);
    return MKA_OK;
}

#ifdef WOLFMKA_KMD
/* Copy the most recently received Key Management Domain. */
MkaStatus wm_Participant_GetKmd(const MkaParticipant* p, uint8_t* kmd,
    size_t cap, size_t* kmd_len)
{
    if ((p == NULL) || (kmd == NULL) || (kmd_len == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (cap < p->rx_kmd_len) {
        return MKA_ERR_BUFFER;
    }
    (void)WOLFMKA_MEMCPY(kmd, p->rx_kmd, p->rx_kmd_len);
    *kmd_len = p->rx_kmd_len;
    return MKA_OK;
}
#endif /* WOLFMKA_KMD */

/**
 * Pick the SCI to report as "the peer" in the PAE status.
 *
 * A live peer is preferred over one merely heard from, so the reported SCI is
 * the peer actually in the association where there is one.
 * @param[in]  p    the participant.
 * @param[out] sci  receives the SCI, left untouched when there is no peer.
 * @return true if a peer was found.
 */
static bool mka_status_peer_sci(const MkaParticipant* p,
    uint8_t sci[MKA_SCI_LEN])
{
    size_t i;
    const MkaPeer* best = NULL;

    /* A live peer is the association's actual counterpart, so it wins. */
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (pe->valid && pe->live) {
            best = pe;
        }
    }
    /* Otherwise report whoever has been heard from, so a session still coming
     * up names the peer it is negotiating with. */
    if (best == NULL) {
        for (i = 0U; i < MKA_MAX_PEERS; i++) {
            const MkaPeer* pe = &p->peers[i];
            if (pe->valid) {
                best = pe;
                break;
            }
        }
    }
    if (best != NULL) {
        (void)WOLFMKA_MEMCPY(sci, best->sci, MKA_SCI_LEN);
    }
    return best != NULL;
}

/* The state is derived rather than stored: every input already exists, and a
 * second copy of the state would be one more thing to keep consistent. */
MkaStatus wm_Participant_GetPaeStatus(const MkaParticipant* p,
    MkaPaeStatus* out)
{
    if ((p == NULL) || (out == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    (void)WOLFMKA_MEMSET(out, 0, sizeof(*out));

    if (!p->cfg.macsec_desired) {
        /* MACsec is not wanted on this participant, so there is no session to
         * report on. */
        out->state = MKA_PAE_UNDEFINED;
        return MKA_OK;
    }

    (void)WOLFMKA_MEMCPY(out->ckn, p->cfg.cak.ckn, p->cfg.cak.ckn_len);
    out->ckn_len = p->cfg.cak.ckn_len;
    (void)mka_status_peer_sci(p, out->peer_sci);

    if (p->latest.valid && p->latest.tx) {
        out->state = MKA_PAE_RUNNING;
        out->cipher_suite = p->sak_cipher_suite;
    }
    else if (p->peer_count != 0U) {
        out->state = MKA_PAE_IN_PROGRESS;
    }
    else if (p->counters.icv_failures != 0U) {
        /* Frames are arriving but none authenticate: the far end is configured
         * with a different CAK, which is a distinct condition from silence. */
        out->state = MKA_PAE_AUTH_FAIL_UNKNOWN_PEER;
    }
    else {
        out->state = MKA_PAE_WAITING_FOR_PEER;
    }
    return MKA_OK;
}

/* MACsec counters live in the SecY, so each of these is a thin, validated
 * pass-through to its hook; wolfMKA adds no counting of its own. */
MkaStatus wm_Participant_GetSecyStats(const MkaParticipant* p,
    MkaSecyStats* out)
{
    if ((p == NULL) || (out == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (p->cfg.secy.get_secy_stats == NULL) {
        return MKA_ERR_STATE;
    }
    (void)WOLFMKA_MEMSET(out, 0, sizeof(*out));
    if (p->cfg.secy.get_secy_stats(p->cfg.secy.ctx, out) != 0) {
        return MKA_ERR_INTERNAL;
    }
    return MKA_OK;
}

MkaStatus wm_Participant_GetTxScStats(const MkaParticipant* p,
    MkaTxScStats* out)
{
    if ((p == NULL) || (out == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (p->cfg.secy.get_tx_sc_stats == NULL) {
        return MKA_ERR_STATE;
    }
    (void)WOLFMKA_MEMSET(out, 0, sizeof(*out));
    if (p->cfg.secy.get_tx_sc_stats(p->cfg.secy.ctx, p->cfg.sci, out) != 0) {
        return MKA_ERR_INTERNAL;
    }
    return MKA_OK;
}

MkaStatus wm_Participant_GetRxScStats(const MkaParticipant* p, size_t index,
    MkaRxScStats* out)
{
    MkaPeerInfo info;
    MkaStatus rc;

    if ((p == NULL) || (out == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (p->cfg.secy.get_rx_sc_stats == NULL) {
        return MKA_ERR_STATE;
    }
    /* Reuse the peer enumeration so the index means the same thing here as it
     * does to wm_Participant_GetPeer, and the SCI comes from one place. */
    rc = wm_Participant_GetPeer(p, index, &info);
    if (rc != MKA_OK) {
        return rc;
    }
    (void)WOLFMKA_MEMSET(out, 0, sizeof(*out));
    if (p->cfg.secy.get_rx_sc_stats(p->cfg.secy.ctx, info.sci, out) != 0) {
        return MKA_ERR_INTERNAL;
    }
    return MKA_OK;
}

/* Copy the running protocol counters. */
MkaStatus wm_Participant_GetCounters(const MkaParticipant* p, MkaCounters* out)
{
    if ((p == NULL) || (out == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    *out = p->counters;
    return MKA_OK;
}

/**
 * Find a Member Identifier in one of an MKPDU's peer lists.
 *
 * Used to see whether a sender has heard from us: our MI in its list, with the
 * Message Number it quotes alongside, is what proves the link is two-way.
 * @param[in]  list  the Live or Potential Peer List to search.
 * @param[in]  mi    the Member Identifier to look for (MKA_MI_LEN octets).
 * @param[out] mn    receives the Message Number listed against mi; untouched
 *                   when mi is absent.
 * @return true if mi appears in the list, else false.
 */
static bool mka_list_echo(const MkaPeerList* list, const uint8_t mi[MKA_MI_LEN],
    uint32_t* mn)
{
    bool found = false;
    size_t i;

    for (i = 0U; i < list->count; i++) {
        if (WOLFMKA_MEMCMP(list->peers[i].mi, mi, MKA_MI_LEN) == 0) {
            *mn = list->peers[i].mn;
            found = true;
        }
    }
    return found;
}

/**
 * Whether a Message Number echoed back to us is acceptably recent.
 *
 * Liveness requires the peer to quote a Message Number this participant
 * actually emitted recently, not merely its Member Identifier (IEEE Std
 * 802.1X-2010, 9.4.3); the depth of "recently" is MKA_MN_RECENT_WINDOW (OPEN
 * Alliance AutoMKA-03005 fixes it at three).
 * @param[in] p   the participant whose emitted Message Numbers are the
 *                reference.
 * @param[in] mn  the Message Number the peer echoed.
 * @return true if mn is one of the last MKA_MN_RECENT_WINDOW emitted.
 */
static bool mka_mn_recent(const MkaParticipant* p, uint32_t mn)
{
    bool recent;

    /* Message Numbers start at 1 and advance per MKPDU emitted, so while
     * actor_mn is still 1 nothing has been sent and no number a peer quotes can
     * be one of ours. */
    if (p->actor_mn <= 1U) {
        recent = false;
    }
    else {
        uint32_t age;

        /* actor_mn is the number the *next* MKPDU will carry, so the newest
         * value already emitted is actor_mn - 1 and the window covers that and
         * the MKA_MN_RECENT_WINDOW - 1 values below it. The subtraction is
         * unsigned, so it stays correct across the 32-bit rollover. */
        age = (p->actor_mn - 1U) - mn;
        recent = (age < (uint32_t)MKA_MN_RECENT_WINDOW);
    }
    return recent;
}

/**
 * Whether this MKPDU is invalid because it reports us live on a stale
 * Message Number (OPEN Alliance AutoMKA-04004).
 *
 * A peer that lists this participant in its *Live* Peer List is asserting
 * two-way connectivity, so the Message Number it quotes must be one we recently
 * emitted. When it is not, the MKPDU is not evidence of anything current: it is
 * discarded without refreshing the peer's Life timer, so a peer looping stale
 * information cannot hold the association open indefinitely. Being listed in
 * the Potential Peer List with a stale number is not an error - the peer is
 * simply reporting what it last heard - so only the Live list is checked here.
 * @param[in] p    the participant.
 * @param[in] pdu  the decoded MKPDU.
 * @return true if the MKPDU must be discarded.
 */
static bool mka_stale_live_echo(const MkaParticipant* p, const MkaPdu* pdu)
{
    uint32_t mn = 0U;

    return mka_list_echo(&pdu->live_peers, p->actor_mi, &mn) &&
           (!mka_mn_recent(p, mn));
}

/* ------------------------------------------------------------------------- */
/* Init                                                                      */
/* ------------------------------------------------------------------------- */

/**
 * Validate a configured cipher suite against the SAK length.
 *
 * A cipher suite of 0 means "default by SAK length". Otherwise it must be a
 * suite supported by this build (XPN suites need WOLFMKA_NO_XPN unset) and
 * consistent with the SAK length.
 * @param[in] cs       the configured cipher suite (0 => default by SAK length).
 * @param[in] sak_len  the configured SAK length in octets.
 * @return true if the cipher suite is acceptable, else false.
 */
static bool mka_cipher_suite_valid(uint64_t cs, uint8_t sak_len)
{
    bool ok;

    if (cs == 0U) {
        ok = true;
    }
    else if (cs == MKA_CIPHER_GCM_AES_128) {
        ok = (sak_len == 16U);
    }
    else if (cs == MKA_CIPHER_GCM_AES_256) {
        ok = (sak_len == 32U);
#ifndef WOLFMKA_NO_XPN
    }
    else if (cs == MKA_CIPHER_GCM_AES_XPN_128) {
        ok = (sak_len == 16U);
    }
    else if (cs == MKA_CIPHER_GCM_AES_XPN_256) {
        ok = (sak_len == 32U);
#endif
    }
    else {
        ok = false;
    }
    return ok;
}

#ifdef WOLFMKA_CIPHER_NEGOTIATION
/* The SAK length a cipher suite requires: 32 octets for the 256-bit suites,
 * 16 for the 128-bit ones (and as the default). */
static uint8_t mka_sak_len_for_cs(uint64_t cs)
{
    uint8_t len = 16U;

    if ((cs == MKA_CIPHER_GCM_AES_256)
    #ifndef WOLFMKA_NO_XPN
        || (cs == MKA_CIPHER_GCM_AES_XPN_256)
    #endif
    ) {
        len = 32U;
    }
    return len;
}

/* The lowest MACsec Capability advertised across the participant and all its
 * live peers (MkaMacsecCapability; lower = less capable). This is the level the
 * Connectivity Association can actually use. */
static uint8_t mka_min_capability(const MkaParticipant* p)
{
    uint8_t min_cap = p->cfg.macsec_capability;
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (pe->valid && pe->live && (pe->macsec_capability < min_cap)) {
            min_cap = pe->macsec_capability;
        }
    }
    return min_cap;
}

/* The confidentiality offset the Key Server distributes: the configured offset
 * when every member supports a selectable offset (INTEGRITY_CONF_OFFSET), else
 * MKA_CONF_OFFSET_0 - the only offset an INTEGRITY_CONF member supports, and a
 * don't-care when the SAK ends up integrity-only. */
static uint8_t mka_negotiate_offset(const MkaParticipant* p)
{
    uint8_t off = (uint8_t)MKA_CONF_OFFSET_0;

    if (mka_min_capability(p) >= (uint8_t)MKA_CAP_INTEGRITY_CONF_OFFSET) {
        off = p->cfg.confidentiality_offset;
    }
    return off;
}
#endif /* WOLFMKA_CIPHER_NEGOTIATION */

/**
 * Validate a participant configuration's cipher-suite, SAK length and
 * confidentiality offset (and, when enabled, its cipher preference list).
 * @param[in] cfg  the configuration to check (non-NULL).
 * @return true if the configuration is acceptable, else false.
 */
static bool mka_cfg_valid(const MkaParticipantConfig* cfg)
{
    if (!mka_aes_key_len_valid(cfg->sak_len)) {
        return false;
    }
    if (!mka_cipher_suite_valid(cfg->cipher_suite, cfg->sak_len)) {
        return false;
    }
#ifdef WOLFMKA_CIPHER_NEGOTIATION
    if ((cfg->cipher_pref_count != 0U) &&
        ((cfg->cipher_prefs == NULL) ||
            (cfg->cipher_pref_count > (uint8_t)MKA_MAX_CIPHER_SUITES))) {
        return false;
    }
#endif
    if (cfg->confidentiality_offset > (uint8_t)MKA_CONF_OFFSET_50) {
        return false;
    }
#ifdef WOLFMKA_KMD
    /* The KMD is copied into a fixed MKA_MAX_KMD_LEN buffer when built. */
    if (cfg->kmd_len > (size_t)MKA_MAX_KMD_LEN) {
        return false;
    }
#endif
    return true;
}

/* Zeroes the object first, then derives keys and a random MI; on any failure
 * the participant is left zeroed (not partially initialised). */
MkaStatus wm_Participant_Init(MkaParticipant* p,
    const MkaParticipantConfig* cfg)
{
    MkaStatus rc;

    if ((p == NULL) || (cfg == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    /* Zero first so the participant is left in a clean, inert state on any
     * failure (including a rejected configuration) - never partially
     * initialised or holding caller stack garbage. */
    (void)WOLFMKA_MEMSET(p, 0, sizeof(*p));
    if (!mka_cfg_valid(cfg)) {
        return MKA_ERR_BAD_ARG;
    }

    p->cfg = *cfg;
#ifndef WOLFMKA_NO_RETRY
    /* first back-off step */
    p->retry_delay_ms = cfg->retry_base_ms;
#endif

    rc = wm_Crypto_DeriveKeys(cfg->cmac, &cfg->cak, &p->keys);
    if (rc == MKA_OK) {
        rc = wm_Crypto_Random(cfg->rng, p->actor_mi, MKA_MI_LEN);
    }
    if (rc == MKA_OK) {
        /* Message Numbers start at 1 (9.4.2) */
        p->actor_mn = 1U;
    }
    return rc;
}

/* Only the fields the OPEN Alliance profile fixes are written; the caller's
 * CAK/CKN, SCI, priority, role and hooks are left alone, so this may be called
 * on a partly filled configuration. Nothing here needs
 * WOLFMKA_AUTOMOTIVE_PROFILE: the profile macro selects the compile-time half
 * (MKPDU version, no Announcements), this is the runtime half. */
MkaStatus wm_Participant_AutomotiveDefaults(MkaParticipantConfig* cfg)
{
    if (cfg == NULL) {
        return MKA_ERR_BAD_ARG;
    }

    /* Answer a peer-list change at once instead of at the next Hello Time. */
    cfg->immediate_response = true;
    /* Let the peer start installing a new SAK as early as we do. */
    cfg->distribute_before_install = true;
#ifndef WOLFMKA_NO_RETRY
    /* Doubling ramp from 10 ms up to the nominal Hello Time. */
    cfg->retry_base_ms = MKA_AUTOMOTIVE_RETRY_BASE_MS;
    cfg->retry_cyclic_ms = MKA_HELLO_TIME_MS;
#endif
    return MKA_OK;
}

/* ------------------------------------------------------------------------- */
/* Key Server election (9.5)                                                 */
/* ------------------------------------------------------------------------- */

/**
 * Compare two Key Server candidates (priority then SCI).
 *
 * Lower priority value wins; ties are broken by the numerically lower SCI.
 * @param[in] pa  priority of the first candidate.
 * @param[in] sa  SCI of the first candidate (MKA_SCI_LEN octets).
 * @param[in] pb  priority of the second candidate.
 * @param[in] sb  SCI of the second candidate (MKA_SCI_LEN octets).
 * @return a negative value if (pa,sa) outranks (pb,sb), 0 if equal, or a
 *         positive value otherwise.
 */
static int mka_ks_cmp(uint8_t pa, const uint8_t* sa, uint8_t pb,
    const uint8_t* sb)
{
    /* The priority difference already carries the right sign (lower priority
     * wins); only when priorities tie does the SCI break it. */
    int result = (int)pa - (int)pb;

    if (result == 0) {
        result = WOLFMKA_MEMCMP(sa, sb, MKA_SCI_LEN);
    }
    return result;
}

/**
 * Elect the Key Server among self and live, MACsec-desiring peers.
 *
 * Updates p->elected, p->is_key_server and p->ks_sci (IEEE 802.1X-2010, 9.5).
 * @param[in,out] p  the participant whose election state is updated.
 */
/* Dynamic election (no pinned role): pick the live, MACsec-desiring candidate -
 * possibly self - with the best priority/SCI, and record the result on p. */
static void mka_elect_dynamic(MkaParticipant* p)
{
    const uint8_t* best_sci = NULL;
    uint8_t best_pri = 0U;
    bool best_is_self = false;
    bool have_candidate = false;
    bool self_ok;
    size_t i;

    /* Self is a candidate if we may be Key Server and want MACsec. */
    self_ok = p->cfg.key_server_capable && p->cfg.macsec_desired;
#ifdef WOLFMKA_AUTOMOTIVE_PROFILE
    if (p->cfg.priority == (uint8_t)MKA_PRIORITY_NEVER_KS) {
        /* Priority 255 is an absolute "never Key Server" in the automotive
         * profile, not merely the least preferred value (AutoMKA-03007). */
        self_ok = false;
    }
#endif
    if (self_ok) {
        best_sci = p->cfg.sci;
        best_pri = p->cfg.priority;
        best_is_self = true;
        have_candidate = true;
    }

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        bool peer_ok = pe->valid && pe->live && pe->macsec_desired;
#ifdef WOLFMKA_AUTOMOTIVE_PROFILE
        if (pe->priority == (uint8_t)MKA_PRIORITY_NEVER_KS) {
            peer_ok = false;
        }
#endif
        if (peer_ok) {
            if ((!have_candidate) ||
                (mka_ks_cmp(pe->priority, pe->sci, best_pri, best_sci) < 0)) {
                best_sci = pe->sci;
                best_pri = pe->priority;
                best_is_self = false;
                have_candidate = true;
            }
        }
    }

    if (have_candidate) {
        p->elected = true;
        p->is_key_server = best_is_self;
        (void)WOLFMKA_MEMCPY(p->ks_sci, best_sci, MKA_SCI_LEN);
    }
    else {
        p->elected = false;
        p->is_key_server = false;
    }
}

/**
 * Elect the Key Server for a fixed PEER-role participant: we never serve, so
 * adopt the SCI of a live peer that advertises the Key Server role.
 * @param[in,out] p  the participant whose election state is updated.
 */
static void mka_elect_fixed_peer(MkaParticipant* p)
{
    size_t i;

    p->is_key_server = false;
    p->elected = false;
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (pe->valid && pe->live && pe->key_server) {
            (void)WOLFMKA_MEMCPY(p->ks_sci, pe->sci, MKA_SCI_LEN);
            p->elected = true;
            break;
        }
    }
}

/**
 * Whether the election outcome changed from a snapshot, so a key_server event
 * should fire.
 * @param[in] p            the participant with the current outcome.
 * @param[in] was_elected  the prior elected state.
 * @param[in] was_self     whether we were previously the Key Server.
 * @param[in] old_sci      the prior Key Server SCI.
 * @return true if elected and the elected state, role or SCI changed.
 */
static bool mka_election_changed(const MkaParticipant* p, bool was_elected,
    bool was_self, const uint8_t old_sci[MKA_SCI_LEN])
{
    return p->elected &&
           ((!was_elected) || (was_self != p->is_key_server) ||
               (WOLFMKA_MEMCMP(old_sci, p->ks_sci, MKA_SCI_LEN) != 0));
}

/**
 * Run Key Server election: pin the outcome for a fixed role or run the dynamic
 * election, then fire a key_server event when the elected outcome changes.
 * @param[in,out] p  the participant whose election state is updated.
 */
static void mka_run_election(MkaParticipant* p)
{
    /* Snapshot the prior result so an event fires only on a real change. */
    bool was_elected = p->elected;
    bool was_self = p->is_key_server;
    uint8_t old_sci[MKA_SCI_LEN];

    (void)WOLFMKA_MEMCPY(old_sci, p->ks_sci, MKA_SCI_LEN);

    if (p->cfg.role == MKA_ROLE_KEY_SERVER) {
        /* Fixed-role configuration (AUTOSAR CP_SWS_Mka_00011): the role is
         * pinned, so the dynamic election is bypassed entirely. */
        p->elected = true;
        p->is_key_server = true;
        (void)WOLFMKA_MEMCPY(p->ks_sci, p->cfg.sci, MKA_SCI_LEN);
    }
    else if (p->cfg.role == MKA_ROLE_PEER) {
        mka_elect_fixed_peer(p);
    }
    else {
        mka_elect_dynamic(p);
    }

    if (mka_election_changed(p, was_elected, was_self, old_sci)) {
        mka_ev_key_server(p, p->ks_sci, p->is_key_server);
    }
}

/* ------------------------------------------------------------------------- */
/* SAK installation into the SecY                                            */
/* ------------------------------------------------------------------------- */

#ifndef WOLFMKA_NO_XPN
    /**
     * Test whether a cipher suite uses Extended Packet Numbering.
     * @param[in] cs  the cipher suite to test (evaluated more than once).
     * @return Non-zero for an XPN cipher suite, else 0.
     */
    #define mka_cipher_is_xpn(cs)                                              \
        (((cs) == MKA_CIPHER_GCM_AES_XPN_128) ||                               \
            ((cs) == MKA_CIPHER_GCM_AES_XPN_256))

/**
 * Deterministically assign a Short SCI for XPN (IEEE 802.1Xbx-2014).
 *
 * The SSCI is the 1-based rank of @p sci among all current members (self plus
 * live peers) ordered by ascending SCI. Both peers compute the same value, so
 * it is never transmitted. The Salt is derived by the SecY from the SAK
 * (802.1AE-2018), not here.
 * @param[in] p    the participant (self plus its live peers form the member
 *                 set).
 * @param[in] sci  the SCI whose Short SCI is computed (MKA_SCI_LEN octets).
 * @return the SSCI (1-based rank) for @p sci.
 */
static uint32_t mka_compute_ssci(const MkaParticipant* p,
    const uint8_t sci[MKA_SCI_LEN])
{
    uint32_t rank = 1U;
    size_t i;

    if (WOLFMKA_MEMCMP(p->cfg.sci, sci, MKA_SCI_LEN) < 0) {
        rank++;
    }
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (pe->valid && pe->live &&
            (WOLFMKA_MEMCMP(pe->sci, sci, MKA_SCI_LEN) < 0)) {
            rank++;
        }
    }
    return rank;
}
#endif /* WOLFMKA_NO_XPN */

/**
 * Configure the SecY cipher suite (and SSCI for XPN) on a channel.
 * @param[in] p    participant.
 * @param[in] sci  the Secure Channel Identifier being configured.
 */
static void mka_apply_cipher_suite(MkaParticipant* p,
    const uint8_t sci[MKA_SCI_LEN])
{
    const MkaSecyOps* s = &p->cfg.secy;

    if (s->set_cipher_suite != NULL) {
        uint32_t ssci = 0U;
        uint8_t offset = p->sak_conf_offset;
#ifndef WOLFMKA_NO_XPN
        if (mka_cipher_is_xpn(p->sak_cipher_suite)) {
            ssci = mka_compute_ssci(p, sci);
        }
#endif
#ifdef WOLFMKA_CIPHER_NEGOTIATION
        /* A member that cannot do confidentiality forces integrity-only. */
        if (p->sak_integrity_only) {
            offset = (uint8_t)MKA_CONF_OFFSET_NONE;
        }
#endif
        mka_secy_track(p, s->set_cipher_suite(s->ctx, sci, p->sak_cipher_suite,
                              ssci, offset));
    }
}

/**
 * Install and enable one receive SA (for a Latest or Old key).
 * @param[in] p   the participant (provides the SecY hooks).
 * @param[in] pe  the peer whose receive SC the SA is installed on.
 * @param[in] k   the key (SAK, AN, KN) to install.
 */
static void mka_install_rx_key(MkaParticipant* p, const MkaPeer* pe,
    const MkaSak* k)
{
    const MkaSecyOps* s = &p->cfg.secy;

    if (s->install_rx_sa != NULL) {
        mka_secy_track(p, s->install_rx_sa(s->ctx, pe->sci, k->an, k->kn,
                              k->sak, k->sak_len));
    }
    if (s->enable_receive != NULL) {
        mka_secy_track(p, s->enable_receive(s->ctx, pe->sci, k->an, true));
    }
}

/**
 * Create a peer's receive SC and install its Latest (and Old) SAs.
 * @param[in] p   the participant (provides the current keys and SecY hooks).
 * @param[in] pe  the peer to install receive SAs for.
 */
static void mka_install_peer_rx(MkaParticipant* p, const MkaPeer* pe)
{
    const MkaSecyOps* s = &p->cfg.secy;

    if (p->latest.valid) {
        if (s->create_rx_sc != NULL) {
            mka_secy_track(p, s->create_rx_sc(s->ctx, pe->sci));
        }
        mka_apply_cipher_suite(p, pe->sci);
        mka_install_rx_key(p, pe, &p->latest);
        if (p->old.valid) {
            mka_install_rx_key(p, pe, &p->old);
        }
    }
}

/**
 * Delete a key's transmit SA and every peer's receive SA for it.
 * @param[in] p  the participant (provides the peer table and SecY hooks).
 * @param[in] k  the key whose Secure Associations are deleted.
 */
static void mka_delete_sak_sas(MkaParticipant* p, const MkaSak* k)
{
    const MkaSecyOps* s = &p->cfg.secy;

    if (s->delete_sa != NULL) {
        size_t i;
        /* transmit SA */
        mka_secy_track(p, s->delete_sa(s->ctx, NULL, k->an));
        for (i = 0U; i < MKA_MAX_PEERS; i++) {
            if (p->peers[i].valid) {
                mka_secy_track(p, s->delete_sa(s->ctx, p->peers[i].sci, k->an));
            }
        }
    }
}

static void mka_program_sak(MkaParticipant* p);

/**
 * Adopt a new SAK as the Latest key, and program the data plane with it.
 *
 * The current Latest key (if any) becomes the Old key and stays installed for
 * in-flight traffic - make-before-break (IEEE Std 802.1X-2010, 9.x).
 *
 * Adoption and programming are separate steps: with
 * MkaParticipantConfig.distribute_before_install the key is adopted here and
 * mka_program_sak() runs later, once the MKPDU carrying it has been sent
 * (AutoMKA-03010). Either way transmit protection stays gated until every live
 * peer reports receiving on the key.
 * @param[in,out] p        participant.
 * @param[in]     sak      The Secure Association Key.
 * @param[in]     sak_len  Length of the SAK in octets.
 * @param[in]     an       Association Number.
 * @param[in]     kn       Key Number.
 */
static void mka_install_sak(MkaParticipant* p, const uint8_t* sak,
    size_t sak_len, uint8_t an, uint32_t kn)
{
    /* Demote the current Latest to Old; force-retire any unfinished Old. A new
     * SAK always carries a fresh Key Number, so a valid Latest is always a
     * different key here. */
    if (p->latest.valid) {
        if (p->old.valid) {
            mka_delete_sak_sas(p, &p->old);
        }
        /* its SecY SAs stay installed */
        p->old = p->latest;
    }

    p->latest.valid = true;
    (void)WOLFMKA_MEMCPY(p->latest.sak, sak, sak_len);
    p->latest.sak_len = sak_len;
    p->latest.an = an;
    p->latest.kn = kn;
    /* newInfo: the MACsec SAK Use set now names a different key, which the CA
     * needs before the transmit gate on either end can release. */
    p->new_info = true;
    /* gated until peers receive on it */
    p->latest.tx = false;
    p->counters.sak_installs++;

#ifdef WOLFMKA_CIPHER_NEGOTIATION
    /* Decide integrity-only once per install, from the current membership, so
     * every channel for this SAK is configured consistently. */
    p->sak_integrity_only =
        (mka_min_capability(p) <= (uint8_t)MKA_CAP_INTEGRITY_ONLY);
#endif

    if (p->cfg.distribute_before_install && p->is_key_server &&
        (p->cfg.send != NULL)) {
        /* Hold the data plane back until the key is on the wire: both ends then
         * start programming at the same moment instead of one after the other
         * (OPEN Alliance AutoMKA-03010). mka_program_sak() runs it once the
         * MKPDU carrying the key has been sent.
         *
         * Only the Key Server defers. A member has nothing to distribute, so
         * waiting would only delay its own data plane - and while deferred a
         * participant does not report itself receiving, which the Key Server
         * would read as the member having lost the key and answer with another
         * rekey. */
        p->sak_program_pending = true;
        /* Raised on adoption, as in the immediate path, so the event means the
         * same thing in both: the key is the participant's Latest. */
        mka_ev_sak_installed(p, kn, an, p->sak_cipher_suite);
        return;
    }
    mka_program_sak(p);
    mka_ev_sak_installed(p, kn, an, p->sak_cipher_suite);
}

/**
 * Program the data plane with the key already adopted as Latest.
 *
 * Split out of mka_install_sak() so the SecY work can be deferred until after
 * the Distributed SAK is on the wire. Nothing here reads the caller's key
 * material - it all comes from p->latest - so the point at which it runs is
 * free to move.
 * @param[in,out] p  the participant whose Latest key is programmed.
 */
static void mka_program_sak(MkaParticipant* p)
{
    const MkaSecyOps* s = &p->cfg.secy;
    size_t i;

    p->sak_program_pending = false;
    /* newInfo: the MACsec SAK Use can now report us receiving on the key, which
     * is what releases the peer's transmit gate. Waiting for the next periodic
     * MKPDU here would give back more than distributing early won. */
    p->new_info = true;

    /* Transmit SC/SA for the Latest key (transmit stays disabled until every
     * live peer reports receiving on it, so we never black-hole traffic). */
    if (s->create_tx_sc != NULL) {
        mka_secy_track(p, s->create_tx_sc(s->ctx, p->cfg.sci));
    }
    mka_apply_cipher_suite(p, p->cfg.sci);
    if (s->install_tx_sa != NULL) {
        mka_secy_track(p, s->install_tx_sa(s->ctx, p->cfg.sci, p->latest.an,
                              p->latest.kn, p->latest.sak, p->latest.sak_len));
    }

    /* Receive SAs for the Latest key on every live peer. */
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (pe->valid && pe->live) {
            if (s->create_rx_sc != NULL) {
                mka_secy_track(p, s->create_rx_sc(s->ctx, pe->sci));
            }
            mka_apply_cipher_suite(p, pe->sci);
            mka_install_rx_key(p, pe, &p->latest);
        }
    }
}

/**
 * Are all live peers receiving on a given key number?
 * @param[in] p   the participant whose live peers are inspected.
 * @param[in] kn  the Key Number that peers must report as their latest receive
 *                key.
 * @return true if there is at least one live peer and every live peer is
 *         receiving on kn, else false.
 */
static bool mka_peers_rx_on(const MkaParticipant* p, uint32_t kn)
{
    size_t live = 0U;
    size_t ready = 0U;
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (pe->valid && pe->live) {
            live++;
            if (pe->sak_rx && (pe->latest_kn == kn)) {
                ready++;
            }
        }
    }
    return (live > 0U) && (ready == live);
}

/**
 * Enable transmit on the Latest key once every peer receives on it.
 *
 * This is the transmit side of the MACsec SAK Use coordination (Tx gating).
 * When transmit moves to the Latest key, transmit on the Old key stops.
 * @param[in,out] p  the participant whose transmit state may advance.
 */
static void mka_maybe_enable_tx(MkaParticipant* p)
{
    const MkaSecyOps* s = &p->cfg.secy;

    if (p->latest.valid && (!p->latest.tx) && (p->secy_pending == 0U) &&
        mka_peers_rx_on(p, p->latest.kn)) {
        if (s->enable_transmit != NULL) {
            mka_secy_track(p, s->enable_transmit(s->ctx, p->latest.an, true));
        }
        p->latest.tx = true;
        if (p->old.valid) {
            if (s->enable_transmit != NULL) {
                mka_secy_track(p, s->enable_transmit(s->ctx, p->old.an, false));
            }
            p->old.tx = false;
        }
        /* newInfo: our SAK Use now reports transmitting on the Latest key,
         * which is what the peer is waiting for to release its own gate. */
        p->new_info = true;
        mka_ev_macsec_up(p, p->latest.kn, p->latest.an);
    }
}

/**
 * Retire the Old key once every live peer transmits on the Latest key.
 *
 * Completes the make-before-break handover by deleting the Old key's SAs.
 * @param[in,out] p  the participant whose Old key may be retired.
 */
static void mka_retire_old(MkaParticipant* p)
{
    if (p->old.valid) {
        size_t live = 0U;
        size_t moved = 0U;
        size_t i;
        for (i = 0U; i < MKA_MAX_PEERS; i++) {
            const MkaPeer* pe = &p->peers[i];
            if (pe->valid && pe->live) {
                live++;
                if (pe->sak_tx && (pe->latest_kn == p->latest.kn)) {
                    moved++;
                }
            }
        }
        if ((live > 0U) && (moved == live)) {
            mka_delete_sak_sas(p, &p->old);
            wm_Crypto_ForceZero(&p->old,
                /* retired key, wipe it */
                sizeof p->old);
        }
    }
}

#ifdef WOLFMKA_CIPHER_NEGOTIATION
/* Whether a live peer accepts a cipher suite: a peer accepts a suite it
 * announced, or any suite when it sent no Announcement (adv_count == 0), in
 * which case we trust the administrative configuration. */
static bool mka_peer_accepts_cs(const MkaPeer* pe, uint64_t cs)
{
    bool ok = (pe->adv_count == 0U);
    size_t i;

    for (i = 0U; (!ok) && (i < pe->adv_count); i++) {
        if (pe->adv_suites[i] == cs) {
            ok = true;
        }
    }
    return ok;
}

/* Whether every live peer accepts a cipher suite. */
static bool mka_all_peers_accept_cs(const MkaParticipant* p, uint64_t cs)
{
    bool ok = true;
    size_t j;

    for (j = 0U; ok && (j < MKA_MAX_PEERS); j++) {
        const MkaPeer* pe = &p->peers[j];
        if (pe->valid && pe->live && !mka_peer_accepts_cs(pe, cs)) {
            ok = false;
        }
    }
    return ok;
}

/* Key Server cipher-suite selection: the first entry of the configured
 * preference list that is valid in this build and accepted by every live peer.
 * Falls back to the mandatory GCM-AES-128 when no preference qualifies. */
static uint64_t mka_select_cipher_suite(const MkaParticipant* p)
{
    uint64_t chosen = MKA_CIPHER_GCM_AES_128;
    bool found = false;
    size_t i;

    for (i = 0U; (!found) && (i < p->cfg.cipher_pref_count); i++) {
        uint64_t cs = p->cfg.cipher_prefs[i];
        if ((cs != 0U) && mka_cipher_suite_valid(cs, mka_sak_len_for_cs(cs)) &&
            mka_all_peers_accept_cs(p, cs)) {
            chosen = cs;
            found = true;
        }
    }
    return chosen;
}
#endif /* WOLFMKA_CIPHER_NEGOTIATION */

/**
 * Key Server: generate a fresh SAK and install it as the Latest key.
 * @param[in,out] p  participant.
 * @return MKA_OK, or MKA_ERR_CRYPTO if SAK generation fails.
 */
static MkaStatus mka_ks_generate_sak(MkaParticipant* p)
{
    uint8_t sak[MKA_MAX_CAK_LEN];
    uint64_t cs;
    uint8_t sak_len;
    MkaStatus rc;

#ifdef WOLFMKA_CIPHER_NEGOTIATION
    if (p->cfg.cipher_pref_count != 0U) {
        /* Pick the best suite every live peer accepts; its length sizes the
         * SAK. */
        cs = mka_select_cipher_suite(p);
        sak_len = mka_sak_len_for_cs(cs);
    }
    else {
        cs = p->cfg.cipher_suite;
        sak_len = p->cfg.sak_len;
    }
#else
    cs = p->cfg.cipher_suite;
    sak_len = p->cfg.sak_len;
#endif
    if (cs == 0U) {
        cs = (sak_len == 32U) ? MKA_CIPHER_GCM_AES_256 : MKA_CIPHER_GCM_AES_128;
    }

    rc = wm_Crypto_GenerateSak(p->cfg.rng, sak, sak_len);
    if (rc == MKA_OK) {
        uint32_t kn;
        uint8_t an;

        p->sak_cipher_suite = cs;
#ifdef WOLFMKA_CIPHER_NEGOTIATION
        /* Reduce the confidentiality offset to what every live peer supports.
         */
        p->sak_conf_offset = mka_negotiate_offset(p);
#else
        p->sak_conf_offset = p->cfg.confidentiality_offset;
#endif
        /* KN increases */
        kn = p->latest.valid ? (p->latest.kn + 1U) : 1U;
        if (kn == 0U) {
            kn = 1U;
        }
        an = p->latest.valid
                 ? (uint8_t)(((uint32_t)p->latest.an + 1U) & MKA_AN_MASK)
                 : 0U;
        mka_install_sak(p, sak, sak_len, an, kn);
    }
    wm_Crypto_ForceZero(sak,
        /* generated key copied into latest */
        sizeof sak);
    return rc;
}

/**
 * Whether a received Distributed SAK should be skipped without installing: it
 * carries no key (a "MACsec not in use" indication), it re-advertises the
 * Latest key that is already installed, or this participant does not want
 * MACsec.
 *
 * The last case is what lets MKA run with MACsec switched off (OPEN Alliance
 * AutoMKA-12002). A participant configured `macsec_desired = false` takes no
 * part in protecting traffic: it never becomes Key Server, and it must not act
 * on a key another one distributes either - installing it would create the
 * Secure Channels and program the SAs it was configured not to have. Declining
 * the key here keeps every downstream SecY call from happening, since they all
 * hang off an installed Latest key.
 * @param[in] p  participant.
 * @param[in] d  the received Distributed SAK parameter set.
 * @return true to skip installation, false to proceed.
 */
static bool mka_dist_sak_skip(const MkaParticipant* p, const MkaDistSak* d)
{
    return (d->wrapped_len == 0U) || (!p->cfg.macsec_desired) ||
           (p->latest.valid && (d->kn == p->latest.kn));
}

/**
 * Non-Key-Server: unwrap and install a distributed SAK as Latest.
 * @param[in,out] p  participant.
 * @param[in]     d  the received Distributed SAK parameter set.
 * @return MKA_OK, or MKA_ERR_CRYPTO if unwrapping fails.
 */
static MkaStatus mka_install_from_dist(MkaParticipant* p, const MkaDistSak* d)
{
    uint8_t sak[MKA_MAX_CAK_LEN];
    size_t sak_len = sizeof(sak);
    MkaStatus rc;

    if (mka_dist_sak_skip(p, d)) {
        return MKA_OK;
    }

    rc = wm_Crypto_UnwrapSak(p->keys.kek, p->keys.kek_len, d->wrapped_sak,
        d->wrapped_len, sak, &sak_len);
    if (rc == MKA_OK) {
        /* The unwrap only guarantees a multiple-of-8 length, and the decoder
         * masks the confidentiality offset to 2 bits (0..3); reject a non-AES
         * key size or the reserved offset value 3 before installing. */
        if (!mka_aes_key_len_valid(sak_len) ||
            (d->confidentiality_offset > (uint8_t)MKA_CONF_OFFSET_50)) {
            rc = MKA_ERR_PARSE;
        }
    }
    if (rc == MKA_OK) {
        /* Adopt the cipher suite and confidentiality offset chosen by the Key
         * Server (cipher suite 0 => 128). */
        p->sak_cipher_suite =
            (d->cipher_suite == 0U) ? MKA_CIPHER_GCM_AES_128 : d->cipher_suite;
        p->sak_conf_offset = d->confidentiality_offset;
        mka_install_sak(p, sak, sak_len, d->distributed_an, d->kn);
    }
    /* unwrapped key copied into latest */
    wm_Crypto_ForceZero(sak, sizeof sak);
    return rc;
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
/**
 * Process a received Distributed CAK: split the body into the wrapped CAK and
 * the CKN using our CAK length (the wrapped CAK is CAK length + 8 octets per
 * RFC 3394), unwrap it with our KEK, and deliver the plaintext group CAK to the
 * integrator. A wrong KEK or tampered body fails the AES Key Unwrap integrity
 * check and is silently ignored. The unwrapped CAK is wiped before returning.
 * @param[in] p  the participant (provides the KEK and the event hook).
 * @param[in] d  the received Distributed CAK parameter set.
 */
static void mka_process_dist_cak(const MkaParticipant* p, const MkaDistCak* d)
{
    /* AES Key Wrap (RFC 3394) */
    size_t wrapped_len = p->cfg.cak.cak_len + 8U;
    uint8_t cak[MKA_MAX_CAK_LEN];
    size_t cak_len = sizeof(cak);

    /* The body must hold the wrapped CAK plus a non-empty, bounded CKN. */
    if ((d->body_len <= wrapped_len) ||
        ((d->body_len - wrapped_len) > MKA_MAX_CKN_LEN)) {
        return;
    }
    if (wm_Crypto_UnwrapSak(p->keys.kek, p->keys.kek_len, d->body, wrapped_len,
            cak, &cak_len) == MKA_OK) {
        mka_ev_cak_received(p, cak, cak_len, &d->body[wrapped_len],
            d->body_len - wrapped_len);
    }
    /* plaintext group CAK */
    wm_Crypto_ForceZero(cak, sizeof cak);
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

/* ------------------------------------------------------------------------- */
/* Receive                                                                   */
/* ------------------------------------------------------------------------- */

/**
 * Whether an MKPDU reports the peer using the SAK currently in force.
 *
 * Written as successive rejections rather than one compound test so each reason
 * a peer might not be using our key stands on its own: it sent no MACsec SAK
 * Use at all, we hold no key for it to use, it is neither receiving nor
 * transmitting, or the Key Number it names is not one we issued.
 *
 * A peer mid-handover legitimately still names the Old key - it has not
 * installed the new one yet - so that Key Number counts as ours too. Treating
 * it as unknown would make every make-before-break rekey look like a key loss
 * and trigger another rekey, and so on.
 * @param[in] p    the participant holding the key in force.
 * @param[in] pdu  the decoded MKPDU.
 * @return true if the peer reports a key we issued as in use.
 */
static bool mka_sak_use_reports_ours(const MkaParticipant* p, const MkaPdu* pdu)
{
    const MkaSakUse* su = &pdu->sak_use;

    if (!su->present) {
        return false;
    }
    if (!p->latest.valid) {
        return false;
    }
    if (!(MKA_SAK_USE_IS_LATEST_RX(su) || MKA_SAK_USE_IS_LATEST_TX(su))) {
        /* present but empty: the peer reports no key in use */
        return false;
    }
    if (su->latest_kn == p->latest.kn) {
        return true;
    }
    /* Still on the Old key while the handover completes. */
    return p->old.valid && (su->latest_kn == p->old.kn);
}

/**
 * Track whether a peer is still using the SAK, and ask for a rekey when one
 * that was using it stops (OPEN Alliance AutoMKA-03011).
 *
 * A peer whose MACsec SAK Use goes missing, empty, or refers to some other Key
 * Number has lost the key - typically its data plane restarted. Nothing in the
 * protocol brings it back on its own: this participant would keep reporting the
 * peer as using a key it no longer holds, and traffic to it would stay
 * undecryptable until something else forced a rekey. Distributing a fresh SAK
 * is what recovers it.
 *
 * The flag is only raised for a peer that *was* using the key, so a member that
 * has not received one yet - the normal case during bring-up - never triggers a
 * rekey. Clearing sak_use_seen at the same time bounds it to one rekey per loss
 * rather than one per MKPDU.
 * @param[in,out] p    the participant.
 * @param[in,out] pe   the sending peer.
 * @param[in]     pdu  the decoded MKPDU.
 */
static void mka_note_sak_use(MkaParticipant* p, MkaPeer* pe, const MkaPdu* pdu)
{
    if (mka_sak_use_reports_ours(p, pdu)) {
        pe->sak_use_seen = true;
    }
    else if (pe->sak_use_seen) {
        pe->sak_use_seen = false;
        p->sak_lost = true;
    }
    else {
        /* it never held this key, so there is nothing to recover */
    }
}

/**
 * Record a peer's MACsec SAK Use state and apply delay protection.
 *
 * When delay protection is enabled, advances the peer's receive replay window
 * to the lowest acceptable PN it reports.
 * @param[in]     p    The participant.
 * @param[in,out] pe   The peer whose SAK Use is being applied.
 * @param[in]     su   The received MACsec SAK Use parameter set.
 * @param[in]     xpn  The received XPN parameter set (MSBs of the Lowest
 *                     Acceptable PNs; @c present is false when the peer sent
 *                     none).
 */
static void mka_apply_sak_use(MkaParticipant* p, MkaPeer* pe,
    const MkaSakUse* su, const MkaXpn* xpn)
{
    const MkaSecyOps* s = &p->cfg.secy;

    pe->latest_kn = su->latest_kn;
    pe->sak_rx = MKA_SAK_USE_IS_LATEST_RX(su);
    pe->sak_tx = MKA_SAK_USE_IS_LATEST_TX(su);
    pe->latest_lpn = su->latest_lpn;
#ifndef WOLFMKA_NO_XPN
    /* XPN: pair the low 32 bits from SAK Use with the MSBs from the XPN set. */
    pe->latest_lpn_msb = xpn->present ? xpn->latest_lpn_msb : 0U;
#else
    /* No XPN cipher suite is possible, so no XPN parameter set is ever in use;
     * the PN has no high bits. */
    (void)xpn;
    pe->latest_lpn_msb = 0U;
#endif

#ifndef WOLFMKA_NO_DELAY_PROTECT
    /* Delay protection: reject unduly delayed frames by advancing the receive
     * lowest acceptable PN to what the transmitter reports (9.4.1). */
    if (p->cfg.delay_protect && p->latest.valid && (s->set_lowest_pn != NULL)) {
        /* Convey the full 64-bit Lowest Acceptable PN: the low 32 bits from the
         * SAK Use set and the high 32 from the XPN set (zero for non-XPN). */
        uint64_t lpn64 =
            ((uint64_t)pe->latest_lpn_msb << 32U) | (uint64_t)pe->latest_lpn;
        (void)s->set_lowest_pn(s->ctx, pe->sci, p->latest.an, lpn64);
    }
#else
    (void)s;
#endif
}

/**
 * Validate a received MKPDU and locate its sending peer.
 *
 * @param[in,out] p          participant.
 * @param[in]     pdu        the decoded MKPDU.
 * @param[out]    pe_out     receives the sending peer, or NULL for a loopback
 * of our own MKPDU (the caller then stops with MKA_OK).
 * @param[out]    added_out  set true if the peer was newly added to the table.
 * @return MKA_OK to proceed (or, with *pe_out NULL, to stop on a loopback);
 *         MKA_ERR_NO_PEER (wrong CKN), MKA_ERR_FULL or MKA_ERR_REPLAY.
 */
static MkaStatus mka_admit_peer(MkaParticipant* p, const MkaPdu* pdu,
    MkaPeer** pe_out, bool* added_out)
{
    MkaPeer* pe;

    *pe_out = NULL;
    *added_out = false;

    /* Must be for our Connectivity Association (same CKN). */
    if ((pdu->basic.ckn_len != p->cfg.cak.ckn_len) ||
        (WOLFMKA_MEMCMP(pdu->basic.ckn, p->cfg.cak.ckn, p->cfg.cak.ckn_len) !=
            0)) {
        return MKA_ERR_NO_PEER;
    }

    /* Ignore a loopback of our own MKPDU (leave *pe_out NULL). */
    if (WOLFMKA_MEMCMP(pdu->basic.mi, p->actor_mi, MKA_MI_LEN) == 0) {
        return MKA_OK;
    }

    pe = mka_find_peer(p, pdu->basic.mi);
    if (pe == NULL) {
        pe = mka_add_peer(p, pdu->basic.mi);
        *added_out = true;
    }
    if (pe == NULL) {
        return MKA_ERR_FULL;
    }

    /* MKPDU replay protection: the Message Number must strictly increase for a
     * given Member Identifier (IEEE Std 802.1X-2010, 9.4.2). */
    if (pe->mn_seen && (pdu->basic.mn <= pe->mn)) {
        return MKA_ERR_REPLAY;
    }

    *pe_out = pe;
    return MKA_OK;
}

/**
 * Refresh a peer's advertised attributes from the MKPDU and recompute liveness.
 *
 * @param[in,out] p       participant.
 * @param[in,out] pe      the peer to update.
 * @param[in]     pdu     the decoded MKPDU.
 * @param[in]     now_ms  current monotonic time in milliseconds.
 * @param[in]     added   true if the peer was just added (fires peer_added).
 * @return true if the peer is now live (it echoes our MI), else false.
 */
static bool mka_refresh_peer(MkaParticipant* p, MkaPeer* pe, const MkaPdu* pdu,
    uint32_t now_ms, bool added)
{
    uint32_t echo_mn = 0U;
    bool echoed;

    pe->mn = pdu->basic.mn;
    pe->mn_seen = true;
    (void)WOLFMKA_MEMCPY(pe->sci, pdu->basic.sci, MKA_SCI_LEN);
    pe->priority = pdu->basic.priority;
    pe->key_server = pdu->basic.key_server;
    pe->macsec_desired = pdu->basic.macsec_desired;
    pe->macsec_capability = pdu->basic.macsec_capability;
    pe->last_seen_ms = now_ms;
#ifdef WOLFMKA_CIPHER_NEGOTIATION
    /* Record the cipher suites the peer announced, for Key Server selection. An
     * MKPDU without an Announcement clears the set (then it constrains no
     * suite). */
    pe->adv_count = 0U;
    if (pdu->announce.present) {
        size_t k;
        /* The decoder clamps the announced suite count to
         * MKA_MAX_CIPHER_SUITES, so the copy into adv_suites[] (sized to that
         * maximum) cannot overflow. */
        WOLFMKA_ASSERT(pdu->announce.count <= (size_t)MKA_MAX_CIPHER_SUITES);
        for (k = 0U; k < pdu->announce.count; k++) {
            pe->adv_suites[k] = pdu->announce.suites[k].cipher_suite;
            pe->adv_count++;
        }
    }
#endif
#ifdef WOLFMKA_SUSPENSION
    /* Record the MKA Suspension Time the peer advertised (0 when not suspended
     * or not carrying an XPN set), so expiry holds it that much longer. */
    pe->suspend_for = pdu->xpn.suspension_time;
#endif
    mka_note_sak_use(p, pe, pdu);
    if (pdu->sak_use.present) {
        mka_apply_sak_use(p, pe, &pdu->sak_use, &pdu->xpn);
    }
    if (added) {
        mka_ev_peer_added(p, pe->mi, pe->sci);
    }

    /* A peer becomes live once it echoes our MI together with a Message Number
     * we recently emitted, proving bidirectional connectivity (9.4.3). Either
     * list carries that proof.
     *
     * The Live list needs no recency test here: mka_stale_live_echo() has
     * already discarded the whole MKPDU if our MI appeared there with a stale
     * number (AutoMKA-04004), so finding it now means the number was recent.
     * Re-testing it would be a condition that can never be false. The Potential
     * list is not covered by that rule, so it is checked here. */
    echoed = mka_list_echo(&pdu->live_peers, p->actor_mi, &echo_mn);
    if (!echoed) {
        echoed = mka_list_echo(&pdu->potential_peers, p->actor_mi, &echo_mn) &&
                 mka_mn_recent(p, echo_mn);
    }
    pe->live = echoed;
    return pe->live;
}

#ifndef WOLFMKA_NO_XPN
/**
 * Reprogram XPN SSCIs after a membership change. An XPN SSCI is the rank of a
 * member's SCI within the live membership, so a member joining shifts the ranks
 * of the other channels. mka_install_sak does this for every channel at install
 * time, but a join after install triggers no rekey, so without this the
 * existing channels keep a stale SSCI and their XPN frames fail to
 * authenticate. Reapply the cipher suite (recomputing the SSCI) for our own
 * transmit SC and every live peer's receive SC. Does nothing until a SAK is
 * installed; for non-XPN suites the reapplied SSCI is 0, so the call is
 * harmless there.
 * @param[in,out] p  the participant whose channels are reprogrammed.
 */
static void mka_reapply_xpn_ssci(MkaParticipant* p)
{
    if (p->latest.valid) {
        size_t i;
        mka_apply_cipher_suite(p, p->cfg.sci);
        for (i = 0U; i < MKA_MAX_PEERS; i++) {
            const MkaPeer* pe = &p->peers[i];
            if (pe->valid && pe->live) {
                mka_apply_cipher_suite(p, pe->sci);
            }
        }
    }
}
#endif

/**
 * Retire a peer's previous incarnation once its new one is live.
 *
 * A device that resets comes back with a fresh Member Identifier but the same
 * SCI. Its old entry would otherwise sit in the table until the Life Time
 * expired it - holding a stale live peer, keeping the Key Server waiting on a
 * member that is gone, and costing up to three Hello Times of downtime (OPEN
 * Alliance AutoMKA-03006).
 *
 * The old entry is removed only once the new MI has proven liveness, never on
 * first sight of it: an attacker replaying or forging an MKPDU with an unknown
 * MI can therefore never evict a working peer, since a forged frame cannot echo
 * this participant's own MI and Message Number back to it.
 *
 * Called before the new peer's receive SA is installed, because both entries
 * share an SCI and the SecY keys its SAs by (SCI, AN) - retiring afterwards
 * would delete the SA just installed for the new MI.
 * @param[in,out] p     the participant owning the peer table.
 * @param[in]     kept  the newly live peer whose SCI identifies the device.
 */
static void mka_retire_stale_mi(MkaParticipant* p, const MkaPeer* kept)
{
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        MkaPeer* pe = &p->peers[i];
        if (pe->valid && (pe != kept) &&
            (WOLFMKA_MEMCMP(pe->sci, kept->sci, MKA_SCI_LEN) == 0)) {
            mka_drop_peer(p, pe);
        }
    }
}

/**
 * React to a refreshed MKPDU: re-run election, install a receive SA for a newly
 * live peer, and act on a distributed SAK (and group CAK) from the Key Server.
 *
 * @param[in,out] p         participant.
 * @param[in,out] pe        the sending peer.
 * @param[in]     pdu       the decoded MKPDU.
 * @param[in]     was_live  the peer's liveness before this MKPDU.
 * @param[in]     now_live  the peer's liveness after this MKPDU.
 * @return MKA_OK, or an error from distributed-SAK installation.
 */
static MkaStatus mka_react_to_pdu(MkaParticipant* p, MkaPeer* pe,
    const MkaPdu* pdu, bool was_live, bool now_live)
{
    MkaStatus rc = MKA_OK;

    /* Re-run election now that liveness may have changed. */
    mka_run_election(p);

    /* If we hold a SAK and this peer just became live, give it an SA. */
    if (now_live && (!was_live)) {
        /* First drop any earlier incarnation of the same device (AutoMKA-03006)
         * so its teardown cannot delete the SA installed just below. */
        mka_retire_stale_mi(p, pe);
        mka_install_peer_rx(p, pe);
        mka_ev_peer_live(p, pe->mi);
        /* newInfo: the Live Peer List changed. As Key Server this is the
         * moment the Distributed SAK becomes worth sending. */
        p->new_info = true;
#ifndef WOLFMKA_NO_XPN
        /* A new member shifts XPN SSCI ranks (an SSCI is the SCI's rank in the
         * live membership), so reprogram the existing channels. For non-XPN
         * suites mka_apply_cipher_suite uses SSCI 0, so this is a harmless,
         * idempotent reapply. */
        mka_reapply_xpn_ssci(p);
#endif
    }

    /* SAK / CAK / KMD distribution is authorised only when it comes from the
     * peer this participant elected as Key Server (IEEE Std 802.1X-2010, 9.8):
     * we are not the Key Server ourselves, an election has settled, and the
     * sender's SCI is the elected Key Server's. Without this gate any CA member
     * holding the CAK (so its MKPDU passes the ICV check) could distribute a
     * SAK and override the real Key Server, desynchronising keys across the CA.
     */
    if ((!p->is_key_server) && p->elected &&
        (WOLFMKA_MEMCMP(pe->sci, p->ks_sci, MKA_SCI_LEN) == 0)) {
        /* A distributed SAK from the Key Server: unwrap and install it. */
        if (pdu->dist_sak.present) {
            rc = mka_install_from_dist(p, &pdu->dist_sak);
        }

#ifdef WOLFMKA_DISTRIBUTED_CAK
        /* A distributed group CAK from the Key Server: unwrap and deliver it.
         */
        if (pdu->dist_cak.present) {
            mka_process_dist_cak(p, &pdu->dist_cak);
        }
#endif

#ifdef WOLFMKA_KMD
        /* A Key Management Domain advertised by the Key Server: record it. */
        if (pdu->kmd.present) {
            (void)WOLFMKA_MEMCPY(p->rx_kmd, pdu->kmd.kmd, pdu->kmd.kmd_len);
            p->rx_kmd_len = pdu->kmd.kmd_len;
        }
#endif
    }

    return rc;
}

/**
 * Update participant state from a decoded, ICV-verified MKPDU.
 *
 * Admits the peer (CKN / loopback / replay guards), refreshes its advertised
 * state and liveness, reacts (election, SA install, distributed SAK/CAK), then
 * advances the make-before-break handover.
 * @param[in,out] p       participant.
 * @param[in]     pdu     the decoded MKPDU.
 * @param[in]     now_ms  current monotonic time in milliseconds.
 * @return MKA_OK, MKA_ERR_REPLAY, MKA_ERR_NO_PEER, MKA_ERR_FULL or MKA_ERR_*.
 */
static MkaStatus mka_receive_process(MkaParticipant* p, const MkaPdu* pdu,
    uint32_t now_ms)
{
    MkaPeer* pe;
    bool added;
    bool was_live;
    bool now_live;
    MkaStatus rc;

    /* Checked before the peer table is touched at all, so an MKPDU rejected
     * here leaves no trace: no slot allocated, no Life timer refreshed
     * (AutoMKA-04004). Our own MKPDUs never list our MI, so a loopback frame
     * cannot trip this. */
    if (mka_stale_live_echo(p, pdu)) {
        return MKA_ERR_REPLAY;
    }

    rc = mka_admit_peer(p, pdu, &pe, &added);
    if ((rc != MKA_OK) || (pe == NULL)) {
        /* rejected, or our own loopback (rc == MKA_OK) */
        return rc;
    }

    /* Capture liveness before the refresh overwrites it. */
    was_live = pe->live;
    now_live = mka_refresh_peer(p, pe, pdu, now_ms, added);
    rc = mka_react_to_pdu(p, pe, pdu, was_live, now_live);

    /* Advance the make-before-break handover: enable transmit on the Latest
     * key once peers receive on it, and retire the Old key once all moved. */
    mka_maybe_enable_tx(p);
    mka_retire_old(p);
    return rc;
}

/* Decodes into a scratch MkaPdu (heap or off-stack per build) so the large
 * working set stays off the caller's stack; wm_Pdu_Decode verifies the ICV
 * before mka_receive_process() acts on any content. */
MkaStatus wm_Participant_Receive(MkaParticipant* p, const uint8_t* frame,
    size_t len, uint32_t now_ms)
{
    MKA_DECLARE_VAR(pdu, MkaPdu, 1, WOLFMKA_HEAP_HINT);
    MkaStatus rc = MKA_OK;

    if ((p == NULL) || (frame == NULL)) {
        return MKA_ERR_BAD_ARG;
    }

    MKA_ALLOC_VAR(pdu, MkaPdu, 1, MKA_DYN_PDU, &p->ws_pdu,
        rc = MKA_ERR_INTERNAL);

    if (MKA_VAR_OK(pdu)) {
        /* Verifies the ICV with our ICK and parses the parameter sets. */
        rc = wm_Pdu_Decode(p->cfg.cmac, frame, len, p->keys.ick,
            p->keys.ick_len, pdu);
        if (rc == MKA_OK) {
            p->counters.mkpdu_in++;
            rc = mka_receive_process(p, pdu, now_ms);
        }
        else if (rc == MKA_ERR_ICV) {
            p->counters.icv_failures++;
            mka_ev_auth_fail(p);
        }
        else {
            /* parse/version errors are not counted as ICV failures */
        }
    }

    MKA_FREE_VAR(pdu, MKA_DYN_PDU);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Build an MKPDU from current state                                         */
/* ------------------------------------------------------------------------- */

/**
 * Populate the Live and Potential Peer Lists from the peer table.
 * @param[in]  p    the participant whose peer table is read.
 * @param[out] pdu  the MKPDU whose peer-list parameter sets are filled.
 */
static void mka_build_peer_lists(const MkaParticipant* p, MkaPdu* pdu)
{
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        MkaPeerList* l;

        if (pe->valid) {
            l = pe->live ? &pdu->live_peers : &pdu->potential_peers;
            /* The peer table holds at most MKA_MAX_PEERS entries split across
             * the two lists, so neither list can overflow. */
            WOLFMKA_ASSERT(l->count < MKA_MAX_PEERS);
            (void)WOLFMKA_MEMCPY(l->peers[l->count].mi, pe->mi, MKA_MI_LEN);
            l->peers[l->count].mn = pe->mn;
            l->count++;
            l->present = true;
        }
    }
}

#ifndef WOLFMKA_NO_XPN
/**
 * Under an XPN cipher suite, advertise the 32 most-significant bits of each
 * Lowest Acceptable PN in the XPN parameter set (11.11.6); the low 32 bits are
 * carried in the MACsec SAK Use set. Always sent while XPN is in use.
 * @param[in]  p    the participant providing the PN hook and key state.
 * @param[out] pdu  the MKPDU whose XPN parameter set is filled.
 */
static void mka_build_xpn(const MkaParticipant* p, MkaPdu* pdu)
{
    if (mka_cipher_is_xpn(p->sak_cipher_suite)) {
        pdu->xpn.present = true;
    #ifdef WOLFMKA_SUSPENSION
        /* While suspended, carry the MKA Suspension Time so peers hold our
         * state (802.1Xbx-2014). */
        if (p->suspended) {
            pdu->xpn.suspension_time = p->suspend_for;
        }
    #endif
        if (p->cfg.secy.get_next_pn != NULL) {
            uint64_t pn64 = 1U;
            if (p->cfg.secy.get_next_pn(p->cfg.secy.ctx, p->latest.an, &pn64) ==
                0) {
                pdu->sak_use.latest_lpn = (uint32_t)pn64;
                pdu->xpn.latest_lpn_msb = (uint32_t)(pn64 >> 32U);
            }
            if (p->old.valid && (p->cfg.secy.get_next_pn(p->cfg.secy.ctx,
                                     p->old.an, &pn64) == 0)) {
                pdu->sak_use.old_lpn = (uint32_t)pn64;
                pdu->xpn.old_lpn_msb = (uint32_t)(pn64 >> 32U);
            }
        }
    }
}
#endif

/**
 * Stamp the elected Key Server's MI into the SAK Use set: our own MI when we
 * are the Key Server, otherwise the MI of the peer we elected.
 * @param[in]  p    the participant providing the actor/peer MIs.
 * @param[out] pdu  the MKPDU whose SAK Use set is updated.
 */
static void mka_set_latest_ks_mi(const MkaParticipant* p, MkaPdu* pdu)
{
    if (p->is_key_server) {
        (void)WOLFMKA_MEMCPY(pdu->sak_use.latest_ks_mi, p->actor_mi,
            MKA_MI_LEN);
    }
    else {
        size_t i;
        for (i = 0U; i < MKA_MAX_PEERS; i++) {
            if (p->peers[i].valid && (WOLFMKA_MEMCMP(p->peers[i].sci, p->ks_sci,
                                          MKA_SCI_LEN) == 0)) {
                (void)WOLFMKA_MEMCPY(pdu->sak_use.latest_ks_mi, p->peers[i].mi,
                    MKA_MI_LEN);
            }
        }
    }
}

/**
 * Populate the MACsec SAK Use parameter set for transmission.
 * @param[in]  p    the participant whose key/PN state is encoded.
 * @param[out] pdu  the MKPDU whose SAK Use parameter set is filled.
 */
static void mka_build_sak_use(const MkaParticipant* p, MkaPdu* pdu)
{
    uint32_t lpn = 1U;

    pdu->sak_use.present = true;
    pdu->sak_use.latest_an = p->latest.an;
    /* Only claim to be receiving once the SecY actually holds the key. Under
     * distribute_before_install the MKPDU that carries a new SAK goes out
     * before the data plane is programmed, and a peer takes this flag as leave
     * to start transmitting protected frames - which we could not yet decrypt.
     * The claim follows one MKPDU later, as soon as programming is done. */
    if (!p->sak_program_pending) {
        MKA_SAK_USE_SET_LATEST_RX(&pdu->sak_use);
    }
    if (p->latest.tx) {
        MKA_SAK_USE_SET_LATEST_TX(&pdu->sak_use);
    }
    pdu->sak_use.latest_kn = p->latest.kn;

    /* During a make-before-break rekey, also advertise the Old key. */
    if (p->old.valid) {
        pdu->sak_use.old_an = p->old.an;
        MKA_SAK_USE_SET_OLD_RX(&pdu->sak_use);
        if (p->old.tx) {
            MKA_SAK_USE_SET_OLD_TX(&pdu->sak_use);
        }
        pdu->sak_use.old_kn = p->old.kn;
        pdu->sak_use.old_lpn = 1U;
    }

#ifndef WOLFMKA_NO_DELAY_PROTECT
    /* Advertise our transmit SA's next PN as the Lowest Acceptable PN and set
     * the delay-protection flag, so a peer can bound frame delay (9.4.1). */
    if (p->cfg.delay_protect) {
        MKA_SAK_USE_SET_DELAY_PROTECT(&pdu->sak_use);
    }
    if (p->cfg.secy.get_next_pn != NULL) {
        uint64_t pn = 1U;
        if (p->cfg.secy.get_next_pn(p->cfg.secy.ctx, p->latest.an, &pn) == 0) {
            lpn = (uint32_t)pn;
        }
    }
#endif
    pdu->sak_use.latest_lpn = lpn;

#ifndef WOLFMKA_NO_XPN
    mka_build_xpn(p, pdu);
#endif

    mka_set_latest_ks_mi(p, pdu);
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
/**
 * Emit the Distributed CAK parameter set: AES-Key-Wrap the staged group CAK
 * with this CA's KEK and append its CKN.
 * @param[in]  p    the participant (provides the KEK and the staged CAK/CKN).
 * @param[out] pdu  the MKPDU whose Distributed CAK set is filled.
 * @return MKA_OK, or MKA_ERR_CRYPTO if the wrap fails.
 */
static MkaStatus mka_build_dist_cak(const MkaParticipant* p, MkaPdu* pdu)
{
    uint8_t wrapped[MKA_MAX_WRAPPED_SAK];
    size_t wlen = sizeof(wrapped);
    MkaStatus rc;

    rc = wm_Crypto_WrapSak(p->keys.kek, p->keys.kek_len, p->dist_cak,
        p->dist_cak_len, wrapped, &wlen);
    if (rc == MKA_OK) {
        (void)WOLFMKA_MEMCPY(pdu->dist_cak.body, wrapped, wlen);
        (void)WOLFMKA_MEMCPY(&pdu->dist_cak.body[wlen], p->dist_ckn,
            p->dist_ckn_len);
        pdu->dist_cak.body_len = wlen + p->dist_ckn_len;
        pdu->dist_cak.present = true;
    }
    return rc;
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

/**
 * Populate the Distributed SAK parameter set (Key Server only).
 * @param[in]  p    the participant holding the SAK to distribute.
 * @param[out] pdu  the MKPDU whose Distributed SAK set is filled.
 * @return MKA_OK on success, or MKA_ERR_CRYPTO if SAK wrapping fails.
 */
static MkaStatus mka_build_dist_sak(const MkaParticipant* p, MkaPdu* pdu)
{
    size_t wlen = sizeof(pdu->dist_sak.wrapped_sak);
    MkaStatus rc;

    rc = wm_Crypto_WrapSak(p->keys.kek, p->keys.kek_len, p->latest.sak,
        p->latest.sak_len, pdu->dist_sak.wrapped_sak, &wlen);
    if (rc == MKA_OK) {
        pdu->dist_sak.present = true;
        pdu->dist_sak.distributed_an = p->latest.an;
        /* Distribute the in-force offset (negotiated when cipher negotiation is
         * on; the configured offset otherwise). */
        pdu->dist_sak.confidentiality_offset = p->sak_conf_offset;
        pdu->dist_sak.kn = p->latest.kn;
        /* Default GCM-AES-128 is signalled by omitting the cipher suite (0). */
        if (p->sak_cipher_suite == MKA_CIPHER_GCM_AES_128) {
            pdu->dist_sak.cipher_suite = 0U;
        }
        else {
            pdu->dist_sak.cipher_suite = p->sak_cipher_suite;
        }
        pdu->dist_sak.wrapped_len = wlen;
    }
    return rc;
}

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
/**
 * Advertise our supported cipher suite in the Announcement set (11.12).
 *
 * Opt-in (cfg.announce_cipher_suites): announcements are optional in IEEE Std
 * 802.1X and removed entirely by the OpenAlliance automotive profile, so they
 * are off by default and enabled for announcement-driven deployments.
 * @param[in]  p    the participant whose configured suite is advertised.
 * @param[out] pdu  the MKPDU whose Announcement set is filled.
 */
static void mka_build_announce(const MkaParticipant* p, MkaPdu* pdu)
{
    #ifdef WOLFMKA_CIPHER_NEGOTIATION
    /* Advertise the whole preference list so whichever participant becomes Key
     * Server can pick a suite common to all peers. */
    if (p->cfg.cipher_pref_count != 0U) {
        size_t i;
        pdu->announce.present = true;
        pdu->announce.count = 0U;
        /* The config validation (mka_cfg_valid) caps cipher_pref_count at
         * MKA_MAX_CIPHER_SUITES, so the announce suites[] array (sized to that
         * maximum) cannot overflow. */
        WOLFMKA_ASSERT(
            p->cfg.cipher_pref_count <= (size_t)MKA_MAX_CIPHER_SUITES);
        for (i = 0U; i < p->cfg.cipher_pref_count; i++) {
            pdu->announce.suites[i].capability =
                (uint16_t)p->cfg.macsec_capability;
            pdu->announce.suites[i].cipher_suite = p->cfg.cipher_prefs[i];
            pdu->announce.count++;
        }
    }
    else
    #endif
    {
        uint64_t cs = p->cfg.cipher_suite;

        if (cs == 0U) {
            cs = (p->cfg.sak_len == 32U) ? MKA_CIPHER_GCM_AES_256
                                         : MKA_CIPHER_GCM_AES_128;
        }
        pdu->announce.present = true;
        pdu->announce.count = 1U;
        pdu->announce.suites[0].capability = (uint16_t)p->cfg.macsec_capability;
        pdu->announce.suites[0].cipher_suite = cs;
    }
}
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */

/**
 * Populate a complete MkaPdu from the participant's current state.
 * @param[in]  p    the participant whose state is encoded.
 * @param[out] pdu  the MKPDU structure to populate.
 * @return MKA_OK on success, or MKA_ERR_CRYPTO from Distributed SAK
 *         construction if SAK wrapping fails.
 */
static MkaStatus mka_build_fill(const MkaParticipant* p, MkaPdu* pdu)
{
    MkaStatus rc = MKA_OK;

    (void)WOLFMKA_MEMSET(pdu, 0, sizeof(*pdu));

    pdu->basic.version = (uint8_t)WOLFMKA_MKA_VERSION;
    pdu->basic.priority = p->cfg.priority;
    pdu->basic.key_server = p->is_key_server;
    pdu->basic.macsec_desired = p->cfg.macsec_desired;
    pdu->basic.macsec_capability = p->cfg.macsec_capability;
    (void)WOLFMKA_MEMCPY(pdu->basic.sci, p->cfg.sci, MKA_SCI_LEN);
    (void)WOLFMKA_MEMCPY(pdu->basic.mi, p->actor_mi, MKA_MI_LEN);
    pdu->basic.mn = p->actor_mn;
    pdu->basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    (void)WOLFMKA_MEMCPY(pdu->basic.ckn, p->cfg.cak.ckn, p->cfg.cak.ckn_len);
    pdu->basic.ckn_len = p->cfg.cak.ckn_len;

    mka_build_peer_lists(p, pdu);

    if (p->latest.valid) {
        mka_build_sak_use(p, pdu);
    }

    /* Distributed SAK (only the Key Server distributes). */
    if (p->is_key_server && p->latest.valid) {
        rc = mka_build_dist_sak(p, pdu);
    }

#ifdef WOLFMKA_DISTRIBUTED_CAK
    /* Distributed CAK: the Key Server distributes a staged group CAK. Needs
     * only the KEK (always derived), independent of any SAK. */
    if ((rc == MKA_OK) && p->is_key_server && (p->dist_cak_len != 0U)) {
        rc = mka_build_dist_cak(p, pdu);
    }
#endif

#ifdef WOLFMKA_KMD
    /* The Key Server advertises its configured Key Management Domain. */
    if (p->is_key_server && (p->cfg.kmd_len != 0U)) {
        pdu->kmd.present = true;
        (void)WOLFMKA_MEMCPY(pdu->kmd.kmd, p->cfg.kmd, p->cfg.kmd_len);
        pdu->kmd.kmd_len = p->cfg.kmd_len;
    }
#endif

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    if (p->cfg.announce_cipher_suites) {
        mka_build_announce(p, pdu);
    }
#endif
    return rc;
}

/* Fills a scratch MkaPdu from current state (mka_build_fill) and encodes it
 * into the caller's buffer; the actor Message Number is only bumped on
 * success. */
MkaStatus wm_Participant_BuildMkpdu(MkaParticipant* p, uint8_t* out, size_t cap,
    size_t* out_len)
{
    MKA_DECLARE_VAR(pdu, MkaPdu, 1, WOLFMKA_HEAP_HINT);
    MkaStatus rc = MKA_OK;

    if ((p == NULL) || (out == NULL) || (out_len == NULL)) {
        return MKA_ERR_BAD_ARG;
    }

    MKA_ALLOC_VAR(pdu, MkaPdu, 1, MKA_DYN_PDU, &p->ws_pdu,
        rc = MKA_ERR_INTERNAL);

    if (MKA_VAR_OK(pdu)) {
        rc = mka_build_fill(p, pdu);
        if (rc == MKA_OK) {
            rc = wm_Pdu_Encode(p->cfg.cmac, pdu, p->keys.ick, p->keys.ick_len,
                out, cap, out_len);
        }
        if (rc == MKA_OK) {
            /* one MN per transmitted MKPDU */
            p->actor_mn++;
            p->counters.mkpdu_out++;
        }
    }

    MKA_FREE_VAR(pdu, MKA_DYN_PDU);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Periodic run                                                              */
/* ------------------------------------------------------------------------- */

/**
 * Expire peers not heard from within the MKA Life Time.
 * @param[in,out] p       The participant.
 * @param[in]     now_ms  Current monotonic time in milliseconds.
 * @return true if a live peer was removed (which triggers a rekey).
 */
static bool mka_expire_peers(MkaParticipant* p, uint32_t now_ms)
{
    bool removed_live = false;
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        MkaPeer* pe = &p->peers[i];
        uint32_t deadline = MKA_LIFE_TIME_MS;
#ifdef WOLFMKA_SUSPENSION
        /* A peer that advertised a suspension time is held that much longer, so
         * its keys survive the planned quiet period (802.1Xbx-2014). */
        deadline += (uint32_t)pe->suspend_for * 1000U;
#endif
        if (pe->valid && ((now_ms - pe->last_seen_ms) > deadline)) {
            if (pe->live) {
                removed_live = true;
            }
            mka_drop_peer(p, pe);
        }
    }
    return removed_live;
}

/**
 * Build and send one MKPDU through the transmit callback.
 *
 * A transmit callback that fails is not an error - the next tick retries - so
 * it is reported through @c sent rather than the return code.
 * @param[in,out] p     participant.
 * @param[out]    sent  set to true if a frame reached the wire (required).
 * @return MKA_OK or an error from build/allocation.
 */
static MkaStatus mka_transmit_mkpdu(MkaParticipant* p, bool* sent)
{
    MKA_DECLARE_VAR(frame, uint8_t, MKA_MKPDU_MAX_LEN, WOLFMKA_HEAP_HINT);
    size_t flen = 0U;
    MkaStatus rc = MKA_OK;

    MKA_ALLOC_VAR(frame, uint8_t, MKA_MKPDU_MAX_LEN, MKA_DYN_TMP_BUFFER,
        p->ws_frame, rc = MKA_ERR_INTERNAL);

    if (MKA_VAR_OK(frame)) {
        rc = wm_Participant_BuildMkpdu(p, frame, MKA_MKPDU_MAX_LEN, &flen);
        if (rc == MKA_OK) {
            if (p->cfg.send(p->cfg.send_ctx, frame, flen) == 0) {
                *sent = true;
            }
        }
    }

    MKA_FREE_VAR(frame, MKA_DYN_TMP_BUFFER);
    return rc;
}

#ifndef WOLFMKA_NO_AUTO_REKEY
/**
 * Whether the transmit SA's packet number has passed the rekey threshold of
 * IEEE Std 802.1X-2020, 9.8 (0xC0000000 for 32-bit PNs, 0xC000000000000000 for
 * XPN). The relevant get-next-PN hook supplies the value; with no hook there is
 * nothing to measure, so exhaustion is reported as not reached.
 * @param[in] p  the participant providing the PN hook and current AN.
 * @return true once the PN has passed the threshold, else false.
 */
static bool mka_pn_exhausted(const MkaParticipant* p)
{
    const MkaSecyOps* s = &p->cfg.secy;
    uint64_t pn = 0U;

    #ifndef WOLFMKA_NO_XPN
    if (mka_cipher_is_xpn(p->sak_cipher_suite)) {
        return (s->get_next_pn != NULL) &&
               (s->get_next_pn(s->ctx, p->latest.an, &pn) == 0) &&
               (pn > MKA_U64(0xC0000000U, 0x00000000U));
    }
    #endif
    return (s->get_next_pn != NULL) &&
           (s->get_next_pn(s->ctx, p->latest.an, &pn) == 0) &&
           (pn > 0xC0000000U);
}
#endif /* WOLFMKA_NO_AUTO_REKEY */

/**
 * Key Server SAK maintenance, run once a live peer exists: generate the first
 * SAK, and rekey when a live peer just departed (forward secrecy) or per the
 * automatic rekey policy.
 * @param[in,out] p             the participant (must be the Key Server).
 * @param[in]     now_ms        current monotonic time in milliseconds.
 * @param[in]     removed_live  true if a live peer expired this step.
 * @return the SAK generation result (MKA_OK when no rekey was due).
 */
static MkaStatus mka_ks_maybe_rekey(MkaParticipant* p, uint32_t now_ms,
    bool removed_live)
{
    /* A peer that has stopped reporting the SAK has lost it, and only a fresh
     * distribution brings it back (AutoMKA-03011) - so it forces a rekey on the
     * same footing as a departed peer, in every build. */
    bool gen = (!p->latest.valid) || removed_live || p->sak_lost;
    MkaStatus rc = MKA_OK;

#ifndef WOLFMKA_NO_AUTO_REKEY
    /* Automatic rekey (AUTOSAR CP_SWS_Mka_00013/00014): with a SAK in use
     * and no handover already running, rekey after the configured time
     * span or once the transmit PN passes the exhaustion threshold. `!gen`
     * already implies a SAK is in use (gen = !latest.valid ||
     * removed_live), so only the no-handover check remains. */
    if ((!gen) && (!p->old.valid)) {
        if ((p->cfg.sak_rekey_time_ms != 0U) &&
            ((now_ms - p->last_rekey_ms) >= p->cfg.sak_rekey_time_ms)) {
            gen = true;
        }
        else if (mka_pn_exhausted(p)) {
            gen = true;
        }
        else {
            /* no rekey due this step */
        }
    }
#endif /* WOLFMKA_NO_AUTO_REKEY */
    if (gen) {
        rc = mka_ks_generate_sak(p);
        if (rc == MKA_OK) {
            p->last_rekey_ms = now_ms;
            /* Whatever prompted this rekey is answered; peers re-report their
             * SAK Use against the new key. */
            p->sak_lost = false;
        }
    }
    return rc;
}

/**
 * Transmit step of wm_Participant_Run, run when a transmit is due: emit an
 * MKPDU (when a send callback is configured), then on success mark the
 * participant started, stamp the TX time, and grow the retry back-off toward
 * the cyclic ceiling.
 * @param[in,out] p                the participant.
 * @param[in]     now_ms           current monotonic time in milliseconds.
 * @param[out]    sent             optional; set non-zero if a frame was sent.
 * @param[in]     not_established  true while no peer is live (retry regime).
 * @return the transmit result.
 */
static MkaStatus mka_transmit_step(MkaParticipant* p, uint32_t now_ms,
    bool* sent, bool not_established)
{
#ifndef WOLFMKA_NO_RETRY
    bool was_started = p->started;
#endif
    /* Whether a frame actually reached the wire. The transmit callback's
     * failure is not an error for the state machine - the next tick retries -
     * so it never shows up in rc, but the deferred SAK programming must not
     * proceed without it. */
    bool did_send = false;
    MkaStatus rc = MKA_OK;

#ifdef WOLFMKA_NO_RETRY
    (void)not_established;
#endif
    if (p->cfg.send != NULL) {
        rc = mka_transmit_mkpdu(p, &did_send);
    }
    if (sent != NULL) {
        *sent = did_send;
    }
    if (rc == MKA_OK) {
        p->started = true;
        p->last_tx_ms = now_ms;
        /* Whatever changed is now on the wire, so the newInfo condition is
         * satisfied until the next state change sets it again. */
        p->new_info = false;
        if (p->sak_program_pending && did_send) {
            /* The MKPDU carrying the key has gone out, so the data plane can be
             * programmed now (AutoMKA-03010). Deferring until the send succeeds
             * means a key is never installed that no peer has been told about;
             * a failed send leaves it pending and the next tick retries.
             *
             * Ordered after the newInfo clear above, not before: programming
             * raises newInfo again so the MACsec SAK Use reporting us able to
             * receive follows at once, and clearing afterwards would discard
             * it. */
            mka_program_sak(p);
        }
#ifndef WOLFMKA_NO_RETRY
        /* Grow the back-off toward the cyclic ceiling. The first
         * (immediate) transmit leaves the interval at the base so the next
         * retry waits exactly MkaRetryBaseDelay. */
        if ((p->cfg.retry_base_ms != 0U) && not_established && was_started) {
            /* Double toward the cyclic ceiling, saturating rather than wrapping
             * when no ceiling is configured (an unconverged CA could otherwise
             * double past 2^32 ms and wrap back to a tiny retry interval). */
            uint32_t next = (p->retry_delay_ms > (UINT32_MAX / 2U))
                                ? UINT32_MAX
                                : (p->retry_delay_ms * 2U);
            if ((p->cfg.retry_cyclic_ms != 0U) &&
                (next > p->cfg.retry_cyclic_ms)) {
                next = p->cfg.retry_cyclic_ms;
            }
            p->retry_delay_ms = next;
        }
#endif
    }
    return rc;
}

/**
 * Key-Server SAK maintenance and the make-before-break handover for one tick:
 * ensure a SAK exists once a live peer is present (and rekey for forward
 * secrecy when one departs), then advance the handover even if SAK generation
 * failed so the data-plane state stays consistent.
 * @param[in,out] p             the participant.
 * @param[in]     now_ms        current monotonic time in milliseconds.
 * @param[in]     removed_live  true if a live peer expired this step.
 * @return any SAK-generation error, else MKA_OK.
 */
static MkaStatus mka_advance_state(MkaParticipant* p, uint32_t now_ms,
    bool removed_live)
{
    MkaStatus rc = MKA_OK;

    if (p->is_key_server && (wm_Participant_LivePeerCount(p) > 0U)) {
        rc = mka_ks_maybe_rekey(p, now_ms, removed_live);
    }
    mka_maybe_enable_tx(p);
    mka_retire_old(p);
    return rc;
}

/**
 * The transmit interval for this tick: the Hello Time, shortened to the Bounded
 * Hello Time under delay protection, or the growing MKA retry back-off until a
 * peer is established (AUTOSAR CP_SWS_Mka_00012; the OPEN Alliance startup ramp
 * of AutoMKA-03004 is this back-off configured to 10 ms .. Hello Time).
 *
 * This is the periodic cadence only. A participant with
 * MkaParticipantConfig.immediate_response may transmit inside the interval when
 * it has new information - see wm_Participant_Run.
 * @param[in,out] p                the participant (its retry delay may update).
 * @param[in]     not_established  true while no peer is live.
 * @return the transmit interval in milliseconds.
 */
static uint32_t mka_tx_interval(MkaParticipant* p, bool not_established)
{
    uint32_t hello = MKA_HELLO_TIME_MS;

#ifndef WOLFMKA_NO_DELAY_PROTECT
    if (p->cfg.delay_protect) {
        hello = MKA_BOUNDED_HELLO_TIME_MS;
    }
#endif
#ifndef WOLFMKA_NO_RETRY
    if (p->cfg.retry_base_ms != 0U) {
        if (not_established) {
            hello = p->retry_delay_ms;
        }
        else {
            p->retry_delay_ms = p->cfg.retry_base_ms;
        }
    }
#else
    (void)not_established;
    #ifdef WOLFMKA_NO_DELAY_PROTECT
    /* neither feature reads p in this build */
    (void)p;
    #endif
#endif
    return hello;
}

/* Periodic step: expire stale peers, re-run the election, maintain the SAK and
 * the make-before-break handover, then transmit an MKPDU when one is due. */
MkaStatus wm_Participant_Run(MkaParticipant* p, uint32_t now_ms, bool* sent)
{
    bool removed_live;
    bool not_established;
    bool do_tx;
    uint32_t hello;
    MkaStatus rc;

    if (sent != NULL) {
        *sent = false;
    }
    if (p == NULL) {
        return MKA_ERR_BAD_ARG;
    }

    removed_live = mka_expire_peers(p, now_ms);
    mka_run_election(p);

    rc = mka_advance_state(p, now_ms, removed_live);
    if (rc != MKA_OK) {
        return rc;
    }

    not_established = (wm_Participant_LivePeerCount(p) == 0U);
    hello = mka_tx_interval(p, not_established);
    /* Transmit on the first run; when there is new information to report and
     * the participant is configured to answer at once (the newInfo behaviour of
     * IEEE Std 802.1X-2010, 9.4; OPEN Alliance AutoMKA-03003); or when the
     * interval has elapsed (Hello / Bounded Hello / retry back-off, per
     * mka_tx_interval). */
    do_tx = (!p->started) || (p->cfg.immediate_response && p->new_info) ||
            ((now_ms - p->last_tx_ms) >= hello);
    if (p->quiesced) {
        /* Another CA on this port has MACsec up, so this one has nothing to
         * negotiate with and stays silent (AutoMKA-09001). Timers and peer
         * expiry still run, so it resumes cleanly when released. */
        do_tx = false;
    }
#ifdef WOLFMKA_SUSPENSION
    /* While suspended, transmit only the one-shot suspension announcement, then
     * go quiet (802.1Xbx-2014). */
    if (p->suspended) {
        do_tx = p->suspend_announce;
        p->suspend_announce = false;
    }
#endif
    if (do_tx) {
        rc = mka_transmit_step(p, now_ms, sent, not_established);
    }

    return rc;
}

/* Report that a pending asynchronous SecY operation has finished; re-checks the
 * transmit gate, which may now release. */
MkaStatus wm_Participant_SecyComplete(MkaParticipant* p)
{
    if (p == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    /* A failed async install is still no longer outstanding; the engine has no
     * recovery path for it, matching the synchronous fire-and-forget design -
     * which is why no result is taken. */
    if (p->secy_pending > 0U) {
        p->secy_pending--;
    }
    /* The data plane may now be ready. mka_maybe_enable_tx re-checks the
     * pending count and every other precondition itself, so this is a harmless
     * no-op when the gate has not actually released. */
    mka_maybe_enable_tx(p);
    return MKA_OK;
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
/* Stage a group CAK and its CKN for the Key Server to wrap and emit in the
 * Distributed CAK parameter set. */
MkaStatus wm_Participant_DistributeCak(MkaParticipant* p, const uint8_t* cak,
    size_t cak_len, const uint8_t* ckn, size_t ckn_len)
{
    if ((p == NULL) || (cak == NULL) || (ckn == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_aes_key_len_valid(cak_len) || (ckn_len == 0U) ||
        (ckn_len > MKA_MAX_CKN_LEN)) {
        return MKA_ERR_BAD_ARG;
    }
    (void)WOLFMKA_MEMCPY(p->dist_cak, cak, cak_len);
    p->dist_cak_len = cak_len;
    (void)WOLFMKA_MEMCPY(p->dist_ckn, ckn, ckn_len);
    p->dist_ckn_len = ckn_len;
    return MKA_OK;
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

/* Thin public wrapper that gates mka_ks_generate_sak() on Key-Server status. */
MkaStatus wm_Participant_Rekey(MkaParticipant* p)
{
    if (p == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    if (!p->is_key_server) {
        return MKA_ERR_NOT_KS;
    }
    return mka_ks_generate_sak(p);
}

#ifdef WOLFMKA_SUSPENSION
/* Suspend MKA: advertise the suspension time once, then go quiet so peers hold
 * our state past the Life Time. */
MkaStatus wm_Participant_Suspend(MkaParticipant* p, uint8_t seconds)
{
    if (p == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    p->suspended = true;
    p->suspend_for = seconds;
    /* announce once, then go quiet */
    p->suspend_announce = true;
    return MKA_OK;
}

/* Resume from suspension: clear the suspended state and return to normal MKPDU
 * transmission. */
MkaStatus wm_Participant_Resume(MkaParticipant* p)
{
    if (p == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    p->suspended = false;
    p->suspend_announce = false;
    p->suspend_for = 0U;
    return MKA_OK;
}
#endif /* WOLFMKA_SUSPENSION */

/* Tear down any installed SecY SAs so the data plane retains no SAK, then
 * securely wipe all key material (CAK, derived KEK/ICK, SAKs). NULL-tolerant.
 */
void wm_Participant_Free(MkaParticipant* p)
{
    if (p == NULL) {
        return;
    }
    if (p->old.valid) {
        mka_delete_sak_sas(p, &p->old);
    }
    if (p->latest.valid) {
        mka_delete_sak_sas(p, &p->latest);
    }
    wm_Crypto_ForceZero(p, sizeof(*p));
}

/* ------------------------------------------------------------------------- */
/* KaY manager: multiple Connectivity Associations on one port               */
/* ------------------------------------------------------------------------- */

/* Participants live inline in the MkaKay; init only resets the count. */
MkaStatus wm_Kay_Init(MkaKay* kay)
{
    if (kay == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    kay->count = 0U;
    /* Every field wm_Kay_Init does not deliberately leave to the participants
     * must be set here: the participant array is not zeroed (it is large, and
     * wm_Kay_AddParticipant initialises each entry as it is added), so anything
     * missed here keeps the caller's stack contents. */
    kay->quiesce_others = false;
    return MKA_OK;
}

/* Securely free every participant (wiping their key material), then reset the
 * count. NULL-tolerant. */
void wm_Kay_Free(MkaKay* kay)
{
    size_t i;

    if (kay == NULL) {
        return;
    }
    for (i = 0U; i < kay->count; i++) {
        wm_Participant_Free(&kay->parts[i]);
    }
    kay->count = 0U;
}

/* Linear scan over the configured CAKs comparing the full CKN. */
MkaParticipant* wm_Kay_Find(MkaKay* kay, const uint8_t* ckn, size_t ckn_len)
{
    MkaParticipant* result = NULL;

    if ((kay != NULL) && (ckn != NULL)) {
        size_t i;
        for (i = 0U; i < kay->count; i++) {
            const MkaCakPair* c = &kay->parts[i].cfg.cak;
            if ((c->ckn_len == ckn_len) &&
                (WOLFMKA_MEMCMP(c->ckn, ckn, ckn_len) == 0)) {
                result = &kay->parts[i];
                break;
            }
        }
    }
    return result;
}

/* Rejects a duplicate CKN before init so the slot is only consumed on success;
 * the count is bumped only after wm_Participant_Init succeeds. */
MkaStatus wm_Kay_AddParticipant(MkaKay* kay, const MkaParticipantConfig* cfg,
    MkaParticipant** out)
{
    MkaStatus rc;

    if ((kay == NULL) || (cfg == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (kay->count >= (size_t)MKA_MAX_PARTICIPANTS) {
        return MKA_ERR_FULL;
    }
    if (wm_Kay_Find(kay, cfg->cak.ckn, cfg->cak.ckn_len) != NULL) {
        /* CKN already managed */
        return MKA_ERR_STATE;
    }

    rc = wm_Participant_Init(&kay->parts[kay->count], cfg);
    if (rc == MKA_OK) {
        if (out != NULL) {
            *out = &kay->parts[kay->count];
        }
        kay->count++;
    }
    return rc;
}

/* Frees the matching participant (deleting its SAs and wiping its keys), then
 * shifts the survivors down so parts[0..count-1] stays contiguous; the vacated
 * tail slot is force-zeroed as it still holds a copy of moved key material. */
MkaStatus wm_Kay_RemoveParticipant(MkaKay* kay, const uint8_t* ckn,
    size_t ckn_len)
{
    size_t i;
    size_t idx = MKA_MAX_PARTICIPANTS;

    if ((kay == NULL) || (ckn == NULL)) {
        return MKA_ERR_BAD_ARG;
    }

    for (i = 0U; i < kay->count; i++) {
        const MkaCakPair* c = &kay->parts[i].cfg.cak;
        if ((c->ckn_len == ckn_len) &&
            (WOLFMKA_MEMCMP(c->ckn, ckn, ckn_len) == 0)) {
            idx = i;
            break;
        }
    }
    if (idx == MKA_MAX_PARTICIPANTS) {
        /* no CA owns this CKN */
        return MKA_ERR_NO_PEER;
    }

    /* tear down SAs, wipe keys */
    wm_Participant_Free(&kay->parts[idx]);
    for (i = idx; (i + 1U) < kay->count; i++) {
        kay->parts[i] = kay->parts[i + 1U];
    }
    /* The old last slot now duplicates the moved-up participant's key material;
     * wipe it before dropping the count. */
    wm_Crypto_ForceZero(&kay->parts[kay->count - 1U], sizeof(MkaParticipant));
    kay->count--;
    return MKA_OK;
}

/* Runs every participant; keeps the first non-OK status but still steps the
 * rest (one CA's failure must not stall the others). */
MkaStatus wm_Kay_SetQuiesceOthers(MkaKay* kay, bool enable)
{
    if (kay == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    kay->quiesce_others = enable;
    if (!enable) {
        /* Release anything already held, so turning the policy off takes
         * effect without waiting for a session to drop. */
        size_t i;
        for (i = 0U; i < kay->count; i++) {
            kay->parts[i].quiesced = false;
        }
    }
    return MKA_OK;
}

/**
 * Apply the quiesce policy for this tick: while one participant has MACsec up,
 * every other one is held silent; otherwise none is.
 * @param[in,out] kay  the KaY.
 */
static void mka_kay_apply_quiesce(MkaKay* kay)
{
    const MkaParticipant* winner = NULL;
    size_t i;

    for (i = 0U; i < kay->count; i++) {
        const MkaParticipant* p = &kay->parts[i];
        if (p->latest.valid && p->latest.tx) {
            winner = p;
            break;
        }
    }
    for (i = 0U; i < kay->count; i++) {
        MkaParticipant* p = &kay->parts[i];
        p->quiesced = (winner != NULL) && (p != winner);
    }
}

MkaStatus wm_Kay_Run(MkaKay* kay, uint32_t now_ms)
{
    MkaStatus rc = MKA_OK;
    size_t i;

    if (kay == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    if (kay->quiesce_others) {
        mka_kay_apply_quiesce(kay);
    }
    for (i = 0U; i < kay->count; i++) {
        MkaStatus s = wm_Participant_Run(&kay->parts[i], now_ms, NULL);
        if ((s != MKA_OK) && (rc == MKA_OK)) {
            /* report the first failure */
            rc = s;
        }
    }
    return rc;
}

/* The CKN is read from the unauthenticated Basic set (peek) only to select the
 * owning participant; that participant then verifies the ICV before acting. */
MkaStatus wm_Kay_Receive(MkaKay* kay, const uint8_t* frame, size_t len,
    uint32_t now_ms)
{
    MkaBasicParamSet basic;
    MkaParticipant* p;
    MkaStatus rc;

    if ((kay == NULL) || (frame == NULL)) {
        return MKA_ERR_BAD_ARG;
    }

    rc = wm_Pdu_PeekBasic(frame, len, &basic);
    if (rc != MKA_OK) {
        /* malformed basic set */
        return rc;
    }

    p = wm_Kay_Find(kay, basic.ckn, basic.ckn_len);
    if (p == NULL) {
        /* no CA owns this CKN */
        return MKA_ERR_NO_PEER;
    }
    return wm_Participant_Receive(p, frame, len, now_ms);
}

/* NULL-tolerant accessor for the participant count. */
size_t wm_Kay_ParticipantCount(const MkaKay* kay)
{
    return (kay != NULL) ? kay->count : 0U;
}
