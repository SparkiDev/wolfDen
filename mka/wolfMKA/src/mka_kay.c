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

/** Notify that the CA no longer has an elected Key Server. */
static void mka_ev_key_server_lost(const MkaParticipant* p,
    const uint8_t sci[MKA_SCI_LEN])
{
    if (p->cfg.events.key_server_lost != NULL) {
        p->cfg.events.key_server_lost(p->cfg.events.ctx, sci);
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
 * Count the peer-table entries already held by one SCI.
 *
 * A device is identified on the wire by its SCI; its Member Identifier changes
 * whenever it restarts. Counting per SCI is therefore what bounds how much of
 * the table one device can occupy.
 *
 * The SCI is self-asserted, so this bounds a device that varies only its MI -
 * which is what a restart, a misconfiguration or a stuck peer actually does. A
 * CAK-holding member intent on filling the table can vary its SCI too and get a
 * fresh allowance each time; inside a CA that is a trust question, not a
 * parsing one (see mka_retire_stale_mi). MKA_MAX_PEERS remains the hard bound.
 * @param[in] p    the participant owning the peer table.
 * @param[in] sci  the SCI to count (MKA_SCI_LEN octets).
 * @return the number of valid entries carrying that SCI.
 */
static size_t mka_sci_entry_count(const MkaParticipant* p,
    const uint8_t sci[MKA_SCI_LEN])
{
    size_t n = 0U;
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (pe->valid && (WOLFMKA_MEMCMP(pe->sci, sci, MKA_SCI_LEN) == 0)) {
            n++;
        }
    }
    return n;
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
    mka_ev_peer_lost(p, pe->mi, pe->ever_live);
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

    /* A live peer is the association's actual counterpart, so it wins. Both
     * loops stop at the first hit: the header describes peer_sci for the
     * point-to-point case, where there is only one, and in a group CA the
     * choice should at least be the same rule twice - scanning on here and
     * breaking below meant the highest-indexed live peer won but the
     * lowest-indexed merely-valid one did, so the reported SCI could change
     * when an unrelated peer was dropped and its slot reused. */
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        if (pe->valid && pe->live) {
            best = pe;
            break;
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

    /* The Old key counts as running: a make-before-break rekey demotes the
     * in-force key (which keeps its transmit SA) and leaves latest.tx false
     * until the peers report receiving on the new one. Protection is unbroken
     * throughout, so testing latest.tx alone would drop the reported state back
     * to IN_PROGRESS on every rekey. */
    if ((p->latest.valid && p->latest.tx) || (p->old.valid && p->old.tx)) {
        out->state = MKA_PAE_RUNNING;
        out->cipher_suite = p->sak_cipher_suite;
    }
    else if (p->peer_count != 0U) {
        out->state = MKA_PAE_IN_PROGRESS;
    }
    else if ((p->counters.icv_failures != 0U) && (p->counters.mkpdu_in == 0U)) {
        /* Frames are arriving and *none* has ever authenticated: the far end is
         * configured with a different CAK, which is a distinct condition from
         * silence. Requiring mkpdu_in == 0 keeps it to that case - a single
         * corrupted frame on an association that has worked is not an
         * authentication failure, and icv_failures never decreases, so without
         * this the state would be reported for the rest of the participant's
         * life every time the peer table happened to be empty. */
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

    /* Stop at the first hit, as mka_set_latest_ks_mi does: a peer list is not
     * required to hold distinct Member Identifiers, and letting a later
     * duplicate overwrite an earlier one would make the last entry win. That
     * matters because the number this returns is what mka_stale_live_echo
     * tests for recency - a stale copy appended after a current one would
     * discard the whole MKPDU. The early exit also usually ends the search at
     * the first element rather than always scanning the list. */
    for (i = 0U; i < list->count; i++) {
        if (WOLFMKA_MEMCMP(list->peers[i].mi, mi, MKA_MI_LEN) == 0) {
            *mn = list->peers[i].mn;
            found = true;
            break;
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
        uint32_t window = (uint32_t)MKA_MN_RECENT_WINDOW;
        /* Only as many numbers as have actually been emitted can be recent.
         * Message Numbers start at 1, so actor_mn - 1 is the count; without
         * this clamp the first two MKPDUs would also accept 0 and 0xFFFFFFFF,
         * which were never sent. */
        if (window > (p->actor_mn - 1U)) {
            window = p->actor_mn - 1U;
        }
        age = (p->actor_mn - 1U) - mn;
        recent = (age < window);
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
    /* Both crypto workspaces are caller-allocated and mandatory. wolfSSL's
     * ~1 KB Cmac context and its WC_RNG are never placed on wolfMKA's stack or
     * heap, so there is nothing to substitute when one is missing - and a
     * silent substitution is exactly what a WOLFMKA_SMALL_STACK /
     * WOLFMKA_NO_MALLOC build cannot afford. Rejected here rather than at first
     * use, so a misconfiguration fails at init instead of at the first rekey.
     */
    if ((cfg->cmac == NULL) || (cfg->rng == NULL)) {
        return false;
    }
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
    /* The MACsec Capability is a two-bit wire field (11.11.1), so a larger
     * value would be advertised as whatever its low two bits happen to be -
     * a configuration of 4 would tell every peer this participant implements
     * no MACsec at all, while the local capability comparison went on reading
     * 4 and concluding the CA can do everything. Failing at init keeps this
     * with the other out-of-range configuration values (FMEA FM-24) rather
     * than letting it become a silent asymmetry. */
    if (cfg->macsec_capability > (uint8_t)MKA_CAP_INTEGRITY_CONF_OFFSET) {
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
    else {
        /* Make good on the promise above. The configuration copy already holds
         * the caller's plaintext CAK, and a failure after DeriveKeys leaves the
         * derived KEK and ICK next to it, so returning here without a wipe
         * would strand key material in the object - and in a caller-provided
         * MkaKay slot that wm_Kay_Free() never walks, because
         * wm_Kay_AddParticipant does not count a participant that failed to
         * initialise. No SecY state exists yet, so zeroing is the whole
         * teardown. */
        wm_Crypto_ForceZero(p, sizeof(*p));
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
 *
 * The automotive profile's priority-255 rule applies here as it does to the
 * dynamic election: 255 is an absolute "never Key Server" (AutoMKA-03007), so a
 * peer advertising both that priority and the Key Server role is contradicting
 * itself and is not adopted. Refusing can leave a pinned peer with no Key
 * Server at all, which is the fail-closed outcome - it distributes no SAK and
 * brings no MACsec up - and is preferable to accepting a SAK from a device that
 * has declared itself ineligible to issue one.
 * @param[in,out] p  the participant whose election state is updated.
 */
static void mka_elect_fixed_peer(MkaParticipant* p)
{
    size_t i;

    p->is_key_server = false;
    p->elected = false;
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        const MkaPeer* pe = &p->peers[i];
        bool peer_ok = pe->valid && pe->live && pe->key_server;
#ifdef WOLFMKA_AUTOMOTIVE_PROFILE
        if (pe->priority == (uint8_t)MKA_PRIORITY_NEVER_KS) {
            peer_ok = false;
        }
#endif
        if (peer_ok) {
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
        if (p->cfg.macsec_desired) {
            /* Fixed-role configuration (AUTOSAR CP_SWS_Mka_00011): the role is
             * pinned, so the dynamic election is bypassed entirely. */
            p->elected = true;
            p->is_key_server = true;
            (void)WOLFMKA_MEMCPY(p->ks_sci, p->cfg.sci, MKA_SCI_LEN);
        }
        else {
            /* A participant that does not want MACsec must not serve keys for
             * it, pinned role or not - the dynamic election already refuses,
             * and running MKA with MACsec disabled depends on it (OPEN Alliance
             * AutoMKA-12002). */
            p->elected = false;
            p->is_key_server = false;
        }
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
    /* The other edge. mka_election_changed only reports an election that was
     * made, so losing one - the last live peer expiring, or a fixed-PEER
     * participant's Key Server ceasing to advertise the role - used to fire
     * nothing at all, and an integrator gating a controlled port on the
     * election never saw it go away. Reported with the SCI that was in force,
     * because p->ks_sci keeps its stale value across the gap and only
     * p->elected distinguishes it. */
    if (was_elected && (!p->elected)) {
        mka_ev_key_server_lost(p, old_sci);
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
 *
 * The cipher suite, confidentiality offset and XPN SSCI are per-Secure-Channel
 * in the SecY interface (see MkaSecyOps::set_cipher_suite), not per-Secure-
 * Association, so the channel carries the Latest key's parameters and the Old
 * key's SA shares them. A rekey that also changes the suite or offset therefore
 * cannot validate the Old key's in-flight frames - a deliberate limit of the
 * abstraction rather than an oversight, and the same trade-off
 * mka_reapply_xpn_ssci documents for SSCI ranks. Supporting it would mean
 * storing the suite and offset in MkaSak and configuring per key, which no
 * SecY this interface targets can express. In practice the suite is fixed for
 * the life of a CA unless WOLFMKA_CIPHER_NEGOTIATION re-derives it from a
 * changed membership.
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
 * @param[in]     ks_mi    Member Identifier of the Key Server issuing the key -
 *                         our own when we are it. Stored with the key so it can
 *                         later be recognised by its full Key Identifier.
 */
static void mka_install_sak(MkaParticipant* p, const uint8_t* sak,
    size_t sak_len, uint8_t an, uint32_t kn, const uint8_t* ks_mi)
{
    /* Demote the current Latest to Old; force-retire any unfinished Old. A new
     * SAK always carries a fresh Key Number, so a valid Latest is always a
     * different key here. */
    if (p->latest.valid) {
        if (p->sak_program_pending) {
            /* This key was adopted but never programmed - its distribution had
             * not reached the wire yet - so there are no SecY SAs to keep for
             * in-flight traffic and none to delete later. Replace it outright
             * rather than demoting a phantom to Old. */
            wm_Crypto_ForceZero(&p->latest, sizeof(p->latest));
        }
        else {
            if (p->old.valid) {
                mka_delete_sak_sas(p, &p->old);
            }
            /* its SecY SAs stay installed */
            p->old = p->latest;
        }
    }

    p->latest.valid = true;
    /* The buffer is a fixed MKA_MAX_CAK_LEN and only sak_len octets are
     * written, so a shorter key than the one it replaces would leave the tail
     * of the old one behind - and once the Old copy is retired and wiped, that
     * tail is the only surviving piece of a dead SAK. Clear the whole buffer.
     */
    wm_Crypto_ForceZero(p->latest.sak, sizeof p->latest.sak);
    (void)WOLFMKA_MEMCPY(p->latest.sak, sak, sak_len);
    p->latest.sak_len = sak_len;
    p->latest.an = an;
    p->latest.kn = kn;
    (void)WOLFMKA_MEMCPY(p->latest.ks_mi, ks_mi, MKA_MI_LEN);
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
        mka_install_sak(p, sak, sak_len, an, kn, p->actor_mi);
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
 *
 * "Already installed" means the same Key Identifier, KI = (Key Server MI || Key
 * Number), not the same Key Number. Key Numbers are unique only per Key-Server
 * incarnation: a Key Server that restarts comes back with a fresh MI, no stored
 * key, and therefore begins again at KN 1 - carrying key bytes nobody else has.
 * Comparing KN alone made the member skip that install and keep the dead key,
 * while the restarted Key Server transmitted on the new one at the same AN.
 * Both ends reported MACsec running over a silent black-hole, with no
 * self-recovery, and it was guaranteed rather than racy wherever the member
 * cannot self-promote (a pinned MKA_ROLE_PEER, or key_server_capable = false -
 * the AUTOSAR and automotive configuration).
 * @param[in] p      participant.
 * @param[in] d      the received Distributed SAK parameter set.
 * @param[in] ks_mi  Member Identifier of the sender, which the caller has
 *                   already established is the elected Key Server.
 * @return true to skip installation, false to proceed.
 */
static bool mka_dist_sak_skip(const MkaParticipant* p, const MkaDistSak* d,
    const uint8_t* ks_mi)
{
    bool already_held =
        p->latest.valid && (d->kn == p->latest.kn) &&
        (WOLFMKA_MEMCMP(p->latest.ks_mi, ks_mi, MKA_MI_LEN) == 0);

    return (d->wrapped_len == 0U) || (!p->cfg.macsec_desired) || already_held;
}

/**
 * Non-Key-Server: unwrap and install a distributed SAK as Latest.
 * @param[in,out] p      participant.
 * @param[in]     d      the received Distributed SAK parameter set.
 * @param[in]     ks_mi  Member Identifier of the Key Server that issued it.
 * @return MKA_OK, or MKA_ERR_CRYPTO if unwrapping fails.
 */
static MkaStatus mka_install_from_dist(MkaParticipant* p, const MkaDistSak* d,
    const uint8_t* ks_mi)
{
    uint8_t sak[MKA_MAX_CAK_LEN];
    size_t sak_len = sizeof(sak);
    MkaStatus rc;

    if (mka_dist_sak_skip(p, d, ks_mi)) {
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
        /* The Key Server's choice still has to be one we implement, and to
         * agree with the key length it actually sent: the suite is carried
         * straight through to the SecY, so an unchecked value would program the
         * data plane with something the CA never negotiated. */
        if (!mka_cipher_suite_valid(d->cipher_suite, (uint8_t)sak_len)) {
            rc = MKA_ERR_PARSE;
        }
    }
    if (rc == MKA_OK) {
        /* Adopt the cipher suite and confidentiality offset chosen by the Key
         * Server (cipher suite 0 => 128). */
        p->sak_cipher_suite =
            (d->cipher_suite == 0U) ? MKA_CIPHER_GCM_AES_128 : d->cipher_suite;
        p->sak_conf_offset = d->confidentiality_offset;
        mka_install_sak(p, sak, sak_len, d->distributed_an, d->kn, ks_mi);
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
 * and trigger another rekey, and so on. The mirror case - a peer naming our key
 * as its *Old* one because it has moved on and we have not - needs no handling
 * here: only the Key Server evaluates this at all (see mka_refresh_peer), and
 * only the Key Server issues Key Numbers, so a peer can never be ahead of it.
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
 * Forget what a peer last reported about its use of a key.
 *
 * A member that still holds a key always includes the MACsec SAK Use parameter
 * set, so its absence is a statement: the peer is no longer using one. Without
 * this the last report would stand indefinitely - the Key Server notices the
 * loss through mka_note_sak_use, but a plain member does not run that check,
 * so its peer table would keep claiming the peer is receiving and transmitting
 * under a key it has dropped. That claim feeds the transmit gate
 * (mka_peers_rx_on) and the Old-key retirement rule (mka_retire_old), both of
 * which would then release on evidence that has expired.
 *
 * The delay-protection side of mka_apply_sak_use is deliberately not undone:
 * the lowest acceptable packet number is a monotonically advancing bound in the
 * SecY, and winding it back is neither possible nor desirable.
 * @param[in,out] pe  The peer whose SAK Use claim is being cleared.
 */
static void mka_clear_sak_use(MkaPeer* pe)
{
    pe->sak_rx = false;
    pe->sak_tx = false;
    pe->latest_kn = 0U;
    pe->latest_lpn = 0U;
    pe->latest_lpn_msb = 0U;
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
    if (p->cfg.delay_protect && (s->set_lowest_pn != NULL)) {
        /* Convey the full 64-bit Lowest Acceptable PN: the low 32 bits from the
         * SAK Use set and the high 32 from the XPN set (zero for non-XPN). */
        uint64_t lpn64 =
            ((uint64_t)pe->latest_lpn_msb << 32U) | (uint64_t)pe->latest_lpn;
        /* Bound the Secure Association the peer is actually reporting on, not
         * whichever one happens to be Latest here. Mid make-before-break a peer
         * that has not installed the new key still names the Old one, and
         * advancing the Latest key's replay window to the Old key's packet
         * number would discard every frame the peer sends once it does install
         * it - a blackhole that lasts until the next rekey, or forever if the
         * rekey was driven by packet-number exhaustion. A Key Number we do not
         * hold bounds nothing. */
        if (p->latest.valid && (su->latest_kn == p->latest.kn)) {
            (void)s->set_lowest_pn(s->ctx, pe->sci, p->latest.an, lpn64);
        }
        else if (p->old.valid && (su->latest_kn == p->old.kn)) {
            (void)s->set_lowest_pn(s->ctx, pe->sci, p->old.an, lpn64);
        }
        else {
            /* not a key of ours */
        }
    }
#else
    (void)s;
#endif
}

/**
 * Reclaim one entry for an SCI that has used up its per-device allowance.
 *
 * A device that resets twice inside the Life Time would otherwise lock itself
 * out: its first incarnation still occupies a slot, its second was admitted but
 * never proved liveness before the second reset, and the third is refused with
 * MKA_ERR_FULL. Nothing else frees either one - mka_retire_stale_mi runs only
 * when an entry for that SCI *becomes live*, which is exactly what cannot
 * happen - so the device stays out until the first entry ages out, up to a full
 * MKA_LIFE_TIME_MS after the reset it already recovered from.
 *
 * Only an entry that has never been live is taken, and the oldest of those. An
 * entry that once proved liveness is a working association until the Life Time
 * says otherwise, and admission happens before the newcomer has proved
 * anything - so a member asserting another member's SCI must not be able to
 * displace it. Never-live entries carry no such standing: nothing was ever
 * established with them.
 *
 * This does not weaken the cap. A member cycling Member Identifiers still holds
 * at most MKA_MAX_PEERS_PER_SCI entries; it can now churn its own share, which
 * is the behaviour the cap was drawn around in the first place.
 * @param[in,out] p       the participant owning the peer table.
 * @param[in]     sci     the SCI whose allowance is exhausted.
 * @param[in]     now_ms  current time, for picking the oldest candidate.
 * @return true if an entry was freed.
 */
static bool mka_evict_stale_sci_entry(MkaParticipant* p,
    const uint8_t sci[MKA_SCI_LEN], uint32_t now_ms)
{
    MkaPeer* victim = NULL;
    uint32_t oldest = 0U;
    size_t i;

    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        MkaPeer* pe = &p->peers[i];
        if (pe->valid && (!pe->ever_live) &&
            (WOLFMKA_MEMCMP(pe->sci, sci, MKA_SCI_LEN) == 0)) {
            /* Unsigned subtraction, so the age is correct across the 32-bit
             * millisecond rollover. */
            uint32_t age = now_ms - pe->last_seen_ms;
            if ((victim == NULL) || (age > oldest)) {
                oldest = age;
                victim = pe;
            }
        }
    }
    if (victim != NULL) {
        mka_drop_peer(p, victim);
    }
    return victim != NULL;
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
    uint32_t now_ms, MkaPeer** pe_out, bool* added_out)
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
        if (mka_sci_entry_count(p, pdu->basic.sci) >= MKA_MAX_PEERS_PER_SCI) {
            /* This device already holds its allowance of entries. Reclaim one
             * that never proved liveness, so a device that reset twice inside
             * the Life Time is not locked out by its own dead incarnations;
             * failing that, refuse. Either way the cap holds, bounding a member
             * that cycles Member Identifiers to its own share of the table
             * instead of letting it crowd out every other CA member. */
            if (!mka_evict_stale_sci_entry(p, pdu->basic.sci, now_ms)) {
                return MKA_ERR_FULL;
            }
        }
        pe = mka_add_peer(p, pdu->basic.mi);
        *added_out = (pe != NULL);
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
    /* Record the cipher suites the peer announced, for Key Server selection.
     * Announcements are optional in every MKPDU (IEEE Std 802.1X-2010, 11.12),
     * so what a peer once announced stands until it announces something else -
     * clearing the set on an MKPDU that simply omits it would read as "accepts
     * anything" and let the next rekey hand that peer a suite it ruled out. A
     * peer that has never announced starts at adv_count == 0, since
     * mka_add_peer zeroes the entry. */
    if (pdu->announce.present) {
        size_t k;

        pe->adv_count = 0U;
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
    if (pe->live) {
        pe->ever_live = true;
    }

    /* Only a peer that has proven two-way liveness may move our state. A CA
     * member holding the CAK - so its ICV verifies - but never echoing our MI
     * stays merely Potential and can win no election and distribute no SAK;
     * without this gate it could still steer the SecY through the SAK Use it
     * claims, naming another member's SCI to poison that member's replay
     * window, or oscillate the Key Number to force a rekey on every tick. */
    if (pe->live) {
        if (p->is_key_server) {
            /* Only the Key Server acts on a lost SAK, and only it can compare
             * a peer's report against the key it issued: a member evaluating
             * this would latch the flag on every rekey, because the Key Server
             * announces the new Key Number before the member has installed
             * it. */
            mka_note_sak_use(p, pe, pdu);
        }
        if (pdu->sak_use.present) {
            mka_apply_sak_use(p, pe, &pdu->sak_use, &pdu->xpn);
        }
        else {
            mka_clear_sak_use(pe);
        }
    }
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
 * first sight of it, so a replayed or truncated exchange cannot evict a working
 * peer. That is the limit of what this check buys: anything reaching here has
 * already passed the ICV, so it holds the CAK. In a group CA - one established
 * by Distributed CAK, where every member shares the key - a member can read
 * this participant's MI and Message Number off the wire (MKPDUs are
 * authenticated, not encrypted), echo them to become live, and assert another
 * member's SCI in its Basic Parameter Set, since the SCI is self-asserted and
 * copied verbatim. Retirement then drops the victim's entry. The same
 * self-asserted SCI is the only gate on accepting a Distributed SAK, so a
 * CAK-holding member is already trusted with far more than this; a group CA is
 * a trust domain, not a set of mutually isolated peers.
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
#ifdef WOLFMKA_CIPHER_NEGOTIATION
        /* A join does not normally rekey - see test_kay_join_no_rekey - but a
         * member less capable than the CA negotiated for is the exception. The
         * confidentiality offset and the integrity-only decision travel inside
         * the Distributed SAK parameter set, so they belong to the key: there
         * is no message that changes them for a key already issued. Without a
         * rekey the Key Server would go on protecting with the offset it chose
         * before, while the joiner programmed its own data plane from its own
         * capability - the two ends disagreeing about what the CA is doing.
         *
         * Only a *reduction* triggers this. A member at least as capable as the
         * CA changes nothing, which is why the ordinary join stays rekey-free.
         */
        if (p->is_key_server && p->latest.valid) {
            bool now_integ_only =
                (mka_min_capability(p) <= (uint8_t)MKA_CAP_INTEGRITY_ONLY);
            if ((now_integ_only != p->sak_integrity_only) ||
                (mka_negotiate_offset(p) != p->sak_conf_offset)) {
                p->cap_reduced = true;
            }
        }
#endif
    }
    else if ((!now_live) && was_live) {
        /* The peer stopped proving liveness and drops out of the Live Peer
         * List. Its receive SAs stay installed until it expires, because the
         * loss may be one-directional and transient and tearing them down would
         * break traffic that is still arriving; but the Key Server must treat
         * the membership change as a departure. Without this the peer's
         * eventual expiry raises no forward-secrecy rekey - it is no longer
         * live by then - and the key it still holds would be handed to whoever
         * joins next. */
        p->live_lost = true;
        p->new_info = true;
#ifndef WOLFMKA_NO_XPN
        /* A departure shifts the XPN ranks exactly as a join does - an SSCI is
         * the SCI's rank within the *live* membership - so the channels have to
         * be reprogrammed here too. On a Key Server this was masked, because a
         * departure forces a rekey and mka_program_sak reapplies the suite to
         * every channel; a member never rekeys, so its ranks simply went stale
         * and it transmitted XPN frames with an SSCI no one else computed. */
        mka_reapply_xpn_ssci(p);
#endif
    }
    else {
        /* liveness unchanged */
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
            rc = mka_install_from_dist(p, &pdu->dist_sak, pdu->basic.mi);
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

    rc = mka_admit_peer(p, pdu, now_ms, &pe, &added);
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
static void mka_build_xpn(const MkaParticipant* p, MkaPdu* pdu,
    uint64_t latest_pn, uint64_t old_pn)
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
        /* The packet numbers were already read by the caller: this only splits
         * out the upper halves. Re-querying here would call get_next_pn a
         * second time per key - four times per MKPDU during a handover - and
         * the SecY hook makes no promise of idempotence. The project's own test
         * shim advances a counter on every call, and a real backend may read a
         * clear-on-read register or cost a management-bus transaction. Sharing
         * one read also removes a split-brain hazard: a second query that
         * failed used to leave the low half from the first read beside a zero
         * upper half, so the peer reconstructed a truncated 64-bit LPN rather
         * than seeing no update. */
        pdu->xpn.latest_lpn_msb = (uint32_t)(latest_pn >> 32U);
        pdu->xpn.old_lpn_msb = (uint32_t)(old_pn >> 32U);
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
        /* Peer-reset handling can leave two entries for one SCI - the stale
         * incarnation and the live one - so match on liveness and stop at the
         * first hit rather than letting a later stale entry overwrite it. */
        for (i = 0U; i < MKA_MAX_PEERS; i++) {
            const MkaPeer* pe = &p->peers[i];
            /* live implies valid: a dropped peer is zeroed. */
            if (pe->live) {
                if (WOLFMKA_MEMCMP(pe->sci, p->ks_sci, MKA_SCI_LEN) == 0) {
                    (void)WOLFMKA_MEMCPY(pdu->sak_use.latest_ks_mi, pe->mi,
                        MKA_MI_LEN);
                    break;
                }
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
    uint64_t latest_pn = 1U;
    uint64_t old_pn = 1U;

    pdu->sak_use.present = true;
    pdu->sak_use.latest_an = p->latest.an;
    /* Only claim to be receiving once the SecY actually holds the key. Under
     * distribute_before_install the MKPDU that carries a new SAK goes out
     * before the data plane is programmed, and a peer takes this flag as leave
     * to start transmitting protected frames - which we could not yet decrypt.
     * The claim follows one MKPDU later, as soon as programming is done.
     *
     * secy_pending is checked for the same reason and is not redundant:
     * mka_program_sak clears sak_program_pending as its first act, *before* it
     * issues create_rx_sc / install_rx_sa / enable_receive, any of which may
     * return MKA_SECY_PENDING on an asynchronous data plane. Without this the
     * two readiness tests disagreed in the unsafe direction -
     * mka_maybe_enable_tx already refuses to transmit while an operation is
     * outstanding, so this end would not send on an SA the hardware lacks, but
     * it told the peer that it could. */
    if ((!p->sak_program_pending) && (p->secy_pending == 0U)) {
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
    }

#ifndef WOLFMKA_NO_DELAY_PROTECT
    /* Tell the peer we are policing delay, so it knows the numbers below are
     * meant to be acted on (9.4.1). */
    if (p->cfg.delay_protect) {
        MKA_SAK_USE_SET_DELAY_PROTECT(&pdu->sak_use);
    }
#endif
    /* The Lowest Acceptable PN is part of the SAK Use set whatever this end
     * does about delay: it is the *peer* that uses it to advance its replay
     * window, and a hard-coded 1 would tell it to accept everything. So the
     * query is not gated on our own delay_protect, nor compiled out with it,
     * and the Old key gets its own number instead of sharing the Latest key's
     * placeholder. */
    if (p->cfg.secy.get_next_pn != NULL) {
        uint64_t pn = 1U;
        if (p->cfg.secy.get_next_pn(p->cfg.secy.ctx, p->latest.an, &pn) == 0) {
            latest_pn = pn;
        }
        if (p->old.valid) {
            pn = 1U;
            if (p->cfg.secy.get_next_pn(p->cfg.secy.ctx, p->old.an, &pn) == 0) {
                old_pn = pn;
            }
        }
    }
    /* One read per key, whatever the cipher suite: the low half goes in the SAK
     * Use set and, under XPN, the upper half in the XPN set. */
    pdu->sak_use.latest_lpn = (uint32_t)latest_pn;
    if (p->old.valid) {
        pdu->sak_use.old_lpn = (uint32_t)old_pn;
    }

#ifndef WOLFMKA_NO_XPN
    mka_build_xpn(p, pdu, latest_pn, old_pn);
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
    /* Wrapped straight into the parameter set rather than through a local: the
     * body is sized MKA_MAX_WRAPPED_SAK + MKA_MAX_CKN_LEN, so the wrapped CAK
     * has exactly its own room at the front and the CKN follows it. A scratch
     * buffer here would put a second copy of the wrapped group CAK on the stack
     * with no wipe on either path - every sibling in this file zeroizes its key
     * scratch (mka_ks_generate_sak, mka_install_from_dist,
     * mka_process_dist_cak), and not having the copy at all is better than
     * remembering to wipe it. The capacity passed is the wrapped-SAK bound, not
     * sizeof(body), so a longer wrap cannot eat the room the CKN needs. */
    size_t wlen = (size_t)MKA_MAX_WRAPPED_SAK;
    MkaStatus rc;

    rc = wm_Crypto_WrapSak(p->keys.kek, p->keys.kek_len, p->dist_cak,
        p->dist_cak_len, pdu->dist_cak.body, &wlen);
    if (rc == MKA_OK) {
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
    /* A participant that cannot serve advertises the never-Key-Server priority
     * rather than its configured one. key_server_capable = false means "I
     * cannot", and it excludes self from the local election - but the Key
     * Server Priority field is the only way to say so on the wire, and
     * advertising an attractive priority while refusing to serve deadlocks the
     * CA: the peer elects us on that priority, we elect the peer because we
     * know we cannot, and neither distributes a SAK. Peers rank 255 last (and
     * exclude it outright under the automotive profile), so this makes the
     * advertisement match the behaviour. */
    pdu->basic.priority = p->cfg.key_server_capable
                              ? p->cfg.priority
                              : (uint8_t)MKA_PRIORITY_NEVER_KS;
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
        uint32_t deadline;

        /* Validate before reading the entry, as mka_find_peer,
         * mka_sci_entry_count, mka_peers_rx_on, mka_retire_old and
         * mka_build_peer_lists all do. A free slot is zeroed by mka_drop_peer
         * so the old ordering was well defined, but it did the deadline
         * arithmetic MKA_MAX_PEERS times per tick whatever the occupancy. */
        if (!pe->valid) {
            continue;
        }
        deadline = MKA_LIFE_TIME_MS;
#ifdef WOLFMKA_SUSPENSION
        /* A peer that advertised a suspension time is held that much longer, so
         * its keys survive the planned quiet period (802.1Xbx-2014). */
        deadline += (uint32_t)pe->suspend_for * 1000U;
#endif
        if ((now_ms - pe->last_seen_ms) > deadline) {
            if (pe->live) {
                removed_live = true;
            }
            mka_drop_peer(p, pe);
        }
    }
#ifndef WOLFMKA_NO_XPN
    if (removed_live) {
        /* The live membership shrank, and an SSCI is a rank within it, so the
         * remaining channels need reprogramming - the mirror of the reapply
         * mka_refresh_peer does on a join. A peer that simply goes quiet leaves
         * by this path rather than by the not-live branch, since that one needs
         * an MKPDU from the peer to run at all. */
        mka_reapply_xpn_ssci(p);
    }
#endif
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
    uint64_t threshold = (uint64_t)MKA_PN_EXHAUSTION_THRESHOLD;

    #ifndef WOLFMKA_NO_XPN
    /* An XPN cipher suite counts in 64 bits, so the same three-quarters-full
     * point sits 2^32 higher. */
    if (mka_cipher_is_xpn(p->sak_cipher_suite)) {
        threshold = MKA_XPN_EXHAUSTION_THRESHOLD;
    }
    #endif
    return (s->get_next_pn != NULL) &&
           (s->get_next_pn(s->ctx, p->latest.an, &pn) == 0) && (pn > threshold);
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
    /* wm_Participant_Rekey has no clock of its own, so a manual rekey leaves
     * its timestamp to be taken here - the first time after it that the
     * participant is told what time it is. Without this the automatic rekey
     * would measure its interval from whenever the *previous* key was issued,
     * and fire again as soon as the manual handover retired; if the manual
     * rekey came before the first wm_Participant_Run, it would measure from
     * zero and fire on that very first run. */
    if (p->rekey_time_pending) {
        p->rekey_time_pending = false;
        p->last_rekey_ms = now_ms;
    }
#endif

#ifdef WOLFMKA_CIPHER_NEGOTIATION
    /* A member joined that the SAK in force was not negotiated for. */
    if (p->cap_reduced) {
        gen = true;
    }
#endif

#ifndef WOLFMKA_NO_AUTO_REKEY
    /* Automatic rekey (AUTOSAR CP_SWS_Mka_00013/00014). `!gen` already implies
     * a SAK is in use (gen = !latest.valid || removed_live), so these two are
     * the remaining triggers.
     *
     * The time-based rekey waits for any handover in flight to finish: it is a
     * hygiene policy, and starting a second handover on top of the first buys
     * nothing.
     *
     * Packet-number exhaustion does not wait. Nothing bounds how long the Old
     * key stays valid - mka_retire_old needs *every* live peer to report
     * transmitting on the Latest key, and a peer that never does (one
     * configured macsec_desired = false, an async SecY whose completion never
     * arrives, a third-party peer that reports Latest Rx but not Latest Tx)
     * pins it indefinitely. Gating exhaustion on the handover therefore used to
     * switch off PN-exhaustion protection entirely, silently and for good,
     * while this end kept transmitting toward GCM nonce reuse - the outcome
     * FMEA FM-08 exists to prevent. Disrupting a stalled handover is the far
     * cheaper failure. */
    if (!gen) {
        if ((!p->old.valid) && (p->cfg.sak_rekey_time_ms != 0U) &&
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
#ifdef WOLFMKA_CIPHER_NEGOTIATION
            /* The new key carries the renegotiated capability. */
            p->cap_reduced = false;
#endif
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
    /* The cadence advances however the attempt went, so a persistently failing
     * transmit path is rate-limited to one attempt per interval rather than one
     * per tick. That covers both ways it can fail: a send callback that rejects
     * the frame (reported through did_send, never through rc), and a build that
     * does not produce one at all - an AES-Key-Wrap or CMAC fault out of
     * wolfSSL, or a peer list too large for the frame. Leaving the stamp to the
     * success path would turn the latter into a full parameter-set fill plus an
     * AES-CMAC on every tick of the integrator's loop, which on a 1 ms loop is
     * two thousand times the intended rate. */
    p->started = true;
    p->last_tx_ms = now_ms;
    if (rc == MKA_OK) {
        /* A participant with no transmit callback has nothing to deliver, so
         * it advances as if the frame had gone out; otherwise only a frame the
         * callback accepted counts. */
        bool delivered = did_send || (p->cfg.send == NULL);

        if (delivered) {
            /* Whatever changed is now on the wire, so the newInfo condition is
             * satisfied until the next state change sets it again. A failed
             * send must leave it set: clearing it would discard the update
             * entirely, and with it the reason to retransmit before the next
             * interval. */
            p->new_info = false;
#ifdef WOLFMKA_SUSPENSION
            /* Same reasoning: the one-shot suspension announcement is spent
             * only when it reaches the wire. */
            p->suspend_announce = false;
#endif
        }
        if (p->sak_program_pending && delivered) {
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

    /* A peer that stopped proving liveness has left the Live Peer List just as
     * surely as one that expired, so both feed the same trigger. */
    bool departed = removed_live || p->live_lost;

    p->live_lost = false;
    /* The trigger must be honoured even when the departing peer was the last
     * one: by this point the live count is already zero, so gating the whole
     * call on it would drop exactly the forward-secrecy rekey it exists for,
     * and a member joining later would be handed the departed member's SAK. */
    if (p->is_key_server &&
        ((wm_Participant_LivePeerCount(p) > 0U) || departed)) {
        rc = mka_ks_maybe_rekey(p, now_ms, departed);
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
        /* Cleared by mka_transmit_step once the frame is actually delivered:
         * consuming it here would lose the announcement outright if the
         * transmit callback rejected the frame. */
        do_tx = p->suspend_announce;
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
    MkaStatus rc;

    if (p == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    if (!p->is_key_server) {
        return MKA_ERR_NOT_KS;
    }
    /* One rekey at a time. Without this an integrator polling the transmit
     * packet number and rekeying on every poll could start a second handover on
     * top of the first: the pending-replace path discards the un-programmed
     * Latest key while leaving the Old key in place, so the two stop tracking
     * each other and the 2-bit Association Number can wrap onto an AN whose
     * Secure Associations are still installed. Refusing is also the honest
     * answer - the previous key has not reached the peers yet, so a second one
     * cannot help.
     *
     * Only the un-distributed case is refused. A make-before-break handover
     * that is merely still running (old.valid, the new key already programmed
     * and on the wire) is a normal state to rekey out of, and the automatic
     * packet-number-exhaustion rekey depends on being able to. */
    if (p->sak_program_pending) {
        return MKA_ERR_REKEY_BUSY;
    }
    rc = mka_ks_generate_sak(p);
#ifndef WOLFMKA_NO_AUTO_REKEY
    if (rc == MKA_OK) {
        /* This call has no now_ms to record, so the automatic rekey interval is
         * restarted from the next wm_Participant_Run rather than left measuring
         * from the previous key. */
        p->rekey_time_pending = true;
    }
#endif
    return rc;
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
    /* Leave the object as wm_Kay_Init would, so a freed KaY that is reused
     * without re-initialising does not carry the old policy. */
    kay->quiesce_others = false;
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

/* Rejects a NULL KaY. Turning the policy off releases every hold at once, so it
 * takes effect without waiting for a session to drop. */
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
        /* The Old key counts: a make-before-break rekey demotes the in-force
         * key to Old (keeping its transmit SA) and leaves latest.tx false until
         * the peers report receiving on the new one. MACsec is protecting
         * traffic throughout, so testing latest.tx alone would find no winner
         * and let the losing CAs talk again for the whole handover. */
        if ((p->latest.valid && p->latest.tx) || (p->old.valid && p->old.tx)) {
            winner = p;
            break;
        }
    }
    for (i = 0U; i < kay->count; i++) {
        MkaParticipant* p = &kay->parts[i];
        p->quiesced = (winner != NULL) && (p != winner);
    }
}

/* Runs every participant; keeps the first non-OK status but still steps the
 * rest (one CA's failure must not stall the others). */
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
