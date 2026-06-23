/* mka_autosar.c
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
 * Driving wolfMKA through its AUTOSAR Mka API (Mka.h, Document ID 1066) instead
 * of the native wm_Participant_* interface.
 *
 * The Mka module is a configured singleton: an integrator describes each PAE
 * (port) and its CKN/CAK table in an Mka_ConfigType, calls Mka_Init once, then
 * services it from two periodic hooks - Mka_MainFunction on a timer and
 * Mka_RxIndication from the lower-layer receive path. This example wires two
 * PAEs back-to-back in one process (a Key Server and a peer), so the frames one
 * PAE transmits are delivered to the other, and steps them until both report
 * MKA_STATUS_MACSEC_RUNNING - the AUTOSAR equivalent of the mka_demo flow.
 *
 * Built with -DWOLFMKA_AUTOSAR against src/autosar/Mka.c; run with:
 *     make example-autosar
 */

#include <stdio.h>
#include <string.h>

#include "wolfmka/autosar/Mka.h"

/* ---- in-process lower layer: a queue of frames tagged by destination ----
 * Each transmitted frame carries the sending PAE's TxPduId; the receiver whose
 * RxPduId matches consumes it. PAE 0 (Tx=1) -> PAE 1 (Rx=1); PAE 1 (Tx=0) ->
 * PAE 0 (Rx=0). */
typedef struct {
    PduIdType dst;
    uint8 data[600];
    uint16 len;
} Frame;

static Frame g_queue[16];
static int g_qhead;
static int g_qtail;

static Std_ReturnType bridge_tx(PduIdType TxPduId, const uint8* f, uint16 n)
{
    Frame* slot;
    if (((g_qtail + 1) % 16) == g_qhead)
        return E_NOT_OK; /* queue full */
    slot = &g_queue[g_qtail];
    slot->dst = TxPduId;
    memcpy(slot->data, f, n);
    slot->len = n;
    g_qtail = (g_qtail + 1) % 16;
    return E_OK;
}

static void drain(void)
{
    while (g_qhead != g_qtail) {
        Frame* fr = &g_queue[g_qhead];
        PduInfoType pdu;
        pdu.SduDataPtr = fr->data;
        pdu.SduLength = fr->len;
        pdu.MetaDataPtr = NULL;
        Mka_RxIndication(fr->dst, &pdu);
        g_qhead = (g_qhead + 1) % 16;
    }
}

static const char* status_name(Mka_MkaStatusType s)
{
    switch (s) {
        case MKA_STATUS_UNDEFINED: return "UNDEFINED";
        case MKA_STATUS_WAITING_PEER_LINK: return "WAITING_PEER_LINK";
        case MKA_STATUS_WAITING_PEER: return "WAITING_PEER";
        case MKA_STATUS_IN_PROGRESS: return "IN_PROGRESS";
        case MKA_STATUS_MACSEC_RUNNING: return "MACSEC_RUNNING";
        default: return "OTHER";
    }
}

int main(void)
{
    /* One CAK/CKN, provisioned identically on both PAEs (pre-shared here; an
     * EAP deployment would derive it - see mka_eap.c). */
    static const uint8 cak[16] = {0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA,
        0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA};
    static const uint8 ckn[8] = {'a', 'u', 't', 'o', '-', 'c', 'k', 'n'};
    Mka_CknConfigType ckn_a = {cak, 16, ckn, 8, TRUE};
    Mka_CknConfigType ckn_b = {cak, 16, ckn, 8, TRUE};
    Mka_PaeConfigType paes[2];
    Mka_ConfigType cfg;
    Mka_PaeStatusType st0, st1;
    int cycle;
    int rc;

    printf("wolfMKA AUTOSAR demo - two PAEs via the Mka API\n");
    printf("========================================================\n");

    /* PAE 0: Key Server (priority 10), RxPduId 0 / TxPduId 1. */
    memset(&paes[0], 0, sizeof(paes[0]));
    paes[0].RxPduId = 0;
    paes[0].TxPduId = 1;
    paes[0].Sci[5] = 0xAA;
    paes[0].Sci[7] = 1;
    paes[0].Priority = 10;
    paes[0].Role = MKA_ROLE_KEY_SERVER;
    paes[0].SakLength = 16;
    paes[0].Transmit = bridge_tx;
    paes[0].Ckns = &ckn_a;
    paes[0].CknCount = 1;

    /* PAE 1: peer (priority 20), RxPduId 1 / TxPduId 0. */
    memset(&paes[1], 0, sizeof(paes[1]));
    paes[1].RxPduId = 1;
    paes[1].TxPduId = 0;
    paes[1].Sci[5] = 0xBB;
    paes[1].Sci[7] = 1;
    paes[1].Priority = 20;
    paes[1].Role = MKA_ROLE_PEER;
    paes[1].SakLength = 16;
    paes[1].Transmit = bridge_tx;
    paes[1].Ckns = &ckn_b;
    paes[1].CknCount = 1;

    cfg.Paes = paes;
    cfg.PaeCount = 2;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;

    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    if (Mka_StartPae(0) != E_OK || Mka_StartPae(1) != E_OK) {
        printf("StartPae failed\n");
        return 1;
    }

    for (cycle = 0; cycle < 16; cycle++) {
        Mka_MainFunction();
        drain();
        if (Mka_GetPaeStatus(0, &st0) == E_OK &&
            Mka_GetPaeStatus(1, &st1) == E_OK) {
            printf("  cycle %2d: PAE0=%-17s PAE1=%s\n", cycle,
                status_name(st0.MkaStatus), status_name(st1.MkaStatus));
            if (st0.MkaStatus == MKA_STATUS_MACSEC_RUNNING &&
                st1.MkaStatus == MKA_STATUS_MACSEC_RUNNING)
                break;
        }
    }

    printf("========================================================\n");
    if (Mka_GetPaeStatus(0, &st0) == E_OK &&
        Mka_GetPaeStatus(1, &st1) == E_OK &&
        st0.MkaStatus == MKA_STATUS_MACSEC_RUNNING &&
        st1.MkaStatus == MKA_STATUS_MACSEC_RUNNING) {
        printf("Result     : SUCCESS - both PAEs report MACSEC_RUNNING\n");
        rc = 0;
    }
    else {
        printf("Result     : FAILURE - PAEs did not reach MACSEC_RUNNING\n");
        rc = 1;
    }
    return rc;
}
