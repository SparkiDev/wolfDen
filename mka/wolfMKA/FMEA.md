# FMEA — wolfMKA component failure-mode & effects analysis

A **component-level** Failure Mode and Effects Analysis for the wolfMKA library,
supporting IEC 61508-3 and IEC 62443-4-1 (see [`COMPLIANCE.md`](COMPLIANCE.md)
for scope). This analyzes the library's own failure modes and how it detects and
contains them. It is **not** a system FMEA/FMEDA: it assigns no failure rates,
no diagnostic-coverage percentages and no SIL/SL — those depend on the enclosing
system and target hardware and are the integrator's responsibility.

Severity reflects the effect *on the secure channel*, not on any safety
function: **High** = loss of secure connectivity or use of an unagreed key;
**Med** = degraded/delayed keying; **Low** = local, self-recovering.

## Method

Each external entry point and each interaction with an external dependency
(wolfSSL, the SecY hooks, the caller's clock and buffers) was examined for: how
it can fail, the local and channel-level effect, how the library detects it, the
in-library mitigation, and the residual risk the integrator must manage.

Entry points analyzed: `wm_Participant_Init`, `wm_Participant_Receive`,
`wm_Participant_Run`, `wm_Participant_BuildMkpdu`, `wm_Participant_Rekey`,
`wm_Participant_SecyComplete`, the opt-in `wm_Participant_DistributeCak` /
`_Suspend` / `_Resume` / `_GetKmd`, and the manager `wm_Kay_*`. Dependencies:
wolfSSL crypto/RNG, the `MkaSecyOps` hooks (synchronous or asynchronous), the
caller-supplied monotonic clock, caller buffers, and the target toolchain's
reported byte order (host-endianness selection).

## Failure modes

| ID | Failure mode | Cause | Local effect | Channel effect | Detection (in library) | Mitigation (in library) | Sev | Residual risk → integrator action |
|----|--------------|-------|--------------|----------------|------------------------|--------------------------|-----|-----------------------------------|
| FM-01 | Forged/corrupted MKPDU accepted | bit error or attacker tampering | — | would install wrong key | AES-CMAC **ICV verified** with ICK in `wm_Pdu_Decode` before any state change | frame rejected → `MKA_ERR_ICV`; no state touched | High | none significant; ensure ICK derivation inputs are correct |
| FM-02 | Replayed/stale MKPDU accepted | replay attack, reordering | — | peer-state rollback | Message Number must strictly increase per MI (`mka_receive_process`, `pe->mn_seen && mn<=pe->mn`) | rejected → `MKA_ERR_REPLAY` | High | none; MN window is per-MI as required |
| FM-03 | Malformed/truncated PDU mis-parsed | bad input, fuzzing | out-of-bounds read risk | DoS / crash | bounds-checked decode; every length validated (negative/branch-tested); coverage-guided libFuzzer harnesses on the decoder and stateful receive path (`make fuzz`, ASan+UBSan) | rejected → `MKA_ERR_PARSE`; no OOB access (valgrind- and ASan-clean) | High | extend the bundled `fuzz-pdu`/`fuzz-receive` harnesses on *your* toolchain/target |
| FM-04 | RNG produces weak/failed output | entropy source failure | weak MI/SAK | predictable key | `wc_InitRng`/`wc_RNG_GenerateBlock` return checked; **fail path verified by fault injection** (`make test-fault`) | `MKA_ERR_CRYPTO` propagated; init or SAK gen fails closed | High | **RNG entropy quality is wolfSSL + platform's** — qualify the entropy source |
| FM-05 | Crypto primitive failure | wolfSSL error (CMAC/keywrap) | derivation/wrap fails | no keying | every wolfSSL call return checked (`mka_crypto.c`); **fail-closed path verified by fault injection** (`make test-fault`, 100% line coverage of `mka_crypto.c`) | `MKA_ERR_CRYPTO` propagated; fails closed | Med | rely on wolfSSL validation posture |
| FM-06 | SAK installed but SecY rejects it | SecY/driver hook returns a (negative) error | SA not actually installed | **traffic on a key the peer can't decrypt** | **Error returns NOT detected** — `mka_secy_track` acts only on the positive `MKA_SECY_PENDING` status (FM-19); a negative error return is not propagated into the engine | none in-library for the error path | High | **Integrator must make SecY hooks fail-safe**: log/alarm internally and hold the SA disabled on error. See FM-06 note below. |
| FM-07 | Transmit enabled before peer can receive | premature key use | — | dropped/garbled frames | Tx held disabled until every live peer reports Rx on the SAK (`mka_maybe_enable_tx`, Tx gating) | gating; `test_tx_gating` | Med | none; gating is automatic |
| FM-08 | Transmit PN (packet number) exhausted | long-lived SAK | nonce reuse risk | **catastrophic for GCM** if it wraps | **auto-detected** by the Key Server: `mka_pn_exhausted` triggers a make-before-break rekey once the transmit PN passes 0xC0000000, or 0xC000000000000000 for XPN suites (both read through the single `get_next_pn` hook); this auto-rekey is compiled out under `WOLFMKA_NO_AUTO_REKEY` | automatic rekey at the exhaustion threshold; `test_pn32_exhaustion_rekey` | High | **In a `WOLFMKA_NO_AUTO_REKEY` build the integrator monitors PN via `get_next_pn` and calls `wm_Participant_Rekey()` before exhaustion** — there, policy belongs to the integrator. |
| FM-09 | Output buffer too small (build MKPDU) | caller passes small buffer | no frame built | missed Hello | capacity checked | `MKA_ERR_BUFFER`; nothing written past `cap` | Low | size buffers to `MKA_MKPDU_MAX_LEN` |
| FM-10 | Peer table full | > `MKA_MAX_PEERS` peers on a CA | new peer not tracked | peer not keyed | bounded table; overflow checked | `MKA_ERR_FULL`; existing peers unaffected | Med | size `MKA_MAX_PEERS` to deployment; alarm on FULL |
| FM-11 | Participant table full (manager) | > `MKA_MAX_PARTICIPANTS` CAs | CA not added | that CA unkeyed | bounded; checked in `wm_Kay_AddParticipant` | `MKA_ERR_FULL` | Low | size `MKA_MAX_PARTICIPANTS` to deployment |
| FM-12 | Duplicate CKN added to manager | mis-configuration | — | ambiguous routing avoided | `wm_Kay_Find` pre-check | `MKA_ERR_STATE`; first CA kept | Low | validate config at startup |
| FM-13 | MKPDU routed to wrong CA | multiple CAs on a port | — | frame mis-applied | routed strictly by CKN from peeked Basic Set (`wm_Kay_Receive`) | unknown CKN dropped → `MKA_ERR_NO_PEER` | Med | none; `test_kay_manager` covers routing & drop |
| FM-14 | Monotonic clock wraps (uint32 ms) | uptime > 49.7 days | interval miscalculated | spurious peer expiry / Hello | unsigned modular subtraction (`now_ms - last_seen_ms`) is wrap-safe for a single wrap with intervals ≪ 2^32 ms | correct across one wrap | Low | supply a monotonic ms clock; never feed wall-clock or a clock that can jump backward |
| FM-15 | Null/invalid arguments | caller defect | — | — | every public function null-checks pointers | `MKA_ERR_BAD_ARG`; no deref | Low | check return codes |
| FM-16 | Dynamic allocation failure | OOM in malloc builds | alloc fails | operation aborts | `MKA_ALLOC_VAR` failure sets error, does not deref | `MKA_ERR_INTERNAL`; fails closed | Med | **Use `WOLFMKA_NO_MALLOC`** to remove this mode entirely (recommended for SIL/SL targets) |
| FM-17 | Stack overflow | deep call / large frame on small target | undefined behavior | crash | bounded, no recursion; `WOLFMKA_SMALL_STACK` moves large objects off-stack | bounded stack option | Med | budget stack depth on target (`-fstack-usage`); enable `WOLFMKA_SMALL_STACK` |
| FM-18 | Key Server election fails to converge | partition, equal priority+SCI | no/disputed KS | no SAK distributed | deterministic election: priority then numeric SCI tie-break | converges; `test_election_tie_break` | Med | assign unique SCIs (MAC-based, inherently unique) |
| FM-19 | Async SecY completion never reported | data-plane/driver hang, or a lost/omitted `wm_Participant_SecyComplete` after a hook returned `MKA_SECY_PENDING` | `secy_pending` stays > 0 | transmit protection never enabled on the new key — **handover stalls, but fails safe: no frame is ever sent on an SA the hardware has not installed** | **NOT auto-detected** — there is no in-library timeout on outstanding async operations | conservative Tx gate withholds transmit while `secy_pending > 0` (`mka_maybe_enable_tx`); `wm_Participant_SecyComplete` is underflow-guarded, so an excess/spurious completion is a safe no-op; `test_async_secy` | High | **Integrator must bound each async SecY op with a timeout** and, on timeout, report completion (with error) or tear down the CA; **match every `MKA_SECY_PENDING` return with exactly one `SecyComplete` call**. See FM-19 note below. |
| FM-20 | Forged/wrong Distributed CAK delivered (opt-in `WOLFMKA_DISTRIBUTED_CAK`) | attacker tampering, wrong KEK, mis-paired CAK | — | integrator could start a group CA with a bad CAK | **doubly authenticated**: the MKPDU ICV is verified with the ICK (FM-01) before decode, and the wrapped CAK is integrity-checked by AES Key Unwrap with the KEK — a wrong KEK or tampered wrap fails and is **silently ignored** (no `cak_received`); body-length guards reject malformed sets. A wrap failure on the Key-Server side is surfaced as `MKA_ERR_CRYPTO` (FM-05) | only a CAK that passes both checks is delivered; `test_distributed_cak` covers wrong-KEK and malformed-body rejection | Med | **Integrator owns the trust/CA-creation policy**: decide whether to start a CA for a delivered CAK; the library only hands over the unwrapped CAK, it does not act on it. Feature is off by default. |
| FM-21 | MKA suspension fails to take effect, or over-holds a peer (opt-in `WOLFMKA_SUSPENSION`, XPN only) | the one-shot suspension announcement is lost; or a member advertises a suspension time then departs without resuming | the suspended participant is expired early, or a departed member's state is held for its advertised time | **lost announcement:** the peer expires the suspended participant at the normal Life Time → SAs torn down and re-keyed on return (the seamless gap is not achieved — degraded, not a breach). **held-but-gone:** a member that suspended and never returned is held up to its advertised time, delaying its expiry and the Key Server's forward-secrecy rekey by that much | the suspension time is **ICV-authenticated** (FM-01), so only a CA member can assert it, and it is a **single octet so the hold is bounded to ≤ 255 s**; a lost announcement degrades safely to normal Life-Time expiry (`mka_expire_peers`) | best-effort one-shot announce + bounded hold; `test_suspension` covers the held-across-the-gap and resume paths | Med | **Integrator bounds the advertised suspension time to its forward-secrecy budget** and treats suspension as best-effort (re-transmit the announcement before going quiet if the seamless gap is critical, or accept the re-key fallback). Off by default; requires an XPN cipher suite. |
| FM-22 | MKPDU multi-octet fields serialized in wrong byte order (big-endian build only) | host byte order misdetected by the toolchain, or integrator forces the wrong `WOLFMKA_LITTLE_ENDIAN`/`WOLFMKA_BIG_ENDIAN` | 16/32-bit fields (Message/Key Number, lengths, EtherType) emitted in reversed order | **no interoperability** — every frame fails the peer's ICV check / parse, so no CA converges; a wrong-order PDU can never authenticate, so it is **rejected, never accepted** (no unagreed key) | **build-time `#error`** when the byte order cannot be deduced (`mka_types.h` — no silent guess); otherwise the mismatch is total and self-evident at first bring-up | byte order auto-detected from standard compiler/arch macros; the Rule 21.15 `memcpy` fast path is the **big-endian branch only** of the shared serializers (`w_be16`/`w_be32`/`w_be48`, `rd_be48` in `mka_bytes.h`), verified by the `-DWOLFMKA_BIG_ENDIAN` MISRA config; the 16/32-bit readers (`rd_be16`/`rd_be32`) are endian-independent byte-shift | Low | **On a new/exotic target, confirm the selected byte order** (the `#error` forces an explicit choice) and run the `test_pdu` round-trip on the target. Fails loud at build/bring-up — never a silent field corruption or security compromise. |
| FM-23 | Non-Key-Server CA member distributes a SAK/CAK/KMD | a member that holds the CAK (so its MKPDU passes the ICV check, FM-01) injects a Distributed SAK/CAK or KMD to override the elected Key Server | — | desynchronised or attacker-chosen keys across the CA; traffic black-holing | **sender-authorisation gate**: distributed key material is acted on only when this participant is not itself the Key Server, an election has settled, and the sender's SCI equals the elected Key Server's SCI (`mka_react_to_pdu`: `pe->sci == p->ks_sci`), re-evaluated from the just-refreshed peer table on every frame | a non-Key-Server member's distribution is ignored; only the elected Key Server's is installed; `test_dist_sak_only_from_key_server` | High | relies on a sound election (FM-18) and ICV (FM-01); the gate closes the insider/non-KS override path |
| FM-24 | Out-of-range configuration value | integrator mis-config (bad SAK/CAK/KMD length, confidentiality offset, or cipher-preference count) | — | could otherwise overrun a fixed-size config buffer | `mka_cfg_valid` rejects an invalid `sak_len`, cipher suite, confidentiality offset, `cipher_pref_count` or `kmd_len`; `wm_Participant_DistributeCak` bounds the CAK length (`mka_aes_key_len_valid`) | fails closed with `MKA_ERR_BAD_ARG`; nothing is initialised or sent; `test_kmd_propagation` covers the oversized-KMD rejection | Low | validate the configuration at startup by checking the `Init` / `DistributeCak` return code |
| FM-25 | Unduly delayed (late-replayed) frame accepted (opt-in delay protection) | a frame is captured and replayed within the SA's replay window | a stale frame is accepted as fresh | bounded staleness, not a key compromise | when `cfg.delay_protect` is set, the receive replay-window lower bound is advanced to the Lowest Acceptable PN the transmitter reports, conveyed to the SecY as the **full 64-bit** value via `set_lowest_pn` (the low 32 bits for non-XPN suites; the XPN MSBs paired in for XPN) | delay protection narrows the acceptance window to the peer-reported floor; `test_delay_protection`, `test_xpn_delay_protect_lpn64`; compiled out under `WOLFMKA_NO_DELAY_PROTECT` | Low | enable `delay_protect` where late-replay matters; a 32-bit-only SecY uses the low word of the conveyed PN |

### FM-06 note — SecY hook errors are not propagated (by design, with a caveat)

The engine calls the `MkaSecyOps` hooks (`install_tx_sa`, `install_rx_sa`,
`delete_sa`, `enable_transmit`, …) through `mka_secy_track`, which inspects the
return value for exactly one thing: the `MKA_SECY_PENDING` status that
defers the transmit-enable handover (FM-19). That status is a distinctive
sentinel (`0x50454E44`, 'PEND'), deliberately not `1`, so a synchronous backend
that idiomatically does `return 1;` for success is treated as done rather than
mistaken for an asynchronous deferral that would stall the handover. A *negative*
error return is **not** propagated into the engine. This keeps the protocol engine independent of any
particular data-plane and matches the abstract-SecY scope. The consequence is
unchanged from the original fire-and-forget design: a *failed* SA installation
is invisible to MKA, which will then gate/enable transmit as if it had succeeded.

**Required integrator mitigation:** implement the SecY hooks so they are
fail-safe in themselves — on any error, keep the affected SA disabled, raise an
alarm/log, and (if appropriate) tear down the CA out-of-band. If your safety
case needs MKA to react to SecY failures, propagating hook return codes into the
engine is a candidate enhancement; it is not present today and is recorded here
as the principal residual risk of the current design.

### FM-19 note — asynchronous SecY completion handshake

A SecY backend that programs the data plane asynchronously (e.g. an AUTOSAR
MacSec module, or hardware that queues SA installs) returns `MKA_SECY_PENDING`
from a hook. The engine then counts the outstanding operation (`secy_pending`)
and **holds back enabling transmit protection** until the integrator reports
completion with `wm_Participant_SecyComplete()`. This is deliberately a
**fail-safe** gate: if a completion is lost or never arrives, the worst case is
that the handover stalls and the new key is never used for transmit — the engine
will **never** transmit on an SA the hardware has not confirmed installed. It
does not, by itself, cause loss of an *existing* secured channel; the prior key
keeps protecting traffic until it is retired.

**Required integrator mitigation:**

- **Bound every async operation with a timeout.** The library has no timer on
  outstanding SecY operations; on timeout, call `wm_Participant_SecyComplete`
  (signalling the error) or tear the CA down out-of-band.
- **Honour the one-completion-per-pending contract.** Each hook that returned
  `MKA_SECY_PENDING` must be matched by exactly one `SecyComplete` call.
  Over-completion is underflow-guarded (a safe no-op); under-completion stalls
  the handover as above.
- A purely **synchronous** SecY returns `0`/negative and never `MKA_SECY_PENDING`,
  so `secy_pending` stays zero and this failure mode cannot arise — it is unique
  to asynchronous backends.

## Summary of fail-safe posture

- **Fails closed.** Every detected error (`MKA_ERR_*`) aborts the operation
  without partial state change; bad frames are dropped, not partially applied.
- **Authenticated before acted upon.** No received PDU mutates participant state
  until its ICV verifies (FM-01) and its Message Number is fresh (FM-02).
- **Bounded resources.** No recursion, no unbounded loops, fixed-size tables,
  and an allocation-free build (`WOLFMKA_NO_MALLOC`) for deterministic targets.
- **Residual risks the integrator owns:** SecY hook *error* detection (FM-06)
  and transmit-PN exhaustion monitoring (FM-08) in every build; and, with the
  optional features enabled, bounding the async completion handshake with a
  timeout (FM-19), the Distributed-CAK trust/CA-creation policy (FM-20), and the
  advertised suspension time (FM-21); and, on a big-endian target, confirming
  the auto-detected byte order at first port (FM-22). All are deliberate scope
  boundaries, documented here so they are managed rather than missed.
