# MC/DC & Per-Configuration Structural Coverage

The core sources (`mka_crypto.c`, `mka_kay.c`, `mka_pdu.c`, `mka_status.c`) meet
**100% line, decision (branch) and MC/DC** coverage (DO-178C DAL A), and the
build **enforces** it: `make coverage` fails below 100% on any of the three
metrics, and `make coverage-configs` re-checks the same across all eleven
delivered configurations. `make coverage-autosar` applies the same enforced bar
to `src/autosar/Mka.c`, which needs its own flags and suite. Between them every
`.c` file in `src/` is gated — nothing is measured by hand. This document describes how MC/DC is measured and records the
evidence behind the 100% figures — in particular how the cipher-negotiation code
and the feature-off builds were brought to full coverage.

## How MC/DC is measured here

GCC 14+ (this tree uses GCC 15) implements MC/DC (the masking variant accepted
by DO-178C) via `-fcondition-coverage`, reported by `gcov --conditions` as
"condition outcomes covered". No new tool is needed. `make coverage` builds with
`-fcondition-coverage`, runs `gcov --conditions`, and **fails** unless every core
source is 100% line + decision + MC/DC — i.e. the gate enforces DAL-A structural
coverage, not just DAL-B.

## Coverage status

`mka_status.c` (the exhaustive `MkaStatus` -> string switch) is enforced in
every configuration too; it is omitted from the table below only because it is
100% in all of them with nothing configuration-dependent to say about it.

| Configuration | mka_crypto.c | mka_kay.c | mka_pdu.c |
|---|---|---|---|
| **Certification base** (`FAULT_INJECT DISTRIBUTED_CAK KMD SUSPENSION`) | **100%** | **100%** | **100%** |
| + `CIPHER_NEGOTIATION` | **100%** | **100%** | **100%** |
| + `AUTOMOTIVE_PROFILE` | **100%** | **100%** | **100%** |
| + `ICV_L2_ADDR` | **100%** | **100%** | **100%** |
| + `SMALL_STACK NO_MALLOC` | **100%** | **100%** | **100%** |
| Feature-off `NO_*` builds | **all six enforced at 100%** (table below) | | |

The certification base meets MC/DC from the suite's exhaustive per-argument
validation tests plus the fault-injection build, which together drive every
condition outcome; the distributed-CAK, KMD and suspension code were likewise
already at 100%, with no new vectors required there. The two areas that needed
work — the **negotiation** code (some condition outcomes uncovered) and the
**feature-off** builds (configurations not previously executed under test) — are
covered in the two sections that follow.

## Negotiation code — reaching 100% MC/DC

The `WOLFMKA_CIPHER_NEGOTIATION` code was at 95.79%. It is now at **100% MC/DC**
(measured with `-fcondition-coverage` on the certification base +
`WOLFMKA_CIPHER_NEGOTIATION`). Eight reachable condition outcomes were closed by
added test vectors; two structurally-unreachable defensive bounds were removed.

| # | Function (decision) | Condition | Covered by |
|---|---|---|---|
| 1 | `mka_cfg_valid` — pref-list checks | `cipher_prefs == NULL` true | `test_negotiation_edge_cases`: `Init` with `cipher_pref_count=1, cipher_prefs=NULL` |
| 2 | same | `cipher_pref_count > MAX` true | `test_negotiation_edge_cases`: `Init` with `cipher_pref_count=5` |
| 3 | `mka_select_cipher_suite` | `cs == 0` entry skipped | `test_negotiation_edge_cases`: pref list with a `0` entry |
| 4 | same | unsupported suite skipped | `test_negotiation_edge_cases`: pref list with an unknown suite |
| 5 | `mka_all_peers_accept_cs` | `pe->live` false / `pe->valid` true | `test_negotiation_edge_cases`: re-key with an injected not-live peer |
| 6 | `mka_min_capability` | `pe->live` false / `pe->valid` true | same scenario as #5 |
| 7 | `mka_sak_len_for_cs` | `cs == GCM_AES_XPN_256` true | `test_negotiation_select_extremes`: both peers prefer XPN-256 |
| 8 | `mka_select_cipher_suite` | loop `i < count` false (exhaustion) | `test_negotiation_select_extremes`: no preference accepted → default 128 |
| 9 | `mka_refresh_peer` | `k < MKA_MAX_CIPHER_SUITES` false — **unreachable** | guard removed; `WOLFMKA_ASSERT(announce.count <= MAX)` documents the (decoder-clamped) invariant |
| 10 | `mka_build_announce` | `i < MKA_MAX_CIPHER_SUITES` false — **unreachable** | guard removed; `WOLFMKA_ASSERT(cipher_pref_count <= MAX)` documents the (validation-capped) invariant |

Rows 9–10 were redundant `&& (i < MAX_CIPHER_SUITES)` loop guards whose false
outcome could never occur (`count` is already clamped/validated ≤ MAX); removing
them eliminated the only structurally-uncoverable conditions, and the added
asserts make the invariant explicit and trap any violation in a debug build.
cppcheck does not flag MISRA 18.1 on the resulting single-condition loops.

## Per-configuration coverage

DO-178C requires structural coverage of the **delivered** configuration. `make
coverage-configs` applies the enforced 100% line + decision + MC/DC check, via a
parameterised worker (`cov-impl`) driven by recursive make, to each delivered
configuration. Every feature-specific test is `#ifndef`-gated, so all eleven
configurations compile and run their suites to `failures: 0 => PASS` under their
own flag. Reachability-driven vectors were added in the process (e.g. an
empty-context KDF call and an explicit XPN make-before-break "old key" emission),
so the default `make test` is now 1408 checks (1462 under `make test-fault`, which adds the injected-failure cases).

Two library fixes were needed along the way: `MKA_VAR_OK` was made
compile-time-true in the object-backed (no-malloc) configuration, removing an
allocation-failure branch that cannot trigger when the off-stack variable is a
caller-object field; and `wm_Participant_Init` now zeroes the participant
*before* validation, so a rejected configuration leaves a clean inert object
(this fixed a `NO_XPN` crash where a test ran a participant left as stack
garbage). The general principle (DO-178C dead/deactivated-code analysis): code
that becomes *genuinely* unreachable once a feature is compiled out is excluded
with the matching `#ifndef` so it is *not present* in that build's object code;
code that is still reachable but which only the feature's own tests happened to
drive is covered with an added requirements-based test rather than excluded.

The `checks` column is each configuration's suite size as `cov-impl` actually
builds it — instrumented with `-DWOLFMKA_FAULT_INJECT` (plus, for the first three
rows, the `DISTRIBUTED_CAK KMD SUSPENSION` certification-base flags) — so it is
larger than the default 1408-check `make test`.

| Configuration            | checks | line | decision | MC/DC |
|--------------------------|:------:|:----:|:--------:|:-----:|
| cert-base                |  1522  | 100% |   100%   | 100%  |
| negotiation              |  1618  | 100% |   100%   | 100%  |
| automotive-profile       |  1440  | 100% |   100%   | 100%  |
| icv-l2                   |  1546  | 100% |   100%   | 100%  |
| small-stack + no-malloc  |  1522  | 100% |   100%   | 100%  |
| `NO_ANNOUNCEMENTS`       |  1417  | 100% |   100%   | 100%  |
| `NO_RETRY`               |  1448  | 100% |   100%   | 100%  |
| `NO_DELAY_PROTECT`       |  1433  | 100% |   100%   | 100%  |
| `NO_XPN`                 |  1373  | 100% |   100%   | 100%  |
| `NO_EAP`                 |  1430  | 100% |   100%   | 100%  |
| `NO_AUTO_REKEY`          |  1444  | 100% |   100%   | 100%  |

Three feature-off builds each had a single feature-conditioned branch below 100%.
Their resolution distinguishes **dead** code from merely **untested** code:

| Config | file:line | branch | nature | resolution |
|--------|-----------|--------|--------|------------|
| `NO_XPN` | `mka_kay.c:1130` | `xpn->present ? ...` *true* outcome | **dead** — with XPN compiled out no code path can make an XPN parameter set "present" | `#ifndef WOLFMKA_NO_XPN` in `mka_apply_sak_use`: the NO_XPN build sets `latest_lpn_msb = 0` with no branch |
| `NO_EAP` | `mka_crypto.c:227` | `if (c1_len > 0U)` *false* outcome | **reachable** — the public `wm_Crypto_Kdf` accepts an empty context (`context_len == 0`); only the EAP derivation test drove it before | `test_kdf_and_keys` now calls `wm_Crypto_Kdf` with `context_len == 0` (a valid SP 800-108 invocation) — covers it in every config |
| `NO_AUTO_REKEY` | `mka_kay.c:1428-1431` | old-key XPN PN emission (`p->old.valid && ...`) | **reachable** — a make-before-break Old key is created by *any* rekey, including the always-available manual `wm_Participant_Rekey` and peer-departure forward secrecy, not just the optional automatic policy | new `test_xpn_old_key_pn_emit` builds that handover state by hand with a succeeding PN hook — covers it independently of `WOLFMKA_NO_AUTO_REKEY` |

Only the `NO_XPN` branch was genuinely dead, and it alone was excluded with
`#ifndef`. The other two are live code paths that the feature-off suite simply
did not reach; excluding them would have been a functional regression (the
empty-context KDF and the manual-rekey Old-key PN advertisement would silently
disappear), so they were closed with requirements-based tests instead.

## The AUTOSAR binding has its own gate

`src/autosar/Mka.c` is outside `COV_FILES`, because it needs
`-DWOLFMKA_AUTOSAR` and its own suite rather than the shared one. That left it
measured by hand and free to regress — which it did: at the point the gate was
added it stood at **97.18% line / 95.83% decision / 95.11% MC/DC**, and the
uncovered outcomes were the failure paths of recently added guards (a `PaeCount`
with a NULL `Paes`, a zero `PermissiveTimeoutMs`, and the whole SecY statistics
pass-through, which no test ever supplied a `get_secy_stats` hook for).

`make coverage-autosar` now enforces the same 100% line + decision + MC/DC bar on
it, and runs in CI. It is at 100% of 335 lines, 226 branch outcomes and 218
condition outcomes. One decision was removed rather than covered:

| File:function | Decision | Nature | Resolution |
|---|---|---|---|
| `Mka.c:mka_active_status` | `wm_Participant_GetPaeStatus(...) == MKA_OK` *false* outcome | **structurally unreachable** — that call fails only on a NULL argument, and neither argument can be NULL at this site | branch removed; `ps.state` is seeded to `MKA_PAE_UNDEFINED` (which ranks lowest, so a hypothetical failure loses to every real status) and the call's result used directly |

## Decisions that exist only on some hosts

Two guards are conditioned on properties of the *host* rather than a wolfMKA
feature flag, so they are not decisions at all in the configuration where the
property does not hold. Both are excluded by the preprocessor for exactly that
reason, which is what keeps them from appearing as uncoverable outcomes:

| Construct | Condition | Why it is excluded rather than tested |
|---|---|---|
| `mka_len_fits_word32` (`mka_crypto.c`) | `#if defined(SIZE_MAX) && (SIZE_MAX > 0xFFFFFFFFU)` | Every length crosses into wolfSSL as a `word32`. Where `size_t` is already 32 bits or narrower the comparison can never be false, so on such a target the guard would be an uncoverable outcome; the body is compiled out and the function returns `true` unconditionally. On a 64-bit host both outcomes are driven by the suite (a length of `0x100000000` is rejected, an ordinary one accepted). |
| `mka_kdf_bounds_check` (`mka_crypto.c`) | negative array bound | Not executable code at all: a `typedef` whose bound goes negative if the KDF label, context and buffer constants stop being consistent. It contributes no line, branch or condition, and is deliberately never referenced — the declaration *is* the check. Recorded as a MISRA 2.3 deviation. |

The same reasoning governs the `#if`-guarded halves of the test suite: a check
that can only hold on a 64-bit host is `#if`-gated in `test_crypto.c` so a
32-bit run neither fails it nor counts it.
