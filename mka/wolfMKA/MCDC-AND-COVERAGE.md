# MC/DC & Per-Configuration Structural Coverage

The core sources (`mka_crypto.c`, `mka_kay.c`, `mka_pdu.c`) meet **100% line,
decision (branch) and MC/DC** coverage (DO-178C DAL A), and the build
**enforces** it: `make coverage` fails below 100% on any of the three metrics,
and `make coverage-configs` re-checks the same across all ten delivered
configurations. This document describes how MC/DC is measured and records the
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

| Configuration | mka_crypto.c | mka_kay.c | mka_pdu.c |
|---|---|---|---|
| **Certification base** (`FAULT_INJECT DISTRIBUTED_CAK KMD SUSPENSION`) | **100%** | **100%** | **100%** |
| + `CIPHER_NEGOTIATION` | **100%** | **100%** | **100%** |
| + `AUTOMOTIVE_PROFILE` | **100%** | **100%** | **100%** |
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
configuration. Every feature-specific test is `#ifndef`-gated, so all ten
configurations compile and run their suites to `failures: 0 => PASS` under their
own flag. Reachability-driven vectors were added in the process (e.g. an
empty-context KDF call and an explicit XPN make-before-break "old key" emission),
so the default `make test` is now 978 checks.

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
larger than the default 728-check `make test`.

| Configuration            | checks | line | decision | MC/DC |
|--------------------------|:------:|:----:|:--------:|:-----:|
| cert-base                |  821   | 100% |   100%   | 100%  |
| negotiation              |  878   | 100% |   100%   | 100%  |
| small-stack + no-malloc  |  821   | 100% |   100%   | 100%  |
| `NO_ANNOUNCEMENTS`       |  733   | 100% |   100%   | 100%  |
| `NO_RETRY`               |  753   | 100% |   100%   | 100%  |
| `NO_DELAY_PROTECT`       |  751   | 100% |   100%   | 100%  |
| `NO_XPN`                 |  719   | 100% |   100%   | 100%  |
| `NO_EAP`                 |  737   | 100% |   100%   | 100%  |
| `NO_AUTO_REKEY`          |  758   | 100% |   100%   | 100%  |

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
