# Compliance scope: IEC 61508 / IEC 62443

This document states **precisely what wolfMKA provides** toward an IEC 61508
(functional safety) or IEC 62443 (industrial cybersecurity) effort, and **what
the integrator must supply**. It exists so the boundary is documented rather
than implied.

## The headline, stated plainly

> wolfMKA is **not certified** to IEC 61508 or IEC 62443, and source code alone
> cannot be. Both are *system-and-lifecycle* standards: conformance is a verdict
> reached by an assessor about a complete product and the process that built it,
> not a property of a library. wolfMKA is written and documented to **support**
> such an effort and to be a clean, traceable component within it.

The wording used throughout this project is deliberate: wolfMKA **supports**
these standards and produces evidence **of the kind they expect**. It does not
"meet", "comply with", or "conform to" them. Do not upgrade that wording in
downstream material.

## What wolfMKA is, in standards terms

- For **IEC 62443**, wolfMKA is a **software component** that helps a product
  satisfy parts of the **62443-4-2** component requirements, developed with
  practices aligned to the **62443-4-1** secure-development lifecycle.
- For **IEC 61508**, wolfMKA is **safety-related software** *only if* it sits
  inside a declared safety function. MKA is a key-agreement protocol, not itself
  a safety function; any SIL is allocated to the enclosing loop, never to this
  library. What wolfMKA offers is the **61508-3 software** artifacts (coding
  standard, modularity, traceability, V&V evidence).

## Responsibility matrix

"Provided" = present in this repository. "Integrator" = you must supply it for
your system; wolfMKA cannot.

| Area | Provided by wolfMKA | Integrator responsibility |
|------|---------------------|---------------------------|
| Coding standard / language subset | MISRA C:2012, Cppcheck-enforced ([`MISRA.md`](MISRA.md)) | Accept the deviation record; run the addon in your CI |
| Requirements → code → test traceability | [`REQUIREMENTS.md`](REQUIREMENTS.md) bidirectional matrix | Map these to your *system* safety/security requirements with SIL/SL allocation |
| Failure-mode analysis (component) | [`FMEA.md`](FMEA.md) | System-level FMEA/FMEDA, hazard & risk analysis, diagnostic coverage figures |
| Vulnerability handling | [`SECURITY.md`](SECURITY.md) process | Adopt/extend it into your product PSIRT; CVE triage for *your* release |
| Verification evidence | 728 unit checks (`make test`, including RFC 4493/3394 and hostapd-pinned crypto known-answer vectors), valgrind-clean, ASan+UBSan-clean (`make sanitize`), GCC `-fanalyzer`-clean (`make analyze`), libFuzzer smoke pass on the decoder and receive path (`make fuzz`), assertion strength validated by mutation testing | Integration & system test, target-hardware test, coverage on your toolchain |
| Structural coverage | 100% line + 100% decision (branch) **+ 100% MC/DC** on the core sources, enforced by `make coverage`; `make coverage-configs` re-checks all ten delivered configurations | Re-run on your target toolchain; structural coverage of your integration code |
| Defensive design | param validation on every entry point; `WOLFMKA_NO_MALLOC`; bounded stack; bounded loops; no recursion | Stack-depth budget on your target; WCET if real-time-relevant |
| Cryptographic primitives | *none* — delegated to wolfSSL | wolfSSL FIPS 140-3 / validation posture; RNG entropy source quality |
| Threat model / attack surface | partial (hardening rationale in `REQUIREMENTS.md` §Security) | Full threat model of the deployed system (feeds both 4-1 and 61508 hazard analysis) |
| Tool qualification | — | Qualify compiler + Cppcheck per 61508-3 §7.4.4 / your tool-confidence level |
| Secure configuration | secure-by-default options; build-time feature stripping | Document your chosen configuration as a security requirement |

## Mapping to IEC 62443-4-2 foundational requirements (FR)

wolfMKA contributes mechanisms toward these; it does not by itself satisfy any
FR for a product.

| FR | Contribution | Where |
|----|--------------|-------|
| FR1 Identification & Authentication | mutual proof of CAK possession (PSK or EAP-MSK derived) before keying | `wm_Crypto_DeriveKeys`, ICV verification |
| FR2 Use Control | Key Server election gates who may distribute SAKs | `mka_run_election` |
| FR3 System Integrity | establishes MACsec SAKs for AES-GCM integrity; MKPDU replay protection (MN); delay protection (LPN) | `mka_install_sak`, `mka_receive_process`, SAK Use |
| FR4 Data Confidentiality | establishes SAKs enabling AES-GCM confidentiality on the wire | SAK distribution / installation |
| FR7 Resource Availability | no dynamic allocation, bounded tables, bounded loops → deterministic resource use | `WOLFMKA_NO_MALLOC`, `MKA_MAX_*` |

The actual confidentiality/integrity transform (AES-GCM), key wrap, CMAC and RNG
are **wolfSSL's**. Any 62443/FIPS crypto claim rests on wolfSSL's validation,
not on this code.

## Mapping to IEC 62443-4-1 practices

| 4-1 practice | Status in this repo |
|--------------|---------------------|
| SM — security management | partial: documented process in `SECURITY.md` |
| SR — security requirements | partial: `REQUIREMENTS.md` security-hardening section |
| SD — secure by design | yes: abstract data-plane/transport seams, least mechanism, secure defaults |
| SI — secure implementation | yes: MISRA, no-malloc/bounded-stack options, full input validation |
| SVV — security verification | yes: unit/negative/branch tests, 100% MC/DC, valgrind, ASan+UBSan, GCC `-fanalyzer`, libFuzzer (decoder + receive path), mutation testing |
| DM — defect management | yes: `SECURITY.md` reporting & handling process |
| SUM — security update management | integrator: tied to your release process |

## Gaps to close for an actual certification effort

In rough priority order (see the closing section of `REQUIREMENTS.md` and
`FMEA.md` residual-risk column for detail):

1. **Threat model / attack-surface analysis** of the deployed system.
2. **Tool qualification** for the compiler and static analyzer.
3. **System-level deliverables** — see `FMEA.md` (failure modes) and
   `SECURITY.md` (vulnerability handling); both are *component-level starting
   points* that the integrator extends to system scope.

Structural coverage is no longer in this list: the core sources meet 100% line,
decision **and** MC/DC, enforced by `make coverage` / `make coverage-configs`
across all ten delivered configurations (the masking MC/DC variant accepted by
DO-178C up to DAL A). The integrator still re-runs it on their target toolchain
and extends it to their integration code.

## Document set

- [`REQUIREMENTS.md`](REQUIREMENTS.md) — requirements ↔ implementation ↔ test traceability.
- [`FMEA.md`](FMEA.md) — component failure-mode & effects analysis.
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting & handling process.
- [`MISRA.md`](MISRA.md) — coding-standard conformance & deviation record.
- [`MCDC-AND-COVERAGE.md`](MCDC-AND-COVERAGE.md) — how MC/DC is measured and the
  per-configuration structural-coverage evidence.
- [`AUTOSAR.md`](AUTOSAR.md) — AUTOSAR Classic `Mka` API conformance map.
- [`OPEN-ALLIANCE.md`](OPEN-ALLIANCE.md) — OPEN Alliance TC17 Automotive MKA
  profile conformance map, including the requirements not yet implemented.
