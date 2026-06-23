# Security policy & vulnerability handling

This document defines how security defects in wolfMKA are reported, triaged,
fixed and disclosed. It is the component-level **defect-management (DM)** and
**security-update-management (SUM)** process expected by IEC 62443-4-1, and
serves as the vulnerability-handling deliverable referenced in
[`COMPLIANCE.md`](COMPLIANCE.md). Integrators should adopt or extend it into
their product PSIRT.

## Scope

In scope: the wolfMKA source in this repository — the MKA protocol engine, PDU
codec, crypto-binding layer, and the SecY/transport abstraction.

Out of scope (report to the respective project): cryptographic primitives, RNG,
and key-wrap — these are **wolfSSL's** and follow wolfSSL's own security process.
Also out of scope: defects in an integrator's SecY hooks, transport, or platform.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.** Report privately:

- Email the wolfSSL security team at `security@wolfssl.com`.
- Optionally encrypt; request the current key in a first low-detail message.

Please include, as far as known:

- affected version / commit, and build configuration (`WOLFMKA_*` defines);
- a description of the issue and its security impact;
- reproduction steps or a proof-of-concept (a crafted MKPDU is ideal);
- any suggested fix.

**Acknowledgement target: 3 business days.** We support coordinated disclosure
and will agree a disclosure timeline with the reporter; the default embargo is
**90 days** or until a fix ships, whichever is sooner.

## Triage and severity

Each report is reproduced and rated using **CVSS v3.1**. Severity sets the
target fix window:

| Severity (CVSS) | Examples | Fix target |
|-----------------|----------|------------|
| Critical (9.0–10.0) | ICV bypass; key disclosure; RCE via PDU parse | ≤ 7 days |
| High (7.0–8.9) | replay/downgrade accepted; OOB read in decode | ≤ 30 days |
| Medium (4.0–6.9) | DoS via malformed PDU; election lock-up | ≤ 90 days |
| Low (0.1–3.9) | local mis-configuration, info leak with no key impact | next release |

Triage cross-references [`FMEA.md`](FMEA.md): a report is mapped to an existing
failure mode where one applies, or a new failure mode is added if it reveals a
gap in the analysis.

## Handling workflow

1. **Receive & acknowledge** within the target above; assign a tracking ID.
2. **Reproduce** against supported versions; confirm scope (is it wolfMKA or a
   dependency / integrator hook?).
3. **Assess** impact and CVSS; identify affected configurations and the root
   failure mode.
4. **Fix** on a private branch, with a **regression test added to the suite**
   (every security fix ships with a test that fails before and passes after) and
   the MISRA/valgrind gates re-run.
5. **Review** the fix independently before merge.
6. **Release** a patched version; request a CVE for Medium+ issues.
7. **Disclose** coordinated with the reporter; publish an advisory (see below).
8. **Post-mortem**: update `FMEA.md` and, where the class of bug is
   generalizable, the negative-test corpus and coding guidance.

## Advisory contents

Each advisory states: affected versions, fixed version, CVSS vector & score,
impact, affected build configurations, the fix commit, workarounds (if any), and
credit to the reporter (unless anonymity is requested).

## Verification gates a security fix must pass

Before a fix is released it must pass the full project gate set:

```sh
make test                 # unit + new regression test
make CPPCHECK=... misra    # MISRA C:2012 clean
make features              # all build configurations compile
make test-nomalloc         # no dynamic allocation symbols
valgrind --leak-check=full ./test/runtests   # memory-clean
```

## Supported versions

Security fixes are provided for the current release line. Define your fork's
support window (e.g. latest minor + previous minor) here before publishing.

## Integrator responsibilities

- Route wolfMKA advisories into your product's PSIRT and SUM process.
- Re-assess CVSS in *your* deployment context (network exposure, SL target).
- Maintain your own reporting channel and patch-delivery mechanism for the
  fielded product — wolfMKA ships source; **you** ship the update.
