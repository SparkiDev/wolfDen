# Protecting Control-Center Communications: wolfMKA and MACsec for NERC CIP-012-2

If you operate part of the North American Bulk Electric System, **NERC
CIP-012-2** — *Cyber Security: Communications between Control Centers* —
requires you to protect the **confidentiality and integrity** of Real-time
Assessment and Real-time monitoring data while it is transmitted between Control
Centers, and to identify where that protection is applied. Both properties have
to be covered, with key management you can stand behind in an audit.

That is exactly what **MACsec (IEEE 802.1AE)** was built for: line-rate Layer 2
encryption, integrity, and replay protection applied directly on the wire,
transparently to whatever rides on top (ICCP/TASE.2, DNP3, SCADA telemetry). But
MACsec doesn't key itself — it needs a control plane to authenticate peers,
elect a Key Server, and securely distribute and rotate the Secure Association
Keys the data plane uses. That control plane is the **MACsec Key Agreement
(MKA)** protocol, **IEEE Std 802.1X-2010, Clause 9**.

Today we're giving a sneak peek: wolfSSL has **preliminary MKA support in
development** — **wolfMKA** — built on the same compact, well-tested
cryptography that already runs across critical infrastructure.

## Why this matters for CIP-012-2

CIP-012-2 lets each entity choose *how* and *where* it protects inter-Control-
Center data. MACsec with MKA is a strong answer wherever you have Layer 2 reach
to that demarcation — dark fiber and direct Ethernet between sites,
metro/carrier Ethernet handoffs, or the segment between your Control Center LAN and the WAN edge:

- **Both halves of the mandate in one mechanism.** AES-GCM delivers
  confidentiality and integrity together, and MKA adds replay protection — no
  bolt-on, no second protocol to cover the gap.
- **Authenticated, automated key management.** MKA establishes mutual proof of
  the pre-shared Connectivity Association Key, elects a Key Server, distributes
  SAKs under AES Key Wrap, and rotates them with make-before-break rekey so
  monitoring traffic is never black-holed during a key change — managed keys,
  not static keys in a config file.
- **Protocol-agnostic and transparent.** Protection lives at Layer 2, so it
  covers every flow on the link regardless of the application — no
  re-engineering your EMS to get it.
- **Crypto you can evidence.** All cryptography flows through wolfSSL, whose
  FIPS 140-3 validation posture gives you a defensible foundation for the
  controls themselves.

## Built for OT assurance

wolfMKA is structurally tested to **100% line, decision (branch) and MC/DC
coverage** of its core sources — enforced by the build across every delivered
configuration. It is deterministic and resource-bounded, with a
no-dynamic-allocation, small-stack configuration that makes **zero heap
allocations**, and it aligns with the security and safety processes you already
run, including **IEC 62443**. An abstract SecY interface drops it onto a Linux
`macsec` device, a hardware offload, or your own data plane.

None of that makes a *product* CIP-012 compliant on its own — compliance is a
program, not a library — but it gives your engineers and assessors a clean,
auditable building block for the communications-protection control instead of a
black box.

If you have questions, or would like to evaluate wolfSSL's preliminary MKA
support, please contact us at **facts@wolfssl.com** or call us at
**+1 425 245 8247**.

Love it? Star us on [GitHub](https://github.com/wolfSSL/wolfssl)!
