# Preliminary MACsec Key Agreement (MKA) Support, Built for AUTOSAR

Secure in‑vehicle and industrial Ethernet is moving from "nice to have" to
"required," and **MACsec (IEEE 802.1AE)** is at the center of it — providing
line‑rate Layer 2 encryption, integrity, and replay protection directly on the
wire. But MACsec doesn't key itself. It needs a control plane to discover peers,
prove liveness, elect a Key Server, and securely distribute the Secure
Association Keys (SAKs) that the data plane uses. That control plane is the
**MACsec Key Agreement (MKA)** protocol, defined in **IEEE Std 802.1X‑2010,
Clause 9**.

Today we're giving a sneak peek: wolfSSL has **preliminary MKA support in
development**, with a binding designed specifically for **AUTOSAR**.

## Why this matters for automotive

Automotive Ethernet backbones increasingly carry safety‑relevant and
privacy‑sensitive traffic, and OEMs are standardizing on MACsec to protect it.
AUTOSAR has responded with its own MACsec/MKA module (**Mka**, Document ID
1066). Our preview implements that **AUTOSAR `Mka` API on top of wolfSSL's
compact, well‑tested cryptography** — so suppliers can bring authenticated,
encrypted Ethernet to ECUs without bolting on a heavyweight networking stack.

## What's in the preview

- **The full MKA handshake** — peer discovery and liveness, Key Server election,
  SAK generation and AES Key Wrap distribution, and make‑before‑break rekey so
  traffic is never black‑holed during a key change.
- **Replay protection and transmit gating** — strictly increasing Message
  Numbers, and transmit held until every peer can receive on the new key.
- **Extended Packet Numbering (XPN)** and **delay protection**, plus optional
  MKA participant **suspension** (802.1Xbx) for planned quiet periods.
- **An AUTOSAR `Mka` binding** that maps cleanly onto the standard API.
- **Built for the smallest ECUs** — a no‑dynamic‑allocation, small‑stack
  configuration that makes **zero heap allocations**, with all cryptography
  flowing through wolfSSL.
- **Written for functional safety** — coded to **MISRA C:2012** and built with
  the kind of evidence automotive safety processes lean on, including the
  **IEC 61508** foundation that **ISO 26262** derives from (plus **IEC 62443**
  for security). Bounded, deterministic, no recursion — and an abstract SecY
  interface that drops onto a Linux `macsec` device, a hardware offload, or your
  own data plane.

## Coming soon

This is our first look at wolfSSL MKA support — there's more to share as the
work matures, including deeper detail on the AUTOSAR integration and
configuration. If MACsec and MKA are on your roadmap for automotive or
industrial Ethernet, we'd love to talk and line you up for early access.

If you have questions about any of the above, or would like to evaluate
wolfSSL's preliminary MKA support, please contact us at **facts@wolfssl.com** or
call us at **+1 425 245 8247**.

Love it? Star us on [GitHub](https://github.com/wolfSSL/wolfssl)!
