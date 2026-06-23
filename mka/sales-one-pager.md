# wolfMKA — Battlecard / One-Pager

**MACsec Key Agreement (IEEE 802.1X-2010, Clause 9) on wolfCrypt**

---

## 30-second pitch
Your silicon does MACsec (802.1AE) encryption. **wolfMKA is what manages the
keys** — mutual authentication, Key Server election, SAK distribution, and
continuous rekey — in a footprint that fits an MCU or a line-card control CPU,
on the same **FIPS 140-3-capable wolfCrypt** you already trust.

## The one qualifying question
> **"You have MACsec in the silicon — what's managing the keys today?"**

"Nothing / manual rekey / we hand-rolled it / wpa_supplicant is too heavy"
→ **that's the wolfMKA deal.**

---

## Top 5 reasons to buy
1. **Fits where wpa_supplicant can't** — ~17 KB code, **no-malloc**, sub-200 B
   stack in the embedded profile. Bare-metal, RTOS, or Linux.
2. **One validated crypto core** — runs on wolfCrypt, including **FIPS 140-3**.
   Cross-sell to anyone already shipping wolfSSL/wolfCrypt.
3. **AUTOSAR-native** — ships the Classic AUTOSAR `Mka_*` interface; drops into
   a BSW stack with no shim.
4. **Audit-grade assurance** — 100% MC/DC, MISRA C:2012, fuzzing, ASan/UBSan,
   static analysis, **big-endian support**.
5. **Interop de-risked** — byte-pinned to hostapd vectors and run live against
   `wpa_supplicant` (control *and* data plane).

## Feature checklist
- ✅ Key Server election + make-before-break rekey
- ✅ **XPN** (GCM-AES-XPN-128/256) for 10/100G+ links
- ✅ Pre-shared, **EAP-derived**, and Distributed CAK
- ✅ Delay protection, cipher suite negotiation
- ✅ Portable `wm_*` API **and** AUTOSAR `Mka_*` API
- ✅ GPLv3 **or** commercial license + wolfSSL support

---

## Who to call (verify against CRM before quoting logos)

| Industry | Hook | Existing-adopter angle | Net-new prospect |
|---|---|---|---|
| **Automotive (AUTOSAR)** | AUTOSAR `Mka` module + MISRA + FIPS crypto | **NXP** (known wolfSSL silicon relationship) | Tier-1 ECU/gateway vendor — Continental, Bosch, Aptiv |
| **Network Equipment** | Footprint + proven wpa_supplicant interop + commercial license | A current wolfSSL firmware account (pull from CRM) | Arista, Juniper, SmartNIC/DPU makers |
| **Power Grid (NERC CIP-012)** | Audit evidence + FIPS crypto for control-center data-in-motion | **SEL** (substation/grid networking — likely fit) | Hitachi Energy, GE Vernova Grid, Siemens Grid |

> Company names are **illustrative**, not CRM-sourced. Confirm account status and
> swap in better-fit logos where the we have them.

---

## Objection handling
| They say… | You say… |
|---|---|
| "We already use wpa_supplicant." | "Great for a Linux host. On an MCU or line-card CPU it's too big and pulls in GPL + a full userland. wolfMKA is no-malloc, sub-200 B stack, and we've proven we interop with wpa_supplicant — mix and match." |
| "MACsec is in our ASIC, we're done." | "The ASIC encrypts; it doesn't authenticate peers or rotate keys. Without MKA you're rekeying by hand or not at all — and XPN links exhaust 32-bit packet numbers in seconds at 100G." |
| "We need FIPS." | "wolfMKA runs on wolfCrypt, including the FIPS 140-3 validated module — same core across your whole stack." |
| "How do we know it's safe-critical ready?" | "100% MC/DC, MISRA C:2012-clean, fuzzed, static-analyzed, and proven on big-endian. We hand you the evidence your auditors want." |
| "Will it talk to the other vendor's box?" | "Byte-pinned to the hostapd reference vectors and run live against wpa_supplicant on both the control and data plane." |

---

## Fast facts
| | |
|---|---|
| **Product** | wolfMKA — IEEE 802.1X-2010 MKA for MACsec |
| **Crypto** | wolfCrypt (CMAC, AES Key Wrap, AES-GCM); FIPS 140-3 capable |
| **Targets** | Bare-metal, RTOS, AUTOSAR Classic, Linux |
| **Footprint** | ~17 KB code · no-malloc option · sub-200 B stack |
| **Verification** | 100% MC/DC · MISRA C:2012 · fuzzing · ASan/UBSan · big-endian-proven |
| **Interop** | hostapd vectors · live wpa_supplicant (control + data plane) |
| **License** | GPLv3 or commercial + support |
