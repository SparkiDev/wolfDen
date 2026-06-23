# wolfMKA: The MACsec Control Plane for Your Switch Firmware

Your switches already do the hard part in silicon. A modern MACsec-capable ASIC
encrypts, authenticates, and replay-protects every frame at line rate on the
physical layer — no CPU in the data path. But that hardware doesn't key itself.
Before a single protected frame goes out, something has to discover peers, prove
liveness, elect a Key Server, and securely distribute and rotate the Secure
Association Keys the ASIC programs into its hardware. That something is the
**MACsec Key Agreement (MKA)** state machine, **IEEE Std 802.1X-2010, Clause
9**.

Today, too many vendors fill that gap by dragging **wpa_supplicant** into their
firmware — a large, GPL-licensed, Linux-centric daemon built for Wi-Fi
supplicants, carrying dependencies and a footprint that don't belong on an
embedded switch. You end up maintaining a heavyweight third-party stack just to
run one state machine.

We're giving a sneak peek at a better option: wolfSSL has **preliminary MKA
support in development** — **wolfMKA** — a compact, **commercially licensed,
royalty-free** MKA implementation that plugs directly into your existing
firmware build.

## Why network-equipment vendors will like it

- **It maps to your ASIC, not to Linux.** wolfMKA talks to the data plane
  through an abstract **SecY interface** — a handful of callbacks to create
  SCs/SAs, install keys, and enable transmit/receive. Wire it to your switch SDK
  or hardware-offload driver; there's no assumption of a Linux `macsec` device.
- **It fits an embedded build.** Pure C with a no-dynamic-allocation,
  small-stack configuration that makes **zero heap allocations** — bounded
  tables, bounded loops, no recursion. All cryptography flows through wolfSSL,
  which you may already ship.
- **The full protocol, not a subset.** Peer discovery and liveness, Key Server
  election, SAK generation and AES Key Wrap distribution, make-before-break
  rekey, replay protection, Extended Packet Numbering for high-rate ports, and
  multiple Connectivity Associations per port.
- **Clean licensing for a commercial product.** A royalty-free commercial
  license, with one vendor standing behind both the MKA control plane and the
  crypto underneath — no GPL entanglement to negotiate around.

The result: you keep the line-rate encryption your hardware already delivers,
and drop in a control plane sized and licensed for a shipping product — instead
of porting and maintaining wpa_supplicant.

If you'd like to evaluate wolfSSL's preliminary MKA support for your switch
platform, please contact us at **facts@wolfssl.com** or call us at
**+1 425 245 8247**.

Love it? Star us on [GitHub](https://github.com/wolfSSL/wolfssl)!
