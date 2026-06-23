# wolfMKA interoperability harness

These scripts validate wolfMKA against an independent MKA implementation
(hostapd/wpa_supplicant) over a real wire, complementing the byte-pinned crypto
vectors in the unit suite (`test_eap_derivation`, `test_icv`). Where those prove
the *cryptographic constructions* match hostapd, these prove two separate stacks
complete the protocol on the wire: discovery, Key Server election, SAK
distribution and — in Tier 2 — kernel MACsec bring-up and protected traffic.

Both tiers run the two implementations in separate Linux **network namespaces**
joined by a **veth** pair, sharing one pre-shared CAK/CKN (PSK-CAK mode; no EAP).

| Script | Tier | Proves |
| --- | --- | --- |
| `run-interop.sh` | 1 — control plane | wolfMKA `mka_link` and wpa_supplicant discover each other, elect a Key Server and agree a SAK |
| `run-interop-dataplane.sh` | 2 — data plane | both program the kernel MACsec SA; `ping` flows protected; on-wire frames are MACsec (0x88e5), not cleartext; a Key Server rekey rolls the key and traffic survives |

## Prerequisites

- **root** (network namespaces, veth, raw sockets, MACsec netlink)
- **iproute2** (`ip`)
- the kernel **`macsec`** module (`modprobe macsec`) — Tier 2
- **wpa_supplicant** built with `CONFIG_MACSEC=y` and
  `CONFIG_DRIVER_MACSEC_LINUX=y`
- **tcpdump** (optional — Tier 2 uses it for the on-wire encryption check)

Each script checks its prerequisites and prints `SKIP` (exit 0) when any is
missing, so it is safe to invoke in a constrained environment; it only does real
work — and can `FAIL` — where it can actually run.

## Running

From the repository root (the Makefile builds the needed example binaries
first):

```sh
make examples            # builds mka_link and mka_macsec
sudo make interop            # Tier 1 (control plane)
sudo make interop-dataplane  # Tier 2 (data plane)
```

or directly:

```sh
sudo MKA_LINK=examples/mka_link            test/interop/run-interop.sh
sudo MKA_MACSEC=examples/mka_macsec        test/interop/run-interop-dataplane.sh
```

Environment overrides: `WPA_SUPPLICANT` (path/name of the binary), `TIMEOUT`
(seconds to wait for convergence), `MKA_LINK` / `MKA_MACSEC` (binary paths).

## Notes / tuning

- These are **not** part of the unit CI: they need privilege, the kernel MACsec
  module, and an external wpa_supplicant build. Run them on a privileged host or
  a `NET_ADMIN` container / self-hosted runner.
- Interface naming for wpa's auto-created MACsec device varies by version; the
  Tier 2 script discovers it with `ip -o link show type macsec`. If your
  wpa_supplicant names it unusually, adjust the discovery `awk`/`sed`.
- Timing of protocol convergence over real sockets is environment-sensitive;
  raise `TIMEOUT` on a slow or loaded host.
- Tier 2 keys both kernel devices from the SAK MKA agreed; if `ping` fails after
  the control plane converged, that is a genuine data-plane interop finding
  (SCI/AN/cipher mismatch) worth investigating, not a harness artefact.
