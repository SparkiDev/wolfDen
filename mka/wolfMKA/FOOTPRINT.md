# wolfMKA footprint

Memory and code-size budget for sizing an integration. Regenerate with
`make footprint` (script: `test/footprint.sh`). All numbers are `gcc -Os`,
bytes; the byte counts below are illustrative of one x86-64 build — your figure
depends on the target ISA and toolchain, so measure on yours.

Code size is the **pre-link** sum of every translation unit's `.text`/`.data`/
`.bss`; the linker's `--gc-sections` then drops the parts of whatever the
application does not actually call, so a real image is smaller. "Large objects"
are the caller-allocated control structures — wolfMKA performs no hidden
allocation, so these are what the integrator budgets. "maxstk" is the deepest
single frame from `-fstack-usage`.

| config | .text | .data | .bss | `MkaParticipant` | `MkaKay` | `MkaPdu` | maxstk |
|--------|------:|------:|-----:|-----------------:|---------:|---------:|-------:|
| default  | 19812 | 0 | 1008 | 2304 |  9232 | 1344 | 1504 |
| minimal  | 17319 | 0 | 1008 | 2288 |  9168 | 1264 | 1424 |
| embedded | 17150 | 0 | 1008 | 4840 | 19376 | 1264 |  192 |
| full     | 21876 | 0 | 1008 | 3968 | 15888 | 1512 | 1696 |

Configurations:

- **default** — little-endian, malloc available, default feature set.
- **minimal** — all `WOLFMKA_NO_*` set (no EAP, XPN, delay protection, retry,
  announcements, auto-rekey): smallest code.
- **embedded** — `minimal` plus `WOLFMKA_SMALL_STACK` and `WOLFMKA_NO_MALLOC`.
- **full** — all opt-in features on (Distributed CAK, KMD, Suspension, cipher
  negotiation): largest code.

## Reading the numbers

- **Code vs. features.** `.text` tracks the feature set: `minimal` is ~13% under
  `default`, `full` ~10% over it. Disabling unused features is the lever for
  flash.
- **The embedded trade.** `WOLFMKA_NO_MALLOC` binds the per-participant working
  buffers into the control structures instead of the heap, so `MkaParticipant`
  and `MkaKay` grow (here ~2.1x) — but `WOLFMKA_SMALL_STACK` then moves the large
  locals off the stack, collapsing the worst-case frame from ~1.5 KiB to **176
  bytes**. That is the point of the embedded profile: predictable, bounded stack
  and zero dynamic allocation, paid for in static RAM.
- **Sizing a node.** Budget one `MkaParticipant` per CKN and one `MkaKay` per
  port (it embeds `MKA_MAX_PARTICIPANTS` participants — tune that macro and
  `MKA_MAX_PEERS` to trade table capacity against RAM). `MkaPdu` is a transient
  decode/encode scratch.
- **`MKA_MAX_PEERS` drives more than the peer table.** `MKA_MKPDU_MAX_LEN` is
  derived from it, because a membership that cannot be encoded stops the
  participant transmitting altogether; the two must agree, and an inconsistent
  override is a build error. At the default of 32 peers the outgoing-frame
  buffer is ~1.3 KiB, which is what the `embedded` column's larger
  `MkaParticipant` and `MkaKay` pay for. A point-to-point link needs
  `MKA_MAX_PEERS` of 2 — the OPEN Alliance automotive profile assumes it — and
  everything above shrinks with it.
