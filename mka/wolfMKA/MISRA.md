# MISRA C:2012 Compliance — wolfMKA

The wolfMKA library source (`src/*.c`, `include/wolfmka/*.h`) is written to
conform to **MISRA C:2012**. This document is the compliance statement and the
deviation record.

Scope: the **library only**. Test code (`test/`) and examples (`examples/`) are
support scaffolding and are *not* claimed to be MISRA-compliant (MISRA explicitly
allows non-compliant test/adaptation code).

## Compliant configuration

The fully compliant build is the no-dynamic-allocation configuration:

```
-DWOLFMKA_NO_MALLOC -DWOLFMKA_SMALL_STACK
```

In this configuration the library makes **no dynamic memory allocations** (large
working buffers are fields of caller-provided objects — see `mka_mem.h`), so the
allocation-related rules are met with no deviation. `make test-nomalloc` proves
the objects link no `malloc`/`free`/`calloc`/`realloc`.

The one large wolfSSL working object, the ~1 KB AES-CMAC context, is supplied
from wolfMKA's static CMAC pool through a caller-held `MkaCmacCtx` workspace
(`wm_Crypto_CmacInit`, passed via `MkaParticipantConfig.cmac` or directly), so
it needs neither a stack frame nor an allocation. The workspace is **mandatory**
in every configuration: wolfMKA never falls back to a stack or heap context for
it, so a `NULL` CMAC argument is rejected with `MKA_ERR_BAD_ARG`. This keeps the
object's placement entirely under the integrator's control.

## Checking tool

Findings were measured with **Cppcheck 2.19.0** (the version pinned in
`.cppcheck-version`) and its bundled MISRA C:2012 addon:

```
make misra        # runs the addon across the checked configurations
```

The target reports any finding that is **not** a documented deviation below; a
clean run means the only remaining findings are the approved deviations.

`make misra` analyses six build configurations: the compliant little-endian
base (`-DWOLFMKA_NO_MALLOC -DWOLFMKA_SMALL_STACK -DWOLFMKA_LITTLE_ENDIAN`), that
base with the opt-in `-DWOLFMKA_DISTRIBUTED_CAK -DWOLFMKA_KMD
-DWOLFMKA_SUSPENSION -DWOLFMKA_CIPHER_NEGOTIATION` features, that base under the
OPEN Alliance automotive profile (`-DWOLFMKA_AUTOMOTIVE_PROFILE`, which selects a
different announced MKPDU version and compiles the Announcement code out), that
base with the L2-address ICV (which adds the streaming
CMAC path), a
**big-endian** build of the base (`-DWOLFMKA_BIG_ENDIAN`, which exercises the
network-order serialization path in the MKPDU codec), and the
maximally-stripped feature-off build.

`src/autosar/Mka.c` is not part of `$(SRC)` - it needs `-DWOLFMKA_AUTOSAR` and
the AUTOSAR base types - so it is scanned by two further invocations of its own,
with `MKA_DEV_ERROR_DETECT` off and on, since the reporting adds statements the
addon sees. Eight configurations in total; between them, every `.c` file under
`src/` is covered.

## Deviation record

Every deviation is from an **Advisory** rule except where noted. No
*Mandatory*-classification rule is deviated.

| Rule | Class | Decision | Rationale |
|------|-------|----------|-----------|
| **15.5** single point of exit | Advisory | Deviate (project-wide) | Guard-clause early returns are used for argument validation and error propagation. They reduce nesting and are clearer than a single-exit equivalent. ~70 sites. |
| **8.7** external linkage used in one TU | Advisory | Deviate | Flagged functions are the **public API** (declared in `include/wolfmka/*.h` for external integrators); they only appear used internally because the analysed set is library-only. |
| **8.9** object could have block scope | Advisory | Complied | Variable scopes minimised. |
| **8.13** pointer could be const | Advisory | Complied | Read-only pointers are `const`-qualified. |
| **2.3 / 2.4 / 2.5** unused type / tag / macro | Advisory | Deviate | Public-API enums (e.g. `MkaConfidentialityOffset`), parameter-set type constants and named error codes are defined for completeness and external use; not every one is referenced *within* the library. |
| **2.3** unused type — static assertion | Advisory | Deviate | `mka_kdf_bounds_check` in `mka_crypto.c` is a `typedef` whose array bound is negative unless the KDF label/context/buffer constants stay consistent with one another. It is deliberately never referenced: the declaration *is* the check. C99 has no `_Static_assert`, and the invariant it guards (a placement that happens before `mka_kdf_run` validates the total length) is otherwise enforced only by three constants declared apart from each other. |
| **20.7** macro parameter parenthesization | Required | Compliant by exception | The three flagged sites are in `MKA_DECLARE_VAR` / `MKA_ALLOC_VAR_BACKED`, where parameters are used as a **type-name** (`(type*)`, `sizeof(type)`) or a **declarator** (`type* name`). Rule 20.7's own amplification states it does not apply where parenthesising would be a syntax error. Cppcheck's addon does not implement that exception. Modelled on wolfSSL's `WC_DECLARE_VAR`. |
| **7.3** lowercase `l` literal suffix | Required | Compliant — tool false positive | The codebase uses **uppercase** literal suffixes only (`U`, `UL`). Cppcheck 2.19.0's addon mis-fires this rule on *identifiers* that merely contain the letter `l` (e.g. `pl`, `body_len`, `peer_list`), not on literals. Suppressed pending a cppcheck fix; re-evaluate on upgrade. |
| **21.1** `#define` of a reserved name (`true`/`false`) | Required | Deviate — pre-C99 shim only | When `<stdbool.h>` is unavailable, `mka_types.h` provides a minimal shim that `typedef`s `bool` and defines `true`/`false` exactly as the standard header would. The selection prefers `<stdbool.h>` (`__STDC_VERSION__ >= C99`, else `__has_include`); the shim is **not present** in the compliant configuration (C99, where the standard header is included), only on an exotic pre-C99 target (or under `WOLFMKA_NO_STDBOOL`). |
| **21.3** use of `malloc`/`free` | Required | Deviate — heap config only | Used **only** when `WOLFMKA_SMALL_STACK` is set *without* `WOLFMKA_NO_MALLOC`. Allocation is funnelled through the single redefinable pair `WOLFMKA_MALLOC`/`WOLFMKA_FREE` so an integrator may supply a static pool. **Not present** in the compliant configuration. |
| **11.5** cast from `void*` | Advisory | Deviate — heap config only | The `(type*)WOLFMKA_MALLOC(...)` cast. As 21.3, **not present** in the compliant configuration. |
| **11.5** cast from `void*` — callback context | Advisory | Deviate — AUTOSAR binding | `mka_send_bridge` recovers its PAE from the opaque `void*` context that `MkaSendFn` carries. A generic callback hook cannot express a typed context, and the alternative — a global lookup keyed by PDU id — trades a checked cast for mutable shared state. Scoped to `src/autosar/Mka.c`. |
| **21.15** `memcpy` pointer types compatible | Required | Deviate — big-endian build only | The shared network-order serializers in `mka_bytes.h` (`w_be16`/`w_be32`/`w_be48` and `rd_be48`, used by both the MKPDU codec and the crypto layer) copy a scalar's native representation directly via `WOLFMKA_MEMCPY` on a big-endian host, so the `memcpy` mixes a `uint8_t*` buffer with a `uint16_t*`/`uint32_t*`/`uint64_t*` scalar (the 48-bit value is left-/right-aligned in a 64-bit word). Host order already equals network order, so each copy is exact — a deliberate, localised serialization pun. **Not present** in a little-endian build, where the byte-shift path is used. The 16/32-bit readers (`rd_be16`/`rd_be32`) are byte-shift on every host. |

### The AUTOSAR binding and the `boolean` type

`src/autosar/Mka.c` is held to the same rules, with one wrinkle: AUTOSAR's
`boolean` is a `uint8` typedef, not C99's `bool`. MISRA's essential type model
therefore reads `if (someBoolean)` as an *integer* controlling expression
(14.4), and `(boolean)(a != b)` as a cast from essentially-boolean to
essentially-unsigned (10.5). Both are avoidable without changing behaviour, and
the file does so: controlling expressions compare explicitly against `FALSE`,
and boolean-valued assignments use `? TRUE : FALSE` rather than a cast. That is
also idiomatic AUTOSAR style, so it costs nothing in readability.

## Directives

- **Dir 4.6** (use typedefs that indicate size/signedness): complied — all
  integer objects use `uint8_t`/`uint16_t`/`uint32_t`/`uint64_t`/`size_t`.
- **Dir 4.1** (run-time failures minimised): every public entry point validates
  its arguments; buffer lengths are checked before use; the ICV is verified
  before any received parameter-set content is trusted.
- **Dir 4.9** (function over function-like macro): **Deviate** (Advisory). The
  library uses function-like macros only where a macro is the right tool: the
  SAK Use flag accessors (`MKA_SAK_USE_IS_*` / `MKA_SAK_USE_SET_*`),
  `MKA_SET_SIZE` / `mka_param_body_len` / `mka_align4`, and the integrator-redefinable
  configuration/allocation hooks (`WOLFMKA_MALLOC` / `WOLFMKA_FREE` /
  `WOLFMKA_MEMCPY` …, `MKA_FI`, `MKA_DECLARE_VAR`, and the AUTOSAR binding's
  `MKA_DET_REPORT_ERROR`, which must compile to nothing when
  `MKA_DEV_ERROR_DETECT` is `STD_OFF` and be redefinable by an integrator
  routing reports elsewhere). These are macros for
  type-genericity, token pasting, or compile-time configurability — not
  interchangeable with a single function. The byte-cursor writers
  (`mka_w_bytes`/`mka_w_u8`/`mka_w_pad4`/`mka_w_be16`/`mka_w_be32`/`mka_w_be64`),
  the matching reader helpers
  (`mka_r_bytes`/`mka_r_be8`/`mka_r_be32`/`mka_r_be64`) and the shared
  `mka_bytes.h` serializers are static inline functions, not macros. Cppcheck's addon does not
  implement Dir 4.9, so this deviation is recorded here rather than suppressed.

## Notes on the essential type model (Rules 10.x)

- Length/size object-like macros carry a `U` suffix (`mka_types.h`) so arithmetic
  with `size_t` stays within one essential type category.
- Boolean flags use the essentially-Boolean type `bool` (`<stdbool.h>`); they are
  never mixed with arithmetic.
- All narrowing or category-changing conversions are explicit casts.
- **Rule 10.8** (composite expression cast to a wider/different essential type)
  shapes how the derived wire constants are used. `MKA_SAK_USE_BODY_LEN` is
  defined from its parts (`2U * (MKA_MI_LEN + MKA_KN_LEN + MKA_LPN_LEN)`) so the
  derivation is visible, which makes it a composite expression - so it is used
  bare and left to widen implicitly to `size_t` rather than cast. The widening
  is unsigned-to-unsigned and value-preserving. Constants that are plain
  literals (`MKA_CIPHER_SUITE_LEN`, `MKA_WRAPPED_SAK_128_LEN`) are not composite
  and may be cast where a cast aids readability.
