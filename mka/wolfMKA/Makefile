# wolfMKA - MACsec Key Agreement (IEEE 802.1X-2010) over wolfSSL
#
# Override WOLFSSL_DIR to point at a wolfSSL install prefix (containing
# include/ and lib/). Defaults to the in-tree build used during development.

WOLFSSL_DIR ?= $(CURDIR)/../wolfssl/install-mka

CC      ?= gcc
# Coverage uses gcov; keep it matched to CC (e.g. CC=gcc-14 GCOV=gcov-14) so the
# .gcno/.gcda format and -fcondition-coverage (GCC >= 14) agree.
GCOV    ?= gcov
CFLAGS  ?= -O2 -g -Wall -Wextra -Wshadow -std=c99
CFLAGS  += -Iinclude -I$(WOLFSSL_DIR)/include

# Build with SMALL_STACK=1 to move all >= 64-octet locals off the stack. With
# malloc available they go on the heap; combine with NO_MALLOC=1 to bind them to
# object fields instead and make zero dynamic allocations.
ifeq ($(SMALL_STACK),1)
CFLAGS  += -DWOLFMKA_SMALL_STACK
endif
ifeq ($(NO_MALLOC),1)
CFLAGS  += -DWOLFMKA_NO_MALLOC
endif
LDFLAGS += -L$(WOLFSSL_DIR)/lib
LDLIBS  += -lwolfssl

# Let the binaries find libwolfssl.so at run time without LD_LIBRARY_PATH.
LDFLAGS += -Wl,-rpath,$(WOLFSSL_DIR)/lib

SRC      := $(wildcard src/*.c)
OBJ      := $(SRC:.c=.o)
DEP      := $(OBJ:.o=.d)
LIB      := libwolfmka.a

# Auto-generate header dependencies (-MMD) plus phony targets for each header
# (-MP) so a removed/renamed header never leaves a cached object stale.
DEPFLAGS := -MMD -MP

# Rebuild objects when the compiler or compile flags change - not only when a
# source/header timestamp does. Without this, switching build profiles (e.g.
# `make test` after `make test-nomalloc`, which compiles with SMALL_STACK /
# NO_MALLOC) silently reuses objects with a different MkaParticipant layout. The
# stamp records "$(CC) $(CFLAGS)" and is rewritten only when that value actually
# changes, so it triggers a rebuild on a flag change but not on every run.
FLAGSTAMP := build/.cflags

# test_custom_alloc.c, test_autosar.c and test_icv_l2.c are standalone programs
# (own main), and the fuzz_*.c harnesses define a libFuzzer entry point (no
# main); exclude them all from the normal runner and build via their own targets
# instead.
TEST_SRC := $(filter-out test/test_custom_alloc.c test/test_autosar.c \
                         test/test_icv_l2.c \
                         test/fuzz_pdu.c test/fuzz_receive.c test/test_endian.c,\
                         $(wildcard test/*.c))
TEST_BIN := test/runtests

# mka_group_cak.c needs the opt-in Distributed CAK feature and mka_autosar.c
# needs -DWOLFMKA_AUTOSAR plus the Mka binding source, so both are excluded from
# the default `examples` build and have their own targets (example-distcak,
# example-autosar).
EXAMPLE_SRC := $(filter-out examples/mka_group_cak.c examples/mka_autosar.c,\
                            $(wildcard examples/*.c))
EXAMPLE_BIN := $(EXAMPLE_SRC:.c=)

.PHONY: all lib test check examples test-alloc test-nomalloc \
        test-fault test-distcak test-kmd test-suspension test-negotiation test-icv-l2 \
        example-distcak example-autosar features cxx misra docs \
        test-automotive example-distcak example-autosar features cxx misra docs \
        autosar coverage sanitize analyze fuzz fuzz-pdu fuzz-receive \
        interop interop-dataplane test-endian footprint format format-check clean FORCE

# Doxygen tool (override on the command line if not on PATH).
DOXYGEN    ?= doxygen

# MISRA C:2012 conformance check (Cppcheck + bundled misra addon). Override
# CPPCHECK= if the binary is not on PATH. Analyses the compliant configuration
# (WOLFMKA_NO_MALLOC) and fails on any finding not in the deviation record.
CPPCHECK   ?= cppcheck
# MISRA findings are cppcheck-version-sensitive; the pinned version (single
# source of truth, also built from source in CI) lives in .cppcheck-version.
CPPCHECK_VERSION := $(shell cat .cppcheck-version 2>/dev/null)
# cppcheck does not predefine the host byte-order macros, so the endianness is
# given explicitly. The little-endian value matches the CI host (and exercises
# the WOLFMKA_LITTLE_ENDIAN override in mka_types.h); a big-endian config is also
# checked so the network-order serialization path (and its documented Rule 21.15
# deviation) is covered.
MISRA_BASE := -DWOLFMKA_SMALL_STACK -DWOLFMKA_NO_MALLOC --max-configs=1
MISRA_DEFS := $(MISRA_BASE) -DWOLFMKA_LITTLE_ENDIAN

# clang-format tool (override on the command line if not on PATH). The style is
# pinned in .clang-format (wolfSSL house style; see sp_int.c); the clang-format
# version is pinned in .clang-format-version (single source of truth, also read
# by CI) since its output is version-sensitive.
CLANG_FORMAT ?= clang-format
CLANG_FORMAT_VERSION := $(shell cat .clang-format-version 2>/dev/null)
FORMAT_FILES := $(wildcard src/*.c) $(wildcard src/autosar/*.c) \
                $(wildcard include/wolfmka/*.h) \
                $(wildcard include/wolfmka/internal/*.h) \
                $(wildcard include/wolfmka/autosar/*.h) \
                $(wildcard test/*.c) $(wildcard test/*.h) \
                $(wildcard examples/*.c)

all: lib examples

lib: $(LIB)

$(LIB): $(OBJ)
	$(AR) rcs $@ $^

src/%.o: src/%.c $(FLAGSTAMP)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

# Refresh the flag stamp every run, but touch it (so objects rebuild) only when
# the recorded compiler/flags differ from the current ones.
$(FLAGSTAMP): FORCE
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC) $(CFLAGS)' | cmp -s - $@ 2>/dev/null || \
	    printf '%s\n' '$(CC) $(CFLAGS)' > $@
FORCE:

# Pull in the auto-generated header dependencies (absent on a clean tree, hence
# the leading '-'); each names the headers its object was compiled against.
-include $(DEP)

$(TEST_BIN): $(TEST_SRC) $(LIB)
	$(CC) $(CFLAGS) $(TEST_SRC) $(LIB) -o $@ $(LDFLAGS) $(LDLIBS)

test check: $(TEST_BIN)
	./$(TEST_BIN)

# Build the whole library + a standalone test with WOLFMKA_SMALL_STACK and a
# custom allocator (configured via test/wolfmka_user_settings.h) to prove the
# allocation hook is honoured and balanced.
test-alloc:
	$(CC) $(CFLAGS) -DWOLFMKA_USER_SETTINGS -Itest \
	    $(SRC) test/test_custom_alloc.c -o test/runalloc $(LDFLAGS) $(LDLIBS)
	./test/runalloc

# Build the small-stack, no-malloc configuration, run the suite, and assert the
# compiled library references no dynamic-allocation symbols at all.
test-nomalloc:
	$(MAKE) clean >/dev/null
	$(MAKE) SMALL_STACK=1 NO_MALLOC=1 test
	@echo "checking library objects for malloc/free/calloc/realloc ..."
	@if nm $(OBJ) | grep -E ' U (malloc|free|calloc|realloc)$$'; then \
	    echo "FAIL: dynamic allocation symbol present"; exit 1; \
	else \
	    echo "OK: no dynamic allocation symbols in libwolfmka"; \
	fi

# Build the suite with fault injection enabled and run it. This exercises the
# error branches that only fire when a wolfSSL primitive fails (MKA_ERR_CRYPTO),
# which valid inputs cannot reach. The flag is test-only; production builds and
# the MISRA-checked configuration never define it.
test-fault:
	$(CC) $(CFLAGS) -DWOLFMKA_FAULT_INJECT $(TEST_SRC) \
	    $(SRC) -o test/runfault $(LDFLAGS) $(LDLIBS)
	./test/runfault

# Build the suite with the optional Distributed CAK feature enabled and run it.
# The feature adds the type-5 parameter set, the wm_Participant_DistributeCak
# Key-Server API and the cak_received event; it is off by default, so the whole
# library and tests are recompiled (the flag changes the MkaPdu layout).
test-distcak:
	$(CC) $(CFLAGS) -DWOLFMKA_DISTRIBUTED_CAK $(TEST_SRC) \
	    $(SRC) -o test/rundistcak $(LDFLAGS) $(LDLIBS)
	./test/rundistcak

# Build the suite with the optional Key Management Domain feature enabled and
# run it. The feature adds the type-6 parameter set, a per-participant KMD to
# advertise, and the wm_Participant_GetKmd accessor; off by default, so the
# whole library and tests are recompiled (the flag changes the MkaPdu layout).
test-kmd:
	$(CC) $(CFLAGS) -DWOLFMKA_KMD $(TEST_SRC) \
	    $(SRC) -o test/runkmd $(LDFLAGS) $(LDLIBS)
	./test/runkmd

# Build the suite with the optional MKA Suspension behaviour (802.1Xbx) enabled
# and run it. Suspension is carried in the XPN parameter set, so the feature
# requires XPN (it must not be combined with WOLFMKA_NO_XPN); off by default.
test-suspension:
	$(CC) $(CFLAGS) -DWOLFMKA_SUSPENSION $(TEST_SRC) \
	    $(SRC) -o test/runsusp $(LDFLAGS) $(LDLIBS)
	./test/runsusp

# Build the suite with Key Server cipher-suite negotiation and run it. The Key
# Server selects the SAK cipher suite common to all peers from the preference
# lists they announce; off by default. Requires the Announcement parameter set.
test-negotiation:
	$(CC) $(CFLAGS) -DWOLFMKA_CIPHER_NEGOTIATION $(TEST_SRC) \
	    $(SRC) -o test/runnego $(LDFLAGS) $(LDLIBS)
	./test/runnego

# Build and run the standalone L2-address ICV test. WOLFMKA_ICV_L2_ADDR makes
# the ICV cover the DA || SA || EtherType L2 prefix ahead of the MKPDU, matching
# wpa_supplicant / the Linux kernel; off by default. The full suite's PDU/KAY
# frame builders assume the non-L2 ICV, so this path is pinned on its own.
test-icv-l2:
	$(CC) $(CFLAGS) -DWOLFMKA_ICV_L2_ADDR test/test_icv_l2.c \
	    $(SRC) -o test/runicvl2 $(LDFLAGS) $(LDLIBS)
	./test/runicvl2

# Build the suite under the OPEN Alliance TC17 Automotive MKA profile and run
# it. The profile emits version 3 MKPDUs and removes Secure Announcements and
# cipher-suite negotiation; the rest of it is runtime configuration applied by
# wm_Participant_AutomotiveDefaults(). See OPEN-ALLIANCE.md for the
# requirement-by-requirement conformance map.
test-automotive:
	$(CC) $(CFLAGS) -DWOLFMKA_AUTOMOTIVE_PROFILE $(TEST_SRC) \
	    $(SRC) -o test/runauto $(LDFLAGS) $(LDLIBS)
	./test/runauto

examples: $(EXAMPLE_BIN)

examples/%: examples/%.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(LDFLAGS) $(LDLIBS)

# Distributed CAK demo: a pairwise Key Server distributes a group CAK and the
# member's integrator starts a new group CA from the cak_received event. Built
# with the feature flag (so against the sources, not the default library).
example-distcak:
	$(CC) $(CFLAGS) -DWOLFMKA_DISTRIBUTED_CAK examples/mka_group_cak.c $(SRC) \
	    -o examples/mka_group_cak $(LDFLAGS) $(LDLIBS)
	./examples/mka_group_cak

# AUTOSAR API demo: two PAEs reach a MACsec session through the Mka_* binding.
# Built with -DWOLFMKA_AUTOSAR against the core sources plus src/autosar/Mka.c
# (the same profile the AUTOSAR binding is validated under).
example-autosar:
	$(CC) $(CFLAGS) -DWOLFMKA_AUTOSAR examples/mka_autosar.c $(SRC) \
	    src/autosar/Mka.c -o examples/mka_autosar $(LDFLAGS) $(LDLIBS)
	./examples/mka_autosar

# Live wire interoperability against wpa_supplicant's MKA over a veth pair in two
# network namespaces (see test/interop/README.md). Tier 1 is control-plane only;
# Tier 2 also brings up the kernel MACsec data plane and checks protected
# traffic + rekey. Both need root, iproute2 and a MACsec-capable wpa_supplicant;
# the scripts SKIP (exit 0) when a prerequisite is missing. Not part of CI.
interop: examples/mka_link
	test/interop/run-interop.sh

interop-dataplane: examples/mka_macsec
	test/interop/run-interop-dataplane.sh

# Big-endian serialization conformance. The native-memcpy MKPDU write path in
# mka_bytes.h is only correct on a big-endian host and is otherwise never
# executed, so test_endian.c (self-contained, no wolfSSL) is run BOTH natively
# (the shift path) and on big-endian ppc64 under qemu (the native path).
# Override ENDIAN_CC / ENDIAN_QEMU for a different big-endian target; the cross
# run is skipped (not failed) when that toolchain or emulator is absent.
ENDIAN_CC   ?= powerpc64-linux-gnu-gcc
ENDIAN_QEMU ?= qemu-ppc64
test-endian:
	@echo "[endian] native ($(CC)):"
	@$(CC) $(CFLAGS) test/test_endian.c -o test/runendian
	@./test/runendian
	@if command -v $(ENDIAN_CC) >/dev/null 2>&1 && \
	    command -v $(ENDIAN_QEMU) >/dev/null 2>&1; then \
	    echo "[endian] big-endian ppc64 ($(ENDIAN_CC) + $(ENDIAN_QEMU)):"; \
	    $(ENDIAN_CC) -std=c99 -O2 -Wall -static -Iinclude \
	        test/test_endian.c -o test/test_endian_be && \
	    $(ENDIAN_QEMU) test/test_endian_be; \
	else \
	    echo "[endian] SKIP big-endian run ($(ENDIAN_CC)/$(ENDIAN_QEMU) absent)"; \
	fi

# Report code size, large-object size and worst-case stack across the default,
# minimal, embedded (no-malloc/small-stack) and all-features configurations.
footprint:
	@test/footprint.sh

# Build and run the AUTOSAR Mka API binding (Document ID 1066) over the core
# library and exercise it end-to-end (two PAEs to a MACsec session). Built with
# -DWOLFMKA_AUTOSAR: the profile the binding needs (XPN, delay protection, retry
# back-off and Announcements all stay in; only EAP-MSK derivation is compiled
# out, since the binding keys from a pre-shared CAK).
autosar:
	$(CC) $(CFLAGS) -DWOLFMKA_AUTOSAR -DWOLFMKA_CMAC_POOL_SIZE=2 -Itest \
	    $(SRC) src/autosar/Mka.c test/test_autosar.c -o test/runautosar \
	    $(LDFLAGS) $(LDLIBS)
	./test/runautosar

# Run the unit suite under AddressSanitizer + UndefinedBehaviorSanitizer. This
# is the reproducible form of the ASan+UBSan evidence cited in COMPLIANCE.md and
# REQUIREMENTS.md (MKA-REQ-067): built from source (the prebuilt .a is not
# instrumented) at -O1 so the stack traces stay readable. -fno-sanitize-recover
# makes any UB a hard failure rather than a logged warning.
SAN_FLAGS := -fsanitize=address,undefined -fno-sanitize-recover=undefined \
             -fno-omit-frame-pointer -O1 -g
sanitize:
	$(CC) $(CFLAGS) $(SAN_FLAGS) $(TEST_SRC) $(SRC) -o test/runsanitize \
	    $(LDFLAGS) $(LDLIBS)
	UBSAN_OPTIONS=print_stacktrace=1 ASAN_OPTIONS=detect_leaks=1 \
	    ./test/runsanitize

# GCC -fanalyzer static analysis (a different bug class than the MISRA/cppcheck
# pass): inter-procedural detection of leaks, use-after-free, NULL derefs and
# bad arithmetic. Compile-only; -Werror turns any finding into a failure.
analyze:
	@set -e; for f in $(SRC) src/autosar/Mka.c; do \
	    def=; case $$f in src/autosar/Mka.c) def=-DWOLFMKA_AUTOSAR;; esac; \
	    $(CC) $(CFLAGS) $$def -fanalyzer -Werror -c $$f -o /dev/null; \
	done; echo "fanalyzer: CLEAN"

# Coverage-guided fuzzing (clang libFuzzer + ASan/UBSan). FUZZ_SECONDS bounds
# each harness so `make fuzz` is a CI smoke test; raise it (and point a corpus
# dir as an argument) for a real campaign. fuzz-pdu drives the stateless MKPDU
# decoder; fuzz-receive drives the stateful participant receive path.
FUZZ_CC      ?= clang
FUZZ_SECONDS ?= 30
FUZZ_FLAGS   := -fsanitize=fuzzer,address,undefined \
                -fno-sanitize-recover=undefined -O1 -g
fuzz: fuzz-pdu fuzz-receive

fuzz-pdu:
	$(FUZZ_CC) $(CFLAGS) $(FUZZ_FLAGS) test/fuzz_pdu.c $(SRC) \
	    -o test/fuzz_pdu $(LDFLAGS) $(LDLIBS)
	./test/fuzz_pdu -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1

fuzz-receive:
	$(FUZZ_CC) $(CFLAGS) $(FUZZ_FLAGS) test/fuzz_receive.c $(SRC) \
	    -o test/fuzz_receive $(LDFLAGS) $(LDLIBS)
	./test/fuzz_receive -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1

# Verify the library compiles under every optional-feature configuration.
FEATURE_OFF := -DWOLFMKA_NO_EAP -DWOLFMKA_NO_XPN -DWOLFMKA_NO_DELAY_PROTECT \
               -DWOLFMKA_NO_RETRY -DWOLFMKA_NO_ANNOUNCEMENTS \
               -DWOLFMKA_NO_AUTO_REKEY
features:
	@set -e; for cfg in "" "-DWOLFMKA_NO_EAP" "-DWOLFMKA_NO_XPN" \
	    "-DWOLFMKA_NO_DELAY_PROTECT" "-DWOLFMKA_NO_RETRY" \
	    "-DWOLFMKA_NO_ANNOUNCEMENTS" "-DWOLFMKA_NO_AUTO_REKEY" \
	    "-DWOLFMKA_DISTRIBUTED_CAK" "-DWOLFMKA_KMD" "-DWOLFMKA_SUSPENSION" \
	    "-DWOLFMKA_CIPHER_NEGOTIATION" "-DWOLFMKA_AUTOMOTIVE_PROFILE" \
	    "-DWOLFMKA_ICV_L2_ADDR" \"-DWOLFMKA_AUTOSAR" "$(FEATURE_OFF)" \
	    "$(FEATURE_OFF) -DWOLFMKA_SMALL_STACK -DWOLFMKA_NO_MALLOC"; do \
	    printf '  [features]%s\n' " $${cfg:-default}"; \
	    for f in $(SRC); do $(CC) $(CFLAGS) $$cfg -c $$f -o /tmp/wmka.o; done; \
	done; rm -f /tmp/wmka.o; echo "all feature configurations compile"

# Verify every wolfMKA source compiles as C++ (g++ treats .c as C++ source), so
# the library can be built into a C++ project; the public headers' extern "C"
# guards keep the API link-compatible.
CXX      ?= g++
CXX_STD  ?= -std=c++11
CXX_SRC  := $(SRC) src/autosar/Mka.c $(wildcard test/*.c) \
            $(wildcard examples/*.c)
cxx:
	@set -e; for f in $(CXX_SRC); do \
	    $(CXX) $(CXX_STD) -Wall -Wextra -Iinclude -Itest \
	        -I$(WOLFSSL_DIR)/include -fsyntax-only $$f; \
	done; echo "all sources compile as C++ ($(CXX) $(CXX_STD))"

misra:
	@command -v $(CPPCHECK) >/dev/null 2>&1 || { \
	    echo "misra: '$(CPPCHECK)' not found on PATH; install cppcheck" \
	         "$(CPPCHECK_VERSION) or pass CPPCHECK=<path>"; exit 1; }
	@$(CPPCHECK) --version | grep -qF "$(CPPCHECK_VERSION)" || \
	    echo "misra: warning: cppcheck is not the pinned" \
	         "$(CPPCHECK_VERSION) (.cppcheck-version); findings may differ"
	@rc=0; for cfg in "$(MISRA_DEFS)" \
	    "$(MISRA_DEFS) -DWOLFMKA_DISTRIBUTED_CAK -DWOLFMKA_KMD -DWOLFMKA_SUSPENSION -DWOLFMKA_CIPHER_NEGOTIATION" \
	    "$(MISRA_DEFS) -DWOLFMKA_AUTOMOTIVE_PROFILE" \
	    "$(MISRA_BASE) -DWOLFMKA_BIG_ENDIAN" \
	    "$(FEATURE_OFF) -DWOLFMKA_SMALL_STACK -DWOLFMKA_NO_MALLOC -DWOLFMKA_LITTLE_ENDIAN --max-configs=1"; \
	  do \
	    out=$$($(CPPCHECK) --addon=misra --std=c99 --enable=style --quiet \
	        --suppressions-list=misra-suppressions.txt \
	        $$cfg -Iinclude -I$(WOLFSSL_DIR)/include $(SRC) 2>&1 \
	        | grep -E "^src/|^include/wolfmka/" || true); \
	    if [ -n "$$out" ]; then \
	        echo "[misra]$$cfg"; echo "$$out"; rc=1; fi; \
	  done; \
	if [ $$rc -ne 0 ]; then \
	    echo "MISRA: undocumented findings (see MISRA.md)"; exit 1; \
	else echo "MISRA: CLEAN in all checked configs (documented deviations only)"; \
	fi

# Generate HTML API documentation from the Doxygen-commented sources into doc/.
# Treats Doxygen warnings (undocumented params, etc.) as failures.
docs:
	@warn=$$($(DOXYGEN) Doxyfile 2>&1 >/dev/null); \
	if [ -n "$$warn" ]; then echo "$$warn"; echo "Doxygen: warnings"; exit 1; \
	else echo "Doxygen: HTML written to doc/html/index.html"; fi

# Structural coverage of the core sources. Builds the suite instrumented for
# gcov + MC/DC at -O0 (so every error path is reachable and branch/condition
# data is not perturbed by optimisation), runs it, and FAILS unless every core
# source reaches 100% line, decision (branch) and MC/DC (condition) coverage.
# Decision coverage is gcov's "Taken at least once" (both outcomes of every
# branch); MC/DC is the masking variant from GCC's -fcondition-coverage,
# reported by `gcov --conditions` as "Condition outcomes covered".
COVDIR := build/coverage
COV_FILES := src/mka_crypto.c src/mka_kay.c src/mka_pdu.c
COV_BASE := -DWOLFMKA_FAULT_INJECT -DWOLFMKA_DISTRIBUTED_CAK -DWOLFMKA_KMD \
            -DWOLFMKA_SUSPENSION

# Parameterised worker: COV_CFG = -D config flags, COV_LABEL = display name.
# Invoked per configuration through recursive make (below) so each delivered
# build is measured and enforced on its own.
COV_CFG ?= $(COV_BASE)
COV_LABEL ?= cert-base
cov-impl:
	@rm -rf $(COVDIR); mkdir -p $(COVDIR)
	@for f in $(SRC) $(TEST_SRC); do \
	    $(CC) $(CFLAGS) -O0 --coverage -fcondition-coverage $(COV_CFG) \
	        -c $$f -o $(COVDIR)/$$(basename $$f .c).o || exit 1; \
	done
	@$(CC) --coverage $(COVDIR)/*.o -o $(COVDIR)/runcov $(LDFLAGS) $(LDLIBS)
	@$(COVDIR)/runcov >/dev/null
	@echo "== coverage [$(COV_LABEL)]: line + decision + MC/DC =="
	@rc=0; M='(Lines executed|Taken at least once|Condition outcomes covered):';\
	for f in $(COV_FILES); do \
	    m=$$($(GCOV) --conditions -b -o $(COVDIR) $$f 2>/dev/null); \
	    line=$$(printf '%s\n' "$$m" | awk -v M="$$M" \
	        '$$0 ~ M {printf "%s  ", $$0} END{print ""}'); \
	    bad=$$(printf '%s\n' "$$m" | awk -v M="$$M" \
	        '$$0 ~ M && $$0 !~ /:100\.00%/ {n++} END{print n+0}'); \
	    printf '  %-18s %s\n' "$$f" "$$line"; \
	    if [ "$$bad" -ne 0 ]; then rc=1; fi; \
	done; \
	rm -f *.gcov; \
	if [ $$rc -ne 0 ]; then echo "coverage [$(COV_LABEL)]: FAILED (< 100%)"; \
	    exit 1; fi; \
	echo "coverage [$(COV_LABEL)]: PASS (100% line + decision + MC/DC)"

# Default coverage gate: the certification-base configuration.
coverage:
	@$(MAKE) --no-print-directory cov-impl COV_CFG="$(COV_BASE)" \
	    COV_LABEL=cert-base

# Per-configuration structural coverage: enforce 100% line + decision + MC/DC
# for every delivered configuration. Every WOLFMKA_NO_* feature-off build
# compiles and runs its suite to PASS under its own flag (feature-specific tests
# are #ifndef-gated), and all ten configurations below reach - and are forced
# to - 100% line + decision + MC/DC. Three feature-off branches were once short
# of 100%; all are now resolved (NO_XPN excluded as genuinely dead code with
# #ifndef; NO_EAP and NO_AUTO_REKEY are reachable paths covered by added tests,
# not dead code). The dead-vs-reachable analysis is recorded in
# MCDC-AND-COVERAGE.md.
coverage-configs:
	@$(MAKE) --no-print-directory cov-impl COV_CFG="$(COV_BASE)" \
	    COV_LABEL=cert-base
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="$(COV_BASE) -DWOLFMKA_CIPHER_NEGOTIATION" COV_LABEL=negotiation
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="-DWOLFMKA_FAULT_INJECT -DWOLFMKA_AUTOMOTIVE_PROFILE" \
	    COV_LABEL=automotive-profile
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="$(COV_BASE) -DWOLFMKA_SMALL_STACK -DWOLFMKA_NO_MALLOC" \
	    COV_LABEL=small-stack-no-malloc
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="-DWOLFMKA_FAULT_INJECT -DWOLFMKA_NO_ANNOUNCEMENTS" \
	    COV_LABEL=no-announcements
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="-DWOLFMKA_FAULT_INJECT -DWOLFMKA_NO_RETRY" \
	    COV_LABEL=no-retry
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="-DWOLFMKA_FAULT_INJECT -DWOLFMKA_NO_DELAY_PROTECT" \
	    COV_LABEL=no-delay-protect
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="-DWOLFMKA_FAULT_INJECT -DWOLFMKA_NO_XPN" \
	    COV_LABEL=no-xpn
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="-DWOLFMKA_FAULT_INJECT -DWOLFMKA_NO_EAP" \
	    COV_LABEL=no-eap
	@$(MAKE) --no-print-directory cov-impl \
	    COV_CFG="-DWOLFMKA_FAULT_INJECT -DWOLFMKA_NO_AUTO_REKEY" \
	    COV_LABEL=no-auto-rekey

# Warn (don't fail) when the local clang-format differs from the pinned version
# in .clang-format-version, since formatting output is version-sensitive.
define CHECK_CLANG_FORMAT
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || { \
	    echo "$@: '$(CLANG_FORMAT)' not found on PATH;"; \
	    echo "    install clang-format or pass CLANG_FORMAT=<path>"; exit 1; }
	@$(CLANG_FORMAT) --version | grep -qF "$(CLANG_FORMAT_VERSION)" || \
	    echo "$@: warning: clang-format is not the pinned" \
	         "$(CLANG_FORMAT_VERSION) (.clang-format-version); output may differ"
endef

# Reformat all wolfMKA C sources/headers in place to the .clang-format style.
format:
	$(CHECK_CLANG_FORMAT)
	$(CLANG_FORMAT) -i $(FORMAT_FILES)
	@echo "format: reformatted $(words $(FORMAT_FILES)) files"

# CI guard: fail (without editing) if any file is not already formatted.
format-check:
	$(CHECK_CLANG_FORMAT)
	@$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_FILES) \
	    && echo "format-check: all $(words $(FORMAT_FILES)) files clean"

clean:
	rm -f $(OBJ) $(DEP) $(LIB) $(TEST_BIN) $(EXAMPLE_BIN) examples/mka_group_cak examples/mka_autosar \
	      test/runalloc test/runfault test/rundistcak test/runkmd test/runsusp \
	      test/runnego test/runauto test/runautosar \
	      test/runsanitize test/fuzz_pdu test/fuzz_receive \
	      test/runendian test/test_endian_be \
	      src/autosar/Mka.o
	rm -rf doc build *.gcov
