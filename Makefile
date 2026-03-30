# de-voidlink — VoidLink Adversary Simulation Framework
# Build system for Zig core + C arsenal + Go C2
#
# Usage:
#   make                     Build all (benign mode)
#   make OPERATIONAL=1       Build all (operational mode — real payloads)

SHELL := /bin/bash
.DEFAULT_GOAL := all

# Operational mode: pass OPERATIONAL=1 to enable real payloads
OPERATIONAL ?= 0

# Tool paths
ZIG := $(shell which zig)
GO := $(shell which go)
GCC := $(shell which gcc)

# Output
BUILD_DIR := build
CORE_BIN := $(BUILD_DIR)/phantom-beacon
C2_BIN := $(BUILD_DIR)/c2server
ARSENAL_DIR := $(BUILD_DIR)/arsenal
PAYLOADS_DIR := payloads

.PHONY: all core core-operational arsenal c2 detection payloads clean test check-tools info

all: check-tools core arsenal c2 payloads
ifeq ($(OPERATIONAL),1)
	@echo "=== de-voidlink build complete (OPERATIONAL MODE) ==="
else
	@echo "=== de-voidlink build complete (benign mode) ==="
endif
	@echo "  Beacon:  $(CORE_BIN)"
	@echo "  C2:      $(C2_BIN)"
	@echo "  Arsenal: $(ARSENAL_DIR)/*.o"
check-tools:
	@command -v $(ZIG) >/dev/null 2>&1 || { echo "ERROR: zig not found at $(ZIG)"; exit 1; }
	@command -v $(GO) >/dev/null 2>&1 || { echo "ERROR: go not found"; exit 1; }
	@command -v $(GCC) >/dev/null 2>&1 || { echo "ERROR: gcc not found"; exit 1; }

# --- Zig Core (implant simulator) ---
core:
	@mkdir -p $(BUILD_DIR)
ifeq ($(OPERATIONAL),1)
	cd core && $(ZIG) build -Doptimize=ReleaseSafe -Doperational=true
else
	cd core && $(ZIG) build -Doptimize=ReleaseSafe
endif
	cp core/zig-out/bin/phantom-beacon $(CORE_BIN)
	@echo "[+] Built phantom-beacon$(if $(filter 1,$(OPERATIONAL)), (OPERATIONAL),)"

core-debug:
	@mkdir -p $(BUILD_DIR)
	cd core && $(ZIG) build
	cp core/zig-out/bin/phantom-beacon $(CORE_BIN)
	@echo "[+] Built phantom-beacon (debug)"

# --- C Arsenal (plugin specimens as ELF .o files) ---
arsenal:
	@mkdir -p $(ARSENAL_DIR)
	$(MAKE) -C arsenal BUILD_DIR=$(abspath $(ARSENAL_DIR)) OPERATIONAL=$(OPERATIONAL)
	@echo "[+] Built arsenal plugins$(if $(filter 1,$(OPERATIONAL)), (OPERATIONAL),)"

# --- Payloads (pre-built beacon binaries for operational C2 serving) ---
# stage1.bin and implant.bin are both the compiled phantom-beacon.
# The C2 server (payload_operational.go) reads these when built with OPERATIONAL=1.
payloads: core
	@mkdir -p $(PAYLOADS_DIR)
	cp $(CORE_BIN) $(PAYLOADS_DIR)/stage1.bin
	cp $(CORE_BIN) $(PAYLOADS_DIR)/implant.bin
	@echo "[+] Populated payloads/ with phantom-beacon$(if $(filter 1,$(OPERATIONAL)), (OPERATIONAL),)"

# --- Go C2 (mock command & control server) ---
c2:
	@mkdir -p $(BUILD_DIR)
ifeq ($(OPERATIONAL),1)
	cd c2 && $(GO) build -tags operational -o ../$(C2_BIN) ./cmd/c2server
else
	cd c2 && $(GO) build -o ../$(C2_BIN) ./cmd/c2server
endif
	@echo "[+] Built c2server$(if $(filter 1,$(OPERATIONAL)),  (OPERATIONAL),)"

# --- Detection rules (validate syntax) ---
detection: detection-yara detection-sigma

detection-yara:
	@command -v yara >/dev/null 2>&1 || { echo "SKIP: yara not installed"; exit 0; }
	@for rule in detection/yara/*.yar; do \
		yara --fail-on-warnings -w $$rule /dev/null 2>/dev/null && echo "[OK] $$rule" || echo "[FAIL] $$rule"; \
	done

detection-sigma:
	@echo "[*] Sigma rules in detection/sigma/ — validate with sigma-cli or sigmac"
	@ls -1 detection/sigma/*.yml 2>/dev/null | while read f; do echo "  $$f"; done

# --- Testing ---
test: all
	@echo "=== Running integration tests ==="
	@PHANTOM_LINK_SAFETY=1 ./test/run_tests.sh

test-core:
	cd core && $(ZIG) build test

# --- Cleanup ---
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(PAYLOADS_DIR)/stage1.bin $(PAYLOADS_DIR)/implant.bin
	cd core && rm -rf zig-out .zig-cache
	$(MAKE) -C arsenal clean BUILD_DIR=$(abspath $(ARSENAL_DIR))
	@echo "[+] Cleaned"

# --- Info ---
info:
	@echo "de-voidlink — VoidLink Adversary Simulation Framework"
	@echo ""
	@echo "Components:"
	@echo "  core/     — Zig implant simulator (beacon, syscalls, evasion, rootkit sim)"
	@echo "  arsenal/  — C plugin specimens (ELF .o relocatable objects)"
	@echo "  c2/       — Go mock C2 server (VoidStream protocol, HTTP camouflage)"
	@echo "  detection/ — YARA, Sigma, Aegis rules for defensive tool testing"
	@echo ""
	@echo "Usage:"
	@echo "  make              Build all components"
	@echo "  make core         Build Zig beacon only"
	@echo "  make c2           Build Go C2 server only"
	@echo "  make arsenal      Build C plugin specimens only"
	@echo "  make test         Run integration tests"
	@echo "  make clean        Remove build artifacts"
