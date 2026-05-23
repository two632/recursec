# RecurSec — Multi-language build system
# Builds Go, Rust, and C components alongside the Python core.

.PHONY: all clean go rust c python test lint help install

SHELL := /bin/bash
BUILD_DIR := build/bin
GO_DIR := go
RUST_DIR := rust
C_DIR := c

# Detect available compilers
GO := $(shell command -v go 2>/dev/null)
CARGO := $(shell command -v cargo 2>/dev/null)
CC := $(shell command -v gcc 2>/dev/null || command -v cc 2>/dev/null)
PYTHON := $(shell command -v python3 2>/dev/null || command -v python 2>/dev/null)

# ── Default target ──────────────────────────────────────
all: dirs go rust c python
	@echo ""
	@echo "╔════════════════════════════════════════════╗"
	@echo "║       RecurSec build complete              ║"
	@echo "╚════════════════════════════════════════════╝"
	@echo ""
	@ls -la $(BUILD_DIR)/

# ── Create build directories ───────────────────────────
dirs:
	@mkdir -p $(BUILD_DIR)

# ── Go targets ─────────────────────────────────────────
go: dirs
ifdef GO
	@echo "Building Go tools..."
	@cd $(GO_DIR)/scanner && $(GO) build -o ../../$(BUILD_DIR)/go-scanner .
	@echo "  ✓ go-scanner"
	@cd $(GO_DIR)/crawler && $(GO) build -o ../../$(BUILD_DIR)/go-crawler .
	@echo "  ✓ go-crawler"
	@cd $(GO_DIR)/dns && $(GO) build -o ../../$(BUILD_DIR)/go-dns .
	@echo "  ✓ go-dns"
else
	@echo "SKIP: Go compiler not found — skipping Go tools"
endif

go-scanner: dirs
ifdef GO
	cd $(GO_DIR)/scanner && $(GO) build -o ../../$(BUILD_DIR)/go-scanner .
endif

go-crawler: dirs
ifdef GO
	cd $(GO_DIR)/crawler && $(GO) build -o ../../$(BUILD_DIR)/go-crawler .
endif

go-dns: dirs
ifdef GO
	cd $(GO_DIR)/dns && $(GO) build -o ../../$(BUILD_DIR)/go-dns .
endif

# ── Rust targets ───────────────────────────────────────
rust: dirs
ifdef CARGO
	@echo "Building Rust tools..."
	@cd $(RUST_DIR)/fuzzer && $(CARGO) build --release 2>/dev/null && \
		cp target/release/fuzzer ../../$(BUILD_DIR)/rust-fuzzer && \
		echo "  ✓ rust-fuzzer" || echo "  ✗ rust-fuzzer (build failed)"
	@cd $(RUST_DIR)/hasher && $(CARGO) build --release 2>/dev/null && \
		cp target/release/hasher ../../$(BUILD_DIR)/rust-hasher && \
		echo "  ✓ rust-hasher" || echo "  ✗ rust-hasher (build failed)"
else
	@echo "SKIP: Cargo not found — skipping Rust tools"
endif

rust-fuzzer: dirs
ifdef CARGO
	cd $(RUST_DIR)/fuzzer && $(CARGO) build --release
	cp $(RUST_DIR)/fuzzer/target/release/fuzzer $(BUILD_DIR)/rust-fuzzer
endif

rust-hasher: dirs
ifdef CARGO
	cd $(RUST_DIR)/hasher && $(CARGO) build --release
	cp $(RUST_DIR)/hasher/target/release/hasher $(BUILD_DIR)/rust-hasher
endif

# ── C targets ──────────────────────────────────────────
c: dirs
ifdef CC
	@echo "Building C tools..."
	@$(CC) -O2 -Wall -o $(BUILD_DIR)/c-probe $(C_DIR)/probe/probe.c 2>/dev/null && \
		echo "  ✓ c-probe" || echo "  ✗ c-probe (build failed)"
else
	@echo "SKIP: C compiler not found — skipping C tools"
endif

c-probe: dirs
ifdef CC
	$(CC) -O2 -Wall -o $(BUILD_DIR)/c-probe $(C_DIR)/probe/probe.c
endif

# ── Python targets ─────────────────────────────────────
python: dirs
ifdef PYTHON
	@echo "Building Python package..."
	@$(PYTHON) -m pip install -e . --quiet 2>/dev/null && echo "  ✓ recursec (editable install)" || echo "  ✗ Python install failed"
else
	@echo "SKIP: Python not found"
endif

# ── Install dependencies ───────────────────────────────
install:
	@echo "Installing Python dependencies..."
	pip install -e ".[dev]" 2>/dev/null || pip install -e .
ifdef GO
	@echo "Downloading Go dependencies..."
	cd $(GO_DIR)/scanner && $(GO) mod tidy 2>/dev/null || true
	cd $(GO_DIR)/crawler && $(GO) mod tidy 2>/dev/null || true
	cd $(GO_DIR)/dns && $(GO) mod tidy 2>/dev/null || true
endif

# ── Test ───────────────────────────────────────────────
test:
	@echo "Running Python tests..."
	$(PYTHON) -m pytest tests/ -v --tb=short 2>/dev/null || echo "Tests failed or pytest not installed"

# ── Lint ───────────────────────────────────────────────
lint:
	@echo "Linting Python code..."
	$(PYTHON) -m ruff check recursec/ --fix 2>/dev/null || echo "Ruff not installed"

# ── Clean ──────────────────────────────────────────────
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(RUST_DIR)/fuzzer/target
	rm -rf $(RUST_DIR)/hasher/target
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete."

# ── Help ───────────────────────────────────────────────
help:
	@echo "RecurSec Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all            Build everything (default)"
	@echo "  go             Build Go tools (scanner, crawler, dns)"
	@echo "  rust           Build Rust tools (fuzzer, hasher)"
	@echo "  c              Build C tools (probe)"
	@echo "  python         Install Python package"
	@echo "  install        Install all dependencies"
	@echo "  test           Run Python test suite"
	@echo "  lint           Lint Python code"
	@echo "  clean          Remove build artifacts"
	@echo ""
	@echo "Individual targets:"
	@echo "  go-scanner     Build Go port scanner"
	@echo "  go-crawler     Build Go web crawler"
	@echo "  go-dns         Build Go DNS enumerator"
	@echo "  rust-fuzzer    Build Rust HTTP fuzzer"
	@echo "  rust-hasher    Build Rust hash tool"
	@echo "  c-probe        Build C network probe"
