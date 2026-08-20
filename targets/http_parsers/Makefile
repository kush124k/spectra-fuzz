# Differential HTTP Parser Fuzzing Targets
#
# Builds two HTTP parser harnesses with AFL++ instrumentation and ASAN.
# Both parse the same raw input and produce structured output for
# differential comparison by spectra-fuzz.
#
# Prerequisites:
#   - AFL++ installed (afl-clang-fast available)
#   - llhttp library installed (apt install libllhttp-dev, or build from source)
#   - picohttpparser source (git clone https://github.com/h2o/picohttpparser)
#
# Usage:
#   make all               # Build both harnesses
#   make harness_llhttp    # Build llhttp harness only
#   make harness_pico      # Build picohttpparser harness only
#   make clean             # Remove binaries

CC         ?= afl-clang-fast
CFLAGS     := -g -O1 -Wall -Wextra
SANITIZERS := -fsanitize=address,undefined

# llhttp — adjust paths if installed elsewhere
LLHTTP_CFLAGS  ?= $(shell pkg-config --cflags libllhttp 2>/dev/null)
LLHTTP_LDFLAGS ?= $(shell pkg-config --libs   libllhttp 2>/dev/null || echo "-lllhttp")

# picohttpparser — expects source files in ./picohttpparser/
PICO_DIR       ?= ./picohttpparser
PICO_CFLAGS    := -I$(PICO_DIR)

.PHONY: all clean deps

all: harness_llhttp harness_picohttpparser

# ── llhttp harness ─────────────────────────────────────────────────
harness_llhttp: harness_llhttp.c
	$(CC) $(CFLAGS) $(SANITIZERS) $(LLHTTP_CFLAGS) -o $@ $< $(LLHTTP_LDFLAGS)
	@echo "✓ Built harness_llhttp"

# ── picohttpparser harness ────────────────────────────────────────
harness_picohttpparser: harness_picohttpparser.c $(PICO_DIR)/picohttpparser.c
	$(CC) $(CFLAGS) $(SANITIZERS) $(PICO_CFLAGS) -o $@ $^
	@echo "✓ Built harness_picohttpparser"

# ── Dependencies ──────────────────────────────────────────────────
deps:
	@echo "Fetching picohttpparser..."
	git clone --depth 1 https://github.com/h2o/picohttpparser.git $(PICO_DIR) 2>/dev/null || true
	@echo "llhttp: install via 'apt install libllhttp-dev' or build from https://github.com/nicholasbradford/llhttp"
	@echo "✓ Dependencies ready"

clean:
	rm -f harness_llhttp harness_picohttpparser
	@echo "✓ Clean"
