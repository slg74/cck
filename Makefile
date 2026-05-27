# cck — SSL/TLS Certificate Checker
# Requires OpenSSL (brew install openssl on macOS)

CC       ?= cc
TARGET   := cck
UNIT_BIN := tests/unit_test

# ── OpenSSL (Homebrew on macOS, system pkg-config on Linux) ─────────
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
  # Homebrew prefers keg-only; look for openssl@3 then openssl
  OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
  CFLAGS  += -I$(OPENSSL_PREFIX)/include
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib
else
  # Linux: use pkg-config
  CFLAGS  += $(shell pkg-config --cflags openssl)
  LDFLAGS += $(shell pkg-config --libs   openssl)
endif

LDFLAGS += -lssl -lcrypto

# ── compiler flags ───────────────────────────────────────────────────
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic \
          -Wno-unused-parameter \
          -D_XOPEN_SOURCE=700

# Debug vs release
ifdef DEBUG
  CFLAGS += -g -O0 -DDEBUG
else
  CFLAGS += -O2 -DNDEBUG
endif

# ── rules ────────────────────────────────────────────────────────────
.PHONY: all clean install test test-unit test-smoke

all: $(TARGET)

$(TARGET): cck.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Unit test binary: includes cck.c wholesale, so same flags apply
$(UNIT_BIN): tests/unit_test.c cck.c
	$(CC) $(CFLAGS) -Wno-unused-function -o $@ tests/unit_test.c $(LDFLAGS)

clean:
	rm -f $(TARGET) $(UNIT_BIN)

# Install to /usr/local/bin (adjust PREFIX as needed)
PREFIX ?= /usr/local
install: $(TARGET)
	install -d $(PREFIX)/bin
	install -m 755 $(TARGET) $(PREFIX)/bin/$(TARGET)

# ── test targets ─────────────────────────────────────────────────────
# Run all tests
test: test-unit test-smoke

# C unit tests — drive evaluate_cert / check_file directly
test-unit: $(UNIT_BIN)
	@echo "Running unit tests..."
	@./$(UNIT_BIN)

# Shell smoke tests — drive the built binary end-to-end
test-smoke: $(TARGET)
	@echo "Running smoke tests..."
	@bash tests/smoke.sh ./$(TARGET)
