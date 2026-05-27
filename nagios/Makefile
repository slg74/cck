# nagios/Makefile — builds the check_cck_ssl Nagios plugin

CC     ?= cc
TARGET := check_cck_ssl

# ── OpenSSL ──────────────────────────────────────────────────────────
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
  OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
  CFLAGS  += -I$(OPENSSL_PREFIX)/include
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib
else
  CFLAGS  += $(shell pkg-config --cflags openssl)
  LDFLAGS += $(shell pkg-config --libs   openssl)
endif
LDFLAGS += -lssl -lcrypto

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wno-unused-parameter \
          -D_XOPEN_SOURCE=700 -O2 -DNDEBUG

# ── Nagios plugin install path (override with make install PLUGINDIR=...) ──
PLUGINDIR ?= /usr/local/nagios/libexec

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): check_cck_ssl.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(PLUGINDIR)
	install -m 755 $(TARGET) $(PLUGINDIR)/$(TARGET)
	@echo "Installed to $(PLUGINDIR)/$(TARGET)"

test: $(TARGET)
	@bash tests/smoke.sh ./$(TARGET)
