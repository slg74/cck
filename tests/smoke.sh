#!/usr/bin/env bash
# tests/smoke.sh — end-to-end smoke tests for cck
#
# Usage:
#   bash tests/smoke.sh ./cck
#
# Exit code: 0 if all pass, 1 if any fail.

set -euo pipefail

CCK="${1:-./cck}"

if [[ ! -x "$CCK" ]]; then
    echo "error: binary not found or not executable: $CCK" >&2
    exit 2
fi

# ── helpers ──────────────────────────────────────────────────────────

PASS=0
FAIL=0
TMPDIR_TESTS="$(mktemp -d /tmp/cck_smoke_XXXXXX)"

cleanup() { rm -rf "$TMPDIR_TESTS"; }
trap cleanup EXIT

VALID="$TMPDIR_TESTS/valid.pem"
EXPIRED="$TMPDIR_TESTS/expired.pem"
VALID2="$TMPDIR_TESTS/valid2.pem"
CHAIN="$TMPDIR_TESTS/chain.pem"
NOTPEM="$TMPDIR_TESTS/not_a_cert.txt"

# Create test certificates
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TMPDIR_TESTS/valid.key" -out "$VALID" \
    -days 3650 -nodes -subj "/CN=valid-smoke-test" 2>/dev/null

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TMPDIR_TESTS/valid2.key" -out "$VALID2" \
    -days 3650 -nodes -subj "/CN=valid-smoke-test-2" 2>/dev/null

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TMPDIR_TESTS/expired.key" -out "$EXPIRED" \
    -nodes -subj "/CN=expired-smoke-test" \
    -not_before 20200101000000Z -not_after 20210101000000Z 2>/dev/null

# PEM chain: valid + expired concatenated
cat "$VALID" "$EXPIRED" > "$CHAIN"

printf 'this is not a certificate\n' > "$NOTPEM"

# ── test framework ────────────────────────────────────────────────────

# check_exit DESC EXPECTED_EXIT CMD [ARGS...]
check_exit() {
    local desc="$1" expected="$2"
    shift 2
    local actual=0
    "$@" >/dev/null 2>&1 || actual=$?
    if [[ "$actual" -eq "$expected" ]]; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s  (expected exit %d, got %d)\n" "$desc" "$expected" "$actual"
        FAIL=$((FAIL + 1))
    fi
}

# check_stdout DESC PATTERN CMD [ARGS...]  — pattern must appear in combined output
check_output() {
    local desc="$1" pattern="$2"
    shift 2
    local output
    output=$("$@" 2>&1 || true)
    if echo "$output" | grep -qE "$pattern"; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s  (pattern '%s' not found)\n" "$desc" "$pattern"
        printf "         output: %s\n" "$output"
        FAIL=$((FAIL + 1))
    fi
}

# check_no_output DESC PATTERN CMD [ARGS...]  — pattern must NOT appear
check_no_output() {
    local desc="$1" pattern="$2"
    shift 2
    local output
    output=$("$@" 2>&1 || true)
    if echo "$output" | grep -qE "$pattern"; then
        printf "  FAIL  %s  (pattern '%s' unexpectedly found)\n" "$desc" "$pattern"
        printf "         output: %s\n" "$output"
        FAIL=$((FAIL + 1))
    else
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    fi
}

# ── tests ─────────────────────────────────────────────────────────────

echo ""
echo "── Exit codes ───────────────────────────────────────────────────"

check_exit "valid cert → exit 0"              0 "$CCK" "$VALID"
check_exit "expired cert → exit 1"            1 "$CCK" "$EXPIRED"
check_exit "warn threshold hit → exit 1"      1 "$CCK" -w 9999 "$VALID"
check_exit "missing file → exit 2"            2 "$CCK" /nonexistent/cert.pem
check_exit "non-PEM file → exit 2"            2 "$CCK" "$NOTPEM"
check_exit "multiple valid files → exit 0"    0 "$CCK" "$VALID" "$VALID2"
check_exit "mixed valid+expired → exit 1"     1 "$CCK" "$VALID" "$EXPIRED"
check_exit "no args → exit 0 (usage)"         0 "$CCK"
check_exit "--help → exit 0"                  0 "$CCK" --help

echo ""
echo "── Output content ───────────────────────────────────────────────"

check_output  "valid cert prints OK"            "^OK"          "$CCK" --no-color "$VALID"
check_output  "expired cert prints EXPIRED"     "^EXPIRED"     "$CCK" --no-color "$EXPIRED"
check_output  "warn threshold prints WARN"      "^WARN"        "$CCK" --no-color -w 9999 "$VALID"
check_output  "output includes expiry date"     "[0-9]{4}-[0-9]{2}-[0-9]{2}" "$CCK" --no-color "$VALID"
check_output  "output includes days count"      "in [0-9]+ day" "$CCK" --no-color "$VALID"
check_output  "expired output includes days ago" "[0-9]+ day.*ago" "$CCK" --no-color "$EXPIRED"
check_output  "output includes file path"       "valid.pem"    "$CCK" --no-color "$VALID"

echo ""
echo "── Quiet mode (-q) ──────────────────────────────────────────────"

check_no_output "quiet+valid → no output"       "."          "$CCK" -q "$VALID"
check_exit      "quiet+valid → exit 0"          0            "$CCK" -q "$VALID"
check_output    "quiet+expired → still prints"  "EXPIRED"    "$CCK" -q "$EXPIRED"
check_exit      "quiet+expired → exit 1"        1            "$CCK" -q "$EXPIRED"

echo ""
echo "── --no-color flag ──────────────────────────────────────────────"

check_no_output "no-color output has no ANSI codes" $'\033\[' "$CCK" --no-color "$VALID"
check_no_output "no-color output has no ANSI codes (expired)" $'\033\[' "$CCK" --no-color "$EXPIRED"

echo ""
echo "── Certificate chain (multi-cert PEM) ───────────────────────────"

# chain = valid + expired → worst status wins → exit 1
check_exit   "chain with expired → exit 1"       1 "$CCK" "$CHAIN"
check_output "chain reports EXPIRED"     "EXPIRED" "$CCK" --no-color "$CHAIN"
check_output "chain reports OK for good cert" "OK" "$CCK" --no-color "$CHAIN"

echo ""
echo "── Verbose mode (-v) ────────────────────────────────────────────"

check_output "verbose expired shows valid-from date" "[0-9]{4}-[0-9]{2}-[0-9]{2}" "$CCK" -v --no-color "$EXPIRED"

echo ""
echo "── Network (skipped if offline) ─────────────────────────────────"

if curl -s --connect-timeout 3 https://example.com >/dev/null 2>&1; then
    check_exit   "live check example.com → exit 0"       0 "$CCK" -H example.com
    check_output "live check prints OK"        "^OK"       "$CCK" --no-color -H example.com
    check_output "live check prints hostname"  "example.com" "$CCK" --no-color -H example.com
    check_output "live check verbose shows CN" "example.com" "$CCK" -v --no-color -H example.com
else
    echo "  SKIP  network tests (no connectivity)"
fi

# ── summary ───────────────────────────────────────────────────────────

echo ""
echo "────────────────────────────────────────────────────────────────"
TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    printf "  All %d tests passed.\n" "$TOTAL"
    exit 0
else
    printf "  %d/%d tests passed, %d FAILED.\n" "$PASS" "$TOTAL" "$FAIL"
    exit 1
fi
