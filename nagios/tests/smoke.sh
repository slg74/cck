#!/usr/bin/env bash
# nagios/tests/smoke.sh — smoke tests for check_cck_ssl
#
# Verifies exit codes and output format match the Nagios plugin interface.
# Usage: bash nagios/tests/smoke.sh ./check_cck_ssl

set -uo pipefail

PLUGIN="${1:-./check_cck_ssl}"

if [[ ! -x "$PLUGIN" ]]; then
    echo "error: plugin not found or not executable: $PLUGIN" >&2
    exit 2
fi

PASS=0; FAIL=0
TMPDIR_T="$(mktemp -d /tmp/cck_nagios_XXXXXX)"
cleanup() { rm -rf "$TMPDIR_T"; }
trap cleanup EXIT

VALID="$TMPDIR_T/valid.pem"
EXPIRED="$TMPDIR_T/expired.pem"
CHAIN="$TMPDIR_T/chain.pem"
NOTPEM="$TMPDIR_T/notpem.txt"

# Generate test certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TMPDIR_T/v.key" -out "$VALID" -days 3650 -nodes \
    -subj "/CN=valid-nagios-test" 2>/dev/null

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TMPDIR_T/e.key" -out "$EXPIRED" -nodes \
    -subj "/CN=expired-nagios-test" \
    -not_before 20200101000000Z -not_after 20210101000000Z 2>/dev/null

cat "$VALID" "$EXPIRED" > "$CHAIN"
printf 'not a cert\n' > "$NOTPEM"

# ── helpers ───────────────────────────────────────────────────────────

check_exit() {
    local desc="$1" expected="$2"; shift 2
    local actual=0; "$@" >/dev/null 2>&1 || actual=$?
    if [[ "$actual" -eq "$expected" ]]; then
        printf "  PASS  %s\n" "$desc"; PASS=$((PASS+1))
    else
        printf "  FAIL  %s  (expected exit %d, got %d)\n" "$desc" "$expected" "$actual"
        FAIL=$((FAIL+1))
    fi
}

check_output() {
    local desc="$1" pattern="$2"; shift 2
    local out; out=$("$@" 2>&1 || true)
    if echo "$out" | grep -qE "$pattern"; then
        printf "  PASS  %s\n" "$desc"; PASS=$((PASS+1))
    else
        printf "  FAIL  %s  (pattern '%s' not found)\n" "$desc" "$pattern"
        printf "         output: %s\n" "$out"
        FAIL=$((FAIL+1))
    fi
}

check_no_output() {
    local desc="$1" pattern="$2"; shift 2
    local out; out=$("$@" 2>&1 || true)
    if echo "$out" | grep -qE "$pattern"; then
        printf "  FAIL  %s  (pattern '%s' unexpectedly found)\n" "$desc" "$pattern"
        printf "         output: %s\n" "$out"
        FAIL=$((FAIL+1))
    else
        printf "  PASS  %s\n" "$desc"; PASS=$((PASS+1))
    fi
}

# ── tests ─────────────────────────────────────────────────────────────

echo ""
echo "── Exit codes ───────────────────────────────────────────────────"

check_exit "valid cert → exit 0 (OK)"       0 "$PLUGIN" -f "$VALID"
check_exit "expired cert → exit 2 (CRIT)"   2 "$PLUGIN" -f "$EXPIRED"
check_exit "warn threshold → exit 1 (WARN)" 1 "$PLUGIN" -f "$VALID" -w 9999 -c 5
check_exit "crit threshold → exit 2 (CRIT)" 2 "$PLUGIN" -f "$VALID" -w 9999 -c 9999
check_exit "missing file → exit 3 (UNKN)"   3 "$PLUGIN" -f /nonexistent/cert.pem
check_exit "non-PEM file → exit 3 (UNKN)"   3 "$PLUGIN" -f "$NOTPEM"
check_exit "no args → exit 3 (UNKN)"        3 "$PLUGIN"
check_exit "-h → exit 0"                    0 "$PLUGIN" -h

echo ""
echo "── Output format (Nagios single-line + perfdata) ────────────────"

check_output "valid: starts with 'SSL CERT OK'"      "^SSL CERT OK"      "$PLUGIN" -f "$VALID"
check_output "expired: starts with 'SSL CERT CRIT'"  "^SSL CERT CRITICAL" "$PLUGIN" -f "$EXPIRED"
check_output "warn: starts with 'SSL CERT WARN'"     "^SSL CERT WARNING"  "$PLUGIN" -f "$VALID" -w 9999 -c 5
check_output "output contains '|' separator"         " \| "               "$PLUGIN" -f "$VALID"
check_output "perfdata: days_remaining=<N>"          "days_remaining=[0-9]" "$PLUGIN" -f "$VALID"
check_output "perfdata: has warn;crit thresholds"    "days_remaining=[0-9]+;[0-9]+;[0-9]+" "$PLUGIN" -f "$VALID"
check_output "expired: output contains 'EXPIRED'"    "EXPIRED"            "$PLUGIN" -f "$EXPIRED"
check_output "expired: perfdata days_remaining negative" "days_remaining=-[0-9]+" "$PLUGIN" -f "$EXPIRED"
check_output "valid: output contains expiry date"    "[0-9]{4}-[0-9]{2}-[0-9]{2}" "$PLUGIN" -f "$VALID"
check_output "output includes file path"             "valid.pem"          "$PLUGIN" -f "$VALID"

echo ""
echo "── Threshold flags ──────────────────────────────────────────────"

# Custom -w and -c land in perfdata
OUT=$("$PLUGIN" -f "$VALID" -w 60 -c 30 2>/dev/null || true)
if echo "$OUT" | grep -qE "days_remaining=[0-9]+;60;30"; then
    printf "  PASS  custom -w/-c appear in perfdata\n"; PASS=$((PASS+1))
else
    printf "  FAIL  custom -w/-c not in perfdata\n  output: %s\n" "$OUT"; FAIL=$((FAIL+1))
fi

echo ""
echo "── Certificate chain ────────────────────────────────────────────"

# Chain of valid+expired → worst (CRITICAL) wins
check_exit   "chain: exit 2 when expired cert present" 2 "$PLUGIN" -f "$CHAIN"
check_output "chain: output says 'chain'"              "chain"     "$PLUGIN" -f "$CHAIN"
check_output "chain: CRITICAL status"                  "^SSL CERT CRITICAL" "$PLUGIN" -f "$CHAIN"

echo ""
echo "── Network (skipped if offline) ─────────────────────────────────"

if curl -s --connect-timeout 3 https://example.com >/dev/null 2>&1; then
    check_exit   "live check example.com → exit 0"      0 "$PLUGIN" -H example.com
    check_output "live check: SSL CERT OK"     "^SSL CERT OK"    "$PLUGIN" -H example.com
    check_output "live check: hostname in output" "example.com"  "$PLUGIN" -H example.com
    check_output "live check: has perfdata"    "days_remaining=" "$PLUGIN" -H example.com
    check_exit   "live check custom port -p 443 → exit 0" 0 "$PLUGIN" -H example.com -p 443
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
