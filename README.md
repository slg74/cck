# cck — SSL/TLS Certificate Checker

A fast, zero-dependency C utility that checks X.509 certificates for expiration and alerts you with the certificate's location and status.

## Features

- ✅ **File check** — inspect PEM files (including chains with multiple certs)
- 🌐 **Live check** — connect to a host and check its TLS certificate in real-time
- 🔴 **Expired** — prints location and how many days ago it expired
- 🟡 **Expiring soon** — warns if expiration is within a configurable threshold
- 🟢 **OK** — confirms the cert is valid with its expiry date
- Handles IPv6, custom ports, and SNI

## Requirements

- C11 compiler (clang or gcc)
- OpenSSL 1.1+ or 3.x

### macOS (Homebrew)
```sh
brew install openssl
```

### Linux
```sh
apt install libssl-dev   # Debian/Ubuntu
dnf install openssl-devel  # Fedora/RHEL
```

## Build

```sh
make
```

Optional debug build:
```sh
make DEBUG=1
```

Install to `/usr/local/bin`:
```sh
make install
```

## Testing

```sh
make test          # run both unit tests and smoke tests
make test-unit     # C unit tests only
make test-smoke    # shell smoke tests only
```

### Unit tests (`tests/unit_test.c`)

Drive the internal C functions (`evaluate_cert`, `check_file`) directly using
certs constructed in memory via the OpenSSL API — no shell-outs, no temp dirs
needed by the test framework itself. Covers:

| Suite | Cases |
|---|---|
| `evaluate_cert` — valid | 10-year cert → `CERT_OK` |
| `evaluate_cert` — expiring soon | cert within warn window → `CERT_WARN` |
| `evaluate_cert` — boundary | exact threshold / threshold+1 / warn=0 |
| `evaluate_cert` — expired | cert expired 1 year ago → `CERT_EXPIRED` |
| `evaluate_cert` — verbose | expired cert in `-v` mode doesn't crash |
| `evaluate_cert` — quiet | `-q` still returns correct status |
| `check_file` — valid PEM | single-cert file → `CERT_OK` |
| `check_file` — expired PEM | single-cert file → `CERT_EXPIRED` |
| `check_file` — chain (mixed) | valid + expired in one file → `CERT_EXPIRED` |
| `check_file` — chain (all OK) | two valid certs → `CERT_OK` |
| `check_file` — missing file | → `CERT_ERROR` |
| `check_file` — non-PEM file | → `CERT_ERROR` |

### Smoke tests (`tests/smoke.sh`)

End-to-end tests that invoke the compiled `cck` binary. Certs are generated
with `openssl req` at the start of each run and cleaned up on exit. Covers:

- **Exit codes** — valid/expired/warn/missing/non-PEM/mixed/no-args/`--help`
- **Output content** — OK/EXPIRED/WARN labels, date format, days count, file path in output
- **Quiet mode** (`-q`) — no stdout for valid certs, still prints on expired
- **`--no-color`** — no ANSI escape codes in output
- **PEM chains** — multi-cert files: worst status wins, all certs reported
- **Verbose** (`-v`) — expired cert shows valid-from date
- **Network** — live TLS check against `example.com` (auto-skipped when offline)

## Usage

```
cck [OPTIONS] <file.pem> [file2.pem ...]   check certificate files
cck [OPTIONS] -H <host[:port]> [...]       check live TLS certs

Options:
  -H <host[:port]>   connect to host and check its TLS certificate
                     (port defaults to 443)
  -w <days>          warn if expiring within N days (default: 30)
  -q                 quiet mode — only show problems
  -v                 verbose — show extra cert details
  --no-color         disable ANSI colour output
  --help             show this help

Exit codes:
  0  all certificates valid
  1  one or more certificates expired or expiring soon
  2  error (file not found, parse failure, connection error)
```

## Examples

```sh
# Check a local certificate file
cck /etc/ssl/certs/my.pem

# Check multiple files
cck /etc/nginx/ssl/*.pem

# Check a live TLS certificate
cck -H example.com

# Check a non-standard port
cck -H example.com:8443

# Warn if cert expires within 14 days
cck -H example.com -w 14

# Quiet mode — only print problems (useful in cron jobs)
cck -q /etc/ssl/certs/*.pem

# Verbose output
cck -v -H example.com

# Use in a script
if ! cck -q /path/to/cert.pem; then
    echo "Certificate problem detected!" | mail -s "CERT ALERT" admin@example.com
fi
```

## Sample Output

```
OK      /etc/ssl/my.pem
         expires 2026-11-15 (in 172 days)

WARN    /etc/ssl/old.pem
         expires 2025-06-10 (in 14 days)

EXPIRED /etc/ssl/ancient.pem
         expired 2024-01-01 (365 days ago)
```

## Cron Integration

Check certs nightly and alert on problems:

```cron
0 6 * * * /usr/local/bin/cck -q /etc/ssl/certs/*.pem || mail -s "CERT EXPIRED" admin@example.com
```
