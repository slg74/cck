# cck — SSL/TLS Certificate Checker

A fast C utility that checks X.509 certificates for expiration and alerts you with the location and status of each cert.

## Features

- ✅ **File check** — inspect PEM files, including chains with multiple certs
- 🌐 **Live check** — connect to a host and check its TLS certificate in real-time
- 🔴 **Expired** — prints location and how many days ago it expired
- 🟡 **Expiring soon** — warns if expiration is within a configurable threshold
- 🟢 **OK** — confirms the cert is valid with its expiry date
- Handles IPv6, custom ports, and SNI
- Connect timeout (`-t`) prevents hung pipelines on slow or unreachable hosts
- Integrates with **Nagios/Icinga** and **Datadog** — see [`nagios/`](nagios/) and [`datadog/`](datadog/)

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
  -t <secs>          TLS connect timeout in seconds (default: 10)
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

## Monitoring Integrations

### Nagios / Icinga ([`nagios/`](nagios/))

A compiled C plugin that follows the Nagios plugin interface exactly:

| Exit | State | Meaning |
|---|---|---|
| 0 | OK | Valid, not expiring soon |
| 1 | WARNING | Expires within `-w` days |
| 2 | CRITICAL | Expires within `-c` days, or already expired |
| 3 | UNKNOWN | Connection / parse error |

Output includes a single status line and `days_remaining` performance data for PNP4Nagios / Graphite:

```
SSL CERT OK - example.com:443 expires 2026-07-01 (in 35 days) | days_remaining=35;30;14;0;
SSL CERT CRITICAL - example.com:443 certificate EXPIRED on 2025-01-01 (147 days ago) | days_remaining=-147;30;14;0;
```

```sh
cd nagios && make && make install   # installs to /usr/local/nagios/libexec
make test                           # 27 smoke tests
```

See [nagios/README.md](nagios/README.md) for command/service object definitions and full usage.

---

### Datadog ([`datadog/`](datadog/))

A Python Datadog Agent check that reports:

| What | Detail |
|---|---|
| `cck.ssl.days_remaining` | Gauge — days until expiry (negative when expired) |
| `cck.ssl.cert` | Service check — OK / WARNING / CRITICAL / UNKNOWN |

Supports `host:port` live checks and local PEM files (including chains). Warning and critical thresholds are configurable globally in `init_config` or overridden per instance — useful when mixing long-lived and short-lived (e.g. Let's Encrypt) certs.

```sh
# Install
sudo cp datadog/checks.d/cck_ssl.py  /etc/datadog-agent/checks.d/
sudo cp -r datadog/conf.d/cck_ssl.d  /etc/datadog-agent/conf.d/
# edit /etc/datadog-agent/conf.d/cck_ssl.d/conf.yaml, then:
sudo systemctl restart datadog-agent

# Test (no Agent required)
python3 -m pytest datadog/tests/test_cck_ssl.py -v   # 27 unit tests
```

See [datadog/README.md](datadog/README.md) for full config reference and a Terraform monitor example.

## Security

### First-pass review (completed)

A security review of [cck.c](cck.c) was performed and the following issues were found and remediated:

| Severity | Finding | Resolution |
|---|---|---|
| 🔴 High | `BIO_new_ssl()` return value not checked — NULL dereference crash on OOM | Added NULL guard before `BIO_get_ssl`, `SSL_set_tlsext_host_name`, and `BIO_push` |
| 🔴 High | `ssl` pointer not validated after `BIO_get_ssl()` before SNI call | Explicit NULL check with early return added |
| 🟠 Med | No connect/handshake timeout — cck hangs forever on a slow or hostile peer | Added `SIGALRM` handler + `alarm(g_timeout)` wrapping both `BIO_do_connect` and `BIO_do_handshake`; exposed as `-t <secs>` (default 10) |
| 🟠 Med | `ERR_print_errors_fp(stderr)` dumped OpenSSL internals unconditionally on error | Gated behind `-v`; calls `ERR_clear_error()` otherwise |
| 🟠 Med | `atoi` used on `-w` input — silently accepts garbage, no overflow protection | Replaced with `strtol` + bounds check (0–36500); invalid input is rejected with a message |
| 🟡 Low | `SSL_get_peer_certificate` deprecated since OpenSSL 3.0 | Replaced with `SSL_get1_peer_certificate` |
| 🟡 Low | Redundant second `BIO_get_ssl` call before cert retrieval | Removed; `ssl` was already valid from the first call |
| 🟡 Low | `port_override` variable was always NULL — dead code | Removed |
| 🟡 Low | `SSL_VERIFY_NONE` had no explanatory comment | Documented: intentional, cck must see certs that may be self-signed or expired, no data is sent over the connection |
| ℹ️ Info | Flags placed after the first `-H` argument are silently ignored by the getopt pass | Documented in source with a `KNOWN LIMITATION` comment; put all flags before targets |

### Design notes

**`SSL_VERIFY_NONE`** — cck deliberately disables chain verification so it can inspect any cert a server presents, including self-signed certs and certs from private CAs not in the system trust store. The connection is read-only and immediately discarded after the cert is retrieved; no sensitive data is transmitted. If you add any feature that sends data over the connection, this setting must be revisited.

**Signal safety** — the `SIGALRM` handler uses only `write(2)` and `_exit(2)`, both of which are listed as async-signal-safe in POSIX. `printf`/`fprintf` are not safe inside signal handlers and are not used there.
