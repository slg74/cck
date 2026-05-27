# check_cck_ssl — Nagios/Icinga SSL Certificate Plugin

A Nagios-compatible plugin that checks SSL/TLS certificate expiry, built on the same OpenSSL logic as [cck](../README.md).

## Nagios plugin interface

| Exit code | State    | Meaning |
|---|---|---|
| 0 | OK       | Certificate is valid and not expiring soon |
| 1 | WARNING  | Certificate expires within `-w` days |
| 2 | CRITICAL | Certificate expires within `-c` days, or is already expired |
| 3 | UNKNOWN  | Connection failed, file missing, parse error |

### Output format

```
SSL CERT OK - example.com:443 expires 2026-07-01 (in 35 days) | days_remaining=35;30;14;0;
SSL CERT WARNING - example.com:443 expires 2025-06-15 (WARNING: in 19 days) | days_remaining=19;30;14;0;
SSL CERT CRITICAL - example.com:443 certificate EXPIRED on 2025-01-01 (147 days ago) | days_remaining=-147;30;14;0;
SSL CERT UNKNOWN - example.com:443 connection failed (port 443 unreachable?) | days_remaining=U;0;0;0;
```

Performance data (`days_remaining=VALUE;warn;crit;0;`) is compatible with PNP4Nagios, Graphite, and Nagios Graph.

## Requirements

- C11 compiler (clang or gcc)
- OpenSSL 1.1+ or 3.x

```sh
brew install openssl        # macOS
apt install libssl-dev      # Debian/Ubuntu
dnf install openssl-devel   # Fedora/RHEL
```

## Build & install

```sh
make
make install                          # → /usr/local/nagios/libexec/check_cck_ssl
make install PLUGINDIR=/usr/lib/nagios/plugins   # custom path
```

## Usage

```
check_cck_ssl -H <host> [-p <port>] [-w <days>] [-c <days>]
check_cck_ssl -f <cert.pem>          [-w <days>] [-c <days>]

Options:
  -H <host>    Hostname to connect to via TLS
  -p <port>    Port (default: 443)
  -f <file>    PEM certificate file to check instead of a live host
  -w <days>    Warning threshold in days (default: 30)
  -c <days>    Critical threshold in days (default: 14)
  -h           Show help
```

### Manual testing

```sh
# Check a live host
./check_cck_ssl -H example.com
./check_cck_ssl -H example.com -p 8443 -w 60 -c 30

# Check a local PEM file
./check_cck_ssl -f /etc/ssl/certs/my-service.pem -w 30 -c 14

# PEM chains: worst cert across the chain determines the status
./check_cck_ssl -f /etc/nginx/ssl/fullchain.pem
```

## Nagios integration

Copy `nagios.cfg` (or the relevant sections) into your Nagios configuration directory, then reload:

```sh
sudo cp nagios.cfg /etc/nagios3/conf.d/cck_ssl.cfg
sudo nagios -v /etc/nagios3/nagios.cfg   # verify
sudo service nagios3 reload
```

### Command definitions

```nagios
define command {
    command_name    check_ssl_cert
    command_line    $USER1$/check_cck_ssl -H $HOSTADDRESS$ -w $ARG1$ -c $ARG2$
}

define command {
    command_name    check_ssl_cert_file
    command_line    $USER1$/check_cck_ssl -f $ARG1$ -w $ARG2$ -c $ARG3$
}
```

### Service definition

```nagios
define service {
    use                     generic-service
    host_name               example.com
    service_description     SSL Certificate
    check_command           check_ssl_cert!30!14
    check_interval          60        ; check every hour
    notification_interval   1440      ; re-notify daily
}
```

See [`nagios.cfg`](nagios.cfg) for more complete examples including custom ports and file-based checks.

## Testing

```sh
make test
```

Runs `tests/smoke.sh` against the compiled plugin binary: 27 tests covering exit codes, output format, performance data, chain certs, and live TLS.
