# cck_ssl — Datadog Agent Check for SSL/TLS Certificate Expiry

A Datadog Agent custom check that monitors SSL/TLS certificate expiry, using the same logic as [cck](../README.md).

## Metrics emitted

| Metric | Type | Description |
|---|---|---|
| `cck.ssl.days_remaining` | gauge | Days until certificate expires. Negative when already expired. |

## Service checks emitted

| Service check | Status | Description |
|---|---|---|
| `cck.ssl.cert` | OK | Certificate valid, not expiring soon |
| `cck.ssl.cert` | WARNING | Expires within `warn_days` |
| `cck.ssl.cert` | CRITICAL | Expires within `crit_days`, or already expired |
| `cck.ssl.cert` | UNKNOWN | Connection failed, file unreadable, or parse error |

## Requirements

- Datadog Agent 7+
- Python `cryptography` library (bundled with the Datadog Agent)

For local development/testing without the full Agent:

```sh
pip install cryptography pytest
```

## Installation

```sh
# 1. Copy the check
sudo cp checks.d/cck_ssl.py /etc/datadog-agent/checks.d/

# 2. Copy and edit the config
sudo mkdir -p /etc/datadog-agent/conf.d/cck_ssl.d
sudo cp conf.d/cck_ssl.d/conf.yaml /etc/datadog-agent/conf.d/cck_ssl.d/

# 3. Edit the config to add your instances
sudo vi /etc/datadog-agent/conf.d/cck_ssl.d/conf.yaml

# 4. Restart the Agent
sudo systemctl restart datadog-agent         # Linux (systemd)
sudo launchctl stop com.datadoghq.agent \
  && sudo launchctl start com.datadoghq.agent  # macOS
```

## Configuration

`conf.d/cck_ssl.d/conf.yaml`:

```yaml
init_config:
  warn_days: 30     # global warning threshold (days before expiry)
  crit_days: 14     # global critical threshold

instances:
  # Live TLS endpoint
  - host: example.com
    tags:
      - service:web
      - env:production

  # Non-standard port
  - host: internal.example.com
    port: 8443
    tags:
      - service:internal-api

  # Local PEM certificate file (or chain)
  - cert_path: /etc/nginx/ssl/fullchain.pem
    tags:
      - service:nginx

  # Override thresholds per-instance (e.g. for short-lived ACME certs)
  - host: letsencrypt-site.example.com
    warn_days: 21
    crit_days: 7
    tags:
      - service:letsencrypt
```

### Configuration reference

| Key | Scope | Default | Description |
|---|---|---|---|
| `warn_days` | `init_config` or instance | 30 | Days before expiry to emit WARNING |
| `crit_days` | `init_config` or instance | 14 | Days before expiry to emit CRITICAL |
| `timeout`   | `init_config` or instance | 10 | Connection timeout in seconds (live checks only) |
| `host`      | instance | — | Hostname to connect to |
| `port`      | instance | 443 | TLS port |
| `cert_path` | instance | — | Path to a local PEM file (mutually exclusive with `host`) |
| `tags`      | instance | `[]` | Additional tags on all metrics and service checks |

Instance-level `warn_days` / `crit_days` override `init_config` values.

### Tags automatically added

| Tag | Source |
|---|---|
| `host:<hostname>` | When checking a live endpoint |
| `port:<port>` | When checking a live endpoint |
| `cert_path:<path>` | When checking a file |

## Verifying the check

```sh
# Run the check once and inspect output
sudo datadog-agent check cck_ssl

# Check the Agent status
sudo datadog-agent status | grep -A 10 cck_ssl
```

## Datadog monitor example

Create a monitor on `cck.ssl.cert` (service check) in the Datadog UI, or via Terraform/API:

```hcl
resource "datadog_monitor" "ssl_cert" {
  name    = "SSL Certificate Expiry"
  type    = "service check"
  query   = "\"cck.ssl.cert\".over(\"env:production\").by(\"host\").last(3).count_by_status()"

  monitor_thresholds {
    warning  = 1
    critical = 1
    ok       = 1
  }

  message = <<-EOT
    SSL certificate on {{host.name}} is {{check_status}}.
    {{#is_warning}}Expiring soon — check and renew.{{/is_warning}}
    {{#is_alert}}EXPIRED or about to expire — renew immediately!{{/is_alert}}
    @pagerduty @slack-infra-alerts
  EOT
}
```

## Testing

```sh
# Unit tests (no Agent required)
python3 -m pytest datadog/tests/test_cck_ssl.py -v
```

27 unit tests across 6 suites:

| Suite | Cases |
|---|---|
| Config validation | Missing host/cert_path, mutually exclusive |
| Cert-path checks | OK / WARN / CRITICAL / EXPIRED / boundary conditions / chain worst-wins |
| Host checks | Valid / expiring / expired / connection error / timeout |
| Metrics | Gauge emitted, value correct, negative when expired, tags propagate |
| init_config | Global thresholds used; instance overrides global |
| _load_pem_file | Real PEM data parsed correctly |
