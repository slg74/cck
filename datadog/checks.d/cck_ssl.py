"""
datadog/checks.d/cck_ssl.py — Datadog Agent check for SSL/TLS certificate expiry

Supports checking:
  - Local PEM certificate files (cert_path)
  - Live TLS endpoints (host + port)

Metrics emitted:
  cck.ssl.days_remaining   gauge   Days until certificate expires (negative = already expired)

Service checks emitted:
  cck.ssl.cert             OK / WARNING / CRITICAL / UNKNOWN

Configuration: conf.d/cck_ssl.d/conf.yaml
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from datadog_checks.base import AgentCheck

try:
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class CckSslCheck(AgentCheck):
    """Datadog Agent check that monitors SSL/TLS certificate expiry."""

    __NAMESPACE__ = "cck"

    SERVICE_CHECK_NAME = "ssl.cert"

    # Default thresholds (days before expiry)
    DEFAULT_WARN_DAYS = 30
    DEFAULT_CRIT_DAYS = 14
    DEFAULT_PORT      = 443
    DEFAULT_TIMEOUT   = 10   # seconds

    def check(self, instance: dict) -> None:
        if not HAS_CRYPTOGRAPHY:
            self.service_check(
                self.SERVICE_CHECK_NAME,
                AgentCheck.UNKNOWN,
                message=(
                    "The 'cryptography' package is required. "
                    "Install it: pip install cryptography"
                ),
            )
            return

        # ── resolve config ──────────────────────────────────────────
        cert_path: Optional[str] = instance.get("cert_path")
        host: Optional[str]      = instance.get("host")
        port: int = int(instance.get("port", self.DEFAULT_PORT))
        warn_days: int = int(
            instance.get("warn_days",
                         self.init_config.get("warn_days", self.DEFAULT_WARN_DAYS))
        )
        crit_days: int = int(
            instance.get("crit_days",
                         self.init_config.get("crit_days", self.DEFAULT_CRIT_DAYS))
        )
        timeout: int = int(
            instance.get("timeout",
                         self.init_config.get("timeout", self.DEFAULT_TIMEOUT))
        )
        tags: list[str] = list(instance.get("tags", []))

        if not cert_path and not host:
            self.service_check(
                self.SERVICE_CHECK_NAME,
                AgentCheck.UNKNOWN,
                message="Instance must specify either 'cert_path' or 'host'.",
                tags=tags,
            )
            return

        if cert_path and host:
            self.service_check(
                self.SERVICE_CHECK_NAME,
                AgentCheck.UNKNOWN,
                message="'cert_path' and 'host' are mutually exclusive.",
                tags=tags,
            )
            return

        # ── load certificate(s) ─────────────────────────────────────
        if cert_path:
            target = cert_path
            tags = tags + [f"cert_path:{cert_path}"]
            try:
                certs = self._load_pem_file(cert_path)
            except Exception as exc:
                self.service_check(
                    self.SERVICE_CHECK_NAME,
                    AgentCheck.UNKNOWN,
                    message=f"Failed to read {cert_path}: {exc}",
                    tags=tags,
                )
                return
        else:
            target = f"{host}:{port}"
            tags = tags + [f"host:{host}", f"port:{port}"]
            try:
                certs = [self._get_host_cert(host, port, timeout)]
            except Exception as exc:
                self.service_check(
                    self.SERVICE_CHECK_NAME,
                    AgentCheck.CRITICAL,
                    message=f"Cannot connect to {target}: {exc}",
                    tags=tags,
                )
                return

        if not certs:
            self.service_check(
                self.SERVICE_CHECK_NAME,
                AgentCheck.UNKNOWN,
                message=f"No certificate found for {target}",
                tags=tags,
            )
            return

        # ── evaluate all certs; report on the worst one ─────────────
        worst_state   = AgentCheck.OK
        worst_days    = None
        worst_message = ""

        now = datetime.now(timezone.utc)

        for cert in certs:
            expiry = self._cert_expiry(cert)
            if expiry is None:
                state   = AgentCheck.UNKNOWN
                days    = None
                message = f"{target}: could not read expiry date"
            else:
                delta = expiry - now
                days  = delta.days   # negative when already expired
                date_str = expiry.strftime("%Y-%m-%d")

                if days < 0:
                    state   = AgentCheck.CRITICAL
                    message = (
                        f"{target}: certificate EXPIRED on {date_str} "
                        f"({-days} day{'s' if days != -1 else ''} ago)"
                    )
                elif days <= crit_days:
                    state   = AgentCheck.CRITICAL
                    message = (
                        f"{target}: expires {date_str} "
                        f"(CRITICAL: in {days} day{'s' if days != 1 else ''})"
                    )
                elif days <= warn_days:
                    state   = AgentCheck.WARNING
                    message = (
                        f"{target}: expires {date_str} "
                        f"(WARNING: in {days} day{'s' if days != 1 else ''})"
                    )
                else:
                    state   = AgentCheck.OK
                    message = (
                        f"{target}: expires {date_str} "
                        f"(in {days} day{'s' if days != 1 else ''})"
                    )

            # Track worst result
            if (state > worst_state or
                    (state == worst_state and
                     days is not None and
                     (worst_days is None or days < worst_days))):
                worst_state   = state
                worst_days    = days
                worst_message = message

        # ── emit metrics ────────────────────────────────────────────
        if worst_days is not None:
            self.gauge("ssl.days_remaining", worst_days, tags=tags)

        self.service_check(
            self.SERVICE_CHECK_NAME,
            worst_state,
            message=worst_message,
            tags=tags,
        )

    # ── helpers ──────────────────────────────────────────────────────

    def _get_host_cert(self, host: str, port: int, timeout: int):
        """Connect to host:port via TLS and return the server's certificate."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)

        return crypto_x509.load_der_x509_certificate(der, default_backend())

    def _load_pem_file(self, path: str) -> list:
        """Read a PEM file and return all certificates it contains."""
        with open(path, "rb") as fh:
            data = fh.read()

        certs = []
        # Split on certificate boundaries; handles chains
        marker = b"-----BEGIN CERTIFICATE-----"
        end_marker = b"-----END CERTIFICATE-----"

        start = 0
        while True:
            begin = data.find(marker, start)
            if begin == -1:
                break
            end = data.find(end_marker, begin)
            if end == -1:
                break
            end += len(end_marker)
            pem_block = data[begin:end]
            try:
                cert = crypto_x509.load_pem_x509_certificate(
                    pem_block, default_backend()
                )
                certs.append(cert)
            except Exception as exc:
                self.log.warning("Skipping unparseable cert block in %s: %s", path, exc)
            start = end

        return certs

    @staticmethod
    def _cert_expiry(cert) -> Optional[datetime]:
        """Return the notAfter time as a timezone-aware UTC datetime."""
        try:
            # cryptography >= 42.0.0
            return cert.not_valid_after_utc
        except AttributeError:
            pass
        try:
            # cryptography < 42.0.0
            naive = cert.not_valid_after
            return naive.replace(tzinfo=timezone.utc)
        except Exception:
            return None
