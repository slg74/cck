"""
datadog/tests/test_cck_ssl.py — unit tests for the cck_ssl Datadog check

Run with:
    pip install datadog-checks-dev cryptography pytest
    pytest datadog/tests/test_cck_ssl.py -v
"""

from __future__ import annotations

import sys
import os
import socket
from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import MagicMock, patch, mock_open
import tempfile
import pytest

# ── Make the check importable without a full Agent install ───────────────
# Stub out datadog_checks.base if it isn't installed
try:
    from datadog_checks.base import AgentCheck
except ImportError:
    # Minimal stub so the check module can be imported in a plain virtualenv
    class AgentCheck:  # type: ignore[no-redef]
        OK       = 0
        WARNING  = 1
        CRITICAL = 2
        UNKNOWN  = 3

        def __init__(self, name="", init_config=None, instances=None):
            self.name        = name
            self.init_config = init_config or {}
            self._gauges     = []
            self._svc_checks = []
            self.log         = MagicMock()

        def gauge(self, metric, value, tags=None):
            self._gauges.append({"metric": metric, "value": value, "tags": tags or []})

        def service_check(self, name, status, message="", tags=None):
            self._svc_checks.append({
                "name": name, "status": status,
                "message": message, "tags": tags or [],
            })

    # Inject stub into sys.modules so the import inside cck_ssl.py works
    datadog_checks_base = MagicMock()
    datadog_checks_base.AgentCheck = AgentCheck
    sys.modules.setdefault("datadog_checks", MagicMock())
    sys.modules["datadog_checks.base"] = datadog_checks_base

# Now import the check itself
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "checks.d"))
from cck_ssl import CckSslCheck  # noqa: E402

# ── Helpers ──────────────────────────────────────────────────────────────

def make_mock_cert(days_until_expiry: int):
    """Return a mock cryptography Certificate with a known expiry."""
    expiry = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)
    cert = MagicMock()
    cert.not_valid_after_utc = expiry
    return cert


def make_check(init_config=None, instance=None):
    """Instantiate the check with default or supplied config."""
    return CckSslCheck(
        "cck_ssl",
        init_config=init_config or {},
        instances=[instance or {}],
    )


# ── Tests: configuration validation ──────────────────────────────────────

class TestConfigValidation:
    def test_no_host_or_cert_path_emits_unknown(self):
        check = make_check(instance={})
        check.check({})
        sc = check._svc_checks[-1]
        assert sc["status"] == AgentCheck.UNKNOWN
        assert "cert_path" in sc["message"] or "host" in sc["message"]

    def test_both_host_and_cert_path_emits_unknown(self):
        check = make_check(instance={})
        check.check({"host": "example.com", "cert_path": "/tmp/cert.pem"})
        sc = check._svc_checks[-1]
        assert sc["status"] == AgentCheck.UNKNOWN
        assert "mutually exclusive" in sc["message"]


# ── Tests: cert_path (file-based checks) ─────────────────────────────────

class TestCertPathChecks:
    def _run(self, days: int, warn: int = 30, crit: int = 14,
             extra_certs: Optional[list] = None) -> dict:
        """Run a file-based check with a mocked cert and return the service check result."""
        certs = [make_mock_cert(days)]
        if extra_certs:
            certs += extra_certs

        check = make_check(instance={"cert_path": "/fake/cert.pem",
                                      "warn_days": warn, "crit_days": crit})
        with patch.object(check, "_load_pem_file", return_value=certs):
            check.check({"cert_path": "/fake/cert.pem",
                         "warn_days": warn, "crit_days": crit})
        return check._svc_checks[-1]

    def test_valid_cert_is_ok(self):
        sc = self._run(days=365)
        assert sc["status"] == AgentCheck.OK, sc["message"]

    def test_cert_within_warn_window_is_warning(self):
        sc = self._run(days=25, warn=30, crit=14)
        assert sc["status"] == AgentCheck.WARNING, sc["message"]
        assert "WARNING" in sc["message"]

    def test_cert_within_crit_window_is_critical(self):
        sc = self._run(days=7, warn=30, crit=14)
        assert sc["status"] == AgentCheck.CRITICAL, sc["message"]
        assert "CRITICAL" in sc["message"]

    def test_expired_cert_is_critical(self):
        sc = self._run(days=-10)
        assert sc["status"] == AgentCheck.CRITICAL, sc["message"]
        assert "EXPIRED" in sc["message"]

    def test_exactly_at_warn_boundary_is_warning(self):
        sc = self._run(days=30, warn=30, crit=14)
        assert sc["status"] == AgentCheck.WARNING

    def test_one_day_past_warn_boundary_is_ok(self):
        # Use days=32 rather than 31: timedelta.days truncates sub-second elapsed
        # time between cert creation and check evaluation, so 31 would land on 30.
        sc = self._run(days=32, warn=30, crit=14)
        assert sc["status"] == AgentCheck.OK

    def test_exactly_at_crit_boundary_is_critical(self):
        sc = self._run(days=14, warn=30, crit=14)
        assert sc["status"] == AgentCheck.CRITICAL

    def test_one_day_past_crit_boundary_is_warning(self):
        # Use days=16 rather than 15 for same timing-truncation reason as above.
        sc = self._run(days=16, warn=30, crit=14)
        assert sc["status"] == AgentCheck.WARNING

    def test_file_read_error_emits_unknown(self):
        check = make_check(instance={"cert_path": "/fake/cert.pem"})
        with patch.object(check, "_load_pem_file", side_effect=IOError("no file")):
            check.check({"cert_path": "/fake/cert.pem"})
        sc = check._svc_checks[-1]
        assert sc["status"] == AgentCheck.UNKNOWN
        assert "no file" in sc["message"]

    def test_empty_pem_file_emits_unknown(self):
        check = make_check(instance={"cert_path": "/fake/cert.pem"})
        with patch.object(check, "_load_pem_file", return_value=[]):
            check.check({"cert_path": "/fake/cert.pem"})
        sc = check._svc_checks[-1]
        assert sc["status"] == AgentCheck.UNKNOWN

    def test_chain_worst_status_wins(self):
        """A chain with one expired cert → CRITICAL even if others are valid."""
        sc = self._run(
            days=365,
            extra_certs=[make_mock_cert(-5)],  # expired
        )
        assert sc["status"] == AgentCheck.CRITICAL

    def test_chain_all_valid_is_ok(self):
        sc = self._run(days=365, extra_certs=[make_mock_cert(200)])
        assert sc["status"] == AgentCheck.OK


# ── Tests: host-based (live TLS) checks ──────────────────────────────────

class TestHostChecks:
    def _run(self, days: int, warn: int = 30, crit: int = 14,
             connect_exc: Optional[Exception] = None) -> dict:
        cert = make_mock_cert(days)
        instance = {"host": "example.com", "port": 443,
                    "warn_days": warn, "crit_days": crit}
        check = make_check(instance=instance)

        if connect_exc:
            with patch.object(check, "_get_host_cert", side_effect=connect_exc):
                check.check(instance)
        else:
            with patch.object(check, "_get_host_cert", return_value=cert):
                check.check(instance)
        return check._svc_checks[-1]

    def test_valid_host_cert_is_ok(self):
        sc = self._run(days=365)
        assert sc["status"] == AgentCheck.OK

    def test_expiring_host_cert_is_warning(self):
        sc = self._run(days=20, warn=30, crit=14)
        assert sc["status"] == AgentCheck.WARNING

    def test_critically_expiring_host_cert(self):
        sc = self._run(days=5, warn=30, crit=14)
        assert sc["status"] == AgentCheck.CRITICAL

    def test_expired_host_cert_is_critical(self):
        sc = self._run(days=-3)
        assert sc["status"] == AgentCheck.CRITICAL

    def test_connection_error_emits_critical(self):
        sc = self._run(days=365, connect_exc=ConnectionRefusedError("refused"))
        assert sc["status"] == AgentCheck.CRITICAL
        assert "refused" in sc["message"] or "Cannot connect" in sc["message"]

    def test_timeout_emits_critical(self):
        sc = self._run(days=365, connect_exc=socket.timeout("timed out"))
        assert sc["status"] == AgentCheck.CRITICAL


# ── Tests: metrics ────────────────────────────────────────────────────────

class TestMetrics:
    def test_gauge_emitted_for_valid_cert(self):
        cert = make_mock_cert(90)
        check = make_check(instance={"cert_path": "/fake/cert.pem"})
        with patch.object(check, "_load_pem_file", return_value=[cert]):
            check.check({"cert_path": "/fake/cert.pem"})
        assert any(g["metric"] == "ssl.days_remaining" for g in check._gauges)

    def test_gauge_value_matches_expiry(self):
        cert = make_mock_cert(90)
        check = make_check(instance={"cert_path": "/fake/cert.pem"})
        with patch.object(check, "_load_pem_file", return_value=[cert]):
            check.check({"cert_path": "/fake/cert.pem"})
        g = next(g for g in check._gauges if g["metric"] == "ssl.days_remaining")
        assert 88 <= g["value"] <= 91   # allow ±1 day for timing

    def test_gauge_is_negative_when_expired(self):
        cert = make_mock_cert(-5)
        check = make_check(instance={"cert_path": "/fake/cert.pem"})
        with patch.object(check, "_load_pem_file", return_value=[cert]):
            check.check({"cert_path": "/fake/cert.pem"})
        g = next(g for g in check._gauges if g["metric"] == "ssl.days_remaining")
        assert g["value"] < 0

    def test_tags_propagate_to_gauge_and_service_check(self):
        cert = make_mock_cert(90)
        instance = {"cert_path": "/fake/cert.pem", "tags": ["env:prod", "team:infra"]}
        check = make_check(instance=instance)
        with patch.object(check, "_load_pem_file", return_value=[cert]):
            check.check(instance)
        g = next(g for g in check._gauges if g["metric"] == "ssl.days_remaining")
        assert "env:prod" in g["tags"]
        assert "team:infra" in g["tags"]


# ── Tests: global init_config thresholds ─────────────────────────────────

class TestInitConfig:
    def test_global_warn_days_used_when_instance_omits_it(self):
        cert = make_mock_cert(25)
        check = make_check(init_config={"warn_days": 30, "crit_days": 14},
                           instance={"cert_path": "/fake/cert.pem"})
        with patch.object(check, "_load_pem_file", return_value=[cert]):
            check.check({"cert_path": "/fake/cert.pem"})
        sc = check._svc_checks[-1]
        assert sc["status"] == AgentCheck.WARNING

    def test_instance_warn_days_overrides_global(self):
        cert = make_mock_cert(25)
        check = make_check(init_config={"warn_days": 30, "crit_days": 14},
                           instance={"cert_path": "/fake/cert.pem", "warn_days": 20})
        with patch.object(check, "_load_pem_file", return_value=[cert]):
            check.check({"cert_path": "/fake/cert.pem", "warn_days": 20})
        sc = check._svc_checks[-1]
        # days=25 with warn=20 → OK
        assert sc["status"] == AgentCheck.OK


# ── Tests: _load_pem_file with real PEM data ──────────────────────────────

class TestLoadPemFile:
    def test_loads_single_cert_from_pem(self):
        """Use openssl-generated PEM data (if available) to test real parsing."""
        pytest.importorskip("cryptography")
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            from cryptography import x509 as cx509
            from cryptography.x509.oid import NameOID
            import ipaddress

            key = ec.generate_private_key(ec.SECP256R1())
            name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "test")])
            now = datetime.now(timezone.utc)
            cert = (
                cx509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(cx509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=365))
                .sign(key, hashes.SHA256())
            )
            from cryptography.hazmat.primitives.serialization import Encoding
            pem_data = cert.public_bytes(Encoding.PEM)
        except Exception as exc:
            pytest.skip(f"Could not generate test cert: {exc}")

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(pem_data)
            path = f.name

        try:
            check = make_check()
            loaded = check._load_pem_file(path)
            assert len(loaded) == 1
        finally:
            os.unlink(path)
