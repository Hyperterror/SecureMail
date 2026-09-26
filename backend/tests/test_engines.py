"""Tests for the rule engine, ML engine, feature engine, and demo generator."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pytest

from app.models.enums import (
    CertificateStatus, Protocol, RiskLevel, TLSVersion, TransportMode,
)
from app.models.schemas import CertificateInfo, Finding, SessionInfo
from app.services.rule_engine import evaluate
from app.services.ml_engine import AnomalyDetector
from app.services.feature_engine import extract_features, extract_features_batch, FEATURE_NAMES
from app.services.risk_aggregator import aggregate_risk, compute_security_posture
from app.services.demo_generator import generate_demo_data


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_session(**overrides) -> SessionInfo:
    """Create a session with sensible defaults, overriding as needed."""
    defaults = dict(
        session_id="SES-TEST",
        protocol=Protocol.SMTP,
        transport_mode=TransportMode.STARTTLS,
        source_ip="10.0.0.1",
        source_port=50000,
        dest_ip="10.0.0.10",
        dest_port=587,
        tls_version=TLSVersion.TLS_1_3,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        key_exchange="ECDHE",
        forward_secrecy=True,
        certificate=CertificateInfo(
            subject="mail.example.com",
            issuer="Let's Encrypt",
            not_before="2025-01-01",
            not_after="2026-12-31",
            public_key_algorithm="RSA",
            public_key_size=2048,
            signature_algorithm="SHA-256 with RSA",
            san=["mail.example.com"],
            status=[CertificateStatus.VALID],
        ),
        starttls_timeline=["SMTP Connection", "EHLO", "STARTTLS", "TLS Handshake", "Encrypted"],
        packet_count=100,
        session_duration_ms=5000.0,
        retransmission_count=1,
    )
    defaults.update(overrides)
    return SessionInfo(**defaults)


# ---------------------------------------------------------------------------
# Rule Engine Tests
# ---------------------------------------------------------------------------

class TestRuleEngine:
    def test_good_session_zero_penalty(self):
        session = _make_session()
        score, findings = evaluate(session)
        assert score == 0
        assert findings == []

    def test_plaintext_penalty(self):
        session = _make_session(
            transport_mode=TransportMode.PLAINTEXT,
            tls_version=TLSVersion.NONE,
            cipher_suite=None,
            key_exchange=None,
            forward_secrecy=False,
            certificate=None,
        )
        score, findings = evaluate(session)
        assert score >= 35
        assert any(f.title == "Plaintext Connection" for f in findings)

    def test_deprecated_tls(self):
        session = _make_session(tls_version=TLSVersion.TLS_1_0)
        score, findings = evaluate(session)
        assert score >= 30
        assert any("Deprecated" in f.title for f in findings)

    def test_legacy_tls(self):
        session = _make_session(tls_version=TLSVersion.TLS_1_1)
        score, findings = evaluate(session)
        assert score >= 15
        assert any("Legacy" in f.title for f in findings)

    def test_weak_cipher(self):
        session = _make_session(cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA")
        score, findings = evaluate(session)
        assert any("Weak Cipher" in f.title for f in findings)

    def test_no_forward_secrecy(self):
        session = _make_session(
            key_exchange="RSA", forward_secrecy=False,
        )
        score, findings = evaluate(session)
        assert any("Forward Secrecy" in f.title for f in findings)

    def test_expired_cert(self):
        session = _make_session(
            certificate=CertificateInfo(
                subject="mail.example.com",
                issuer="CA",
                status=[CertificateStatus.EXPIRED],
            ),
        )
        score, findings = evaluate(session)
        assert any("Expired" in f.title for f in findings)

    def test_self_signed(self):
        session = _make_session(
            certificate=CertificateInfo(
                subject="mail.example.com",
                issuer="mail.example.com",
                status=[CertificateStatus.SELF_SIGNED],
            ),
        )
        score, findings = evaluate(session)
        assert any("Self-Signed" in f.title for f in findings)

    def test_hostname_mismatch(self):
        session = _make_session(
            certificate=CertificateInfo(
                subject="other.com",
                status=[CertificateStatus.HOSTNAME_MISMATCH],
            ),
        )
        score, findings = evaluate(session)
        assert any("Hostname" in f.title for f in findings)

    def test_penalty_capped_at_100(self):
        """Multiple violations should cap at 100."""
        session = _make_session(
            transport_mode=TransportMode.PLAINTEXT,
            tls_version=TLSVersion.NONE,
            cipher_suite=None,
            key_exchange=None,
            forward_secrecy=False,
            certificate=CertificateInfo(
                status=[CertificateStatus.EXPIRED, CertificateStatus.SELF_SIGNED, CertificateStatus.HOSTNAME_MISMATCH],
            ),
        )
        score, _ = evaluate(session)
        assert score <= 100

    def test_findings_have_required_fields(self):
        session = _make_session(tls_version=TLSVersion.TLS_1_0)
        _, findings = evaluate(session)
        for f in findings:
            assert f.finding_id
            assert f.session_id == "SES-TEST"
            assert f.severity in list(RiskLevel)
            assert f.title
            assert f.description
            assert f.recommendation


# ---------------------------------------------------------------------------
# ML Engine Tests
# ---------------------------------------------------------------------------

class TestMLEngine:
    def test_scores_in_range(self):
        features = np.random.rand(20, 12)
        detector = AnomalyDetector()
        scores = detector.fit_and_predict(features)
        assert scores.shape == (20,)
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_small_dataset_returns_neutral(self):
        features = np.random.rand(3, 12)
        detector = AnomalyDetector()
        scores = detector.fit_and_predict(features)
        assert np.allclose(scores, 0.5)

    def test_deterministic_with_seed(self):
        features = np.random.RandomState(42).rand(15, 12)
        d1 = AnomalyDetector(random_state=42)
        d2 = AnomalyDetector(random_state=42)
        s1 = d1.fit_and_predict(features)
        s2 = d2.fit_and_predict(features)
        np.testing.assert_array_equal(s1, s2)

    def test_is_fitted_flag(self):
        detector = AnomalyDetector()
        assert not detector.is_fitted
        features = np.random.rand(10, 12)
        detector.fit_and_predict(features)
        assert detector.is_fitted


# ---------------------------------------------------------------------------
# Feature Engine Tests
# ---------------------------------------------------------------------------

class TestFeatureEngine:
    def test_feature_dimension(self):
        session = _make_session()
        features = extract_features(session)
        assert features.shape == (len(FEATURE_NAMES),)
        assert features.dtype == np.float64

    def test_batch_extraction(self):
        sessions = [_make_session(session_id=f"SES-{i}") for i in range(5)]
        features = extract_features_batch(sessions)
        assert features.shape == (5, len(FEATURE_NAMES))

    def test_handles_missing_certificate(self):
        session = _make_session(certificate=None)
        features = extract_features(session)
        assert features.shape == (len(FEATURE_NAMES),)
        # Key size should be 0
        assert features[3] == 0.0

    def test_empty_batch(self):
        features = extract_features_batch([])
        assert features.shape == (0, len(FEATURE_NAMES))


# ---------------------------------------------------------------------------
# Risk Aggregator Tests
# ---------------------------------------------------------------------------

class TestRiskAggregator:
    def test_low_risk(self):
        combined, level, conf = aggregate_risk(0, 0.0)
        assert combined == 0
        assert level == RiskLevel.LOW

    def test_critical_risk(self):
        combined, level, conf = aggregate_risk(100, 1.0)
        assert combined == 100
        assert level == RiskLevel.CRITICAL

    def test_70_30_formula(self):
        combined, _, _ = aggregate_risk(50, 0.5)
        expected = int(0.7 * 50 + 0.3 * 50)
        assert combined == expected

    def test_security_posture_perfect(self):
        sessions = [_make_session()]
        sessions[0].rule_score = 0
        assert compute_security_posture(sessions) == 100

    def test_security_posture_empty(self):
        assert compute_security_posture([]) == 100


# ---------------------------------------------------------------------------
# Demo Generator Tests
# ---------------------------------------------------------------------------

class TestDemoGenerator:
    def test_generates_valid_result(self):
        result = generate_demo_data()
        assert result.analysis_id
        assert result.total_sessions == 37
        assert len(result.sessions) == 37
        assert result.security_posture >= 0
        assert result.security_posture <= 100

    def test_sessions_have_required_fields(self):
        result = generate_demo_data()
        for s in result.sessions:
            assert s.session_id
            assert s.protocol in list(Protocol)
            assert s.transport_mode in list(TransportMode)
            assert s.tls_version in list(TLSVersion)
            assert s.risk_level in list(RiskLevel)
            assert s.source_ip
            assert s.dest_ip
            assert s.packet_count > 0

    def test_has_distributions(self):
        result = generate_demo_data()
        assert len(result.tls_version_distribution) > 0
        assert len(result.protocol_distribution) > 0
        assert len(result.transport_mode_distribution) > 0
        assert len(result.risk_distribution) > 0

    def test_ml_scores_populated(self):
        result = generate_demo_data()
        for s in result.sessions:
            assert 0.0 <= s.ml_anomaly_score <= 1.0

    def test_has_critical_sessions(self):
        result = generate_demo_data()
        critical = [s for s in result.sessions if s.risk_level == RiskLevel.CRITICAL]
        # Should have at least some high-risk sessions
        high_risk = [s for s in result.sessions if s.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        assert len(high_risk) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
