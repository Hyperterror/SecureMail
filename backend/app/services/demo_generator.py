"""
Demo data generator for SecureMailScope.

Produces a realistic synthetic dataset of 37 email sessions with diverse
TLS configurations, cipher suites, certificate issues, and anomalies.
This enables full UI development and demos without requiring tshark or
a real PCAP file.

Distribution:
- 18 TLS 1.3 sessions (all low risk)
- 14 TLS 1.2 sessions (mix of low/medium)
- 3 TLS 1.1 sessions (high risk)
- 2 TLS 1.0 sessions (critical risk)
- 21 SMTP, 9 IMAP, 7 POP3
- 12 Implicit TLS, 19 STARTTLS, 6 Plaintext
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

import numpy as np

from app.models.enums import (
    CertificateStatus,
    Protocol,
    RiskLevel,
    TLSVersion,
    TransportMode,
)
from app.models.schemas import (
    AnalysisResult,
    CertificateInfo,
    Finding,
    SessionInfo,
)
from app.services.feature_engine import extract_features_batch
from app.services.ml_engine import AnomalyDetector
from app.services.risk_aggregator import aggregate_risk, compute_security_posture
from app.services.rule_engine import evaluate


# ---------------------------------------------------------------------------
# Session templates — each defines a "persona" for realistic variety
# ---------------------------------------------------------------------------

_TEMPLATES: list[dict] = [
    # ── TLS 1.3 sessions (18) — mostly good ──────────────────────────
    *[{
        "tls_version": TLSVersion.TLS_1_3,
        "cipher_suite": random.choice([
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ]),
        "key_exchange": "ECDHE",
        "forward_secrecy": True,
        "cert_status": [CertificateStatus.VALID],
        "protocol": random.choice([Protocol.SMTP] * 10 + [Protocol.IMAP] * 5 + [Protocol.POP3] * 3),
        "transport_mode": random.choice([TransportMode.STARTTLS] * 10 + [TransportMode.IMPLICIT_TLS] * 8),
    } for _ in range(18)],

    # ── TLS 1.2 sessions (14) — mostly good, some medium risk ────────
    *[{
        "tls_version": TLSVersion.TLS_1_2,
        "cipher_suite": random.choice([
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        ]),
        "key_exchange": random.choice(["ECDHE"] * 10 + ["DHE"] * 3 + ["RSA"]),
        "forward_secrecy": True,
        "cert_status": [CertificateStatus.VALID],
        "protocol": random.choice([Protocol.SMTP] * 7 + [Protocol.IMAP] * 4 + [Protocol.POP3] * 3),
        "transport_mode": random.choice([TransportMode.STARTTLS] * 8 + [TransportMode.IMPLICIT_TLS] * 6),
    } for _ in range(14)],

    # ── TLS 1.1 sessions (3) — high risk ─────────────────────────────
    {
        "tls_version": TLSVersion.TLS_1_1,
        "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "key_exchange": "RSA",
        "forward_secrecy": False,
        "cert_status": [CertificateStatus.VALID],
        "protocol": Protocol.POP3,
        "transport_mode": TransportMode.STARTTLS,
    },
    {
        "tls_version": TLSVersion.TLS_1_1,
        "cipher_suite": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "key_exchange": "DHE",
        "forward_secrecy": True,
        "cert_status": [CertificateStatus.SELF_SIGNED],
        "protocol": Protocol.IMAP,
        "transport_mode": TransportMode.IMPLICIT_TLS,
    },
    {
        "tls_version": TLSVersion.TLS_1_1,
        "cipher_suite": "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "key_exchange": "RSA",
        "forward_secrecy": False,
        "cert_status": [CertificateStatus.EXPIRED],
        "protocol": Protocol.SMTP,
        "transport_mode": TransportMode.STARTTLS,
    },

    # ── TLS 1.0 sessions (2) — critical risk ─────────────────────────
    {
        "tls_version": TLSVersion.TLS_1_0,
        "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "key_exchange": "RSA",
        "forward_secrecy": False,
        "cert_status": [CertificateStatus.EXPIRED],
        "protocol": Protocol.SMTP,
        "transport_mode": TransportMode.STARTTLS,
    },
    {
        "tls_version": TLSVersion.TLS_1_0,
        "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "key_exchange": "RSA",
        "forward_secrecy": False,
        "cert_status": [CertificateStatus.HOSTNAME_MISMATCH],
        "protocol": Protocol.POP3,
        "transport_mode": TransportMode.IMPLICIT_TLS,
    },
]

# Subnet prefixes for realistic IPs
_CLIENT_SUBNETS = ["10.0.0.", "10.0.1.", "192.168.1."]
_SERVER_IPS = ["10.0.0.10", "10.0.0.15", "10.0.0.20", "10.0.1.5", "192.168.1.100"]

_HOSTNAMES = [
    "mail.example.com",
    "smtp.example.com",
    "imap.example.com",
    "pop3.example.com",
    "mx1.corp.example.com",
    "mail.internal.example.com",
]

_ISSUERS = [
    "Example Internal CA",
    "Let's Encrypt Authority X3",
    "DigiCert Global Root G2",
    "GlobalSign RSA OV SSL CA 2018",
]


def _generate_starttls_timeline(transport_mode: TransportMode, protocol: Protocol) -> list[str]:
    """Generate a realistic STARTTLS negotiation timeline."""
    if transport_mode == TransportMode.PLAINTEXT:
        greeting = "EHLO" if protocol == Protocol.SMTP else "LOGIN"
        return [
            f"{protocol.value} Connection",
            greeting,
            "No encryption negotiated",
            "Plaintext session",
        ]

    if transport_mode == TransportMode.IMPLICIT_TLS:
        return [
            f"{protocol.value} Connection (port {'465' if protocol == Protocol.SMTP else '993' if protocol == Protocol.IMAP else '995'})",
            "TLS Handshake (immediate)",
            "Encrypted session established",
        ]

    # STARTTLS
    if protocol == Protocol.SMTP:
        return [
            "SMTP Connection",
            "EHLO",
            "STARTTLS advertised",
            "STARTTLS requested",
            "TLS Handshake",
            "Encrypted session",
        ]
    elif protocol == Protocol.IMAP:
        return [
            "IMAP Connection",
            "CAPABILITY",
            "STARTTLS advertised",
            "STARTTLS requested",
            "TLS Handshake",
            "Encrypted session",
        ]
    else:
        return [
            "POP3 Connection",
            "CAPA",
            "STLS advertised",
            "STLS requested",
            "TLS Handshake",
            "Encrypted session",
        ]


def _port_for(protocol: Protocol, transport: TransportMode) -> int:
    """Return the standard port for a protocol/transport combination."""
    if transport == TransportMode.IMPLICIT_TLS:
        return {Protocol.SMTP: 465, Protocol.IMAP: 993, Protocol.POP3: 995}[protocol]
    return {Protocol.SMTP: 587, Protocol.IMAP: 143, Protocol.POP3: 110}[protocol]


def _build_certificate(
    cert_statuses: list[CertificateStatus],
    hostname: str,
) -> CertificateInfo:
    """Generate a realistic certificate based on status flags."""
    is_self_signed = CertificateStatus.SELF_SIGNED in cert_statuses

    return CertificateInfo(
        subject=hostname,
        issuer=hostname if is_self_signed else random.choice(_ISSUERS),
        not_before="2025-01-01T00:00:00Z",
        not_after="2024-12-31T23:59:59Z" if CertificateStatus.EXPIRED in cert_statuses else "2026-12-31T23:59:59Z",
        public_key_algorithm="RSA",
        public_key_size=random.choice([2048, 4096]),
        signature_algorithm="SHA-256 with RSA",
        san=[hostname, f"alt.{hostname}"],
        status=cert_statuses,
    )


def generate_demo_data() -> AnalysisResult:
    """
    Generate a complete demo analysis result.

    Returns an AnalysisResult with 37 sessions, fully scored by
    both rule engine and ML anomaly detection.
    """
    rng = random.Random(42)
    analysis_id = str(uuid.uuid4())[:8]

    # Also add 6 plaintext sessions
    plaintext_templates = [
        {
            "tls_version": TLSVersion.NONE,
            "cipher_suite": None,
            "key_exchange": None,
            "forward_secrecy": False,
            "cert_status": [],
            "protocol": rng.choice([Protocol.SMTP, Protocol.IMAP, Protocol.POP3]),
            "transport_mode": TransportMode.PLAINTEXT,
        }
        for _ in range(6)
    ]

    # Combine all templates (we'll take the first 37 to hit our target)
    all_templates = _TEMPLATES + plaintext_templates
    # Shuffle for variety but with fixed seed for reproducibility
    rng.shuffle(all_templates)
    templates = all_templates[:37]

    sessions: list[SessionInfo] = []

    for idx, tmpl in enumerate(templates, start=1):
        session_id = f"SES-{idx:04d}"
        protocol = tmpl["protocol"]
        transport = tmpl["transport_mode"]
        dest_port = _port_for(protocol, transport)
        hostname = rng.choice(_HOSTNAMES)

        cert = None
        if tmpl["tls_version"] != TLSVersion.NONE:
            cert = _build_certificate(tmpl["cert_status"], hostname)

        session = SessionInfo(
            session_id=session_id,
            protocol=protocol,
            transport_mode=transport,
            source_ip=f"{rng.choice(_CLIENT_SUBNETS)}{rng.randint(20, 250)}",
            source_port=rng.randint(49152, 65535),
            dest_ip=rng.choice(_SERVER_IPS),
            dest_port=dest_port,
            tls_version=tmpl["tls_version"],
            cipher_suite=tmpl["cipher_suite"],
            key_exchange=tmpl["key_exchange"],
            forward_secrecy=tmpl["forward_secrecy"],
            certificate=cert,
            starttls_timeline=_generate_starttls_timeline(transport, protocol),
            packet_count=rng.randint(15, 500),
            session_duration_ms=rng.uniform(50.0, 15000.0),
            retransmission_count=rng.randint(0, 8),
        )

        sessions.append(session)

    # ── Run rule engine on each session ───────────────────────────────
    for session in sessions:
        rule_score, findings = evaluate(session)
        session.rule_score = rule_score
        session.findings = findings

    # ── Run ML anomaly detection ──────────────────────────────────────
    features = extract_features_batch(sessions)
    detector = AnomalyDetector()
    anomaly_scores = detector.fit_and_predict(features)

    for session, ml_score in zip(sessions, anomaly_scores):
        session.ml_anomaly_score = round(float(ml_score), 3)

    # ── Aggregate hybrid risk ─────────────────────────────────────────
    for session in sessions:
        combined, risk_level, confidence = aggregate_risk(
            session.rule_score,
            session.ml_anomaly_score,
        )
        session.risk_level = risk_level
        session.confidence = confidence

    # ── Compute distributions ─────────────────────────────────────────
    tls_dist: dict[str, int] = {}
    proto_dist: dict[str, int] = {}
    transport_dist: dict[str, int] = {}
    risk_dist: dict[str, int] = {}

    for s in sessions:
        tls_dist[s.tls_version.value] = tls_dist.get(s.tls_version.value, 0) + 1
        proto_dist[s.protocol.value] = proto_dist.get(s.protocol.value, 0) + 1
        transport_dist[s.transport_mode.value] = transport_dist.get(s.transport_mode.value, 0) + 1
        risk_dist[s.risk_level.value] = risk_dist.get(s.risk_level.value, 0) + 1

    total_findings = sum(len(s.findings) for s in sessions)

    return AnalysisResult(
        analysis_id=analysis_id,
        filename="enterprise_mail_traffic.pcap",
        file_size_bytes=13_421_568,  # ~12.8 MB
        total_packets=8421,
        total_sessions=len(sessions),
        total_findings=total_findings,
        security_posture=compute_security_posture(sessions),
        sessions=sessions,
        tls_version_distribution=tls_dist,
        protocol_distribution=proto_dist,
        transport_mode_distribution=transport_dist,
        risk_distribution=risk_dist,
        completed_at=datetime.now(timezone.utc).isoformat(),
    )
