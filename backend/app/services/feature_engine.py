"""
Feature engineering for the ML anomaly detection pipeline.

Converts each SessionInfo into a fixed-length numeric feature vector
suitable for Isolation Forest.
"""

from __future__ import annotations

import numpy as np

from app.models.enums import (
    CertificateStatus,
    TLSVersion,
    TransportMode,
    TLS_VERSION_SECURITY,
)
from app.models.schemas import SessionInfo


# ---------------------------------------------------------------------------
# Feature mapping helpers
# ---------------------------------------------------------------------------

def _tls_version_numeric(version: TLSVersion) -> float:
    """Map TLS version to numeric security rank (0=worst, 4=best, -1=none)."""
    return float(TLS_VERSION_SECURITY.get(version, -1))


_CIPHER_STRENGTH: dict[str, float] = {
    # Strong
    "AES_256_GCM": 100.0,
    "CHACHA20_POLY1305": 100.0,
    "AES_128_GCM": 90.0,
    "AES_256_CCM": 90.0,
    "AES_128_CCM": 85.0,
    # Moderate
    "AES_256_CBC": 70.0,
    "AES_128_CBC": 65.0,
    "CAMELLIA": 65.0,
    # Weak
    "3DES": 20.0,
    "DES": 5.0,
    "RC4": 10.0,
    "NULL": 0.0,
}


def _cipher_strength(cipher: str | None) -> float:
    """Score cipher strength from 0 (worst) to 100 (best)."""
    if not cipher:
        return 0.0
    cipher_upper = cipher.upper()
    for pattern, score in _CIPHER_STRENGTH.items():
        if pattern in cipher_upper:
            return score
    return 50.0  # Unknown cipher — neutral


_KEY_EXCHANGE_SCORE: dict[str, float] = {
    "ECDHE": 100.0,
    "DHE": 80.0,
    "ECDH": 60.0,
    "DH": 50.0,
    "RSA": 30.0,
    "PSK": 40.0,
}


def _key_exchange_score(kex: str | None) -> float:
    """Score key exchange from 0 (worst) to 100 (best)."""
    if not kex:
        return 0.0
    kex_upper = kex.upper()
    for pattern, score in _KEY_EXCHANGE_SCORE.items():
        if pattern in kex_upper:
            return score
    return 50.0


def _cert_expired(session: SessionInfo) -> float:
    if not session.certificate:
        return 0.0
    return 1.0 if CertificateStatus.EXPIRED in session.certificate.status else 0.0


def _cert_self_signed(session: SessionInfo) -> float:
    if not session.certificate:
        return 0.0
    return 1.0 if CertificateStatus.SELF_SIGNED in session.certificate.status else 0.0


def _hostname_match(session: SessionInfo) -> float:
    if not session.certificate:
        return 0.0
    return 0.0 if CertificateStatus.HOSTNAME_MISMATCH in session.certificate.status else 1.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "tls_version",
    "cipher_strength",
    "key_exchange",
    "key_size",
    "forward_secrecy",
    "cert_expired",
    "cert_self_signed",
    "hostname_match",
    "is_starttls",
    "packet_count",
    "session_duration_ms",
    "retransmission_count",
]


def extract_features(session: SessionInfo) -> np.ndarray:
    """
    Convert a session into a 12-dimensional feature vector.

    The vector captures both security properties (TLS version, cipher strength)
    and behavioral properties (packet count, duration, retransmissions)
    for the Isolation Forest to learn from.
    """
    key_size = 0.0
    if session.certificate and session.certificate.public_key_size:
        key_size = float(session.certificate.public_key_size)

    return np.array([
        _tls_version_numeric(session.tls_version),
        _cipher_strength(session.cipher_suite),
        _key_exchange_score(session.key_exchange),
        key_size,
        1.0 if session.forward_secrecy else 0.0,
        _cert_expired(session),
        _cert_self_signed(session),
        _hostname_match(session),
        1.0 if session.transport_mode == TransportMode.STARTTLS else 0.0,
        float(session.packet_count),
        session.session_duration_ms,
        float(session.retransmission_count),
    ], dtype=np.float64)


def extract_features_batch(sessions: list[SessionInfo]) -> np.ndarray:
    """Extract features for all sessions, returning a 2D array."""
    if not sessions:
        return np.empty((0, len(FEATURE_NAMES)))
    return np.vstack([extract_features(s) for s in sessions])
