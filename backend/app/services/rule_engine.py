"""
Rule-based security evaluation engine.

Applies deterministic security rules to each email session,
generating findings and a cumulative risk penalty score (0-100).
"""

from __future__ import annotations

from typing import Callable

from app.models.enums import (
    CertificateStatus,
    RiskLevel,
    TLSVersion,
    TransportMode,
)
from app.models.schemas import Finding, SessionInfo


# ---------------------------------------------------------------------------
# Cipher classification helpers
# ---------------------------------------------------------------------------

WEAK_CIPHERS = {
    "3DES", "DES", "RC4", "RC2", "NULL", "EXPORT", "anon", "MD5",
}

STRONG_CIPHERS = {
    "AES_256_GCM", "AES_128_GCM", "CHACHA20_POLY1305",
    "AES_256_CCM", "AES_128_CCM",
}


def _is_weak_cipher(cipher: str | None) -> bool:
    if not cipher:
        return False
    cipher_upper = cipher.upper()
    return any(weak in cipher_upper for weak in WEAK_CIPHERS)


def _has_no_forward_secrecy(session: SessionInfo) -> bool:
    return not session.forward_secrecy and session.tls_version != TLSVersion.NONE


def _is_cert_expired(session: SessionInfo) -> bool:
    if not session.certificate:
        return False
    return CertificateStatus.EXPIRED in session.certificate.status


def _is_cert_self_signed(session: SessionInfo) -> bool:
    if not session.certificate:
        return False
    return CertificateStatus.SELF_SIGNED in session.certificate.status


def _hostname_mismatch(session: SessionInfo) -> bool:
    if not session.certificate:
        return False
    return CertificateStatus.HOSTNAME_MISMATCH in session.certificate.status


def _is_small_key(session: SessionInfo) -> bool:
    if not session.certificate or not session.certificate.public_key_size:
        return False
    return session.certificate.public_key_size < 2048


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

RuleEntry = tuple[
    Callable[[SessionInfo], bool],  # condition
    int,                             # penalty (0-100)
    str,                             # title
    str,                             # description template
    str,                             # recommendation
]

RULES: list[RuleEntry] = [
    (
        lambda s: s.transport_mode == TransportMode.PLAINTEXT,
        35,
        "Plaintext Connection",
        "Email traffic on this session is completely unencrypted. "
        "All data, including credentials, is sent in cleartext.",
        "Enable TLS via STARTTLS or switch to an implicit-TLS port (465/993/995).",
    ),
    (
        lambda s: s.tls_version in (TLSVersion.TLS_1_0, TLSVersion.SSL_3_0),
        30,
        "Deprecated TLS Version",
        f"Session uses {{version}} which has known cryptographic vulnerabilities "
        f"and is deprecated by RFC 8996.",
        "Upgrade server and client configurations to TLS 1.2 or TLS 1.3.",
    ),
    (
        lambda s: s.tls_version == TLSVersion.TLS_1_1,
        15,
        "Legacy TLS Version",
        "TLS 1.1 is deprecated by RFC 8996 and is no longer considered secure "
        "for production use.",
        "Upgrade to TLS 1.2 or TLS 1.3.",
    ),
    (
        lambda s: _is_weak_cipher(s.cipher_suite),
        25,
        "Weak Cipher Suite",
        "Cipher suite {cipher} is considered cryptographically weak and may be "
        "vulnerable to known attacks.",
        "Configure the server to prefer AES-256-GCM, AES-128-GCM, or ChaCha20-Poly1305.",
    ),
    (
        lambda s: _has_no_forward_secrecy(s),
        15,
        "No Forward Secrecy",
        "The key exchange method does not provide forward secrecy. If the server's "
        "private key is compromised, all past sessions can be decrypted.",
        "Use ECDHE or DHE key exchange instead of static RSA.",
    ),
    (
        lambda s: _is_cert_expired(s),
        20,
        "Expired Certificate",
        "The server certificate has expired. Clients may reject the connection or "
        "users may be trained to bypass security warnings.",
        "Renew the certificate immediately and set up automated renewal.",
    ),
    (
        lambda s: _is_cert_self_signed(s),
        10,
        "Self-Signed Certificate",
        "The server certificate is not issued by a trusted Certificate Authority. "
        "Clients cannot verify the server's identity.",
        "Obtain a certificate from a trusted CA (e.g., Let's Encrypt).",
    ),
    (
        lambda s: _hostname_mismatch(s),
        15,
        "Certificate Hostname Mismatch",
        "The certificate's Common Name or Subject Alternative Names do not match "
        "the server hostname, enabling potential man-in-the-middle attacks.",
        "Reissue the certificate with the correct hostname in the SAN field.",
    ),
    (
        lambda s: _is_small_key(s),
        10,
        "Weak Key Size",
        "The certificate uses a {key_size}-bit key which is below the recommended "
        "minimum of 2048 bits.",
        "Regenerate the key pair with at least 2048-bit RSA or 256-bit ECDSA.",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _penalty_to_severity(penalty: int) -> RiskLevel:
    """Map a rule penalty to a risk severity level."""
    if penalty >= 30:
        return RiskLevel.CRITICAL
    if penalty >= 20:
        return RiskLevel.HIGH
    if penalty >= 15:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def evaluate(session: SessionInfo) -> tuple[int, list[Finding]]:
    """
    Evaluate a session against all security rules.

    Returns:
        (total_penalty, findings) — penalty capped at 100.
    """
    total = 0
    findings: list[Finding] = []
    finding_counter = 0

    for condition, penalty, title, desc_template, recommendation in RULES:
        try:
            if not condition(session):
                continue
        except Exception:
            continue

        total += penalty
        finding_counter += 1

        # Format description with session-specific values
        description = desc_template.format(
            version=session.tls_version.value if session.tls_version else "Unknown",
            cipher=session.cipher_suite or "Unknown",
            key_size=session.certificate.public_key_size if session.certificate else "Unknown",
        )

        findings.append(Finding(
            finding_id=f"FND-{session.session_id}-{finding_counter:03d}",
            session_id=session.session_id,
            severity=_penalty_to_severity(penalty),
            title=title,
            description=description,
            recommendation=recommendation,
        ))

    return min(total, 100), findings
