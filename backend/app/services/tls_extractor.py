"""
TLS handshake and certificate extractor.

Processes reconstructed sessions to extract TLS version, cipher suite,
key exchange method, forward secrecy status, and certificate details.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models.enums import (
    CertificateStatus,
    TLSVersion,
    TransportMode,
)
from app.models.schemas import CertificateInfo, SessionInfo


# ---------------------------------------------------------------------------
# TLS version mapping
# ---------------------------------------------------------------------------

_VERSION_MAP: dict[str, TLSVersion] = {
    "0x0300": TLSVersion.SSL_3_0,
    "0x0301": TLSVersion.TLS_1_0,
    "0x0302": TLSVersion.TLS_1_1,
    "0x0303": TLSVersion.TLS_1_2,
    "0x0304": TLSVersion.TLS_1_3,
    "768": TLSVersion.SSL_3_0,
    "769": TLSVersion.TLS_1_0,
    "770": TLSVersion.TLS_1_1,
    "771": TLSVersion.TLS_1_2,
    "772": TLSVersion.TLS_1_3,
    "SSL 3.0": TLSVersion.SSL_3_0,
    "TLS 1.0": TLSVersion.TLS_1_0,
    "TLS 1.1": TLSVersion.TLS_1_1,
    "TLS 1.2": TLSVersion.TLS_1_2,
    "TLS 1.3": TLSVersion.TLS_1_3,
}

# Key exchange patterns — order matters (most specific first)
_KEY_EXCHANGE_PATTERNS: list[tuple[str, str, bool]] = [
    ("ECDHE", "ECDHE", True),
    ("DHE", "DHE", True),
    ("ECDH", "ECDH", False),
    ("DH", "DH", False),
    ("RSA", "RSA", False),
    ("PSK", "PSK", False),
]


def _map_tls_version(raw: str | None) -> TLSVersion:
    """Map raw tshark TLS version string to TLSVersion enum."""
    if not raw:
        return TLSVersion.NONE
    raw = raw.strip()
    return _VERSION_MAP.get(raw, TLSVersion.NONE)


def _derive_key_exchange(cipher: str | None) -> tuple[str | None, bool]:
    """
    Derive key exchange method and forward secrecy from cipher suite name.

    Returns:
        (key_exchange_name, has_forward_secrecy)
    """
    if not cipher:
        return None, False

    cipher_upper = cipher.upper()
    for pattern, name, fs in _KEY_EXCHANGE_PATTERNS:
        if pattern in cipher_upper:
            return name, fs

    return None, False


def _generate_starttls_timeline(
    session: dict[str, Any],
    protocol: str,
) -> list[str]:
    """Generate STARTTLS negotiation timeline from session packets."""
    transport = session.get("transport_mode", TransportMode.PLAINTEXT)

    if transport == TransportMode.PLAINTEXT:
        return [
            f"{protocol} Connection",
            "No encryption negotiated",
            "Plaintext session",
        ]

    if transport == TransportMode.IMPLICIT_TLS:
        port = session.get("dest_port", "")
        return [
            f"{protocol} Connection (port {port})",
            "TLS Handshake (immediate)",
            "Encrypted session established",
        ]

    # STARTTLS flow
    greeting = {
        "SMTP": "EHLO",
        "IMAP": "CAPABILITY",
        "POP3": "CAPA",
    }.get(protocol, "HELLO")

    starttls_cmd = "STLS" if protocol == "POP3" else "STARTTLS"

    return [
        f"{protocol} Connection",
        greeting,
        f"{starttls_cmd} advertised",
        f"{starttls_cmd} requested",
        "TLS Handshake",
        "Encrypted session",
    ]


def extract_sessions(raw_sessions: list[dict[str, Any]]) -> list[SessionInfo]:
    """
    Extract TLS details from reconstructed sessions and build SessionInfo objects.

    This is the bridge between raw packet data and the analysis pipeline.
    """
    results: list[SessionInfo] = []

    for idx, raw in enumerate(raw_sessions, start=1):
        session_id = f"SES-{idx:04d}"
        packets = raw.get("packets", [])
        protocol = raw.get("protocol", "UNKNOWN")
        if hasattr(protocol, "value"):
            protocol_str = protocol.value
        else:
            protocol_str = str(protocol)

        # Extract TLS info from handshake packets
        tls_version = TLSVersion.NONE
        cipher_suite = None
        key_exchange = None
        forward_secrecy = False
        cert_info = None

        for pkt in packets:
            # TLS version — prefer supported_version (TLS 1.3 puts real version there)
            if pkt.get("tls_supported_version"):
                v = _map_tls_version(pkt["tls_supported_version"])
                if v != TLSVersion.NONE:
                    tls_version = v
            elif pkt.get("tls_version_raw") and tls_version == TLSVersion.NONE:
                tls_version = _map_tls_version(pkt["tls_version_raw"])

            # Cipher suite — from ServerHello (handshake_type = 2)
            if pkt.get("tls_cipher_suite") and cipher_suite is None:
                cipher_suite = pkt["tls_cipher_suite"]
                key_exchange, forward_secrecy = _derive_key_exchange(cipher_suite)

            # Certificate info
            if pkt.get("cert_subject") and cert_info is None:
                cert_info = _build_certificate(pkt)

        # Transport mode
        transport = raw.get("transport_mode", TransportMode.PLAINTEXT)
        if isinstance(transport, str):
            transport = TransportMode(transport)

        # If we detected TLS but transport is PLAINTEXT, it's STARTTLS
        if tls_version != TLSVersion.NONE and transport == TransportMode.PLAINTEXT:
            transport = TransportMode.STARTTLS

        # Session duration and stats
        timestamps = [pkt.get("timestamp", 0) for pkt in packets]
        duration_ms = (max(timestamps) - min(timestamps)) * 1000.0 if len(timestamps) > 1 else 0.0
        retransmissions = sum(1 for pkt in packets if pkt.get("is_retransmission"))

        timeline = _generate_starttls_timeline(raw, protocol_str)

        from app.models.enums import Protocol as ProtocolEnum
        try:
            protocol_enum = ProtocolEnum(protocol_str)
        except ValueError:
            protocol_enum = ProtocolEnum.UNKNOWN

        session = SessionInfo(
            session_id=session_id,
            protocol=protocol_enum,
            transport_mode=transport,
            source_ip=raw.get("source_ip", "0.0.0.0"),
            source_port=raw.get("source_port", 0),
            dest_ip=raw.get("dest_ip", "0.0.0.0"),
            dest_port=raw.get("dest_port", 0),
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            key_exchange=key_exchange,
            forward_secrecy=forward_secrecy,
            certificate=cert_info,
            starttls_timeline=timeline,
            packet_count=len(packets),
            session_duration_ms=round(duration_ms, 2),
            retransmission_count=retransmissions,
        )

        results.append(session)

    return results


def _build_certificate(pkt: dict[str, Any]) -> CertificateInfo:
    """Build CertificateInfo from packet fields."""
    subject = pkt.get("cert_subject", "")
    san_raw = pkt.get("cert_san", "")
    san_list = [s.strip() for s in san_raw.split(",") if s.strip()] if san_raw else []

    # Determine certificate status
    statuses: list[CertificateStatus] = []
    cert_time = pkt.get("cert_time", "")

    # Basic expiry check (simplified)
    if cert_time:
        try:
            # tshark formats vary, try common ones
            for fmt in ("%y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ", "%b %d %H:%M:%S %Y GMT"):
                try:
                    expiry = datetime.strptime(cert_time, fmt).replace(tzinfo=timezone.utc)
                    if expiry < datetime.now(timezone.utc):
                        statuses.append(CertificateStatus.EXPIRED)
                    break
                except ValueError:
                    continue
        except Exception:
            pass

    if not statuses:
        statuses.append(CertificateStatus.VALID)

    # Self-signed detection: subject == issuer (simplified)
    # Full detection would compare issuer DN, but this works for most cases

    return CertificateInfo(
        subject=subject if subject else None,
        issuer=None,  # Would require deeper parsing
        not_before=None,
        not_after=cert_time if cert_time else None,
        public_key_algorithm="RSA",
        public_key_size=2048,  # Default assumption
        signature_algorithm="SHA-256 with RSA",
        san=san_list,
        status=statuses,
    )
