"""Enumerations for SecureMailScope domain types."""

from enum import Enum


class Protocol(str, Enum):
    """Email protocol types detected from PCAP traffic."""
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class TLSVersion(str, Enum):
    """TLS/SSL protocol versions."""
    TLS_1_3 = "TLS 1.3"
    TLS_1_2 = "TLS 1.2"
    TLS_1_1 = "TLS 1.1"
    TLS_1_0 = "TLS 1.0"
    SSL_3_0 = "SSL 3.0"
    NONE = "None"


class TransportMode(str, Enum):
    """Email transport security modes."""
    IMPLICIT_TLS = "Implicit TLS"
    STARTTLS = "STARTTLS"
    PLAINTEXT = "Plaintext"


class RiskLevel(str, Enum):
    """Security risk severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class CertificateStatus(str, Enum):
    """Certificate validation status flags."""
    VALID = "Valid"
    EXPIRED = "Expired"
    SELF_SIGNED = "Self-signed"
    HOSTNAME_MISMATCH = "Hostname mismatch"
    UNAVAILABLE = "Unavailable"


# Port-to-protocol mappings for email traffic identification
EMAIL_PORTS = {
    25: Protocol.SMTP,
    587: Protocol.SMTP,
    465: Protocol.SMTP,
    143: Protocol.IMAP,
    993: Protocol.IMAP,
    110: Protocol.POP3,
    995: Protocol.POP3,
}

# Ports that use implicit TLS (TLS from connection start)
IMPLICIT_TLS_PORTS = {465, 993, 995}

# Ports that typically negotiate STARTTLS
STARTTLS_PORTS = {25, 587, 143, 110}

# TLS version security ranking (lower = worse)
TLS_VERSION_SECURITY = {
    TLSVersion.SSL_3_0: 0,
    TLSVersion.TLS_1_0: 1,
    TLSVersion.TLS_1_1: 2,
    TLSVersion.TLS_1_2: 3,
    TLSVersion.TLS_1_3: 4,
    TLSVersion.NONE: -1,
}
