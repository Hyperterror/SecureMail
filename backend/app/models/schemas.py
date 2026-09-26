"""Pydantic schemas for SecureMailScope data models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .enums import CertificateStatus, Protocol, RiskLevel, TLSVersion, TransportMode


class CertificateInfo(BaseModel):
    """X.509 certificate details extracted from TLS handshake."""
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    public_key_algorithm: str | None = None
    public_key_size: int | None = None
    signature_algorithm: str | None = None
    san: list[str] = Field(default_factory=list)
    status: list[CertificateStatus] = Field(default_factory=list)


class Finding(BaseModel):
    """Individual security finding from rule-based or ML analysis."""
    finding_id: str
    session_id: str
    severity: RiskLevel
    title: str
    description: str
    recommendation: str


class SessionInfo(BaseModel):
    """Complete information about a single email session."""
    session_id: str
    protocol: Protocol
    transport_mode: TransportMode
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    tls_version: TLSVersion
    cipher_suite: str | None = None
    key_exchange: str | None = None
    forward_secrecy: bool = False
    certificate: CertificateInfo | None = None
    starttls_timeline: list[str] = Field(default_factory=list)
    packet_count: int = 0
    session_duration_ms: float = 0.0
    retransmission_count: int = 0
    # Scores
    rule_score: int = 0
    ml_anomaly_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    confidence: float = 0.0
    findings: list[Finding] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Complete analysis output for a PCAP file."""
    analysis_id: str
    filename: str
    file_size_bytes: int
    total_packets: int
    total_sessions: int
    total_findings: int
    security_posture: int  # 0-100, higher = better
    sessions: list[SessionInfo] = Field(default_factory=list)
    tls_version_distribution: dict[str, int] = Field(default_factory=dict)
    protocol_distribution: dict[str, int] = Field(default_factory=dict)
    transport_mode_distribution: dict[str, int] = Field(default_factory=dict)
    risk_distribution: dict[str, int] = Field(default_factory=dict)
    completed_at: str = ""


class AnalysisProgress(BaseModel):
    """Progress update sent via SSE during analysis."""
    stage: str
    progress: int  # 0-100
    message: str = ""


class UploadResponse(BaseModel):
    """Response after successful PCAP upload."""
    analysis_id: str
    filename: str
    file_size_bytes: int
