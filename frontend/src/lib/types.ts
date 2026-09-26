/**
 * TypeScript types matching the backend Pydantic schemas.
 * This is the contract between frontend and backend.
 */

export type Protocol = "SMTP" | "IMAP" | "POP3" | "UNKNOWN";
export type TLSVersion = "TLS 1.3" | "TLS 1.2" | "TLS 1.1" | "TLS 1.0" | "SSL 3.0" | "None";
export type TransportMode = "Implicit TLS" | "STARTTLS" | "Plaintext";
export type RiskLevel = "Critical" | "High" | "Medium" | "Low" | "Info";
export type CertificateStatus = "Valid" | "Expired" | "Self-signed" | "Hostname mismatch" | "Unavailable";

export interface CertificateInfo {
  subject: string | null;
  issuer: string | null;
  not_before: string | null;
  not_after: string | null;
  public_key_algorithm: string | null;
  public_key_size: number | null;
  signature_algorithm: string | null;
  san: string[];
  status: CertificateStatus[];
}

export interface Finding {
  finding_id: string;
  session_id: string;
  severity: RiskLevel;
  title: string;
  description: string;
  recommendation: string;
}

export interface SessionInfo {
  session_id: string;
  protocol: Protocol;
  transport_mode: TransportMode;
  source_ip: string;
  source_port: number;
  dest_ip: string;
  dest_port: number;
  tls_version: TLSVersion;
  cipher_suite: string | null;
  key_exchange: string | null;
  forward_secrecy: boolean;
  certificate: CertificateInfo | null;
  starttls_timeline: string[];
  packet_count: number;
  session_duration_ms: number;
  retransmission_count: number;
  rule_score: number;
  ml_anomaly_score: number;
  risk_level: RiskLevel;
  confidence: number;
  findings: Finding[];
}

export interface AnalysisResult {
  analysis_id: string;
  filename: string;
  file_size_bytes: number;
  total_packets: number;
  total_sessions: number;
  total_findings: number;
  security_posture: number;
  sessions: SessionInfo[];
  tls_version_distribution: Record<string, number>;
  protocol_distribution: Record<string, number>;
  transport_mode_distribution: Record<string, number>;
  risk_distribution: Record<string, number>;
  completed_at: string;
}

export interface AnalysisProgress {
  stage: string;
  progress: number;
  message: string;
  result?: AnalysisResult;
}

export interface UploadResponse {
  analysis_id: string;
  filename: string;
  file_size_bytes: number;
}
