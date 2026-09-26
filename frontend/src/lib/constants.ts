/**
 * Color maps, labels, and display constants for the UI.
 */

import type { RiskLevel, TLSVersion } from "./types";

export const TLS_VERSION_COLORS: Record<string, string> = {
  "TLS 1.3": "#0F766E",
  "TLS 1.2": "#2563EB",
  "TLS 1.1": "#EA580C",
  "TLS 1.0": "#DC2626",
  "SSL 3.0": "#991B1B",
  "None": "#94A3B8",
};

export const RISK_COLORS: Record<RiskLevel, string> = {
  Critical: "#DC2626",
  High: "#EA580C",
  Medium: "#D97706",
  Low: "#16A34A",
  Info: "#2563EB",
};

export const RISK_BG_COLORS: Record<RiskLevel, string> = {
  Critical: "rgba(220, 38, 38, 0.1)",
  High: "rgba(234, 88, 12, 0.1)",
  Medium: "rgba(217, 119, 6, 0.1)",
  Low: "rgba(22, 163, 74, 0.1)",
  Info: "rgba(37, 99, 235, 0.1)",
};

export const PROTOCOL_ICONS: Record<string, string> = {
  SMTP: "📧",
  IMAP: "📬",
  POP3: "📥",
  UNKNOWN: "❓",
};

export const TRANSPORT_ICONS: Record<string, string> = {
  "Implicit TLS": "🔒",
  STARTTLS: "🔐",
  Plaintext: "⚠️",
};

export const ANALYSIS_STAGES: Record<string, string> = {
  parsing: "Parsing PCAP",
  detecting_protocols: "Detecting protocols",
  reconstructing: "Reconstructing sessions",
  extracting_tls: "Extracting TLS",
  analyzing_certs: "Analyzing certificates",
  rule_engine: "Evaluating security rules",
  ml_detection: "Running anomaly detection",
  finalizing: "Finalizing results",
  complete: "Analysis complete",
  error: "Error",
};

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export function formatNumber(n: number): string {
  return n.toLocaleString();
}

export function truncateCipher(cipher: string | null, maxLen = 28): string {
  if (!cipher) return "N/A";
  if (cipher.length <= maxLen) return cipher;
  return cipher.slice(0, maxLen) + "…";
}
