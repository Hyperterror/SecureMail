"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import type { AnalysisResult, SessionInfo } from "@/lib/types";
import { TLS_VERSION_COLORS, RISK_COLORS, RISK_BG_COLORS } from "@/lib/constants";
import styles from "./page.module.css";

export default function SessionDetailPage() {
  const params = useParams();
  const router = useRouter();
  const analysisId = params.id as string;
  const sessionId = params.sessionId as string;

  const [session, setSession] = useState<SessionInfo | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem(`analysis_${analysisId}`);
    if (stored) {
      const a: AnalysisResult = JSON.parse(stored);
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setAnalysis(a);
      const s = a.sessions.find((s) => s.session_id === sessionId);
      if (s) setSession(s);
    }
  }, [analysisId, sessionId]);

  if (!session) {
    return (
      <div className={styles.loading}>
        <div className={styles.spinner} />
        <p>Loading session...</p>
      </div>
    );
  }

  const riskColor = RISK_COLORS[session.risk_level];
  const riskBg = RISK_BG_COLORS[session.risk_level];
  const tlsColor = TLS_VERSION_COLORS[session.tls_version] || "#94A3B8";

  return (
    <div className={styles.page}>
      {/* Back Button */}
      <button className={styles.backBtn} onClick={() => router.push(`/analysis/${analysisId}`)}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M19 12H5M12 19l-7-7 7-7" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        Back to Dashboard
      </button>

      {/* Session Header */}
      <div className={styles.sessionHeader}>
        <div className={styles.headerLeft}>
          <div className={styles.protoBadge}>{session.protocol}</div>
          <h1 className={styles.sessionTitle}>Session {session.session_id}</h1>
        </div>
        <div className={styles.riskBadgeLg} style={{ color: riskColor, background: riskBg }}>
          {session.risk_level}
        </div>
      </div>

      <div className={styles.grid}>
        {/* Connection Info */}
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>Connection</h2>
          <div className={styles.connFlow}>
            <div className={styles.endpoint}>
              <span className={styles.endpointLabel}>Client</span>
              <span className={styles.endpointValue}>{session.source_ip}:{session.source_port}</span>
            </div>
            <div className={styles.arrow}>→</div>
            <div className={styles.endpoint}>
              <span className={styles.endpointLabel}>Server</span>
              <span className={styles.endpointValue}>{session.dest_ip}:{session.dest_port}</span>
            </div>
          </div>
          <div className={styles.detailGrid}>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Protocol</span>
              <span className={styles.detailValue}>{session.protocol}</span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Transport</span>
              <span className={styles.detailValue}>{session.transport_mode}</span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Packets</span>
              <span className={styles.detailValue}>{session.packet_count}</span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Duration</span>
              <span className={styles.detailValue}>{(session.session_duration_ms / 1000).toFixed(2)}s</span>
            </div>
          </div>
        </div>

        {/* TLS Info */}
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>TLS Configuration</h2>
          <div className={styles.detailGrid}>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>TLS Version</span>
              <span className={styles.tlsVersionBadge} style={{ color: tlsColor, background: `${tlsColor}18` }}>
                {session.tls_version}
              </span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Cipher Suite</span>
              <span className={styles.detailValueMono}>{session.cipher_suite || "N/A"}</span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Key Exchange</span>
              <span className={styles.detailValue}>{session.key_exchange || "N/A"}</span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Forward Secrecy</span>
              <span className={session.forward_secrecy ? styles.statusGood : styles.statusBad}>
                {session.forward_secrecy ? "✓ Yes" : "✗ No"}
              </span>
            </div>
          </div>
        </div>

        {/* STARTTLS Timeline */}
        <div className={styles.card}>
          <h2 className={styles.cardTitle}>
            {session.transport_mode === "STARTTLS" ? "STARTTLS" : session.transport_mode} Timeline
          </h2>
          <div className={styles.timeline}>
            {session.starttls_timeline.map((step, i) => (
              <div key={i} className={styles.timelineItem}>
                <div className={styles.timelineDot}>
                  <div className={`${styles.dot} ${i === session.starttls_timeline.length - 1 ? styles.dotFinal : ""}`} />
                  {i < session.starttls_timeline.length - 1 && <div className={styles.timelineLine} />}
                </div>
                <span className={styles.timelineLabel}>{step}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Certificate Info */}
        {session.certificate ? (
          <div className={styles.card}>
            <h2 className={styles.cardTitle}>Certificate</h2>
            <div className={styles.detailGrid}>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Subject</span>
                <span className={styles.detailValue}>{session.certificate.subject || "N/A"}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Issuer</span>
                <span className={styles.detailValue}>{session.certificate.issuer || "N/A"}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Valid</span>
                <span className={styles.detailValue}>
                  {session.certificate.not_before || "?"} → {session.certificate.not_after || "?"}
                </span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Public Key</span>
                <span className={styles.detailValue}>
                  {session.certificate.public_key_algorithm} {session.certificate.public_key_size}
                </span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Signature</span>
                <span className={styles.detailValue}>{session.certificate.signature_algorithm}</span>
              </div>
              {session.certificate.san.length > 0 && (
                <div className={styles.detailItem}>
                  <span className={styles.detailLabel}>SAN</span>
                  <span className={styles.detailValue}>{session.certificate.san.join(", ")}</span>
                </div>
              )}
            </div>
            <div className={styles.certStatus}>
              {session.certificate.status.map((s, i) => (
                <span
                  key={i}
                  className={`${styles.certBadge} ${s === "Valid" ? styles.certValid : styles.certWarning}`}
                >
                  {s === "Valid" ? "✓" : "⚠"} {s}
                </span>
              ))}
            </div>
          </div>
        ) : (
          <div className={styles.card}>
            <h2 className={styles.cardTitle}>Certificate</h2>
            <p className={styles.noCert}>
              {session.tls_version === "None"
                ? "No TLS — plaintext connection"
                : session.tls_version === "TLS 1.3"
                ? "Certificate encrypted by TLS 1.3 (not visible without keylog)"
                : "Certificate data not available"}
            </p>
          </div>
        )}

        {/* Risk Breakdown */}
        <div className={`${styles.card} ${styles.fullWidth}`}>
          <h2 className={styles.cardTitle}>Risk Assessment</h2>
          <div className={styles.riskGrid}>
            <div className={styles.riskSection}>
              <div className={styles.riskScoreContainer}>
                <div className={styles.riskScoreCircle} style={{
                  background: `conic-gradient(${riskColor} ${session.rule_score * 3.6}deg, var(--bg-secondary) 0deg)`
                }}>
                  <div className={styles.riskScoreInner}>
                    <span className={styles.riskScoreValue} style={{ color: riskColor }}>{session.rule_score}</span>
                    <span className={styles.riskScoreLabel}>Rule Score</span>
                  </div>
                </div>
              </div>
            </div>

            <div className={styles.riskSection}>
              <h3 className={styles.riskSectionTitle}>ML Anomaly</h3>
              <div className={styles.anomalyBar}>
                <div
                  className={styles.anomalyFill}
                  style={{
                    width: `${session.ml_anomaly_score * 100}%`,
                    background: session.ml_anomaly_score > 0.7 ? "var(--color-critical)" : session.ml_anomaly_score > 0.4 ? "var(--color-medium)" : "var(--color-low)",
                  }}
                />
              </div>
              <div className={styles.anomalyMeta}>
                <span>Score: {(session.ml_anomaly_score * 100).toFixed(0)}%</span>
                <span>Confidence: {session.confidence.toFixed(0)}%</span>
              </div>
            </div>

            <div className={styles.riskSection}>
              <h3 className={styles.riskSectionTitle}>Overall</h3>
              <div className={styles.overallRisk} style={{ color: riskColor, background: riskBg }}>
                {session.risk_level}
              </div>
            </div>
          </div>
        </div>

        {/* Findings */}
        {session.findings.length > 0 && (
          <div className={`${styles.card} ${styles.fullWidth}`}>
            <h2 className={styles.cardTitle}>Findings ({session.findings.length})</h2>
            <div className={styles.findingsList}>
              {session.findings.map((finding) => (
                <div key={finding.finding_id} className={styles.findingItem}>
                  <div className={styles.findingHeader}>
                    <span
                      className={styles.findingSeverity}
                      style={{ color: RISK_COLORS[finding.severity], background: RISK_BG_COLORS[finding.severity] }}
                    >
                      {finding.severity}
                    </span>
                    <span className={styles.findingTitle}>{finding.title}</span>
                  </div>
                  <p className={styles.findingDesc}>{finding.description}</p>
                  <p className={styles.findingRec}>💡 {finding.recommendation}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
