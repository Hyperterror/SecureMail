"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import type { AnalysisResult, SessionInfo, RiskLevel, TLSVersion, TransportMode, Protocol } from "@/lib/types";
import { TLS_VERSION_COLORS, RISK_COLORS, RISK_BG_COLORS, PROTOCOL_ICONS, TRANSPORT_ICONS, formatBytes, formatNumber, truncateCipher } from "@/lib/constants";
import { getExportUrl } from "@/lib/api";
import styles from "./page.module.css";

interface Filters {
  protocol: string;
  tlsVersion: string;
  transport: string;
  risk: string;
  forwardSecrecy: string;
  search: string;
}

const defaultFilters: Filters = {
  protocol: "All",
  tlsVersion: "All",
  transport: "All",
  risk: "All",
  forwardSecrecy: "All",
  search: "",
};

export default function DashboardPage() {
  const params = useParams();
  const router = useRouter();
  const analysisId = params.id as string;

  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [filters, setFilters] = useState<Filters>(defaultFilters);
  const [sortColumn, setSortColumn] = useState<string>("risk_level");
  const [sortAsc, setSortAsc] = useState(false);
  const [sidebarActive, setSidebarActive] = useState("overview");

  useEffect(() => {
    const stored = sessionStorage.getItem(`analysis_${analysisId}`);
    if (stored) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setAnalysis(JSON.parse(stored));
    }
  }, [analysisId]);

  const filteredSessions = useMemo(() => {
    if (!analysis) return [];
    let sessions = [...analysis.sessions];

    if (filters.protocol !== "All") sessions = sessions.filter((s) => s.protocol === filters.protocol);
    if (filters.tlsVersion !== "All") sessions = sessions.filter((s) => s.tls_version === filters.tlsVersion);
    if (filters.transport !== "All") sessions = sessions.filter((s) => s.transport_mode === filters.transport);
    if (filters.risk !== "All") sessions = sessions.filter((s) => s.risk_level === filters.risk);
    if (filters.forwardSecrecy !== "All") sessions = sessions.filter((s) => filters.forwardSecrecy === "Yes" ? s.forward_secrecy : !s.forward_secrecy);
    if (filters.search) {
      const q = filters.search.toLowerCase();
      sessions = sessions.filter((s) =>
        s.source_ip.includes(q) || s.dest_ip.includes(q) || s.session_id.toLowerCase().includes(q) || (s.cipher_suite && s.cipher_suite.toLowerCase().includes(q))
      );
    }

    const riskOrder: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    sessions.sort((a, b) => {
      let cmp = 0;
      switch (sortColumn) {
        case "protocol": cmp = a.protocol.localeCompare(b.protocol); break;
        case "source": cmp = a.source_ip.localeCompare(b.source_ip); break;
        case "dest": cmp = a.dest_ip.localeCompare(b.dest_ip); break;
        case "tls_version": cmp = a.tls_version.localeCompare(b.tls_version); break;
        case "risk_level": cmp = (riskOrder[a.risk_level] ?? 5) - (riskOrder[b.risk_level] ?? 5); break;
        default: cmp = 0;
      }
      return sortAsc ? cmp : -cmp;
    });

    return sessions;
  }, [analysis, filters, sortColumn, sortAsc]);

  const handleSort = useCallback((col: string) => {
    if (sortColumn === col) setSortAsc(!sortAsc);
    else { setSortColumn(col); setSortAsc(true); }
  }, [sortColumn, sortAsc]);

  const setFilter = useCallback((key: keyof Filters, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  }, []);

  const quickFilters = useMemo(() => {
    if (!analysis) return [];
    const items: { label: string; count: number; filterKey: keyof Filters; filterValue: string }[] = [];
    const tls10 = analysis.sessions.filter((s) => s.tls_version === "TLS 1.0").length;
    const tls11 = analysis.sessions.filter((s) => s.tls_version === "TLS 1.1").length;
    const expired = analysis.sessions.filter((s) => s.certificate?.status.includes("Expired")).length;
    const weakCiphers = analysis.sessions.filter((s) => s.cipher_suite && /3DES|DES|RC4|NULL/i.test(s.cipher_suite)).length;
    const noFS = analysis.sessions.filter((s) => !s.forward_secrecy && s.tls_version !== "None").length;
    const anomalies = analysis.sessions.filter((s) => s.ml_anomaly_score > 0.7).length;
    const plaintext = analysis.sessions.filter((s) => s.transport_mode === "Plaintext").length;

    if (tls10 > 0) items.push({ label: "TLS 1.0", count: tls10, filterKey: "tlsVersion", filterValue: "TLS 1.0" });
    if (tls11 > 0) items.push({ label: "TLS 1.1", count: tls11, filterKey: "tlsVersion", filterValue: "TLS 1.1" });
    if (expired > 0) items.push({ label: "Expired Certs", count: expired, filterKey: "risk", filterValue: "Critical" });
    if (weakCiphers > 0) items.push({ label: "Weak Ciphers", count: weakCiphers, filterKey: "risk", filterValue: "High" });
    if (noFS > 0) items.push({ label: "No Forward Secrecy", count: noFS, filterKey: "forwardSecrecy", filterValue: "No" });
    if (plaintext > 0) items.push({ label: "Plaintext", count: plaintext, filterKey: "transport", filterValue: "Plaintext" });
    if (anomalies > 0) items.push({ label: "Anomalies", count: anomalies, filterKey: "risk", filterValue: "High" });
    return items;
  }, [analysis]);

  if (!analysis) {
    return (
      <div className={styles.loading}>
        <div className={styles.spinner} />
        <p>Loading analysis...</p>
      </div>
    );
  }

  const postureColor = analysis.security_posture >= 75 ? "var(--color-low)" : analysis.security_posture >= 50 ? "var(--color-medium)" : analysis.security_posture >= 25 ? "var(--color-high)" : "var(--color-critical)";
  const hasActiveFilters = Object.values(filters).some((v) => v !== "All" && v !== "");

  return (
    <div className={styles.layout}>
      {/* Sidebar */}
      <aside className={styles.sidebar}>
        <div className={styles.sidebarLogo}>
          <svg width="28" height="28" viewBox="0 0 48 48" fill="none">
            <rect width="48" height="48" rx="10" fill="url(#sgrad)" />
            <path d="M14 18L24 25L34 18M14 30H34M14 18V30H34V18H14Z" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            <defs>
              <linearGradient id="sgrad" x1="0" y1="0" x2="48" y2="48">
                <stop stopColor="#0F172A" /><stop offset="0.5" stopColor="#155E75" /><stop offset="1" stopColor="#0F766E" />
              </linearGradient>
            </defs>
          </svg>
          <span>SecureMailScope</span>
        </div>

        <nav className={styles.sidebarNav}>
          <button className={`${styles.navItem} ${sidebarActive === "overview" ? styles.navActive : ""}`} onClick={() => setSidebarActive("overview")}>
            <span>📊</span> Overview
          </button>
          <button className={`${styles.navItem} ${sidebarActive === "sessions" ? styles.navActive : ""}`} onClick={() => setSidebarActive("sessions")}>
            <span>🔗</span> Sessions
          </button>
          <button className={`${styles.navItem} ${sidebarActive === "findings" ? styles.navActive : ""}`} onClick={() => setSidebarActive("findings")}>
            <span>🔍</span> Findings
          </button>
          <button className={`${styles.navItem} ${sidebarActive === "certificates" ? styles.navActive : ""}`} onClick={() => setSidebarActive("certificates")}>
            <span>📜</span> Certificates
          </button>
        </nav>

        <div className={styles.sidebarDivider} />

        <nav className={styles.sidebarNav}>
          <a href={getExportUrl(analysisId, "json")} className={styles.navItem} target="_blank" rel="noreferrer">
            <span>📄</span> Export JSON
          </a>
          <a href={getExportUrl(analysisId, "html")} className={styles.navItem} target="_blank" rel="noreferrer">
            <span>🌐</span> Export HTML
          </a>
        </nav>

        <div className={styles.sidebarFooter}>
          <button className={styles.newAnalysis} onClick={() => router.push("/")}>
            + New Analysis
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className={styles.main}>
        {/* Header */}
        <header className={styles.header}>
          <div>
            <h1 className={styles.headerTitle}>
              Analysis: <span className={styles.headerFilename}>{analysis.filename}</span>
            </h1>
            <p className={styles.headerMeta}>
              Completed • {formatNumber(analysis.total_packets)} packets • {analysis.total_sessions} sessions • {formatBytes(analysis.file_size_bytes)}
            </p>
          </div>
        </header>

        {/* Summary Cards */}
        <div className={`${styles.summaryGrid} stagger-children`}>
          <div className={styles.summaryCard}>
            <div className={styles.summaryValue} style={{ color: postureColor }}>
              {analysis.security_posture}
              <span className={styles.summaryUnit}>/100</span>
            </div>
            <div className={styles.summaryLabel}>Security Posture</div>
            <div className={styles.postureBar}>
              <div className={styles.postureFill} style={{ width: `${analysis.security_posture}%`, background: postureColor }} />
            </div>
          </div>

          <div className={styles.summaryCard}>
            <div className={styles.summaryValue}>{analysis.total_sessions}</div>
            <div className={styles.summaryLabel}>Sessions</div>
          </div>

          <div className={styles.summaryCard}>
            <div className={styles.summaryValue} style={{ color: analysis.total_findings > 0 ? "var(--color-high)" : "var(--color-low)" }}>
              {analysis.total_findings}
            </div>
            <div className={styles.summaryLabel}>Findings</div>
          </div>

          <div className={styles.summaryCard}>
            <div className={styles.summaryValue} style={{ color: "var(--color-critical)" }}>
              {analysis.risk_distribution["Critical"] || 0}
            </div>
            <div className={styles.summaryLabel}>Critical Issues</div>
          </div>
        </div>

        {/* Charts Row */}
        <div className={styles.chartsRow}>
          {/* TLS Version Distribution */}
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}>TLS Versions</h3>
            <div className={styles.barChart}>
              {Object.entries(analysis.tls_version_distribution)
                .sort(([a], [b]) => {
                  const order = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "None"];
                  return order.indexOf(a) - order.indexOf(b);
                })
                .map(([version, count]) => {
                  const maxCount = Math.max(...Object.values(analysis.tls_version_distribution));
                  const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
                  const color = TLS_VERSION_COLORS[version] || "#94A3B8";
                  const isActive = filters.tlsVersion === version;

                  return (
                    <button
                      key={version}
                      className={`${styles.barRow} ${isActive ? styles.barActive : ""}`}
                      onClick={() => setFilter("tlsVersion", isActive ? "All" : version)}
                    >
                      <span className={styles.barLabel}>{version}</span>
                      <div className={styles.barTrack}>
                        <div className={styles.barFill} style={{ width: `${pct}%`, background: color }} />
                      </div>
                      <span className={styles.barCount} style={{ color }}>{count}</span>
                    </button>
                  );
                })}
            </div>
          </div>

          {/* Protocol Breakdown */}
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}>Protocols</h3>
            <div className={styles.statsList}>
              {Object.entries(analysis.protocol_distribution).map(([proto, count]) => (
                <button
                  key={proto}
                  className={`${styles.statItem} ${filters.protocol === proto ? styles.statActive : ""}`}
                  onClick={() => setFilter("protocol", filters.protocol === proto ? "All" : proto)}
                >
                  <span className={styles.statIcon}>{PROTOCOL_ICONS[proto] || "📨"}</span>
                  <span className={styles.statName}>{proto}</span>
                  <span className={styles.statCount}>{count}</span>
                </button>
              ))}
            </div>

            <h3 className={styles.chartTitle} style={{ marginTop: "1.5rem" }}>Transport Mode</h3>
            <div className={styles.statsList}>
              {Object.entries(analysis.transport_mode_distribution).map(([mode, count]) => (
                <button
                  key={mode}
                  className={`${styles.statItem} ${filters.transport === mode ? styles.statActive : ""}`}
                  onClick={() => setFilter("transport", filters.transport === mode ? "All" : mode)}
                >
                  <span className={styles.statIcon}>{TRANSPORT_ICONS[mode] || "🔗"}</span>
                  <span className={styles.statName}>{mode}</span>
                  <span className={styles.statCount}>{count}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Quick Filters */}
        {quickFilters.length > 0 && (
          <div className={styles.quickFilters}>
            {quickFilters.map((qf) => (
              <button
                key={qf.label}
                className={`${styles.filterChip} ${filters[qf.filterKey] === qf.filterValue ? styles.chipActive : ""}`}
                onClick={() => setFilter(qf.filterKey, filters[qf.filterKey] === qf.filterValue ? "All" : qf.filterValue)}
              >
                {qf.label}: {qf.count}
              </button>
            ))}
            {hasActiveFilters && (
              <button className={styles.clearFilters} onClick={() => setFilters(defaultFilters)}>
                Clear all
              </button>
            )}
          </div>
        )}

        {/* Session Explorer */}
        <div className={styles.tableCard}>
          <div className={styles.tableHeader}>
            <h3 className={styles.tableTitle}>
              Session Explorer
              {hasActiveFilters && <span className={styles.filteredCount}>{filteredSessions.length} of {analysis.total_sessions}</span>}
            </h3>
            <div className={styles.searchBox}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" strokeLinecap="round" />
              </svg>
              <input
                type="text"
                placeholder="Search IP, host, session..."
                value={filters.search}
                onChange={(e) => setFilter("search", e.target.value)}
              />
            </div>
          </div>

          <div className={styles.tableWrapper}>
            <table className={styles.table}>
              <thead>
                <tr>
                  {[
                    { key: "protocol", label: "Protocol" },
                    { key: "source", label: "Source" },
                    { key: "dest", label: "Destination" },
                    { key: "tls_version", label: "TLS" },
                    { key: "cipher", label: "Cipher" },
                    { key: "fs", label: "FS" },
                    { key: "risk_level", label: "Risk" },
                  ].map(({ key, label }) => (
                    <th key={key} onClick={() => handleSort(key)} className={styles.sortable}>
                      {label}
                      {sortColumn === key && <span className={styles.sortArrow}>{sortAsc ? "↑" : "↓"}</span>}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredSessions.map((session) => (
                  <tr
                    key={session.session_id}
                    className={styles.tableRow}
                    onClick={() => router.push(`/analysis/${analysisId}/session/${session.session_id}`)}
                  >
                    <td>
                      <span className={styles.protoBadge}>{session.protocol}</span>
                    </td>
                    <td className={styles.monoCell}>{session.source_ip}:{session.source_port}</td>
                    <td className={styles.monoCell}>{session.dest_ip}:{session.dest_port}</td>
                    <td>
                      <span className={styles.tlsBadge} style={{ color: TLS_VERSION_COLORS[session.tls_version], background: `${TLS_VERSION_COLORS[session.tls_version]}18` }}>
                        {session.tls_version}
                      </span>
                    </td>
                    <td className={styles.cipherCell}>{truncateCipher(session.cipher_suite)}</td>
                    <td>
                      <span className={session.forward_secrecy ? styles.fsYes : styles.fsNo}>
                        {session.forward_secrecy ? "✓" : "✗"}
                      </span>
                    </td>
                    <td>
                      <span className={styles.riskBadge} style={{ color: RISK_COLORS[session.risk_level], background: RISK_BG_COLORS[session.risk_level] }}>
                        {session.risk_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredSessions.length === 0 && (
              <div className={styles.emptyState}>
                <p>No sessions match the current filters</p>
                <button onClick={() => setFilters(defaultFilters)}>Clear filters</button>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
