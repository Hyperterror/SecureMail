"""
Export service for generating JSON and HTML reports.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from app.models.schemas import AnalysisResult


def export_json(result: AnalysisResult) -> str:
    """Export analysis result as formatted JSON string."""
    return result.model_dump_json(indent=2)


def export_html(result: AnalysisResult) -> str:
    """Export analysis result as a self-contained HTML report."""
    data = result.model_dump()
    sessions_html = ""

    for s in data["sessions"]:
        risk_color = {
            "Critical": "#DC2626",
            "High": "#EA580C",
            "Medium": "#D97706",
            "Low": "#16A34A",
        }.get(s["risk_level"], "#64748B")

        findings_html = ""
        for f in s.get("findings", []):
            findings_html += f"""
            <div class="finding">
                <span class="severity" style="color: {
                    {"Critical": "#DC2626", "High": "#EA580C", "Medium": "#D97706", "Low": "#16A34A"}.get(f["severity"], "#64748B")
                }">⬤ {f["severity"]}</span>
                <strong>{f["title"]}</strong>
                <p>{f["description"]}</p>
                <p class="recommendation">💡 {f["recommendation"]}</p>
            </div>"""

        sessions_html += f"""
        <div class="session">
            <div class="session-header">
                <span class="protocol">{s["protocol"]}</span>
                <span class="endpoints">{s["source_ip"]}:{s["source_port"]} → {s["dest_ip"]}:{s["dest_port"]}</span>
                <span class="risk-badge" style="background: {risk_color}">{s["risk_level"]}</span>
            </div>
            <div class="session-details">
                <div class="detail-grid">
                    <div><strong>TLS Version:</strong> {s["tls_version"]}</div>
                    <div><strong>Cipher Suite:</strong> {s["cipher_suite"] or "N/A"}</div>
                    <div><strong>Key Exchange:</strong> {s["key_exchange"] or "N/A"}</div>
                    <div><strong>Forward Secrecy:</strong> {"Yes" if s["forward_secrecy"] else "No"}</div>
                    <div><strong>Transport:</strong> {s["transport_mode"]}</div>
                    <div><strong>Rule Score:</strong> {s["rule_score"]}/100</div>
                    <div><strong>ML Anomaly:</strong> {s["ml_anomaly_score"]:.2f}</div>
                    <div><strong>Confidence:</strong> {s.get("confidence", 0):.0f}%</div>
                </div>
                {findings_html}
            </div>
        </div>"""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope Report — {data["filename"]}</title>
    <style>
        :root {{
            --bg: #07111F;
            --card: #0B1727;
            --text: #E2E8F0;
            --text2: #94A3B8;
            --border: #1E293B;
            --teal: #0F766E;
            --cyan: #155E75;
            --navy: #0F172A;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .header {{
            background: linear-gradient(135deg, var(--navy), var(--cyan), var(--teal));
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; }}
        .header p {{ color: var(--text2); margin-top: 0.5rem; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }}
        .summary-card .value {{ font-size: 2rem; font-weight: 700; color: var(--teal); }}
        .summary-card .label {{ color: var(--text2); font-size: 0.875rem; }}
        .session {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}
        .session-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .protocol {{ font-weight: 700; color: var(--teal); }}
        .endpoints {{ color: var(--text2); flex: 1; font-family: monospace; font-size: 0.875rem; }}
        .risk-badge {{
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 700;
        }}
        .session-details {{ padding: 1rem 1.5rem; }}
        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
            font-size: 0.875rem;
        }}
        .finding {{
            margin-top: 1rem;
            padding: 0.75rem;
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
        }}
        .finding .severity {{ font-weight: 700; font-size: 0.75rem; margin-right: 0.5rem; }}
        .finding p {{ color: var(--text2); font-size: 0.813rem; margin-top: 0.25rem; }}
        .recommendation {{ font-style: italic; }}
        .footer {{
            text-align: center;
            color: var(--text2);
            margin-top: 2rem;
            font-size: 0.75rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 SecureMailScope — Security Analysis Report</h1>
        <p>{data["filename"]} · {data["file_size_bytes"] / 1_048_576:.1f} MB · {data["total_packets"]:,} packets · Generated {now}</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <div class="value">{data["security_posture"]}/100</div>
            <div class="label">Security Posture</div>
        </div>
        <div class="summary-card">
            <div class="value">{data["total_sessions"]}</div>
            <div class="label">Sessions</div>
        </div>
        <div class="summary-card">
            <div class="value">{data["total_findings"]}</div>
            <div class="label">Findings</div>
        </div>
        <div class="summary-card">
            <div class="value">{data.get("risk_distribution", {{}}).get("Critical", 0)}</div>
            <div class="label">Critical Issues</div>
        </div>
    </div>

    <h2 style="margin-bottom: 1rem;">Sessions</h2>
    {sessions_html}

    <div class="footer">
        <p>SecureMailScope — Passive Email Cryptographic Forensics</p>
    </div>
</body>
</html>"""

    return html
