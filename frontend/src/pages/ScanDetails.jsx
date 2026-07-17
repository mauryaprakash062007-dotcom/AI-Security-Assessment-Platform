import { useParams, Link } from "react-router-dom";
import { useEffect, useState, useCallback, useRef } from "react";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
const WS_API = API.replace(/^http/, "ws");

const SEV_STYLE = {
  critical:              { bg: "#7f1d1d33", color: "#f87171",  border: "#f8717144" },
  high:                  { bg: "#7c2d1233", color: "#fb923c",  border: "#fb923c44" },
  medium:                { bg: "#78350f33", color: "#fbbf24",  border: "#fbbf2444" },
  low:                   { bg: "#14532d33", color: "#4ade80",  border: "#4ade8044" },
  info:                  { bg: "#1e3a5f33", color: "#60a5fa",  border: "#60a5fa44" },
  "unscored (pre-nvd)":  { bg: "#1f2937",   color: "#9ca3af",  border: "#374151"   },
  unknown:               { bg: "#1f2937",   color: "#9ca3af",  border: "#374151"   },
};

function SevBadge({ severity }) {
  const key = (severity || "unknown").toLowerCase();
  const s   = SEV_STYLE[key] || SEV_STYLE.unknown;
  return (
    <span style={{
      background: s.bg, color: s.color,
      border: `1px solid ${s.border}`,
      padding: "2px 10px", borderRadius: 20,
      fontSize: 11, fontWeight: 700,
      textTransform: "uppercase", letterSpacing: "0.06em",
    }}>
      {severity || "Unknown"}
    </span>
  );
}

function Section({ title, children }) {
  return (
    <div style={{
      background: "var(--surface)", border: "1px solid var(--border)",
      borderRadius: 12, padding: "1.5rem", marginBottom: "1.5rem",
    }}>
      <h2 style={{
        margin: "0 0 1.2rem", fontSize: "0.85rem", fontWeight: 700,
        textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--text-muted)",
      }}>
        {title}
      </h2>
      {children}
    </div>
  );
}

function Table({ cols, rows, empty = "No data." }) {
  if (!rows || rows.length === 0)
    return <p style={{ color: "var(--text-muted)", fontSize: 14, margin: 0 }}>{empty}</p>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid var(--border)" }}>
            {cols.map(c => (
              <th key={c} style={{
                textAlign: "left", padding: "8px 12px",
                fontSize: 11, textTransform: "uppercase",
                letterSpacing: "0.07em", color: "var(--text-muted)", fontWeight: 600,
              }}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  );
}

export default function ScanDetails() {
  const { id } = useParams();

  const [scanResult,  setScanResult]  = useState(null);
  const [report,      setReport]      = useState(null);
  const [phase,       setPhase]       = useState("queued");
  const [status,      setStatus]      = useState("");
  const [loadError,   setLoadError]   = useState("");
  const [reportError, setReportError] = useState("");
  const [reportLoading, setReportLoading] = useState(false);
  const reportLoadedRef = useRef(false);

  // Load scan result from DB
  const loadScanResult = useCallback(async () => {
    try {
      const res  = await fetch(`${API}/scan/result/${id}`);
      if (!res.ok) { setLoadError("Scan not found."); return null; }
      const data = await res.json();
      setScanResult(data);
      setPhase(data.phase  || "queued");
      setStatus(data.status || "");
      return data;
    } catch (e) {
      setLoadError("Failed to load scan: " + e.message);
      return null;
    }
  }, [id]);

  // Load report (CVE data) — only once when scan is done
  const loadReport = useCallback(async () => {
    if (reportLoadedRef.current) return;
    reportLoadedRef.current = true;
    setReportLoading(true);
    try {
      // Trigger CVE population first
      await fetch(`${API}/vulnerabilities/${id}`);
      // Then fetch the report
      const res  = await fetch(`${API}/report/${id}`);
      if (!res.ok) { setReportError("Report not available yet."); return; }
      const data = await res.json();
      setReport(data);
    } catch (e) {
      setReportError("Failed to load report: " + e.message);
    } finally {
      setReportLoading(false);
    }
  }, [id]);

  useEffect(() => {
    let stopped = false;
    let iv = null;
    let ws = null;

    // Initial load from DB
    loadScanResult().then((data) => {
      if (!data || stopped) return;
      if (data.phase === "done") {
        setTimeout(() => loadReport(), 800);
        return;
      }
      if (data.phase === "failed") return;

      // Try WebSocket for live updates
      try {
        ws = new WebSocket(`${WS_API}/ws/scan/${id}`);
        ws.onmessage = (event) => {
          const msg = JSON.parse(event.data);
          if (msg.type === "progress") {
            setPhase(msg.phase);
          } else if (msg.type === "complete") {
            setPhase("done");
            loadScanResult().then(() => setTimeout(() => loadReport(), 800));
          } else if (msg.type === "failed") {
            setPhase("failed");
            loadScanResult();
          }
        };
        ws.onerror = () => startPolling();
        ws.onclose = () => { ws = null; };
      } catch {
        startPolling();
      }
    });

    // Fallback: HTTP polling
    function startPolling() {
      if (stopped || iv) return;
      iv = setInterval(async () => {
        const data = await loadScanResult();
        if (!data || stopped) return;
        if (data.phase === "done") {
          clearInterval(iv);
          setTimeout(() => loadReport(), 800);
        } else if (data.phase === "failed") {
          clearInterval(iv);
        }
      }, 3000);
    }

    return () => {
      stopped = true;
      if (iv) clearInterval(iv);
      if (ws) ws.close();
    };
  }, [id, loadScanResult, loadReport]);

  // ── Render ──────────────────────────────────────────────────────────────

  // Still waiting for first load
  if (!scanResult) {
    return (
      <div style={{
        minHeight: "100vh", background: "var(--bg)",
        display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
        fontFamily: "var(--font-mono)", color: "var(--text)",
      }}>
        {loadError ? (
          <p style={{ color: "var(--red)" }}>{loadError}</p>
        ) : (
          <>
            <div style={{
              width: 48, height: 48,
              border: "3px solid var(--border)",
              borderTop: "3px solid var(--accent)",
              borderRadius: "50%",
              animation: "spin 0.8s linear infinite",
              marginBottom: 20,
            }} />
            <p style={{ color: "var(--text-muted)", fontSize: 14 }}>
              Waiting for scan #{id}…
            </p>
          </>
        )}
      </div>
    );
  }

  const isRunning = phase !== "done" && phase !== "failed";
  const isFailed  = phase === "failed";

  const STEP_PCT = {
    queued: 5, nmap: 40, scanning_ports: 40,
    nuclei: 75, scanning_web: 75, done: 100, failed: 100,
  };
  const pct = STEP_PCT[phase] || 5;
  const phaseLabel = {
    queued:         "Queued",
    nmap:           "Phase 1 — Port Scanning",
    scanning_ports: "Phase 1 — Port Scanning",
    nuclei:         "Phase 2 — Web Scanning",
    scanning_web:   "Phase 2 — Web Scanning",
    done:           "Complete",
    failed:         "Failed",
  }[phase] || phase;

  // Use ML risk from scan result (always consistent)
  const riskScore = scanResult.risk_score ?? report?.risk_score ?? 0;
  const riskLevel = scanResult.risk_level ?? report?.risk_level ?? "Low";
  const confidence = scanResult.confidence ?? report?.confidence ?? 0;

  const nucleiSev = scanResult.severity_summary || { critical:0, high:0, medium:0, low:0, info:0 };
  const cveSev    = report?.summary             || { critical:0, high:0, medium:0, low:0 };

  return (
    <div style={{
      minHeight: "100vh", background: "var(--bg)",
      color: "var(--text)", fontFamily: "var(--font-mono)", padding: "2rem",
    }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
      `}</style>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>

        <Link to="/" style={{
          color: "var(--text-muted)", fontSize: 13,
          textDecoration: "none", display: "inline-block", marginBottom: "1.5rem",
        }}>
          ← Dashboard
        </Link>

        {/* Header */}
        <div style={{
          background: "var(--surface)", border: "1px solid var(--border)",
          borderRadius: 12, padding: "1.5rem", marginBottom: "1.5rem",
        }}>
          <div style={{
            display: "flex", justifyContent: "space-between",
            alignItems: "flex-start", flexWrap: "wrap", gap: 12,
          }}>
            <div>
              <div style={{
                fontSize: 11, color: "var(--text-muted)",
                textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 6,
              }}>
                Scan #{id}
              </div>
              <h1 style={{
                margin: 0, fontSize: "1.8rem", fontWeight: 800,
                fontFamily: "var(--font-display)",
              }}>
                {scanResult.target}
              </h1>
              <div style={{ marginTop: 8, fontSize: 13, color: "var(--text-muted)" }}>
                Started: {new Date(scanResult.created_at).toLocaleString()}
                {scanResult.completed_at && (
                  <span style={{ marginLeft: 16 }}>
                    Finished: {new Date(scanResult.completed_at).toLocaleString()}
                  </span>
                )}
              </div>
            </div>

            {/* Risk badge — shown as soon as scan result is available */}
            {phase === "done" && (
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span style={{
                  background: riskLevel === "High" || riskLevel === "Critical"
                    ? "#7f1d1d33" : riskLevel === "Medium" ? "#78350f33" : "#14532d33",
                  color: riskLevel === "High" || riskLevel === "Critical"
                    ? "var(--red)" : riskLevel === "Medium" ? "var(--yellow)" : "var(--green)",
                  border: "1px solid currentColor",
                  padding: "6px 16px", borderRadius: 8, fontWeight: 700, fontSize: 14,
                }}>
                  {riskLevel} Risk
                </span>
                <span style={{
                  background: "#1e3a5f33", color: "var(--accent)",
                  border: "1px solid var(--accent)44",
                  padding: "6px 16px", borderRadius: 8, fontWeight: 700, fontSize: 14,
                }}>
                  Score: {riskScore}/100
                </span>
                {confidence > 0 && (
                  <span style={{
                    color: "var(--text-muted)", fontSize: 12,
                  }}>
                    {Math.round(confidence * 100)}% confidence
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Progress bar */}
          <div style={{ marginTop: 20 }}>
            <div style={{
              display: "flex", justifyContent: "space-between",
              fontSize: 12, color: "var(--text-muted)", marginBottom: 6,
            }}>
              <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                {isRunning && (
                  <span style={{
                    display: "inline-block", width: 7, height: 7,
                    borderRadius: "50%", background: "var(--accent)",
                    animation: "pulse 1.2s ease infinite",
                  }} />
                )}
                {phaseLabel}
              </span>
              <span>{pct}%</span>
            </div>
            <div style={{
              background: "var(--border)", borderRadius: 6,
              height: 8, overflow: "hidden",
            }}>
              <div style={{
                width: `${pct}%`, height: "100%",
                background: isFailed
                  ? "var(--red)" : pct === 100
                  ? "var(--green)" : "var(--accent)",
                transition: "width 0.7s ease", borderRadius: 6,
              }} />
            </div>
          </div>

          {isFailed && (
            <div style={{
              marginTop: 12, padding: "10px 14px",
              background: "#7f1d1d22", border: "1px solid var(--red)",
              borderRadius: 8, color: "var(--red)", fontSize: 13,
            }}>
              {status}
            </div>
          )}
        </div>

        {/* Severity cards */}
        {phase === "done" && (
          <div style={{
            display: "grid", gridTemplateColumns: "repeat(5, 1fr)",
            gap: 12, marginBottom: "1.5rem",
          }}>
            {[
              { label: "Critical", cve: cveSev.critical, nuc: nucleiSev.critical, color: "var(--red)" },
              { label: "High",     cve: cveSev.high,     nuc: nucleiSev.high,     color: "#fb923c" },
              { label: "Medium",   cve: cveSev.medium,   nuc: nucleiSev.medium,   color: "var(--yellow)" },
              { label: "Low",      cve: cveSev.low,      nuc: nucleiSev.low,      color: "var(--green)" },
              { label: "Info",     cve: 0,               nuc: nucleiSev.info,     color: "var(--accent)" },
            ].map(({ label, cve, nuc, color }) => (
              <div key={label} style={{
                background: "var(--surface)",
                border: `1px solid ${color}44`,
                borderRadius: 10, padding: "1rem",
              }}>
                <div style={{
                  fontSize: 11, textTransform: "uppercase",
                  letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 6,
                }}>
                  {label}
                </div>
                <div style={{
                  fontSize: "2rem", fontWeight: 800,
                  color, fontFamily: "var(--font-display)",
                }}>
                  {cve + nuc}
                </div>
                {(cve > 0 || nuc > 0) && (
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                    {cve > 0 && <span>CVE: {cve} </span>}
                    {nuc > 0 && <span>Nuclei: {nuc}</span>}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Open Ports */}
        {scanResult.open_ports && (
          <Section title={`Open Ports (${scanResult.open_ports.length})`}>
            {scanResult.open_ports.length === 0 && phase === "done" ? (
              <div style={{
                background: "#78350f22", border: "1px solid var(--yellow)",
                color: "var(--yellow)", padding: "10px 14px",
                borderRadius: 8, fontSize: 13, marginBottom: 8,
              }}>
                ⚠ No open ports found. The target may be firewalled or blocking scans.
                Try <strong>scanme.nmap.org</strong> to verify your scanner is working.
              </div>
            ) : (
              <Table
                cols={["Port", "Proto", "Service", "Product", "Version", "Web?"]}
                empty="No open ports found."
                rows={scanResult.open_ports.map((p, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "10px 12px", fontWeight: 700, color: "var(--accent)" }}>{p.port}</td>
                    <td style={{ padding: "10px 12px", color: "var(--text-muted)", fontSize: 12 }}>{p.proto || "tcp"}</td>
                    <td style={{ padding: "10px 12px" }}>{p.service || "—"}</td>
                    <td style={{ padding: "10px 12px" }}>{p.product || "—"}</td>
                    <td style={{ padding: "10px 12px", color: "var(--text-muted)" }}>{p.version || "—"}</td>
                    <td style={{ padding: "10px 12px" }}>
                      {p.is_web
                        ? <span style={{ color: "var(--green)", fontSize: 12 }}>● Web</span>
                        : <span style={{ color: "var(--border)", fontSize: 12 }}>—</span>}
                    </td>
                  </tr>
                ))}
              />
            )}
          </Section>
        )}

        {/* Nuclei Findings */}
        {scanResult.nuclei_findings?.length > 0 && (
          <Section title={`Nuclei Findings (${scanResult.nuclei_findings.length})`}>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {scanResult.nuclei_findings.map((f, i) => (
                <div key={i} style={{
                  border: "1px solid var(--border)", borderRadius: 8,
                  padding: "1rem", background: "var(--bg)",
                }}>
                  <div style={{
                    display: "flex", justifyContent: "space-between",
                    alignItems: "flex-start", gap: 12, flexWrap: "wrap", marginBottom: 8,
                  }}>
                    <div>
                      <span style={{ fontWeight: 700, fontSize: 14 }}>
                        {f.template_name || f.template_id}
                      </span>
                      <span style={{ marginLeft: 10, fontSize: 11, color: "var(--text-muted)" }}>
                        {f.template_id}
                      </span>
                    </div>
                    <SevBadge severity={f.severity} />
                  </div>
                  <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 6 }}>
                    {f.matched_at}
                  </div>
                  {f.description && (
                    <p style={{
                      fontSize: 13, color: "var(--text-muted)",
                      margin: 0, lineHeight: 1.6,
                    }}>
                      {f.description.slice(0, 300)}
                      {f.description.length > 300 ? "…" : ""}
                    </p>
                  )}
                  {f.tags && (
                    <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {f.tags.split(",").map(t => (
                        <span key={t} style={{
                          fontSize: 10, background: "var(--border)",
                          color: "var(--text-muted)", padding: "2px 8px", borderRadius: 10,
                        }}>
                          {t.trim()}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* CVE Vulnerabilities */}
        {reportLoading && (
          <Section title="CVE Vulnerabilities">
            <p style={{ color: "var(--text-muted)", fontSize: 14 }}>
              Loading CVE data…
            </p>
          </Section>
        )}

        {reportError && (
          <Section title="CVE Vulnerabilities">
            <p style={{ color: "var(--red)", fontSize: 14 }}>{reportError}</p>
          </Section>
        )}

        {report?.vulnerabilities?.length > 0 && (
          <Section title={`CVE Vulnerabilities (${report.vulnerabilities.length})`}>
            <Table
              cols={["CVE", "Severity", "Port", "Service", "Source"]}
              rows={report.vulnerabilities.map((v, i) => (
                <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "10px 12px", fontWeight: 700, fontSize: 13, color: "var(--accent)" }}>
                    {v.cve}
                  </td>
                  <td style={{ padding: "10px 12px" }}><SevBadge severity={v.severity} /></td>
                  <td style={{ padding: "10px 12px", color: "var(--text-muted)" }}>{v.port || "—"}</td>
                  <td style={{ padding: "10px 12px" }}>{v.service || "—"}</td>
                  <td style={{ padding: "10px 12px", fontSize: 11, color: "var(--text-muted)" }}>{v.source}</td>
                </tr>
              ))}
            />
          </Section>
        )}

        {/* Executive Summary */}
        {report?.executive_summary && (
          <Section title="Executive Summary">
            <p style={{ margin: 0, fontSize: 14, lineHeight: 1.7, color: "var(--text-muted)" }}>
              {report.executive_summary}
            </p>
          </Section>
        )}

        {/* Actions */}
        {phase === "done" && (
          <div style={{ display: "flex", gap: 12, marginBottom: "2rem", flexWrap: "wrap" }}>
            {[
              { href: `${API}/report/${id}/pdf`,  label: "↓ PDF Report",  bg: "var(--green)",  color: "#000" },
              { href: `${API}/report/${id}/json`, label: "↓ JSON Export", bg: "var(--accent)", color: "#000" },
              { href: `${API}/report/${id}/csv`,  label: "↓ CSV Export",  bg: "#a78bfa",       color: "#000" },
            ].map(({ href, label, bg, color }) => (
              <a
                key={label}
                href={href}
                target="_blank"
                rel="noreferrer"
                style={{
                  background: bg, color,
                  padding: "12px 24px", borderRadius: 8,
                  fontWeight: 700, fontSize: 14,
                  textDecoration: "none", fontFamily: "var(--font-mono)",
                  transition: "opacity 0.2s",
                }}
                onMouseEnter={e => e.currentTarget.style.opacity = "0.85"}
                onMouseLeave={e => e.currentTarget.style.opacity = "1"}
              >
                {label}
              </a>
            ))}
            <Link
              to="/"
              style={{
                background: "var(--surface)",
                color: "var(--text)",
                border: "1px solid var(--border)",
                padding: "12px 24px",
                borderRadius: 8,
                fontWeight: 700,
                fontSize: 14,
                textDecoration: "none",
                fontFamily: "var(--font-mono)",
              }}
            >
              ← New Scan
            </Link>
          </div>
        )}

      </div>
    </div>
  );
}
