import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const SEV_STYLE = {
  critical: { bg: "#7f1d1d33", color: "#f87171", border: "#f8717144" },
  high:     { bg: "#7c2d1233", color: "#fb923c", border: "#fb923c44" },
  medium:   { bg: "#78350f33", color: "#fbbf24", border: "#fbbf2444" },
  low:      { bg: "#14532d33", color: "#4ade80", border: "#4ade8044" },
  info:     { bg: "#1e3a5f33", color: "#60a5fa", border: "#60a5fa44" },
};

function SevBadge({ severity }) {
  const key = (severity || "unknown").toLowerCase();
  const s = SEV_STYLE[key] || { bg: "#1f2937", color: "#9ca3af", border: "#374151" };
  return (
    <span style={{
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
      padding: "2px 10px", borderRadius: 20, fontSize: 11, fontWeight: 700,
      textTransform: "uppercase", letterSpacing: "0.06em",
    }}>
      {severity || "Unknown"}
    </span>
  );
}

function Section({ title, count, children }) {
  return (
    <div style={{
      background: "var(--surface)", border: "1px solid var(--border)",
      borderRadius: 12, padding: "1.5rem", marginBottom: "1.5rem",
    }}>
      <h2 style={{
        margin: "0 0 1.2rem", fontSize: "0.85rem", fontWeight: 700,
        textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--text-muted)",
        display: "flex", gap: 8, alignItems: "center",
      }}>
        {title}
        {count !== undefined && (
          <span style={{
            background: "var(--border)", padding: "2px 8px",
            borderRadius: 10, fontSize: 10,
          }}>
            {count}
          </span>
        )}
      </h2>
      {children}
    </div>
  );
}

function DiffTag({ type }) {
  const map = {
    added:     { label: "+ Added",    bg: "#14532d33", color: "#4ade80", border: "#4ade8044" },
    removed:   { label: "\u2212 Removed",  bg: "#7f1d1d33", color: "#f87171", border: "#f8717144" },
    new:       { label: "\u26a0 New",      bg: "#7f1d1d33", color: "#f87171", border: "#f8717144" },
    fixed:     { label: "\u2713 Fixed",    bg: "#14532d33", color: "#4ade80", border: "#4ade8044" },
    unchanged: { label: "= Same",     bg: "#1f293766", color: "#9ca3af", border: "#37415166" },
  };
  const s = map[type] || map.unchanged;
  return (
    <span style={{
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
      padding: "2px 10px", borderRadius: 20, fontSize: 10, fontWeight: 700,
      textTransform: "uppercase", letterSpacing: "0.06em",
    }}>
      {s.label}
    </span>
  );
}

export default function ScanDiff() {
  const [params] = useSearchParams();
  const idA = params.get("a");
  const idB = params.get("b");

  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!idA || !idB) {
      setError("Missing scan IDs. Use ?a=1&b=2");
      setLoading(false);
      return;
    }
    (async () => {
      try {
        const res = await fetch(`${API}/scan/diff?scan_a=${idA}&scan_b=${idB}`);
        if (!res.ok) {
          setError("Failed to load diff: " + (await res.json()).detail);
          return;
        }
        setDiff(await res.json());
      } catch (e) {
        setError("Network error: " + e.message);
      } finally {
        setLoading(false);
      }
    })();
  }, [idA, idB]);

  if (loading) {
    return (
      <div style={{
        minHeight: "100vh", background: "var(--bg)",
        display: "flex", alignItems: "center", justifyContent: "center",
        fontFamily: "var(--font-mono)", color: "var(--text)",
      }}>
        <div style={{
          width: 48, height: 48,
          border: "3px solid var(--border)", borderTop: "3px solid var(--accent)",
          borderRadius: "50%", animation: "spin 0.8s linear infinite",
        }} />
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        minHeight: "100vh", background: "var(--bg)", padding: "2rem",
        fontFamily: "var(--font-mono)", color: "var(--text)",
      }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <Link to="/" style={{ color: "var(--text-muted)", fontSize: 13, textDecoration: "none" }}>
            ← Dashboard
          </Link>
          <p style={{ color: "var(--red)", marginTop: 20 }}>{error}</p>
        </div>
      </div>
    );
  }

  const { scan_a, scan_b, ports, nuclei_findings, risk_delta } = diff;

  const riskColor = (level) => {
    const l = (level || "").toLowerCase();
    if (l === "critical" || l === "high") return "var(--red)";
    if (l === "medium") return "var(--yellow)";
    return "var(--green)";
  };

  const scoreDelta = risk_delta.after.score - risk_delta.before.score;
  const deltaColor = scoreDelta > 0 ? "var(--red)" : scoreDelta < 0 ? "var(--green)" : "var(--text-muted)";
  const deltaSign  = scoreDelta > 0 ? "+" : "";

  return (
    <div style={{
      minHeight: "100vh", background: "var(--bg)",
      color: "var(--text)", fontFamily: "var(--font-mono)", padding: "2rem",
    }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
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
            display: "flex", alignItems: "center", gap: 12, marginBottom: 8,
          }}>
            <div style={{
              width: 10, height: 10, borderRadius: "50%",
              background: "#a78bfa", boxShadow: "0 0 8px #a78bfa",
            }} />
            <span style={{
              color: "#a78bfa", fontSize: 12, letterSpacing: "0.15em", textTransform: "uppercase",
            }}>
              Scan Comparison
            </span>
          </div>
          <h1 style={{
            margin: 0, fontSize: "1.8rem", fontWeight: 800, fontFamily: "var(--font-display)",
          }}>
            {scan_a.target === scan_b.target
              ? `${scan_a.target} \u2014 Over Time`
              : `${scan_a.target} vs ${scan_b.target}`}
          </h1>

          {/* Side-by-side scan metadata */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 20 }}>
            {[
              { label: "Scan A (Before)", scan: scan_a, id: idA },
              { label: "Scan B (After)",  scan: scan_b, id: idB },
            ].map(({ label, scan, id }) => (
              <div key={id} style={{
                background: "var(--bg)", border: "1px solid var(--border)",
                borderRadius: 8, padding: "1rem",
              }}>
                <div style={{
                  fontSize: 10, textTransform: "uppercase",
                  letterSpacing: "0.1em", color: "var(--text-muted)", marginBottom: 6,
                }}>
                  {label}
                </div>
                <div style={{ fontSize: 14, fontWeight: 700 }}>
                  <Link to={`/scan/${id}`} style={{ color: "var(--accent)", textDecoration: "none" }}>
                    #{id}
                  </Link>
                  <span style={{ color: "var(--text-muted)", marginLeft: 8, fontWeight: 400, fontSize: 12 }}>
                    {scan.created_at ? new Date(scan.created_at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) : "\u2014"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Risk Delta */}
        <div style={{
          display: "grid", gridTemplateColumns: "1fr auto 1fr", gap: 16,
          marginBottom: "1.5rem", alignItems: "center",
        }}>
          <div style={{
            background: "var(--surface)", border: "1px solid var(--border)",
            borderRadius: 10, padding: "1.2rem", textAlign: "center",
          }}>
            <div style={{
              fontSize: 10, textTransform: "uppercase",
              letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 8,
            }}>
              Before
            </div>
            <div style={{
              fontSize: "2rem", fontWeight: 800,
              color: riskColor(risk_delta.before.level), fontFamily: "var(--font-display)",
            }}>
              {risk_delta.before.score}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              {risk_delta.before.level} Risk
            </div>
          </div>

          <div style={{ textAlign: "center" }}>
            <div style={{
              fontSize: "1.5rem", fontWeight: 800, color: deltaColor,
              fontFamily: "var(--font-display)",
            }}>
              {deltaSign}{scoreDelta}
            </div>
            <div style={{ fontSize: 22, color: "var(--text-muted)" }}>→</div>
          </div>

          <div style={{
            background: "var(--surface)", border: "1px solid var(--border)",
            borderRadius: 10, padding: "1.2rem", textAlign: "center",
          }}>
            <div style={{
              fontSize: 10, textTransform: "uppercase",
              letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 8,
            }}>
              After
            </div>
            <div style={{
              fontSize: "2rem", fontWeight: 800,
              color: riskColor(risk_delta.after.level), fontFamily: "var(--font-display)",
            }}>
              {risk_delta.after.score}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              {risk_delta.after.level} Risk
            </div>
          </div>
        </div>

        {/* Summary cards */}
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: "1.5rem",
        }}>
          {[
            { label: "Ports Added",    value: ports.added.length,              color: "var(--red)" },
            { label: "Ports Removed",  value: ports.removed.length,            color: "var(--green)" },
            { label: "New Findings",   value: nuclei_findings.new.length,      color: "var(--red)" },
            { label: "Fixed Findings", value: nuclei_findings.fixed.length,    color: "var(--green)" },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              background: "var(--surface)", border: `1px solid ${color}44`,
              borderRadius: 10, padding: "1rem",
            }}>
              <div style={{
                fontSize: 10, textTransform: "uppercase",
                letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 6,
              }}>
                {label}
              </div>
              <div style={{
                fontSize: "1.8rem", fontWeight: 800,
                color, fontFamily: "var(--font-display)",
              }}>
                {value}
              </div>
            </div>
          ))}
        </div>

        {/* Port Changes */}
        <Section title="Port Changes" count={ports.added.length + ports.removed.length + ports.unchanged.length}>
          {ports.added.length === 0 && ports.removed.length === 0 && ports.unchanged.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: 14, margin: 0 }}>No ports to compare.</p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    {["Status", "Port", "Service", "Product", "Version"].map(h => (
                      <th key={h} style={{
                        textAlign: "left", padding: "8px 12px",
                        fontSize: 11, textTransform: "uppercase",
                        letterSpacing: "0.07em", color: "var(--text-muted)", fontWeight: 600,
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {ports.added.map((p, i) => (
                    <tr key={`a-${i}`} style={{ borderBottom: "1px solid var(--border)", background: "#14532d11" }}>
                      <td style={{ padding: "8px 12px" }}><DiffTag type="added" /></td>
                      <td style={{ padding: "8px 12px", fontWeight: 700, color: "var(--red)" }}>{p.port}</td>
                      <td style={{ padding: "8px 12px" }}>{p.service || "\u2014"}</td>
                      <td style={{ padding: "8px 12px" }}>{p.product || "\u2014"}</td>
                      <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>{p.version || "\u2014"}</td>
                    </tr>
                  ))}
                  {ports.removed.map((p, i) => (
                    <tr key={`r-${i}`} style={{ borderBottom: "1px solid var(--border)", background: "#7f1d1d11" }}>
                      <td style={{ padding: "8px 12px" }}><DiffTag type="removed" /></td>
                      <td style={{ padding: "8px 12px", fontWeight: 700, color: "var(--green)" }}>{p.port}</td>
                      <td style={{ padding: "8px 12px" }}>{p.service || "\u2014"}</td>
                      <td style={{ padding: "8px 12px" }}>{p.product || "\u2014"}</td>
                      <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>{p.version || "\u2014"}</td>
                    </tr>
                  ))}
                  {ports.unchanged.map((p, i) => (
                    <tr key={`u-${i}`} style={{ borderBottom: "1px solid var(--border)" }}>
                      <td style={{ padding: "8px 12px" }}><DiffTag type="unchanged" /></td>
                      <td style={{ padding: "8px 12px", fontWeight: 700, color: "var(--text-muted)" }}>{p.port}</td>
                      <td style={{ padding: "8px 12px" }}>{p.service || "\u2014"}</td>
                      <td style={{ padding: "8px 12px" }}>{p.product || "\u2014"}</td>
                      <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>{p.version || "\u2014"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        {/* Nuclei Finding Changes */}
        <Section title="Vulnerability Changes" count={nuclei_findings.new.length + nuclei_findings.fixed.length + nuclei_findings.unchanged.length}>
          {nuclei_findings.new.length === 0 && nuclei_findings.fixed.length === 0 && nuclei_findings.unchanged.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: 14, margin: 0 }}>No findings to compare.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {/* New findings */}
              {nuclei_findings.new.map((f, i) => (
                <div key={`new-${i}`} style={{
                  border: "1px solid #f8717144", borderRadius: 8,
                  padding: "1rem", background: "#7f1d1d11",
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap", marginBottom: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <DiffTag type="new" />
                      <span style={{ fontWeight: 700, fontSize: 14 }}>
                        {f.template_name || f.template_id}
                      </span>
                    </div>
                    <SevBadge severity={f.severity} />
                  </div>
                  {f.matched_at && (
                    <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 6 }}>{f.matched_at}</div>
                  )}
                  {f.description && (
                    <p style={{ fontSize: 13, color: "var(--text-muted)", margin: 0, lineHeight: 1.6 }}>
                      {f.description.slice(0, 300)}{f.description.length > 300 ? "\u2026" : ""}
                    </p>
                  )}
                </div>
              ))}

              {/* Fixed findings */}
              {nuclei_findings.fixed.map((f, i) => (
                <div key={`fixed-${i}`} style={{
                  border: "1px solid #4ade8044", borderRadius: 8,
                  padding: "1rem", background: "#14532d11",
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap", marginBottom: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <DiffTag type="fixed" />
                      <span style={{ fontWeight: 700, fontSize: 14 }}>
                        {f.template_name || f.template_id}
                      </span>
                    </div>
                    <SevBadge severity={f.severity} />
                  </div>
                  {f.matched_at && (
                    <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 6 }}>{f.matched_at}</div>
                  )}
                  {f.description && (
                    <p style={{ fontSize: 13, color: "var(--text-muted)", margin: 0, lineHeight: 1.6 }}>
                      {f.description.slice(0, 300)}{f.description.length > 300 ? "\u2026" : ""}
                    </p>
                  )}
                </div>
              ))}

              {/* Unchanged findings */}
              {nuclei_findings.unchanged.map((f, i) => (
                <div key={`unc-${i}`} style={{
                  border: "1px solid var(--border)", borderRadius: 8,
                  padding: "1rem", background: "var(--bg)", opacity: 0.7,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap", marginBottom: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <DiffTag type="unchanged" />
                      <span style={{ fontWeight: 700, fontSize: 14 }}>
                        {f.template_name || f.template_id}
                      </span>
                    </div>
                    <SevBadge severity={f.severity} />
                  </div>
                  {f.matched_at && (
                    <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 6 }}>{f.matched_at}</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Section>

        {/* Back button */}
        <div style={{ display: "flex", gap: 12, marginBottom: "2rem" }}>
          <Link to="/" style={{
            background: "var(--surface)", color: "var(--text)",
            border: "1px solid var(--border)", padding: "12px 24px",
            borderRadius: 8, fontWeight: 700, fontSize: 14,
            textDecoration: "none", fontFamily: "var(--font-mono)",
          }}>
            ← Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
