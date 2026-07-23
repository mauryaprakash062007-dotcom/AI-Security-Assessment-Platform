import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

function SevBadge({ severity }) {
  const isCrit = severity.toLowerCase() === "critical";
  return (
    <span style={{
      background: isCrit ? "#7f1d1d33" : "#7c2d1233",
      color: isCrit ? "#f87171" : "#fb923c",
      border: `1px solid ${isCrit ? "#f8717144" : "#fb923c44"}`,
      padding: "2px 10px", borderRadius: 20,
      fontSize: 11, fontWeight: 700,
      textTransform: "uppercase", letterSpacing: "0.06em",
    }}>
      {severity}
    </span>
  );
}

export default function ThreatIntelligence() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API}/zero-day-alerts`)
      .then(r => {
        if (!r.ok) throw new Error("Failed to fetch alerts");
        return r.json();
      })
      .then(data => {
        setAlerts(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  return (
    <div style={{
      minHeight: "100vh", background: "var(--bg)",
      color: "var(--text)", fontFamily: "var(--font-mono)", padding: "2rem",
    }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        
        <Link to="/" style={{
          color: "var(--text-muted)", fontSize: 13,
          textDecoration: "none", display: "inline-block", marginBottom: "1.5rem",
        }}>
          ← Dashboard
        </Link>

        <div style={{
          background: "var(--surface)", border: "1px solid var(--border)",
          borderRadius: 12, padding: "1.5rem", marginBottom: "1.5rem",
          borderTop: "4px solid var(--red)"
        }}>
          <h1 style={{
            margin: "0 0 0.5rem", fontSize: "1.8rem", fontWeight: 800,
            fontFamily: "var(--font-display)", display: "flex", alignItems: "center", gap: 10
          }}>
            <span style={{ animation: "pulse 2s infinite" }}>🚨</span> 
            Zero-Day Intelligence Alerts
          </h1>
          <p style={{ color: "var(--text-muted)", margin: 0, fontSize: 14 }}>
            Autonomous Threat Exposure Management (ATEM) continuously monitors global threat feeds 
            (NVD, CISA KEV) and automatically cross-references new zero-days against your historical assets.
          </p>
        </div>

        {loading ? (
          <p style={{ color: "var(--text-muted)" }}>Loading intelligence feeds...</p>
        ) : error ? (
          <p style={{ color: "var(--red)" }}>{error}</p>
        ) : alerts.length === 0 ? (
          <div style={{
            background: "var(--surface)", border: "1px solid var(--border)",
            borderRadius: 12, padding: "3rem", textAlign: "center",
          }}>
            <h3 style={{ margin: "0 0 1rem", color: "var(--green)" }}>No Active Alerts</h3>
            <p style={{ color: "var(--text-muted)", margin: 0 }}>
              Your infrastructure has no known exposure to zero-days published in the last 24 hours.
            </p>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {alerts.map(alert => (
              <div key={alert.id} style={{
                background: "var(--surface)", border: "1px solid var(--border)",
                borderRadius: 12, padding: "1.5rem",
                display: "flex", flexDirection: "column", gap: 12
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <h3 style={{ margin: "0 0 8px", color: "var(--red)", fontSize: "1.2rem" }}>
                      {alert.cve_id}
                    </h3>
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      Detected: {new Date(alert.discovered_at).toLocaleString()}
                    </div>
                  </div>
                  <SevBadge severity={alert.severity} />
                </div>
                
                <div style={{
                  background: "#7f1d1d11", border: "1px solid #7f1d1d44",
                  padding: "1rem", borderRadius: 8, fontSize: 14, lineHeight: 1.6
                }}>
                  {alert.description}
                </div>
                
                <div style={{ fontSize: 13, color: "var(--text-muted)" }}>
                  <strong>Affected Asset:</strong> {alert.target}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
