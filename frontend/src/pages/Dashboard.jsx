import { useEffect, useState, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";

// Reads from Vite env at build time so the same build can point at
// localhost, a VM's IP, or a Docker service name. Falls back to
// localhost for local `npm run dev`.
const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const PHASE_STEPS = {
  queued:        { label: "Queued",            pct: 5  },
  nmap:          { label: "Port Scanning…",    pct: 40 },
  scanning_ports:{ label: "Port Scanning…",    pct: 40 },
  nuclei:        { label: "Web Scanning…",     pct: 75 },
  scanning_web:  { label: "Web Scanning…",     pct: 75 },
  done:          { label: "Complete",          pct: 100 },
  failed:        { label: "Failed",            pct: 100 },
};

function ScanProgressBar({ phase }) {
  const step = PHASE_STEPS[phase] || PHASE_STEPS.queued;
  const isFailed = phase === "failed";
  return (
    <div className="mt-2">
      <div className="flex justify-between text-xs mb-1" style={{ color: "var(--text-muted)" }}>
        <span>{step.label}</span>
        <span>{step.pct}%</span>
      </div>
      <div style={{ background: "var(--border)", borderRadius: 4, height: 6, overflow: "hidden" }}>
        <div
          style={{
            width: `${step.pct}%`,
            height: "100%",
            background: isFailed ? "var(--red)" : step.pct === 100 ? "var(--green)" : "var(--accent)",
            transition: "width 0.6s ease",
            borderRadius: 4,
          }}
        />
      </div>
    </div>
  );
}

function StatusBadge({ phase }) {
  const map = {
    done:          { label: "Complete",  color: "var(--green)",  bg: "#064e3b22" },
    failed:        { label: "Failed",    color: "var(--red)",    bg: "#7f1d1d22" },
    queued:        { label: "Queued",    color: "var(--yellow)", bg: "#78350f22" },
    nmap:          { label: "Scanning",  color: "var(--accent)", bg: "#1e3a5f22" },
    scanning_ports:{ label: "Scanning",  color: "var(--accent)", bg: "#1e3a5f22" },
    nuclei:        { label: "Scanning",  color: "var(--accent)", bg: "#1e3a5f22" },
    scanning_web:  { label: "Scanning",  color: "var(--accent)", bg: "#1e3a5f22" },
  };
  const s = map[phase] || map.queued;
  return (
    <span style={{
      background: s.bg, color: s.color,
      padding: "3px 10px", borderRadius: 20,
      fontSize: 12, fontWeight: 700, letterSpacing: "0.04em",
      border: `1px solid ${s.color}44`,
    }}>
      {s.label}
    </span>
  );
}

const validateTarget = (input) => {
  const trimmed = input.trim();
  // Block URLs with protocol
  if (/^https?:\/\//i.test(trimmed)) {
    return "Enter a hostname or IP only — no http:// or https://";
  }
  // Block IP:port format
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(trimmed)) {
    return "Enter just the IP address — no port number (e.g. 192.168.1.1)";
  }
  // Block trailing slashes
  if (trimmed.endsWith("/")) {
    return "Remove the trailing slash from your target";
  }
  // Must be a valid IP or hostname
  const ipPattern       = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;
  const hostnamePattern = /^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/;
  if (!ipPattern.test(trimmed) && !hostnamePattern.test(trimmed)) {
    return "Enter a valid IP (192.168.1.1) or hostname (scanme.nmap.org)";
  }
  return null; // valid
};

export default function Dashboard() {
  const [scans, setScans]   = useState([]);
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState("");
  const pollRefs = useRef({});
  const navigate = useNavigate();

  const loadHistory = async () => {
    try {
      const res  = await fetch(`${API}/history`);
      const data = await res.json();
      data.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      setScans(data);
    } catch { setError("Failed to load scan history"); }
  };

  useEffect(() => {
    loadHistory();
    const iv = setInterval(loadHistory, 4000);
    return () => { clearInterval(iv); Object.values(pollRefs.current).forEach(clearInterval); };
  }, []);

  const startScan = async () => {
    if (!target.trim()) { setError("Enter a target IP or hostname"); return; }
    
    const validationError = validateTarget(target);
    if (validationError) {
      setError(validationError);
      return;
    }
    
    setLoading(true);
    setError("");
    
    try {
      const res  = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.detail || "Failed to start scan"); setLoading(false); return; }
      
      setTarget("");
      await loadHistory();
      
      const iv = setInterval(async () => {
        const r = await fetch(`${API}/scan/status/${data.task_id}`);
        const s = await r.json();
        if (s.state === "SUCCESS" || s.state === "FAILURE") {
          clearInterval(iv);
          delete pollRefs.current[data.task_id];
          await loadHistory();
          navigate(`/scan/${data.scan_id}`);
        }
      }, 3000);
      pollRefs.current[data.task_id] = iv;
    } catch { setError("Failed to start scan"); }
    
    setLoading(false);
  };

  const completed = scans.filter(s => s.phase === "done").length;
  const failed    = scans.filter(s => s.phase === "failed").length;
  const running   = scans.filter(s => !["done","failed"].includes(s.phase)).length;

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)", color: "var(--text)", fontFamily: "var(--font-mono)", padding: "2rem" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ marginBottom: "2.5rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />
            <span style={{ color: "var(--accent)", fontSize: 12, letterSpacing: "0.15em", textTransform: "uppercase" }}>Security Platform</span>
          </div>
          <h1 style={{ fontSize: "2.8rem", fontWeight: 800, fontFamily: "var(--font-display)", letterSpacing: "-0.02em", margin: 0 }}>
            Vulnerability Scanner
          </h1>
          <p style={{ color: "var(--text-muted)", marginTop: 6, fontSize: 14 }}>
            Nmap + Nuclei async pipeline · PostgreSQL backed
          </p>
        </div>

        {error && (
          <div style={{ background: "#7f1d1d22", border: "1px solid var(--red)", color: "var(--red)", padding: "12px 16px", borderRadius: 8, marginBottom: 20, fontSize: 14 }}>
            {error}
          </div>
        )}

        {/* Scan Input */}
        <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 12, padding: "1.5rem", marginBottom: "2rem" }}>
          <h2 style={{ margin: "0 0 1rem", fontSize: "1rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--text-muted)" }}>
            New Scan
          </h2>
          <div style={{ display: "flex", gap: 12 }}>
            <input
              type="text"
              placeholder="scanme.nmap.org or 192.168.1.1"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === "Enter" && startScan()}
              style={{
                flex: 1, background: "var(--bg)", border: "1px solid var(--border)",
                borderRadius: 8, padding: "12px 16px", color: "var(--text)",
                fontFamily: "var(--font-mono)", fontSize: 14, outline: "none",
              }}
            />
            <button
              onClick={startScan}
              disabled={loading}
              style={{
                background: loading ? "var(--border)" : "var(--accent)",
                color: loading ? "var(--text-muted)" : "#000",
                border: "none", borderRadius: 8, padding: "12px 28px",
                fontWeight: 700, fontSize: 14, cursor: loading ? "not-allowed" : "pointer",
                fontFamily: "var(--font-mono)", letterSpacing: "0.05em",
                transition: "all 0.2s",
              }}
            >
              {loading ? "Starting…" : "► Scan"}
            </button>
          </div>
        </div>

        {/* Stats */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: "2rem" }}>
          {[
            { label: "Total",     value: scans.length, color: "var(--text)" },
            { label: "Running",   value: running,       color: "var(--accent)" },
            { label: "Complete",  value: completed,     color: "var(--green)" },
            { label: "Failed",    value: failed,        color: "var(--red)" },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 10, padding: "1.2rem" }}>
              <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--text-muted)", marginBottom: 8 }}>{label}</div>
              <div style={{ fontSize: "2.2rem", fontWeight: 800, color, fontFamily: "var(--font-display)" }}>{value}</div>
            </div>
          ))}
        </div>

        {/* Scan History Table */}
        <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ padding: "1.2rem 1.5rem", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2 style={{ margin: 0, fontSize: "1rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--text-muted)" }}>
              Scan History
            </h2>
            <button onClick={loadHistory} style={{ background: "transparent", border: "1px solid var(--border)", color: "var(--text-muted)", padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12, fontFamily: "var(--font-mono)" }}>
              ↻ Refresh
            </button>
          </div>

          {scans.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)", fontSize: 14 }}>
              No scans yet. Enter a target above to get started.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  {["ID", "Target", "Status", "Progress", "Started", "Action"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "10px 16px", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.map(scan => (
                  <tr key={scan.id} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "14px 16px", color: "var(--text-muted)", fontSize: 13 }}>#{scan.id}</td>
                    <td style={{ padding: "14px 16px", fontWeight: 600, fontSize: 14 }}>{scan.target}</td>
                    <td style={{ padding: "14px 16px" }}><StatusBadge phase={scan.phase} /></td>
                    <td style={{ padding: "14px 16px", minWidth: 160 }}><ScanProgressBar phase={scan.phase} /></td>
                    <td style={{ padding: "14px 16px", color: "var(--text-muted)", fontSize: 12 }}>{new Date(scan.created_at).toLocaleString()}</td>
                    <td style={{ padding: "14px 16px" }}>
                      {scan.phase === "done" ? (
                        <Link to={`/scan/${scan.id}`} style={{ background: "var(--accent)", color: "#000", padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 700, textDecoration: "none", fontFamily: "var(--font-mono)" }}>
                          View →
                        </Link>
                      ) : scan.phase === "failed" ? (
                        <span style={{ color: "var(--red)", fontSize: 12 }}>—</span>
                      ) : (
                        <span style={{ color: "var(--text-muted)", fontSize: 12 }}>scanning…</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
