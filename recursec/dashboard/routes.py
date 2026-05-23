"""Dashboard API routes — REST endpoints for the web UI.

Provides comprehensive API for:
- Scan management (create, list, status, results)
- Agent monitoring (status, spawn history, kill)
- Model management (health, load, metrics)
- Finding management (list, filter, export)
- Attack chain visualization
- Real-time WebSocket events
- System statistics and metrics
"""

from __future__ import annotations

import time
from typing import Any

import structlog

logger = structlog.get_logger()


# ── Data Stores (in-memory for simplicity) ─────────────────

_scans: dict[str, dict[str, Any]] = {}
_agents: dict[str, dict[str, Any]] = {}
_findings: list[dict[str, Any]] = []
_models: dict[str, dict[str, Any]] = {}
_metrics_history: list[dict[str, Any]] = []
_attack_chains: list[dict[str, Any]] = []
_tasks: list[dict[str, Any]] = []


def register_routes(app: Any) -> None:
    """Register all dashboard routes on a FastAPI app."""
    from fastapi import HTTPException, Query
    from fastapi.responses import HTMLResponse

    # ── Dashboard Home ─────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home() -> str:
        return _generate_dashboard_html()

    @app.get("/api/health")
    async def health_check() -> dict[str, Any]:
        return {
            "status": "healthy",
            "uptime_s": time.time() - _start_time,
            "version": "0.1.0",
            "agents_active": sum(1 for a in _agents.values() if a.get("status") == "running"),
            "scans_active": sum(1 for s in _scans.values() if s.get("status") == "running"),
            "total_findings": len(_findings),
        }

    # ── Scan Management ────────────────────────────────────

    @app.get("/api/scans")
    async def list_scans(
        status: str = Query("", description="Filter by status"),
        limit: int = Query(50, ge=1, le=500),
    ) -> dict[str, Any]:
        scans = list(_scans.values())
        if status:
            scans = [s for s in scans if s.get("status") == status]
        return {"scans": scans[-limit:], "total": len(scans)}

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict[str, Any]:
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return _scans[scan_id]

    @app.post("/api/scans")
    async def create_scan(body: dict[str, Any]) -> dict[str, Any]:
        scan_id = f"scan_{int(time.time())}_{len(_scans)}"
        scan = {
            "id": scan_id,
            "target": body.get("target", ""),
            "scan_type": body.get("scan_type", "full"),
            "status": "queued",
            "created_at": time.time(),
            "findings_count": 0,
            "progress": 0,
        }
        _scans[scan_id] = scan
        return scan

    @app.delete("/api/scans/{scan_id}")
    async def cancel_scan(scan_id: str) -> dict[str, str]:
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        _scans[scan_id]["status"] = "cancelled"
        return {"status": "cancelled"}

    # ── Agent Management ───────────────────────────────────

    @app.get("/api/agents")
    async def list_agents() -> dict[str, Any]:
        return {
            "agents": list(_agents.values()),
            "total": len(_agents),
            "active": sum(1 for a in _agents.values() if a.get("status") == "running"),
        }

    @app.get("/api/agents/{agent_id}")
    async def get_agent(agent_id: str) -> dict[str, Any]:
        if agent_id not in _agents:
            raise HTTPException(status_code=404, detail="Agent not found")
        return _agents[agent_id]

    @app.post("/api/agents/{agent_id}/kill")
    async def kill_agent(agent_id: str) -> dict[str, str]:
        if agent_id not in _agents:
            raise HTTPException(status_code=404, detail="Agent not found")
        _agents[agent_id]["status"] = "killed"
        return {"status": "killed"}

    # ── Model Management ───────────────────────────────────

    @app.get("/api/models")
    async def list_models() -> dict[str, Any]:
        return {
            "models": list(_models.values()),
            "total": len(_models),
            "healthy": sum(1 for m in _models.values() if m.get("status") == "healthy"),
        }

    @app.get("/api/models/{model_id}")
    async def get_model(model_id: str) -> dict[str, Any]:
        if model_id not in _models:
            raise HTTPException(status_code=404, detail="Model not found")
        return _models[model_id]

    @app.post("/api/models/{model_id}/reload")
    async def reload_model(model_id: str) -> dict[str, str]:
        if model_id not in _models:
            raise HTTPException(status_code=404, detail="Model not found")
        _models[model_id]["status"] = "reloading"
        return {"status": "reloading"}

    # ── Findings ───────────────────────────────────────────

    @app.get("/api/findings")
    async def list_findings(
        severity: str = Query("", description="Filter by severity"),
        category: str = Query("", description="Filter by category"),
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        filtered = _findings
        if severity:
            filtered = [f for f in filtered if f.get("severity") == severity]
        if category:
            filtered = [f for f in filtered if f.get("category") == category]
        return {
            "findings": filtered[offset:offset + limit],
            "total": len(filtered),
            "severity_counts": _count_severities(filtered),
        }

    @app.get("/api/findings/stats")
    async def findings_stats() -> dict[str, Any]:
        return {
            "total": len(_findings),
            "by_severity": _count_severities(_findings),
            "by_category": _count_field(_findings, "category"),
        }

    # ── Attack Chains ──────────────────────────────────────

    @app.get("/api/chains")
    async def list_chains() -> dict[str, Any]:
        return {"chains": _attack_chains, "total": len(_attack_chains)}

    # ── Tasks ──────────────────────────────────────────────

    @app.get("/api/tasks")
    async def list_tasks(
        status: str = Query("", description="Filter by status"),
    ) -> dict[str, Any]:
        filtered = _tasks
        if status:
            filtered = [t for t in filtered if t.get("status") == status]
        return {"tasks": filtered, "total": len(filtered)}

    @app.post("/api/tasks")
    async def create_task(body: dict[str, Any]) -> dict[str, Any]:
        task = {
            "id": f"task_{int(time.time())}_{len(_tasks)}",
            "description": body.get("description", ""),
            "priority": body.get("priority", 5),
            "status": "queued",
            "created_at": time.time(),
        }
        _tasks.append(task)
        return task

    # ── Metrics ────────────────────────────────────────────

    @app.get("/api/metrics")
    async def get_metrics() -> dict[str, Any]:
        return {
            "scans": {"total": len(_scans), "active": sum(1 for s in _scans.values() if s.get("status") == "running")},
            "agents": {"total": len(_agents), "active": sum(1 for a in _agents.values() if a.get("status") == "running")},
            "models": {"total": len(_models), "healthy": sum(1 for m in _models.values() if m.get("status") == "healthy")},
            "findings": {"total": len(_findings), **_count_severities(_findings)},
            "chains": len(_attack_chains),
            "uptime_s": time.time() - _start_time,
        }

    @app.get("/api/metrics/history")
    async def get_metrics_history(
        limit: int = Query(100, ge=1, le=1000),
    ) -> dict[str, Any]:
        return {"history": _metrics_history[-limit:]}

    # ── System ─────────────────────────────────────────────

    @app.get("/api/system/tools")
    async def list_tools() -> dict[str, Any]:
        """List all registered tools and their availability."""
        import shutil
        tools = [
            "nmap", "masscan", "nuclei", "sqlmap", "nikto", "gobuster", "ffuf",
            "semgrep", "hydra", "john", "hashcat", "aircrack-ng", "wireshark",
            "metasploit", "burpsuite", "trivy", "grype", "volatility",
            "binwalk", "yara", "subfinder", "amass", "httpx", "whatweb",
            "wpscan", "testssl.sh", "sslscan", "dig", "whois", "nslookup",
        ]
        return {
            "tools": {t: shutil.which(t) is not None for t in tools},
            "installed": sum(1 for t in tools if shutil.which(t)),
            "total": len(tools),
        }


def _count_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_field(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        val = item.get(field, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


_start_time = time.time()


def _generate_dashboard_html() -> str:
    """Generate the main dashboard HTML page."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RecurSec Dashboard</title>
<style>
:root{--bg:#0a0a0f;--surface:#12121a;--border:#1e1e2e;--text:#e0e0e8;--dim:#888;
--critical:#ff4444;--high:#ff8800;--medium:#ffcc00;--low:#44bbff;--info:#88cc44;
--accent:#6c5ce7;--success:#00d2d3;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'JetBrains Mono',monospace;background:var(--bg);color:var(--text);padding:20px;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;
border-bottom:1px solid var(--border);padding-bottom:16px;}
.header h1{font-size:24px;color:var(--accent);}
.header .status{color:var(--success);font-size:14px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin-bottom:24px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;}
.card h3{font-size:12px;text-transform:uppercase;color:var(--dim);margin-bottom:8px;}
.card .value{font-size:32px;font-weight:700;}
.card .sub{font-size:12px;color:var(--dim);margin-top:4px;}
.severity-critical{color:var(--critical);} .severity-high{color:var(--high);}
.severity-medium{color:var(--medium);} .severity-low{color:var(--low);} .severity-info{color:var(--info);}
.table{width:100%;border-collapse:collapse;margin-top:16px;}
.table th,.table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--border);font-size:13px;}
.table th{color:var(--dim);font-weight:600;text-transform:uppercase;font-size:11px;}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;}
.badge-critical{background:rgba(255,68,68,0.2);color:var(--critical);}
.badge-high{background:rgba(255,136,0,0.2);color:var(--high);}
.badge-medium{background:rgba(255,204,0,0.2);color:var(--medium);}
.badge-low{background:rgba(68,187,255,0.2);color:var(--low);}
.badge-running{background:rgba(0,210,211,0.2);color:var(--success);}
.badge-healthy{background:rgba(136,204,68,0.2);color:var(--info);}
.section{background:var(--surface);border:1px solid var(--border);border-radius:8px;
padding:16px;margin-bottom:16px;}
.section h2{font-size:16px;margin-bottom:12px;color:var(--accent);}
#log{background:#000;border:1px solid var(--border);border-radius:4px;padding:12px;
font-size:12px;max-height:300px;overflow-y:auto;margin-top:12px;}
.log-entry{margin:2px 0;opacity:0.9;}
</style>
</head>
<body>
<div class="header">
  <h1>⟐ RecurSec</h1>
  <div class="status" id="status">● Connecting...</div>
</div>
<div class="grid">
  <div class="card"><h3>Active Scans</h3><div class="value" id="scans">0</div><div class="sub">running</div></div>
  <div class="card"><h3>Active Agents</h3><div class="value" id="agents">0</div><div class="sub">spawned</div></div>
  <div class="card"><h3>Models Online</h3><div class="value" id="models">0</div><div class="sub">healthy</div></div>
  <div class="card"><h3>Total Findings</h3><div class="value" id="findings">0</div><div class="sub">discovered</div></div>
</div>
<div class="grid">
  <div class="card"><h3>Critical</h3><div class="value severity-critical" id="crit">0</div></div>
  <div class="card"><h3>High</h3><div class="value severity-high" id="high">0</div></div>
  <div class="card"><h3>Medium</h3><div class="value severity-medium" id="med">0</div></div>
  <div class="card"><h3>Low / Info</h3><div class="value severity-low" id="low">0</div></div>
</div>
<div class="section">
  <h2>Recent Findings</h2>
  <table class="table"><thead><tr>
    <th>Severity</th><th>Title</th><th>Target</th><th>Time</th>
  </tr></thead><tbody id="findings-table"></tbody></table>
</div>
<div class="section">
  <h2>Live Activity Log</h2>
  <div id="log"></div>
</div>
<script>
const ws=new WebSocket(`ws://${location.host}/ws`);
ws.onopen=()=>{document.getElementById('status').innerHTML='● Connected';};
ws.onclose=()=>{document.getElementById('status').innerHTML='● Disconnected';
document.getElementById('status').style.color='#ff4444';};
ws.onmessage=(e)=>{
  const data=JSON.parse(e.data);
  const log=document.getElementById('log');
  const entry=document.createElement('div');
  entry.className='log-entry';
  entry.textContent=`[${new Date().toISOString().slice(11,19)}] ${data.type}: ${data.message||JSON.stringify(data.data||{})}`;
  log.appendChild(entry);
  log.scrollTop=log.scrollHeight;
};
async function refresh(){
  try{
    const r=await fetch('/api/metrics');
    const d=await r.json();
    document.getElementById('scans').textContent=d.scans?.active||0;
    document.getElementById('agents').textContent=d.agents?.active||0;
    document.getElementById('models').textContent=d.models?.healthy||0;
    document.getElementById('findings').textContent=d.findings?.total||0;
    document.getElementById('crit').textContent=d.findings?.critical||0;
    document.getElementById('high').textContent=d.findings?.high||0;
    document.getElementById('med').textContent=d.findings?.medium||0;
    document.getElementById('low').textContent=(d.findings?.low||0)+(d.findings?.info||0);
  }catch(e){}
}
setInterval(refresh,5000);
refresh();
</script>
</body>
</html>"""
