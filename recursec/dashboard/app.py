"""Web dashboard — FastAPI-based monitoring and control interface."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="RecurSec Dashboard", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global engine reference — set by the CLI
_engine = None


def set_engine(engine: Any) -> None:
    global _engine
    _engine = engine


def get_engine() -> Any:
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    return _engine


# ── Request Models ──────────────────────────────────────

class TaskRequest(BaseModel):
    objective: str
    target: str | None = None
    target_type: str = "host"
    agent_role: str = "orchestrator"
    priority: int = 5


class ModelRequest(BaseModel):
    name: str
    backend: str = "openai_compatible"
    model_id: str
    base_url: str
    api_key: str = ""
    task_types: list[str] = ["general"]
    priority: int = 5


class ToolRequest(BaseModel):
    name: str
    binary: str
    category: str = "misc"
    description: str = ""
    install_cmd: str = ""


# ── API Routes ──────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Main dashboard page."""
    return DASHBOARD_HTML


@app.get("/api/status")
async def get_status(engine=Depends(get_engine)):
    return await engine.get_status()


@app.post("/api/tasks")
async def submit_task(req: TaskRequest, engine=Depends(get_engine)):
    task = await engine.submit_task(
        objective=req.objective,
        target=req.target,
        target_type=req.target_type,
        agent_role=req.agent_role,
        priority=req.priority,
    )
    return {"task_id": task.id, "status": task.status.value}


@app.get("/api/tasks")
async def list_tasks(engine=Depends(get_engine)):
    active = [
        {"id": t.id, "objective": t.objective[:100], "status": t.status.value, "findings": len(t.findings)}
        for t in engine._active_tasks.values()
    ]
    completed = [
        {"id": t.id, "objective": t.objective[:100], "status": t.status.value, "findings": len(t.findings)}
        for t in engine._completed_tasks[-50:]
    ]
    return {"active": active, "completed": completed}


@app.get("/api/findings")
async def get_findings(
    severity: str | None = None,
    validated_only: bool = False,
    limit: int = 100,
    engine=Depends(get_engine),
):
    return await engine.memory.get_findings(severity=severity, validated_only=validated_only, limit=limit)


@app.get("/api/models")
async def list_models(engine=Depends(get_engine)):
    return engine.router.list_models()


@app.post("/api/models")
async def add_model(req: ModelRequest, engine=Depends(get_engine)):
    await engine.add_model_runtime(
        name=req.name,
        backend=req.backend,
        model_id=req.model_id,
        base_url=req.base_url,
        api_key=req.api_key,
        task_types=req.task_types,
        priority=req.priority,
    )
    return {"status": "added", "name": req.name}


@app.delete("/api/models/{name}")
async def remove_model(name: str, engine=Depends(get_engine)):
    await engine.remove_model_runtime(name)
    return {"status": "removed", "name": name}


@app.get("/api/models/health")
async def health_check(engine=Depends(get_engine)):
    return await engine.router.health_check_all()


@app.get("/api/tools")
async def list_tools(engine=Depends(get_engine)):
    return engine.tools.list_available()


@app.post("/api/tools")
async def add_tool(req: ToolRequest, engine=Depends(get_engine)):
    engine.tools.add_custom_tool(
        name=req.name,
        binary=req.binary,
        category=req.category,
        description=req.description,
        install_cmd=req.install_cmd,
    )
    return {"status": "added", "name": req.name}


@app.post("/api/tools/{name}/install")
async def install_tool(name: str, engine=Depends(get_engine)):
    result = await engine.tools.install_tool(name)
    return {"tool": name, "success": result.exit_code == 0, "output": result.stdout[:500]}


@app.get("/api/memory/stats")
async def memory_stats(engine=Depends(get_engine)):
    return await engine.memory.get_stats()


@app.get("/api/safety/stats")
async def safety_stats(engine=Depends(get_engine)):
    return engine.safety.stats()


@app.get("/api/chains")
async def get_chains(engine=Depends(get_engine)):
    return engine.chain_builder.get_summary()


@app.get("/api/chains/report")
async def chain_report(engine=Depends(get_engine)):
    return engine.chain_builder.generate_report_data()


@app.get("/api/memory/search")
async def search_memory(q: str, top_k: int = 5, engine=Depends(get_engine)):
    if engine.vector_memory:
        results = await engine.vector_memory.search(q, top_k=top_k)
        return [{"text": r["text"][:500], "score": r["score"], "metadata": r["metadata"]} for r in results]
    return []


# ── Dashboard HTML ──────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RecurSec Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Cascadia Code','Fira Code',monospace;background:#0a0a0f;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#1a0030,#0d001a);padding:20px 30px;border-bottom:1px solid #333;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:24px;background:linear-gradient(90deg,#ff0044,#ff6600,#ff0044);-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:glow 2s ease-in-out infinite alternate}
@keyframes glow{from{filter:brightness(1)}to{filter:brightness(1.3)}}
.status-bar{display:flex;gap:20px;font-size:12px}
.status-item{display:flex;align-items:center;gap:6px}
.dot{width:8px;height:8px;border-radius:50%;animation:pulse 2s infinite}
.dot.green{background:#00ff44}.dot.red{background:#ff0044}.dot.yellow{background:#ffaa00}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.container{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding:20px;max-width:1600px;margin:0 auto}
.card{background:#111118;border:1px solid #222;border-radius:8px;padding:20px}
.card h2{font-size:14px;color:#888;text-transform:uppercase;letter-spacing:2px;margin-bottom:15px;border-bottom:1px solid #222;padding-bottom:8px}
.metric{font-size:36px;font-weight:bold;color:#fff;margin:5px 0}
.metric.critical{color:#ff0044}.metric.high{color:#ff6600}.metric.medium{color:#ffaa00}.metric.low{color:#00aaff}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.mini-card{background:#0a0a12;padding:12px;border-radius:6px;border:1px solid #1a1a2a}
.mini-card .label{font-size:11px;color:#666;text-transform:uppercase}
.mini-card .value{font-size:20px;font-weight:bold;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:#666;font-size:11px;text-transform:uppercase;padding:8px;border-bottom:1px solid #222}
td{padding:8px;border-bottom:1px solid #111}
.severity{padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold}
.severity.critical{background:#ff004422;color:#ff0044}.severity.high{background:#ff660022;color:#ff6600}
.severity.medium{background:#ffaa0022;color:#ffaa00}.severity.low{background:#00aaff22;color:#00aaff}
.severity.info{background:#88888822;color:#888}
.full-width{grid-column:1/-1}
.btn{background:#1a1a2a;color:#e0e0e0;border:1px solid #333;padding:8px 16px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px}
.btn:hover{background:#2a2a3a;border-color:#555}
.btn.primary{background:#ff004433;border-color:#ff0044;color:#ff0044}
input,select{background:#0a0a12;border:1px solid #333;color:#e0e0e0;padding:8px;border-radius:4px;font-family:inherit;font-size:12px;width:100%}
.form-row{display:flex;gap:10px;margin-bottom:10px}
.form-row>*{flex:1}
.model-list{max-height:200px;overflow-y:auto}
.model-item{display:flex;justify-content:space-between;align-items:center;padding:8px;border-bottom:1px solid #111}
.tool-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;max-height:300px;overflow-y:auto}
.tool-item{background:#0a0a12;padding:8px;border-radius:4px;border:1px solid #1a1a2a;font-size:11px}
.tool-item.available{border-color:#00ff4433}.tool-item.missing{border-color:#ff004433;opacity:.6}
#log{background:#050508;border:1px solid #222;border-radius:4px;padding:10px;max-height:300px;overflow-y:auto;font-size:11px;line-height:1.6;font-family:'Cascadia Code',monospace}
.log-entry{border-bottom:1px solid #0a0a12;padding:2px 0}
</style>
</head>
<body>
<div class="header">
    <h1>RECURSEC</h1>
    <div class="status-bar">
        <div class="status-item"><div class="dot" id="engine-dot"></div><span id="engine-status">Connecting...</span></div>
        <div class="status-item">Models: <strong id="model-count">-</strong></div>
        <div class="status-item">Tools: <strong id="tool-count">-</strong></div>
        <div class="status-item">Findings: <strong id="finding-count">-</strong></div>
    </div>
</div>
<div class="container">
    <div class="card">
        <h2>Submit Task</h2>
        <div class="form-row">
            <input id="task-objective" placeholder="Objective (e.g. 'Full pentest of 192.168.1.0/24')">
        </div>
        <div class="form-row">
            <input id="task-target" placeholder="Target (IP, URL, path, CIDR)">
            <select id="task-type">
                <option value="host">Host</option><option value="url">URL</option>
                <option value="network_range">Network Range</option><option value="code_repo">Code Repo</option>
                <option value="api">API</option>
            </select>
            <select id="task-role">
                <option value="orchestrator">Orchestrator (Auto)</option>
                <option value="recon">Recon Only</option><option value="vuln_scanner">Vuln Scan Only</option>
                <option value="web_scanner">Web Scan Only</option><option value="exploit">Exploit Only</option>
                <option value="code_auditor">Code Audit Only</option><option value="osint">OSINT Only</option>
            </select>
        </div>
        <button class="btn primary" onclick="submitTask()">Launch</button>
    </div>
    <div class="card">
        <h2>Engine Status</h2>
        <div class="grid-3">
            <div class="mini-card"><div class="label">Active Tasks</div><div class="value" id="active-tasks">0</div></div>
            <div class="mini-card"><div class="label">Queued</div><div class="value" id="queued-tasks">0</div></div>
            <div class="mini-card"><div class="label">Completed</div><div class="value" id="completed-tasks">0</div></div>
            <div class="mini-card"><div class="label">Critical</div><div class="value metric critical" id="crit-count">0</div></div>
            <div class="mini-card"><div class="label">High</div><div class="value metric high" id="high-count">0</div></div>
            <div class="mini-card"><div class="label">Medium</div><div class="value metric medium" id="med-count">0</div></div>
        </div>
    </div>
    <div class="card">
        <h2>LLM Models (Hot-Add/Remove)</h2>
        <div class="form-row">
            <input id="model-name" placeholder="Name"><input id="model-id" placeholder="Model ID">
        </div>
        <div class="form-row">
            <input id="model-url" placeholder="Base URL"><select id="model-backend">
                <option value="vllm">vLLM</option><option value="llama_cpp">llama.cpp</option>
                <option value="sglang">SGLang</option><option value="litellm">LiteLLM</option>
                <option value="ollama">Ollama</option><option value="openai_compatible">OpenAI-Compatible</option>
            </select>
        </div>
        <button class="btn" onclick="addModel()">Add Model</button>
        <div class="model-list" id="model-list"></div>
    </div>
    <div class="card">
        <h2>Findings</h2>
        <table><thead><tr><th>Severity</th><th>Title</th><th>Component</th><th>Confidence</th></tr></thead>
        <tbody id="findings-table"></tbody></table>
    </div>
    <div class="card full-width">
        <h2>Tools (<span id="tools-available">0</span>/<span id="tools-total">0</span> available)</h2>
        <div class="tool-grid" id="tool-grid"></div>
    </div>
    <div class="card full-width">
        <h2>Activity Log</h2>
        <div id="log"></div>
    </div>
</div>
<script>
const API='';
async function fetchJSON(url,opts){const r=await fetch(API+url,opts);return r.json();}
function addLog(msg){const log=document.getElementById('log');const e=document.createElement('div');e.className='log-entry';e.textContent=new Date().toLocaleTimeString()+' '+msg;log.prepend(e);if(log.children.length>200)log.lastChild.remove();}

async function refresh(){
    try{
        const s=await fetchJSON('/api/status');
        document.getElementById('engine-dot').className='dot green';
        document.getElementById('engine-status').textContent='Running';
        document.getElementById('model-count').textContent=s.models?.length||0;
        document.getElementById('tool-count').textContent=s.tools_available+'/'+s.tools_total;
        document.getElementById('active-tasks').textContent=s.active_tasks;
        document.getElementById('queued-tasks').textContent=s.queued_tasks;
        document.getElementById('completed-tasks').textContent=s.completed_tasks;
        const sev=s.memory?.findings_by_severity||{};
        document.getElementById('crit-count').textContent=sev.critical||0;
        document.getElementById('high-count').textContent=sev.high||0;
        document.getElementById('med-count').textContent=sev.medium||0;
        document.getElementById('finding-count').textContent=s.memory?.findings_count||0;

        // Models
        const ml=document.getElementById('model-list');ml.innerHTML='';
        (s.models||[]).forEach(m=>{
            const d=document.createElement('div');d.className='model-item';
            d.innerHTML='<span>'+m.name+' ('+m.model_id+')</span><span>'+m.avg_latency_ms+'ms | '+m.total_requests+' reqs</span>';
            ml.appendChild(d);
        });

        // Findings
        const findings=await fetchJSON('/api/findings?limit=20');
        const ft=document.getElementById('findings-table');ft.innerHTML='';
        findings.forEach(f=>{
            const tr=document.createElement('tr');
            tr.innerHTML='<td><span class="severity '+f.severity+'">'+f.severity+'</span></td><td>'+f.title+'</td><td>'+(f.affected_component||'-')+'</td><td>'+(f.confidence*100).toFixed(0)+'%</td>';
            ft.appendChild(tr);
        });

        // Tools
        const tools=await fetchJSON('/api/tools');
        const tg=document.getElementById('tool-grid');tg.innerHTML='';
        let avail=0;
        tools.forEach(t=>{
            if(t.available)avail++;
            const d=document.createElement('div');d.className='tool-item '+(t.available?'available':'missing');
            d.innerHTML='<strong>'+t.name+'</strong><br><span style="color:#666">'+t.category+'</span>';
            tg.appendChild(d);
        });
        document.getElementById('tools-available').textContent=avail;
        document.getElementById('tools-total').textContent=tools.length;
    }catch(e){
        document.getElementById('engine-dot').className='dot red';
        document.getElementById('engine-status').textContent='Disconnected';
    }
}

async function submitTask(){
    const obj=document.getElementById('task-objective').value;
    const tgt=document.getElementById('task-target').value;
    const type=document.getElementById('task-type').value;
    const role=document.getElementById('task-role').value;
    const r=await fetchJSON('/api/tasks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({objective:obj,target:tgt||null,target_type:type,agent_role:role})});
    addLog('Task submitted: '+r.task_id);
}

async function addModel(){
    const r=await fetchJSON('/api/models',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
        name:document.getElementById('model-name').value,
        model_id:document.getElementById('model-id').value,
        base_url:document.getElementById('model-url').value,
        backend:document.getElementById('model-backend').value,
    })});
    addLog('Model added: '+r.name);refresh();
}

setInterval(refresh,5000);refresh();
</script>
</body>
</html>"""
