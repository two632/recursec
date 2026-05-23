# RecurSec

**Recursive Multi-Agent Security Framework**

Autonomous security testing with unlimited local LLMs, 200+ tools, recursive agent spawning, and 24/7 daemon mode. Everything runs locally — no cloud required.

```
 ____  ____  ____  _  _  ____  ____  ____  ____
(  _ \( ___)/ ___)( )( )(  _ \/ ___)( ___)/ ___)
 )   / )__)( (__   )()(  )   /\___ \ )__)( (__
(_)\_)(____)\___) (____)((_)\_)(____/(____)\___) 
```

---

## What This Does

RecurSec is a framework that connects your local LLMs to 200+ security tools and lets them run autonomously. The **DecisionBrain** (orchestrator) analyzes your target, breaks the work into specialized sub-tasks, and dispatches them to **15 specialized agents** — each an expert in their domain.

Agents can spawn child agents recursively (up to configurable depth), creating attack chains that would take a human team days to assemble.

### Architecture

```
┌──────────────────────────────────────────────────────┐
│              YOUR LLMs (unlimited)                    │
│  vLLM • llama.cpp • SGLang • LiteLLM • any endpoint │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│          INTELLIGENT MODEL ROUTER                     │
│  Routes by task type • Load balancing • Fallbacks    │
│  Hot-add/remove models at runtime                    │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│            DECISIONBRAIN (Orchestrator)               │
│  Decomposes targets • Assembles attack chains        │
│  Spawns specialized agents recursively               │
└───────────────────────┬──────────────────────────────┘
                        │
  ┌─────────┬─────────┬─┴───────┬─────────┬──────────┐
  ▼         ▼         ▼         ▼         ▼          ▼
┌─────┐ ┌─────┐ ┌─────────┐ ┌──────┐ ┌──────┐ ┌────────┐
│Recon│ │Vuln │ │Web Scan │ │Exploit│ │Code  │ │Post-   │
│Agent│ │Scan │ │Agent    │ │Agent │ │Audit │ │Exploit │
└─────┘ └─────┘ └─────────┘ └──────┘ └──────┘ └────────┘
  + OSINT, Network, Fuzzer, Crypto, Cloud, Wireless,
    Forensics, Report, Validator agents
```

### Key Features

- **Unlimited LLMs** — Not hardcoded to any number. Add 1 or 100 models. Hot-add/remove at runtime via API.
- **6 Inference Backends** — vLLM (fastest throughput), llama.cpp (lightest), SGLang (lowest latency), LiteLLM (universal proxy), Ollama, any OpenAI-compatible endpoint.
- **Intelligent Routing** — Routes each task to the best model based on task type (code analysis → DeepSeek, reasoning → Qwen, fast queries → Mistral-7B, etc.). Load balancing, weighted selection, automatic fallbacks.
- **200+ Security Tools** — nmap, masscan, nuclei, sqlmap, metasploit, semgrep, hydra, hashcat, wireshark, and 190+ more. All auto-detected, installable via CLI.
- **15 Specialized Agents** — Recon, VulnScan, WebScan, Exploit, PostExploit, CodeAudit, Network, OSINT, Fuzzer, Crypto, Cloud, Wireless, Forensics, Report, Validator.
- **Recursive Agent Spawning** — Agents create sub-agents for specialized tasks. The Orchestrator plans, delegates, and aggregates results up the tree.
- **Anti-Hallucination Validation** — Dedicated Validator agent cross-checks every finding with different tools and models before marking it confirmed.
- **24/7 Daemon Mode** — Task queue, scheduled recurring scans, auto-restart on failure.
- **Web Dashboard** — Real-time monitoring, task submission, model management, findings viewer.
- **Docker Sandboxed** — Everything runs in containers. Host system protected.
- **Fully Configurable** — Single YAML file controls everything. Every parameter is tunable.

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/youruser/recursec.git
cd recursec
pip install -e .
```

### 2. Generate Config

```bash
recursec init
```

This creates `recursec.yaml`. Edit it to add your LLM endpoints.

### 3. Start Your LLM Servers

You need at least one LLM server running. Pick any backend:

**vLLM (recommended for GPU):**
```bash
python -m vllm.entrypoints.openai.api_server \
    --model deepseek-ai/deepseek-coder-v2-lite-instruct \
    --port 8000
```

**llama.cpp (recommended for CPU):**
```bash
./llama-server -m your-model.gguf --host 0.0.0.0 --port 8080 -ngl 99
```

**SGLang (fastest latency):**
```bash
python -m sglang.launch_server --model-path meta-llama/Meta-Llama-3.1-8B-Instruct --port 30000
```

### 4. Run a Scan

```bash
# Single target scan
recursec run --target 192.168.1.100 --objective "Full security assessment"

# Daemon mode (24/7)
recursec run --daemon --config recursec.yaml

# Check available tools
recursec tools
```

### 5. Docker (Recommended)

```bash
cd docker
docker compose up -d
```

The Docker image comes with Kali Linux + all 200+ tools pre-installed.

---

## Configuration

Everything is in `recursec.yaml`:

### Adding LLMs

```yaml
models:
  - name: my-model
    backend: vllm          # vllm, llama_cpp, sglang, litellm, ollama, openai_compatible
    model_id: my-model-id
    base_url: http://localhost:8000
    task_types: [code, security]  # What this model is good at
    priority: 1            # 1 = highest priority
    max_concurrent: 10     # Max parallel requests
    weight: 1.0            # Selection weight
```

Task types: `general`, `code`, `reasoning`, `security`, `writing`, `fast`

### Adding Custom Tools

```yaml
tools:
  custom_tools:
    - name: my-scanner
      binary: my-scanner
      category: vuln_scan
      description: "My custom vulnerability scanner"
      install: "pip install my-scanner"
```

### Scheduled Scans

```yaml
daemon:
  schedule:
    - objective: "Scan internal network"
      target: "192.168.1.0/24"
      target_type: network_range
      interval_s: 21600  # Every 6 hours
```

---

## API

The dashboard exposes a REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Engine status |
| `/api/tasks` | POST | Submit a task |
| `/api/tasks` | GET | List tasks |
| `/api/findings` | GET | Get findings |
| `/api/models` | GET | List models |
| `/api/models` | POST | Add a model (hot-add) |
| `/api/models/{name}` | DELETE | Remove a model |
| `/api/models/health` | GET | Health check all models |
| `/api/tools` | GET | List tools |
| `/api/tools` | POST | Add custom tool |
| `/api/tools/{name}/install` | POST | Install a tool |
| `/api/memory/stats` | GET | Memory statistics |

### Example: Add a Model at Runtime

```bash
curl -X POST http://localhost:8080/api/models \
  -H "Content-Type: application/json" \
  -d '{
    "name": "new-model",
    "backend": "vllm",
    "model_id": "Qwen/Qwen2.5-32B-Instruct",
    "base_url": "http://localhost:8002",
    "task_types": ["reasoning"],
    "priority": 2
  }'
```

### Example: Submit a Task

```bash
curl -X POST http://localhost:8080/api/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "objective": "Find all SQL injection vulnerabilities",
    "target": "https://example.com",
    "target_type": "url",
    "agent_role": "web_scanner"
  }'
```

---

## How It Works

### Recursive Agent Flow

1. You submit a task: "Full pentest of 192.168.1.0/24"
2. **DecisionBrain** receives the task and plans:
   - Spawn ReconAgent → discover hosts and services
   - Spawn VulnScanAgent → scan discovered services
   - Spawn WebScanAgent → test any web apps found
   - Spawn ExploitAgent → attempt exploitation of confirmed vulns
   - Spawn ValidatorAgent → verify all findings
   - Spawn ReportAgent → compile report
3. Each agent may spawn its own children (e.g., WebScanAgent spawns SQLi sub-agent and XSS sub-agent)
4. Results flow back up the tree
5. ValidatorAgent cross-checks everything to eliminate false positives
6. ReportAgent compiles the final report with severity ratings

### Model Routing

The router assigns models based on what they're best at:

| Task Type | Best Models | Why |
|-----------|-------------|-----|
| Code analysis | DeepSeek Coder, CodeLlama | Trained on code |
| Reasoning | Qwen 72B, Llama 70B | Large context, strong reasoning |
| Security | DeepSeek, Qwen | Domain knowledge |
| Writing | Llama, Yi | Natural language quality |
| Fast queries | Mistral 7B, Phi-3 | Low latency |

---

## Tools (210+)

| Category | Count | Examples |
|----------|-------|---------|
| Recon | 30 | nmap, masscan, subfinder, amass, httpx |
| Vuln Scan | 17 | nuclei, nikto, openvas, wpscan, trivy |
| Web | 25 | sqlmap, xsstrike, ffuf, gobuster, dalfox |
| Exploit | 9 | metasploit, searchsploit, pwntools, ropper |
| Network | 13 | wireshark, tcpdump, bettercap, mitmproxy |
| Post-Exploit | 14 | linpeas, bloodhound, mimikatz, impacket |
| Code Analysis | 16 | semgrep, codeql, bandit, gosec, brakeman |
| Crypto | 11 | hashcat, john, hydra, medusa |
| OSINT | 11 | shodan, censys, sherlock, spiderfoot |
| Fuzzing | 8 | afl++, honggfuzz, boofuzz, schemathesis |
| Wireless | 10 | aircrack-ng, kismet, wifite, reaver |
| Cloud | 10 | prowler, scoutsuite, pacu, cloudfox |
| Forensics | 14 | volatility, radare2, ghidra, binwalk, yara |
| Reporting | 4 | pandoc, wkhtmltopdf, faraday |
| Misc | 22 | curl, git, docker, openssl, tor |

All tools are auto-detected on startup. Missing tools can be installed via:
```bash
recursec tools                          # List all tools
curl -X POST localhost:8080/api/tools/nmap/install  # Install via API
```

---

## Project Structure

```
recursec/
├── recursec/
│   ├── core/
│   │   ├── models.py          # Data models (Vulnerability, Task, Target, etc.)
│   │   └── base_agent.py      # Base agent class with ReAct loop
│   ├── llm/
│   │   ├── backends.py        # LLM backends (vLLM, llama.cpp, SGLang, etc.)
│   │   └── router.py          # Intelligent model router
│   ├── tools/
│   │   ├── base.py            # Base tool class + shell execution
│   │   └── registry.py        # 200+ tool definitions + registry
│   ├── agents/
│   │   ├── prompts.py         # System prompts for all 15 agent roles
│   │   ├── security_agents.py # Agent implementations
│   │   └── factory.py         # Agent factory
│   ├── memory/
│   │   └── store.py           # SQLite + in-memory state management
│   ├── config/
│   │   └── settings.py        # Pydantic settings from YAML
│   ├── daemon/
│   │   └── engine.py          # Main engine + task queue + daemon mode
│   ├── dashboard/
│   │   └── app.py             # FastAPI web dashboard
│   └── cli.py                 # Typer CLI
├── docker/
│   ├── Dockerfile             # Kali Linux + all tools
│   └── docker-compose.yml     # Full stack deployment
├── configs/
│   └── recursec.yaml          # Default configuration
├── tests/
├── pyproject.toml
└── README.md
```

---

## Comparison

| Feature | RecurSec | PentAGI | Agent Zero | CyberStrike |
|---------|----------|---------|------------|-------------|
| Unlimited LLMs | **Yes** | 1 | 1 | 1 |
| LLM backends | **6** (vLLM, llama.cpp, SGLang, LiteLLM, Ollama, custom) | Ollama | Ollama | BYOK |
| Intelligent routing | **Yes** (task-type, load balance, fallback) | No | No | No |
| Hot-add models | **Yes** (API) | No | No | No |
| Security tools | **210+** | ~20 | ~10 | 7,300 skills |
| Specialized agents | **15** | 1 | 1 | 13 |
| Recursive spawning | **Yes** (configurable depth) | No | No | No |
| Anti-hallucination | **Yes** (Validator agent) | No | No | No |
| 24/7 daemon | **Yes** | No | No | No |
| Web dashboard | **Yes** | Yes | Yes | Yes |
| Scheduled scans | **Yes** | No | No | No |
| Docker sandboxed | **Yes** | Yes | Yes | No |

---

## Security Notice

This framework is intended for **authorized security testing only**. Always obtain explicit written permission before testing any system you don't own. Unauthorized access to computer systems is illegal.

---

## License

AGPL-3.0
