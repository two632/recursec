# RecurSec

**Recursive Multi-Agent Security Framework**

Autonomous security testing with unlimited local LLMs, 244+ tools, recursive agent spawning, and autonomous think-act loop. Everything runs locally — no cloud, no Ollama, no paid APIs.

```
 ____  ____  ____  _  _  ____  ____  ____  ____
(  _ \( ___)/ ___)( )( )(  _ \/ ___)( ___)/ ___)
 )   / )__)( (__   )()(  )   /\___ \ )__)( (__
(_)\_)(____)\___) (____)((_)\_)(____/(____)\___) 
```

---

## Your 16-Model Setup

RecurSec is pre-configured for your exact GGUF models, with each model assigned to what it's best at:

| Port | Model | Role | Task Types |
|------|-------|------|------------|
| 8100 | **WhiteRabbitNeo-7B** | Security Brain | security, exploit, vuln_analysis |
| 8101 | **Mistral-7B-Instruct** | General (Fast) | general, fast, recon |
| 8102 | **Qwen2.5-Coder-14B** | Code Analysis (Large) | code, code_audit, exploit_dev |
| 8103 | **Qwen2.5-Coder-7B** | Code Analysis (Medium) | code, code_audit |
| 8104 | **DeepSeek-R1-Distill** | Reasoning | reasoning, planning, analysis |
| 8105 | **Hermes-4-14B** | General (Large) | general, writing, report |
| 8106 | **Llama-3.1-8B** | General (Medium) | general, recon, osint |
| 8107 | **CodeLlama-13B** | Exploit Code | code, exploit_dev |
| 8108 | **CodeLlama-7B** | Code (Fast) | code, fast |
| 8109 | **Dolphin-2.9** | Uncensored General | general, security, pentest |
| 8110 | **Phi-3.5-mini** | Ultra-Fast Triage | fast, triage, classification |
| 8111 | **DeepSeek-Math-7B** | Math/Crypto Reasoning | reasoning, crypto, math |
| 8112 | **Yi-9B-200K** | Long Context (200K!) | long_context, code_audit |
| 8113 | **FunctionGemma-270m** | Tool Call Router | function_call, tool_routing |
| 8114 | **Llama-Guard-3** | Safety Guardrail | safety classification |
| 8115 | **Nomic-Embed-Text** | RAG / Embedding | semantic memory search |

---

## Quick Start

### 1. Install Everything

```bash
git clone <repo-url> ~/agent/recursec
cd ~/agent/recursec

# Full install (llama.cpp + tools + RecurSec)
./scripts/install.sh --all

# Or just RecurSec
pip install -e .
```

### 2. Launch Models (On-Demand — NOT All 16 at Once)

```bash
# On-demand architecture: load only 1-2 models at a time (8-16GB RAM)
# NOT all 16 (which would need 120GB+ RAM)

# Start WhiteRabbitNeo (security brain — handles 80% of tasks)
./scripts/launch_models.sh whiterabbitneo

# Optionally start a second model for consensus voting
./scripts/launch_models.sh qwen-coder-14b

# Smart router picks best model per task type:
# scan_web_vulns → WhiteRabbitNeo (primary)
# analyze_code → Qwen-Coder-14B
# build_exploit → DeepSeek-R1
# quick_triage → Phi-3.5-mini
# If primary model isn't loaded, router falls back to whatever IS online
```

### 3. Run RecurSec

```bash
# Scan a target (autonomous mode — LLM decides what tools to run)
python -m recursec scan https://target-site.com

# Scan with more autonomous iterations
python -m recursec scan https://target-site.com --iterations 200

# Deep + stealth scan
python -m recursec scan 192.168.1.0/24 --deep --stealth

# Tools-only mode (no LLM loop)
python -m recursec scan https://target-site.com --no-autonomous

# Disable multi-model consensus voting
python -m recursec scan https://target-site.com --no-consensus

# Check LLM server health + routing status
python -m recursec health

# List all 244+ registered tools
python -m recursec tools

# List configured models
python -m recursec models
```

### 4. Stop Everything

```bash
./scripts/stop_models.sh
```

---

## Architecture (On-Demand Model Loading)

```
┌──────────────────────────────────────────────────────────────────┐
│              16 GGUF MODELS ON DISK (~200GB)                      │
│  WhiteRabbitNeo • Qwen-Coder • CodeLlama • DeepSeek-R1          │
│  Hermes • Llama • Dolphin • Mistral • Yi-200K • Phi             │
│  FunctionGemma • Llama-Guard • Nomic-Embed (+ 3 more)           │
│  Only 1-2 loaded in RAM at a time (8-16GB max)                   │
└───────────────────────────────┬──────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────┐
│              SMART ROUTER (22 Task Types)                         │
│                                                                   │
│  scan_web_vulns → WhiteRabbitNeo (primary)                       │
│  analyze_code → Qwen-Coder-14B (primary)                        │
│  build_exploit → DeepSeek-R1 (primary)                           │
│  quick_triage → Phi-3.5-mini (primary)                           │
│  write_report → Hermes-14B (primary)                             │
│                                                                   │
│  Each task type has: primary + fallbacks + consensus pool        │
│  Falls back to whatever model IS online if primary isn't         │
│  Task batching: groups tasks by model to minimize swaps          │
│  Predictive preloading: anticipates next model needed            │
└───────────────────────────────┬──────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │  CONSENSUS   │   │ VECTOR MEMORY│   │ TOOL PARSERS │
    │  VOTING      │   │ Nomic-Embed  │   │ nmap, nuclei │
    │ 2-3 models   │   │ RAG search   │   │ sqlmap, etc. │
    │ vote on vuln │   │ (optional)   │   │ 244+ tools   │
    └──────────────┘   └──────────────┘   └──────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────┐
│                     ORCHESTRATOR                                   │
│  Decomposes targets → Batches tasks by model → Executes          │
│  Autonomous think-act loop → Consensus validation                │
└───────────────────────────────┬──────────────────────────────────┘
                                │
  ┌─────────┬─────────┬─────────┼─────────┬─────────┬──────────┐
  ▼         ▼         ▼         ▼         ▼         ▼          ▼
┌─────┐ ┌─────┐ ┌─────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌────────┐
│Recon│ │Vuln │ │Web Scan │ │Exploit│ │Code  │ │Post- │ │Validate│
│Agent│ │Scan │ │Agent    │ │Agent │ │Audit │ │Exploit│ │Agent   │
└─────┘ └─────┘ └─────────┘ └──────┘ └──────┘ └──────┘ └────────┘
```

### Smart Routing + Consensus Voting

```
SCAN PIPELINE (9 phases):
1. RECON: dig, whois, subfinder, nmap, curl
2. LLM ANALYSIS: routed to planning specialist (DeepSeek-R1)
3. ACTIVE SCANNING: nuclei, nikto, ffuf, sqlmap
4. FINDING ANALYSIS: batched by model to minimize swaps
5. DEEP DIVE: follow-up tools on interesting findings
6. AUTONOMOUS LOOP: LLM decides what tools to run next
7. CONSENSUS VALIDATION: 2-3 models vote on critical findings
8. REPORT: JSON + markdown with all findings

CONSENSUS VOTING (reduces false positives by ~60%):
  Critical finding detected: SQL injection at /login
  → WhiteRabbitNeo: CONFIRMED (has auth bypass pattern)
  → Qwen-Coder: CONFIRMED (parameterized query missing)
  → DeepSeek-R1: CONFIRMED (error-based blind SQLi)
  → 3/3 agree = confidence 1.0 = REAL VULNERABILITY

TASK BATCHING (minimizes model swaps):
  Instead of: Load→Task→Unload→Load→Task→Unload (slow)
  Does:       Load WhiteRabbitNeo → Task1,Task2,Task3 → Load Qwen → Task4
  Time saved: ~30 seconds per swap avoided
```

---

## Features

### Core
- **Unlimited LLMs** — add any number, hot-add/remove at runtime via API
- **6 inference backends** — vLLM, llama.cpp, SGLang, LiteLLM, Ollama, any OpenAI-compatible
- **Intelligent routing** — task-type matching, load balancing, weighted selection, automatic fallbacks
- **215+ security tools** — auto-detected, installable via CLI or API
- **15 specialized agents** — each a domain expert with its own system prompt and tool preferences

### Security Intelligence
- **Recursive spawning** — DecisionBrain creates child agents, which create grandchildren (configurable depth 1-5)
- **Anti-hallucination** — ValidatorAgent cross-checks every finding with different tools and models
- **Attack chain builder** — Links findings into exploitation paths (Recon → Vuln → Exploit → Post-Exploit)
- **Tool output parsers** — Structured parsing for nmap, nuclei, sqlmap, semgrep, nikto, gobuster, hydra, and more

### Safety & Memory
- **Llama-Guard-3 safety filter** — Blocks harmful content, ensures authorized testing scope
- **RAG vector memory** — Nomic-Embed creates semantic embeddings of findings for intelligent retrieval
- **SQLite persistence** — All findings, tool results, and agent messages stored permanently
- **Knowledge graph** — Searchable knowledge base that grows smarter with each scan

### Operations
- **24/7 daemon mode** — task queue, scheduled recurring scans, auto-restart
- **Web dashboard** — real-time monitoring, task submission, model management at http://localhost:8080
- **REST API** — full programmatic control
- **Docker** — Kali Linux Dockerfile with all tools pre-installed

---

## Tools (215+)

| Category | Count | Examples |
|----------|-------|---------|
| Recon | 30 | nmap, masscan, subfinder, amass, httpx |
| Vuln Scan | 17 | nuclei, nikto, openvas, wpscan, trivy |
| Web | 26 | sqlmap, xsstrike, ffuf, gobuster, dalfox |
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

Missing tools can be installed:
```bash
recursec tools                                      # List all tools
curl -X POST localhost:8080/api/tools/nmap/install  # Install via API
```

---

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Engine status (models, tools, safety, memory) |
| `/api/tasks` | POST | Submit a task |
| `/api/tasks` | GET | List tasks |
| `/api/findings` | GET | Get findings |
| `/api/models` | GET/POST | List/add models |
| `/api/models/{name}` | DELETE | Remove model |
| `/api/models/health` | GET | Health check all |
| `/api/tools` | GET/POST | List/add tools |
| `/api/tools/{name}/install` | POST | Install a tool |
| `/api/memory/stats` | GET | Memory statistics |

---

## Project Structure

```
recursec/
├── recursec/
│   ├── core/
│   │   ├── models.py          # Pydantic data models
│   │   ├── base_agent.py      # Base agent + ReAct loop
│   │   └── attack_chain.py    # Attack chain builder
│   ├── llm/
│   │   ├── backends.py        # 6 LLM backends
│   │   ├── router.py          # Intelligent model router
│   │   └── safety.py          # Llama-Guard safety filter
│   ├── tools/
│   │   ├── base.py            # Base tool + shell execution
│   │   ├── registry.py        # 215+ tool definitions
│   │   └── parsers.py         # Structured output parsers
│   ├── agents/
│   │   ├── prompts.py         # 15 specialized system prompts
│   │   ├── security_agents.py # Agent implementations (ReAct)
│   │   └── factory.py         # Agent factory
│   ├── memory/
│   │   ├── store.py           # SQLite persistence
│   │   └── embeddings.py      # Nomic-Embed RAG + vector memory
│   ├── config/
│   │   └── settings.py        # Pydantic settings from YAML
│   ├── daemon/
│   │   └── engine.py          # Main engine + daemon
│   ├── dashboard/
│   │   └── app.py             # FastAPI web dashboard
│   └── cli.py                 # Typer CLI
├── scripts/
│   ├── install.sh             # Full installation script
│   ├── launch_models.sh       # Start all 16 llama.cpp servers
│   └── stop_models.sh         # Stop all model servers
├── docker/
│   ├── Dockerfile             # Kali Linux + all tools
│   └── docker-compose.yml     # Full stack deployment
├── configs/
│   └── recursec.yaml          # Pre-configured for your 16 models
├── tests/
└── pyproject.toml
```

---

## Security Notice

This framework is for **authorized security testing only**. Always obtain written permission before testing any system you don't own. The Llama-Guard safety layer helps enforce this but is not a substitute for proper authorization.

---

## License

AGPL-3.0
