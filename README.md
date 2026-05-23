# RecurSec

**Recursive Multi-Agent Security Framework**

Autonomous security testing with unlimited local LLMs, 215+ tools, recursive agent spawning, and 24/7 daemon mode. Everything runs locally — no cloud, no Ollama.

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
| 8101 | **Qwen2.5-Coder-14B** | Code Analysis (Large) | code, code_audit, exploit_dev |
| 8102 | **Qwen2.5-Coder-7B** | Code Analysis (Medium) | code, code_audit |
| 8103 | **CodeLlama-13B** | Exploit Code | code, exploit_dev |
| 8104 | **CodeLlama-7B** | Code (Fast) | code, fast |
| 8105 | **DeepSeek-R1-Distill** | Reasoning | reasoning, planning, analysis |
| 8106 | **DeepSeek-Math-7B** | Math/Crypto Reasoning | reasoning, crypto, math |
| 8107 | **Hermes-4-14B** | General (Large) | general, writing, report |
| 8108 | **Llama-3.1-8B** | General (Medium) | general, recon, osint |
| 8109 | **Dolphin-2.9** | Uncensored General | general, security, pentest |
| 8110 | **Mistral-7B** | General (Fast) | general, fast, recon |
| 8111 | **Yi-9B-200K** | Long Context (200K!) | long_context, code_audit |
| 8112 | **Phi-3.5-mini** | Ultra-Fast Triage | fast, triage, classification |
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

### 2. Launch All 16 Models

```bash
# Make sure your GGUF models are in ~/agent/models/gguf/
./scripts/launch_models.sh

# This starts 16 llama.cpp servers on ports 8100-8115
# Each model gets its own server with optimal settings
```

### 3. Run RecurSec

```bash
# Single target scan
recursec run --config configs/recursec.yaml --target 192.168.1.100

# Full auto-assessment
recursec run --target 192.168.1.0/24 --objective "Complete security assessment"

# Daemon mode (24/7)
recursec run --daemon

# Check available tools
recursec tools
```

### 4. Stop Everything

```bash
./scripts/stop_models.sh
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    YOUR 16 GGUF MODELS                            │
│  WhiteRabbitNeo • Qwen-Coder • CodeLlama • DeepSeek-R1          │
│  Hermes • Llama • Dolphin • Mistral • Yi-200K • Phi             │
│  FunctionGemma (router) • Llama-Guard (safety) • Nomic (embed)  │
└───────────────────────────────┬──────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────┐
│                   INTELLIGENT MODEL ROUTER                        │
│  Security tasks → WhiteRabbitNeo + Dolphin (priority)            │
│  Code analysis → Qwen-Coder-14B + CodeLlama-13B                 │
│  Reasoning → DeepSeek-R1 (chain-of-thought)                     │
│  Long files → Yi-9B-200K (200K context)                          │
│  Quick triage → Phi-3.5-mini + FunctionGemma (instant)          │
│  Reports → Hermes-14B (best writing)                             │
│  Load balanced • Fallback chains • Hot-add/remove                │
└───────────────────────────────┬──────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │ SAFETY GUARD │   │ VECTOR MEMORY│   │ TOOL PARSERS │
    │ Llama-Guard  │   │ Nomic-Embed  │   │ nmap, nuclei │
    │ Pre-check    │   │ RAG search   │   │ sqlmap, etc. │
    └──────────────┘   └──────────────┘   └──────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────┐
│                     DECISIONBRAIN                                  │
│  Decomposes targets → Spawns agents → Builds attack chains       │
└───────────────────────────────┬──────────────────────────────────┘
                                │
  ┌─────────┬─────────┬─────────┼─────────┬─────────┬──────────┐
  ▼         ▼         ▼         ▼         ▼         ▼          ▼
┌─────┐ ┌─────┐ ┌─────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌────────┐
│Recon│ │Vuln │ │Web Scan │ │Exploit│ │Code  │ │Post- │ │Validate│
│Agent│ │Scan │ │Agent    │ │Agent │ │Audit │ │Exploit│ │Agent   │
└─────┘ └─────┘ └─────────┘ └──────┘ └──────┘ └──────┘ └────────┘
  + OSINT, Network, Fuzzer, Crypto, Cloud, Wireless,
    Forensics, Report agents (15 total)
```

### How Model Routing Works

When an agent needs to think, the router picks the best model:

```
ReconAgent needs to analyze nmap output
  → Router checks task_type="security"
  → Selects WhiteRabbitNeo (priority=1, weight=2.0)
  → If busy: falls back to Dolphin (uncensored, priority=2)

CodeAuditAgent reviewing Python source
  → Router checks task_type="code"  
  → Selects Qwen-Coder-14B (largest code model, priority=1)
  → If busy: Qwen-Coder-7B → CodeLlama-13B → CodeLlama-7B

OrchestratorAgent planning attack
  → Router checks task_type="reasoning"
  → Selects DeepSeek-R1 (chain-of-thought, priority=1)

ReportAgent writing final report
  → Router checks task_type="writing"
  → Selects Hermes-14B (best writing quality)

Quick tool selection
  → Router checks task_type="function_call"
  → FunctionGemma-270m responds in <50ms
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
