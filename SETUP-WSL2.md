# RecurSec — WSL2 Setup Guide

## Prerequisites

- Windows 10/11 with WSL2 enabled
- Ubuntu (via WSL2)
- GGUF models in `~/agent/models/gguf/`

## Step 1 — Install Dependencies

```bash
cd ~/agent/recursec
./scripts/install.sh --all
```

This installs:
- Build tools (gcc, cmake, git)
- llama.cpp (built from source with GPU if available)
- Go security tools (nuclei, subfinder, httpx, ffuf, gobuster, etc.)
- Python security tools (semgrep, bandit, sqlmap, etc.)
- RecurSec itself

## Step 2 — Verify Models

```bash
ls ~/agent/models/gguf/
# Should show all 16 .gguf files
```

## Step 3 — Launch All Models

```bash
cd ~/agent/recursec
./scripts/launch_models.sh
# Or specify custom model directory:
./scripts/launch_models.sh ~/agent/models/gguf
```

This starts 16 llama.cpp servers on ports 8100-8115. Each model gets:
- Its own dedicated server
- Optimal context size (8K for most, 131K for Yi-200K, 2K for small models)
- Tuned parallel slots (16 for FunctionGemma, 8 for small/safety, 4 for standard)

Wait for all servers to report healthy (check logs in `~/agent/logs/`).

## Step 4 — Run RecurSec

```bash
# Single target
recursec run --target 192.168.1.100

# Full network assessment
recursec run --target 192.168.1.0/24 --objective "Complete security assessment"

# Daemon mode (24/7)
recursec run --daemon

# Dashboard
# Open http://localhost:8080 in your browser
```

## Step 5 — Access Dashboard from Windows

The dashboard runs on port 8080 inside WSL2. Access it from Windows:
```
http://localhost:8080
```

WSL2 automatically forwards ports to the Windows host.

## GPU Passthrough

If you have an NVIDIA GPU and want GPU acceleration:

```bash
# In Windows PowerShell (admin):
wsl --update

# In WSL2:
nvidia-smi  # Verify GPU is visible

# Rebuild llama.cpp with CUDA:
./scripts/install.sh --llama-cpp --gpu
```

## Stop Everything

```bash
./scripts/stop_models.sh
```

## Troubleshooting

### Models fail to start
- Check `~/agent/logs/` for error messages
- Ensure llama-server is in PATH: `which llama-server`
- Try starting one model manually:
  ```bash
  llama-server -m ~/agent/models/gguf/Phi-3.5-mini-instruct-Q4_K_M.gguf --port 8112 -c 4096
  ```

### Out of memory
- Edit `scripts/launch_models.sh` — reduce `--ctx-size` or `--parallel` for large models
- Run fewer models: comment out models you don't need

### Port conflicts
- Check if something else is using 8100-8115:
  ```bash
  ss -tlnp | grep -E '810[0-9]|811[0-5]'
  ```

### Dashboard not accessible from Windows
- Try `http://$(hostname -I | awk '{print $1}'):8080`
- Or add to `.wslconfig` in Windows:
  ```ini
  [wsl2]
  networkingMode=mirrored
  ```

## File Paths

| What | WSL2 Path | Windows Path |
|------|-----------|-------------|
| Models | `~/agent/models/gguf/` | `\\wsl.localhost\Ubuntu\home\<user>\agent\models\gguf\` |
| Logs | `~/agent/logs/` | `\\wsl.localhost\Ubuntu\home\<user>\agent\logs\` |
| Config | `~/agent/recursec/configs/recursec.yaml` | `\\wsl.localhost\Ubuntu\home\<user>\agent\recursec\configs\recursec.yaml` |
| Data | `~/agent/recursec/data/` | `\\wsl.localhost\Ubuntu\home\<user>\agent\recursec\data\` |
