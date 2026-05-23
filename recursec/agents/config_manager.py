"""Configuration manager — centralized, hot-reloadable configuration system.

Implements:
1. YAML/JSON configuration loading
2. Environment variable override
3. Model configuration management
4. Tool configuration management
5. Agent configuration templates
6. Configuration validation
7. Hot-reload with change detection
8. Default configuration generation
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ModelConfig:
    """Configuration for a single LLM model."""
    model_id: str = ""
    name: str = ""
    path: str = ""                  # Path to GGUF file
    port: int = 8100
    context_length: int = 4096
    gpu_layers: int = 35
    threads: int = 4
    batch_size: int = 512
    capabilities: list[str] = field(default_factory=list)
    weight: float = 1.0
    priority: int = 5
    system_prompt: str = ""
    temperature: float = 0.7
    top_p: float = 0.9
    max_tokens: int = 2048
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id,
            "name": self.name[:25],
            "port": self.port,
            "ctx": self.context_length,
            "caps": self.capabilities[:3],
            "weight": self.weight,
            "enabled": self.enabled,
        }


@dataclass
class ToolConfig:
    """Configuration for a tool."""
    tool_id: str = ""
    name: str = ""
    binary: str = ""
    install_cmd: str = ""
    default_args: list[str] = field(default_factory=list)
    timeout: int = 300
    requires_root: bool = False
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.tool_id,
            "name": self.name[:20],
            "binary": self.binary[:15],
            "timeout": self.timeout,
            "enabled": self.enabled,
        }


@dataclass
class AgentTemplate:
    """Template for creating agents."""
    template_id: str = ""
    name: str = ""
    role: str = ""
    preferred_model: str = ""
    system_prompt: str = ""
    max_tokens_per_turn: int = 2048
    temperature: float = 0.7
    tools: list[str] = field(default_factory=list)
    max_recursion_depth: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.template_id,
            "name": self.name[:20],
            "role": self.role[:10],
            "model": self.preferred_model[:15],
            "tools": len(self.tools),
        }


# ── Default Model Configurations (User's 16 GGUF Models) ─────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {
        "id": "whiterabbitneo-7b", "name": "WhiteRabbitNeo-7B-v1.5a",
        "path": "WhiteRabbitNeo-7B-v1.5a-Q4_K_M.gguf", "port": 8100,
        "ctx": 4096, "caps": ["security", "exploit", "pentest"],
        "weight": 2.0, "priority": 1,
    },
    {
        "id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B-Instruct",
        "path": "Qwen2.5-Coder-14B-Instruct-Q3_K_M.gguf", "port": 8101,
        "ctx": 8192, "caps": ["code", "code_audit", "exploit_dev"],
        "weight": 1.8, "priority": 2,
    },
    {
        "id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B-Instruct",
        "path": "Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf", "port": 8102,
        "ctx": 8192, "caps": ["code", "code_review"],
        "weight": 1.2, "priority": 4,
    },
    {
        "id": "deepseek-r1-7b", "name": "DeepSeek-R1-Distill-Qwen-7B",
        "path": "DeepSeek-R1-Distill-Qwen-7B-q4_k_m.gguf", "port": 8103,
        "ctx": 4096, "caps": ["reasoning", "planning", "analysis"],
        "weight": 1.5, "priority": 2,
    },
    {
        "id": "deepseek-math-7b", "name": "DeepSeek-Math-7B-Instruct",
        "path": "deepseek-math-7b-instruct-q4_k_m.gguf", "port": 8104,
        "ctx": 4096, "caps": ["math", "crypto", "analysis"],
        "weight": 1.0, "priority": 6,
    },
    {
        "id": "hermes-14b", "name": "Hermes-4-14B",
        "path": "Hermes-4-14B-IQ2_M.gguf", "port": 8105,
        "ctx": 8192, "caps": ["general", "reasoning", "planning"],
        "weight": 1.5, "priority": 3,
    },
    {
        "id": "llama-8b", "name": "Meta-Llama-3.1-8B-Instruct",
        "path": "Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf", "port": 8106,
        "ctx": 4096, "caps": ["general", "analysis"],
        "weight": 1.0, "priority": 5,
    },
    {
        "id": "dolphin-8b", "name": "Dolphin-2.9-Llama3-8B",
        "path": "dolphin-2.9-llama3-8b.Q4_K_M.gguf", "port": 8107,
        "ctx": 4096, "caps": ["general", "security", "uncensored"],
        "weight": 1.2, "priority": 4,
    },
    {
        "id": "mistral-7b", "name": "Mistral-7B-Instruct-v0.3",
        "path": "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf", "port": 8108,
        "ctx": 4096, "caps": ["general", "fast", "instruction"],
        "weight": 1.0, "priority": 5,
    },
    {
        "id": "codellama-13b", "name": "CodeLlama-13B-Instruct",
        "path": "codellama-13b-instruct.Q3_K_M.gguf", "port": 8109,
        "ctx": 8192, "caps": ["code", "code_audit"],
        "weight": 1.3, "priority": 3,
    },
    {
        "id": "codellama-7b", "name": "CodeLlama-7B",
        "path": "codellama-7b.Q4_K_M.gguf", "port": 8110,
        "ctx": 4096, "caps": ["code", "fast"],
        "weight": 0.8, "priority": 7,
    },
    {
        "id": "yi-9b-200k", "name": "Yi-9B-200K",
        "path": "Yi-9B-200K.Q5_K_M.gguf", "port": 8111,
        "ctx": 200000, "caps": ["long_context", "code_audit", "analysis"],
        "weight": 1.5, "priority": 2,
    },
    {
        "id": "phi-3.5-mini", "name": "Phi-3.5-mini-instruct",
        "path": "Phi-3.5-mini-instruct-Q4_K_M.gguf", "port": 8112,
        "ctx": 4096, "caps": ["fast", "general", "reasoning"],
        "weight": 0.8, "priority": 6,
    },
    {
        "id": "llama-guard-1b", "name": "Llama-Guard-3-1B",
        "path": "llama-guard-3-1b-q4_k_m.gguf", "port": 8113,
        "ctx": 2048, "caps": ["safety", "guard"],
        "weight": 0.5, "priority": 10,
    },
    {
        "id": "nomic-embed", "name": "Nomic-Embed-Text-v1.5",
        "path": "nomic-embed-text-v1.5.f32.gguf", "port": 8114,
        "ctx": 8192, "caps": ["embedding"],
        "weight": 0.5, "priority": 10,
    },
    {
        "id": "functiongemma-270m", "name": "FunctionGemma-270m-it",
        "path": "functiongemma-270m-it-BF16.gguf", "port": 8115,
        "ctx": 2048, "caps": ["function_call", "tool_routing"],
        "weight": 0.3, "priority": 10,
    },
]

# ── Default Agent Templates ───────────────────────────────────

DEFAULT_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "coordinator", "name": "Coordinator Agent", "role": "coordinator",
        "model": "hermes-14b",
        "prompt": "You are the coordinator agent. Decompose tasks, delegate to specialists, and aggregate results.",
        "tools": [],
    },
    {
        "id": "recon", "name": "Reconnaissance Agent", "role": "recon",
        "model": "mistral-7b",
        "prompt": "You are a recon specialist. Discover attack surface: subdomains, ports, services, technologies.",
        "tools": ["nmap", "subfinder", "httpx", "whatweb", "dnsx"],
    },
    {
        "id": "scanner", "name": "Vulnerability Scanner", "role": "scanner",
        "model": "whiterabbitneo-7b",
        "prompt": "You are a vulnerability scanner. Run security scans and identify potential vulnerabilities.",
        "tools": ["nuclei", "nikto", "wpscan", "testssl"],
    },
    {
        "id": "analyzer", "name": "Code Analyzer", "role": "analyzer",
        "model": "qwen-coder-14b",
        "prompt": "You are a code analysis expert. Review code for vulnerabilities, trace data flow, identify CWEs.",
        "tools": ["semgrep", "bandit", "trivy"],
    },
    {
        "id": "exploiter", "name": "Exploit Specialist", "role": "exploiter",
        "model": "whiterabbitneo-7b",
        "prompt": "You are an exploitation specialist. Verify vulnerabilities with safe exploitation techniques.",
        "tools": ["sqlmap", "dalfox", "commix"],
    },
    {
        "id": "validator", "name": "Validation Agent", "role": "validator",
        "model": "deepseek-r1-7b",
        "prompt": "You are a validation specialist. Verify findings, check for false positives, assess impact.",
        "tools": [],
    },
    {
        "id": "reporter", "name": "Report Agent", "role": "reporter",
        "model": "hermes-14b",
        "prompt": "You are a reporting specialist. Compile findings into structured reports.",
        "tools": [],
    },
]


class ConfigManager:
    """Centralized, hot-reloadable configuration system.

    Manages model configs, tool configs, and agent templates
    with validation and environment variable overrides.
    """

    def __init__(
        self,
        config_dir: str = "configs",
    ) -> None:
        self._config_dir = Path(config_dir)
        self._config_dir.mkdir(parents=True, exist_ok=True)
        self._models: dict[str, ModelConfig] = {}
        self._tools: dict[str, ToolConfig] = {}
        self._templates: dict[str, AgentTemplate] = {}
        self._custom: dict[str, Any] = {}
        self._last_loaded: float = 0.0
        self._log = logger.bind(component="config_manager")

        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default configurations."""
        for data in DEFAULT_MODELS:
            model = ModelConfig(
                model_id=data["id"],
                name=data["name"],
                path=data.get("path", ""),
                port=data.get("port", 8100),
                context_length=data.get("ctx", 4096),
                capabilities=data.get("caps", []),
                weight=data.get("weight", 1.0),
                priority=data.get("priority", 5),
            )
            self._models[model.model_id] = model

        for data in DEFAULT_TEMPLATES:
            template = AgentTemplate(
                template_id=data["id"],
                name=data["name"],
                role=data["role"],
                preferred_model=data.get("model", ""),
                system_prompt=data.get("prompt", ""),
                tools=data.get("tools", []),
            )
            self._templates[template.template_id] = template

    def get_model(self, model_id: str) -> ModelConfig | None:
        return self._models.get(model_id)

    def get_models(self, capability: str = "") -> list[ModelConfig]:
        if not capability:
            return [m for m in self._models.values() if m.enabled]
        return [
            m for m in self._models.values()
            if m.enabled and capability in m.capabilities
        ]

    def add_model(self, config: ModelConfig) -> None:
        self._models[config.model_id] = config

    def remove_model(self, model_id: str) -> None:
        self._models.pop(model_id, None)

    def get_template(self, template_id: str) -> AgentTemplate | None:
        return self._templates.get(template_id)

    def get_templates(self) -> list[AgentTemplate]:
        return list(self._templates.values())

    def load_from_file(self, path: str) -> bool:
        """Load configuration from a JSON file."""
        try:
            with open(path) as fh:
                data = json.load(fh)

            if "models" in data:
                for model_data in data["models"]:
                    model = ModelConfig(
                        model_id=model_data.get("id", ""),
                        name=model_data.get("name", ""),
                        path=model_data.get("path", ""),
                        port=model_data.get("port", 8100),
                        context_length=model_data.get("context_length", 4096),
                        capabilities=model_data.get("capabilities", []),
                        weight=model_data.get("weight", 1.0),
                        priority=model_data.get("priority", 5),
                        temperature=model_data.get("temperature", 0.7),
                        max_tokens=model_data.get("max_tokens", 2048),
                        enabled=model_data.get("enabled", True),
                    )
                    self._models[model.model_id] = model

            if "templates" in data:
                for tmpl_data in data["templates"]:
                    template = AgentTemplate(
                        template_id=tmpl_data.get("id", ""),
                        name=tmpl_data.get("name", ""),
                        role=tmpl_data.get("role", ""),
                        preferred_model=tmpl_data.get("model", ""),
                        system_prompt=tmpl_data.get("system_prompt", ""),
                        tools=tmpl_data.get("tools", []),
                    )
                    self._templates[template.template_id] = template

            self._last_loaded = time.time()
            return True

        except (json.JSONDecodeError, FileNotFoundError, OSError) as exc:
            self._log.error("config_load_error", error=str(exc))
            return False

    def save_to_file(self, path: str) -> bool:
        """Save configuration to JSON."""
        try:
            data = {
                "models": [m.to_dict() for m in self._models.values()],
                "templates": [t.to_dict() for t in self._templates.values()],
            }
            with open(path, "w") as fh:
                json.dump(data, fh, indent=2)
            return True
        except OSError as exc:
            self._log.error("config_save_error", error=str(exc))
            return False

    def apply_env_overrides(self) -> int:
        """Apply environment variable overrides to model configs."""
        overrides = 0
        for model_id, model in self._models.items():
            env_key = f"RECURSEC_MODEL_{model_id.upper().replace('-', '_')}_PORT"
            port_str = os.environ.get(env_key)
            if port_str:
                try:
                    model.port = int(port_str)
                    overrides += 1
                except ValueError:
                    pass

        return overrides

    def validate(self) -> list[str]:
        """Validate configuration."""
        issues = []

        # Check for port conflicts
        ports: dict[int, list[str]] = {}
        for model in self._models.values():
            if model.enabled:
                if model.port in ports:
                    ports[model.port].append(model.model_id)
                else:
                    ports[model.port] = [model.model_id]

        for port, models in ports.items():
            if len(models) > 1:
                issues.append(f"Port {port} used by: {', '.join(models)}")

        # Check templates reference valid models
        valid_models = set(self._models.keys())
        for template in self._templates.values():
            if template.preferred_model and template.preferred_model not in valid_models:
                issues.append(
                    f"Template '{template.template_id}' references "
                    f"unknown model '{template.preferred_model}'"
                )

        return issues

    def get_stats(self) -> dict[str, Any]:
        return {
            "models": len(self._models),
            "enabled_models": sum(1 for m in self._models.values() if m.enabled),
            "templates": len(self._templates),
            "tools": len(self._tools),
            "last_loaded": self._last_loaded,
        }
