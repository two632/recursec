"""Configuration system — fully configurable via YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class LLMModelConfig(BaseModel):
    name: str
    backend: str = "openai_compatible"  # vllm, llama_cpp, sglang, litellm, ollama, openai_compatible
    model_id: str
    base_url: str
    api_key: str = ""
    task_types: list[str] = Field(default_factory=lambda: ["general"])
    priority: int = 5
    max_concurrent: int = 10
    weight: float = 1.0
    extra: dict[str, Any] = Field(default_factory=dict)


class AgentConfig(BaseModel):
    max_steps: int = 50
    max_depth: int = 5
    temperature: float = 0.3
    max_tokens: int = 4096
    human_approval_required: bool = False
    allowed_tools: list[str] | None = None


class DaemonConfig(BaseModel):
    enabled: bool = True
    poll_interval_s: int = 60
    max_concurrent_tasks: int = 5
    auto_restart: bool = True
    schedule: list[dict[str, Any]] = Field(default_factory=list)


class DashboardConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080
    auth_enabled: bool = True
    username: str = "admin"
    password: str = "changeme"


class DockerConfig(BaseModel):
    enabled: bool = True
    image: str = "recursec/kali-tools:latest"
    network_mode: str = "host"
    memory_limit: str = "4g"
    cpu_limit: float = 2.0
    auto_build: bool = True


class SafetyConfig(BaseModel):
    enabled: bool = True
    base_url: str = "http://localhost:8114"
    model_id: str = "llama-guard-3-1b"
    authorization_scope: str = ""


class EmbeddingConfig(BaseModel):
    enabled: bool = True
    base_url: str = "http://localhost:8115"
    model_id: str = "nomic-embed-text"


class ToolsConfig(BaseModel):
    sandbox_mode: bool = True
    docker_image: str | None = None
    auto_install: bool = False
    custom_tools: list[dict[str, str]] = Field(default_factory=list)
    disabled_tools: list[str] = Field(default_factory=list)


class RecurSecConfig(BaseSettings):
    """Main configuration for RecurSec."""

    # LLM models — unlimited, fully configurable
    models: list[LLMModelConfig] = Field(default_factory=list)

    # Agent settings
    agent: AgentConfig = Field(default_factory=AgentConfig)

    # Daemon mode
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)

    # Dashboard
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)

    # Docker sandbox
    docker: DockerConfig = Field(default_factory=DockerConfig)

    # Tools
    tools: ToolsConfig = Field(default_factory=ToolsConfig)

    # Safety guard (Llama-Guard)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)

    # Embedding / RAG (Nomic-Embed)
    embedding: EmbeddingConfig = Field(default_factory=EmbeddingConfig)

    # Memory
    db_path: str = "recursec_memory.db"
    data_dir: str = "data"

    # Logging
    log_level: str = "INFO"
    log_file: str | None = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> RecurSecConfig:
        """Load configuration from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def to_yaml(self, path: str | Path) -> None:
        """Save configuration to a YAML file."""
        with open(path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, sort_keys=False)

    class Config:
        env_prefix = "RECURSEC_"
