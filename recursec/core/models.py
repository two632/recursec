"""Core data models for RecurSec."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    WAITING_APPROVAL = "waiting_approval"


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    VULN_SCANNER = "vuln_scanner"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CODE_AUDITOR = "code_auditor"
    WEB_SCANNER = "web_scanner"
    NETWORK_SCANNER = "network_scanner"
    OSINT = "osint"
    FUZZER = "fuzzer"
    CRYPTO_ANALYST = "crypto_analyst"
    CLOUD_SCANNER = "cloud_scanner"
    WIRELESS_SCANNER = "wireless_scanner"
    FORENSICS = "forensics"
    REPORT_WRITER = "report_writer"
    VALIDATOR = "validator"
    CUSTOM = "custom"


class ToolCategory(str, Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CODE_ANALYSIS = "code_analysis"
    WEB = "web"
    NETWORK = "network"
    CRYPTO = "crypto"
    REPORTING = "reporting"
    FORENSICS = "forensics"
    OSINT = "osint"
    FUZZING = "fuzzing"
    WIRELESS = "wireless"
    CLOUD = "cloud"
    MISC = "misc"


class ToolResult(BaseModel):
    tool_name: str
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    execution_time_s: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_output: str = ""
    parsed_data: dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    severity: Severity
    cvss_score: float | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    description: str
    evidence: str = ""
    affected_component: str = ""
    reproduction_steps: list[str] = Field(default_factory=list)
    remediation: str = ""
    confidence: float = 0.0  # 0.0 - 1.0
    validated: bool = False
    false_positive: bool = False
    tool_source: str = ""
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_findings: list[dict[str, Any]] = Field(default_factory=list)


class Target(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str
    target_type: str = "host"  # host, url, code_repo, network_range, api
    value: str  # IP, URL, path, CIDR, etc.
    ports: list[int] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaskMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str  # system, user, assistant, tool
    content: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentTask(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    parent_task_id: str | None = None
    agent_role: AgentRole
    objective: str
    target: Target | None = None
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 5  # 1-10, 1=highest
    depth: int = 0
    max_depth: int = 5
    max_steps: int = 50
    step_count: int = 0
    messages: list[TaskMessage] = Field(default_factory=list)
    child_task_ids: list[str] = Field(default_factory=list)
    findings: list[Vulnerability] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    assigned_model: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class AttackChain(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str
    steps: list[AgentTask] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    success: bool = False
    impact: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
