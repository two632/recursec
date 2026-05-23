"""Agent factory — creates agents by role."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from recursec.agents.security_agents import (
    CloudAgent,
    CodeAuditAgent,
    CryptoAgent,
    ExploitAgent,
    ForensicsAgent,
    FuzzerAgent,
    NetworkAgent,
    OrchestratorAgent,
    OSINTAgent,
    PostExploitAgent,
    ReconAgent,
    ReportAgent,
    SecurityAgent,
    ValidatorAgent,
    VulnScanAgent,
    WebScanAgent,
)
from recursec.core.models import AgentRole

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter
    from recursec.memory.store import MemoryStore
    from recursec.tools.registry import ToolRegistry

AGENT_MAP: dict[AgentRole, type[SecurityAgent]] = {
    AgentRole.ORCHESTRATOR: OrchestratorAgent,
    AgentRole.RECON: ReconAgent,
    AgentRole.VULN_SCANNER: VulnScanAgent,
    AgentRole.WEB_SCANNER: WebScanAgent,
    AgentRole.EXPLOIT: ExploitAgent,
    AgentRole.POST_EXPLOIT: PostExploitAgent,
    AgentRole.CODE_AUDITOR: CodeAuditAgent,
    AgentRole.NETWORK_SCANNER: NetworkAgent,
    AgentRole.OSINT: OSINTAgent,
    AgentRole.FUZZER: FuzzerAgent,
    AgentRole.CRYPTO_ANALYST: CryptoAgent,
    AgentRole.CLOUD_SCANNER: CloudAgent,
    AgentRole.FORENSICS: ForensicsAgent,
    AgentRole.REPORT_WRITER: ReportAgent,
    AgentRole.VALIDATOR: ValidatorAgent,
}


class AgentFactory:
    """Creates agent instances by role."""

    @staticmethod
    def create(
        role: AgentRole,
        model_router: ModelRouter,
        tool_registry: ToolRegistry,
        memory: MemoryStore,
        **kwargs: Any,
    ) -> SecurityAgent:
        cls = AGENT_MAP.get(role, SecurityAgent)
        return cls(
            model_router=model_router,
            tool_registry=tool_registry,
            memory=memory,
            **kwargs,
        )

    @staticmethod
    def list_roles() -> list[str]:
        return [r.value for r in AGENT_MAP.keys()]
