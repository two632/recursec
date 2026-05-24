"""Integration test — validates all agent components work together.

Tests the full pipeline:
Input → Intent → KB → Prompt → Model → Reasoning → Tool → Analysis → Report
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()


def test_intent_classification() -> bool:
    """Test intent classifier."""
    from recursec.agents.intent_classifier import IntentClassifier
    classifier = IntentClassifier()
    result = classifier.classify("find SQL injection vulnerabilities in https://example.com")
    assert result.primary_intent is not None
    assert result.confidence > 0.0
    assert len(result.recommended_kbs) > 0
    return True


def test_kb_registry() -> bool:
    """Test KB registry."""
    from recursec.agents.kb_registry import KB_REGISTRY, get_all_domains, get_registry_stats
    assert len(KB_REGISTRY) >= 30
    domains = get_all_domains()
    assert len(domains) >= 30
    stats = get_registry_stats()
    assert stats["total_kbs"] >= 30
    assert stats["total_patterns"] >= 150
    return True


def test_prompt_assembler() -> bool:
    """Test prompt assembler."""
    from recursec.agents.prompt_assembler import PromptAssembler
    assembler = PromptAssembler()
    result = assembler.assemble(
        role="scanner",
        phase="scanning",
        intent="web_vuln_scan",
        user_input="Scan example.com for vulnerabilities",
        kb_domains=["web_vuln"],
    )
    assert result.system_prompt != ""
    assert result.user_instruction != ""
    return True


def test_reasoning_engine() -> bool:
    """Test reasoning engine."""
    from recursec.agents.reasoning_engine import ReasoningEngine, ReasoningMode
    engine = ReasoningEngine()
    prompt = engine.get_reasoning_prompt(ReasoningMode.CHAIN_OF_THOUGHT)
    assert "step by step" in prompt.lower()
    step = engine.create_step(ReasoningMode.HYPOTHESIS_TEST, thought="Test hypothesis")
    assert step.step_id > 0
    hyp = engine.create_hypothesis("Possible SQLi", "example.com", "sqli")
    assert hyp.hypothesis_id != ""
    return True


def test_task_executor() -> bool:
    """Test task executor."""
    from recursec.agents.task_executor import TaskExecutor, ExecutionPhase
    executor = TaskExecutor()
    plan = executor.create_plan("example.com", "web_vuln_scan")
    assert plan.plan_id != ""
    assert ExecutionPhase.VULNERABILITY in plan.phases
    tools = executor.get_tools_for_phase(ExecutionPhase.VULNERABILITY)
    assert len(tools) > 0
    return True


def test_llm_client() -> bool:
    """Test LLM client."""
    from recursec.agents.llm_client import LLMClient
    client = LLMClient()
    models = client.get_available_models()
    assert len(models) >= 16
    endpoint = client.get_endpoint("whiterabbitneo")
    assert "8100" in endpoint
    ctx = client.get_model_context_size("yi-9b-200k")
    assert ctx == 200000
    return True


def test_conversation_manager() -> bool:
    """Test conversation manager."""
    from recursec.agents.conversation_manager import ConversationManager
    mgr = ConversationManager()
    conv = mgr.create_conversation("whiterabbit", "You are a security agent.", purpose="test")
    assert conv.conversation_id != ""
    msg = mgr.add_user_message(conv.conversation_id, "Find vulns in example.com")
    assert msg is not None
    request = mgr.build_llm_request(conv.conversation_id)
    assert request is not None
    assert len(request["messages"]) == 2
    return True


def test_model_ensemble() -> bool:
    """Test model ensemble."""
    from recursec.agents.model_ensemble import ModelEnsemble, ModelVote
    ensemble = ModelEnsemble()
    models = ensemble.get_models_for_task("vulnerability_assessment", max_models=3)
    assert len(models) > 0
    votes = [
        ModelVote(model_id="whiterabbit", response="Found SQLi", confidence=0.9),
        ModelVote(model_id="deepseek-r1", response="Confirmed SQLi", confidence=0.85),
    ]
    result = ensemble.compute_consensus(votes, "vulnerability_assessment")
    assert result.consensus_confidence > 0.5
    return True


def test_agent_spawner() -> bool:
    """Test agent spawner."""
    from recursec.agents.agent_spawner import AgentSpawner, AgentRole
    spawner = AgentSpawner(max_depth=5, max_agents=10)
    agent = spawner.spawn(AgentRole.WEB, "Scan web app", "example.com", depth=0)
    assert agent is not None
    assert agent.model_id == "whiterabbit"
    assert "web_vuln" in agent.kbs
    child = spawner.spawn(AgentRole.VALIDATOR, "Validate finding", parent_id=agent.agent_id, depth=1)
    assert child is not None
    findings = spawner.aggregate_findings(agent.agent_id)
    assert isinstance(findings, list)
    return True


def test_output_analyzer() -> bool:
    """Test output analyzer."""
    from recursec.agents.output_analyzer import OutputAnalyzer, OutputFormat
    analyzer = OutputAnalyzer()
    nmap_output = "22/tcp open ssh OpenSSH 8.2\n80/tcp open http Apache 2.4\n443/tcp open https nginx"
    findings = analyzer.extract_findings(nmap_output, "nmap", "192.168.1.1", OutputFormat.NMAP)
    assert len(findings) > 0
    deduped = analyzer.deduplicate(findings)
    assert len(deduped) <= len(findings)
    return True


def test_tool_orchestrator() -> bool:
    """Test tool orchestrator."""
    from recursec.agents.tool_orchestrator import ToolOrchestrator
    orch = ToolOrchestrator()
    cmd = orch.build_command("nmap", "192.168.1.1", args_preset="fast")
    assert "nmap" in cmd
    assert "192.168.1.1" in cmd
    web_tools = orch.get_tools_for_category("web_scanner")
    assert len(web_tools) > 0
    return True


def test_finding_correlator() -> bool:
    """Test finding correlator."""
    from recursec.agents.finding_correlator import FindingCorrelator
    correlator = FindingCorrelator()
    findings = [
        {"id": "f1", "title": "Info disclosure", "type": "info_disclosure", "target": "example.com", "severity": "medium"},
        {"id": "f2", "title": "Auth bypass", "type": "auth_bypass", "target": "example.com", "severity": "high"},
    ]
    corrs = correlator.correlate_findings(findings)
    assert isinstance(corrs, list)
    gaps = correlator.find_coverage_gaps(["nmap"], ["web_vuln"])
    assert len(gaps) > 0  # Should find gaps since we only used 1 tool
    return True


def test_target_profiler() -> bool:
    """Test target profiler."""
    from recursec.agents.target_profiler import TargetProfiler, TargetType
    profiler = TargetProfiler()
    profile = profiler.profile("https://example.com/api/v1")
    assert profile.target_type == TargetType.API_ENDPOINT
    profile2 = profiler.profile("192.168.1.0/24")
    assert profile2.target_type == TargetType.NETWORK_RANGE
    profile3 = profiler.profile("example.com")
    assert profile3.target_type == TargetType.DOMAIN
    return True


def test_self_improvement() -> bool:
    """Test self-improvement engine."""
    from recursec.agents.self_improvement import SelfImprovementEngine
    engine = SelfImprovementEngine()
    engine.record_tool_use("nmap", success=True, findings_count=5)
    engine.record_tool_use("nmap", success=True, findings_count=3)
    engine.record_tool_use("nmap", success=False)
    engine.record_tool_use("nikto", success=True, findings_count=1)
    engine.record_tool_use("nikto", success=True, findings_count=0)
    engine.record_tool_use("nikto", success=True, findings_count=0)
    top = engine.get_top_tools(3)
    assert len(top) > 0
    return True


def test_autonomous_controller() -> bool:
    """Test autonomous controller."""
    from recursec.agents.autonomous_controller import AutonomousController, TaskPriority
    controller = AutonomousController()
    session = controller.create_session()
    task = controller.create_task(session.session_id, "Scan example.com", TaskPriority.HIGH)
    assert task.task_id != ""
    assert controller.should_continue(task)
    stats = controller.get_stats()
    assert stats["total_tasks"] == 1
    return True


def test_master_agent() -> bool:
    """Test master agent."""
    from recursec.agents.master_agent import MasterAgent, AgentConfig
    config = AgentConfig(max_depth=3, token_budget=16384)
    agent = MasterAgent(config)
    status = agent.get_status()
    assert "state" in status
    assert "config" in status
    assert "components" in status
    return True


def test_report_generator() -> bool:
    """Test report generator."""
    from recursec.agents.report_generator import ReportGenerator
    gen = ReportGenerator()
    findings = [
        {"title": "SQL Injection", "severity": "critical", "type": "sqli", "description": "Found SQLi in login form", "evidence": "Response time difference"},
        {"title": "Missing HSTS", "severity": "low", "type": "header_missing", "description": "HSTS header not set"},
    ]
    report = gen.generate("example.com", findings, tools_used=["sqlmap", "nmap"])
    assert report.total_findings == 2
    assert report.critical_count == 1
    md = gen.to_markdown(report)
    assert "SQL Injection" in md
    return True


ALL_TESTS = [
    ("Intent Classification", test_intent_classification),
    ("KB Registry", test_kb_registry),
    ("Prompt Assembler", test_prompt_assembler),
    ("Reasoning Engine", test_reasoning_engine),
    ("Task Executor", test_task_executor),
    ("LLM Client", test_llm_client),
    ("Conversation Manager", test_conversation_manager),
    ("Model Ensemble", test_model_ensemble),
    ("Agent Spawner", test_agent_spawner),
    ("Output Analyzer", test_output_analyzer),
    ("Tool Orchestrator", test_tool_orchestrator),
    ("Finding Correlator", test_finding_correlator),
    ("Target Profiler", test_target_profiler),
    ("Self-Improvement", test_self_improvement),
    ("Autonomous Controller", test_autonomous_controller),
    ("Master Agent", test_master_agent),
    ("Report Generator", test_report_generator),
]


def run_all_tests() -> dict[str, Any]:
    """Run all integration tests."""
    results: dict[str, Any] = {"passed": 0, "failed": 0, "errors": []}
    for name, test_func in ALL_TESTS:
        try:
            test_func()
            results["passed"] += 1
            logger.info("test_passed", name=name)
        except Exception as exc:
            results["failed"] += 1
            results["errors"].append(f"{name}: {exc}")
            logger.error("test_failed", name=name, error=str(exc))
    return results


if __name__ == "__main__":
    results = run_all_tests()
    print(f"\nResults: {results['passed']} passed, {results['failed']} failed")
    for err in results["errors"]:
        print(f"  FAIL: {err}")
