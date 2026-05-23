"""Test the tool registry and basic framework components."""



from recursec.config.settings import RecurSecConfig
from recursec.core.models import AgentRole, AgentTask, Severity, Target, Vulnerability
from recursec.tools.registry import ToolRegistry


def test_tool_registry_load():
    """Test that all 200+ tools load correctly."""
    registry = ToolRegistry(sandbox_mode=False)
    count = registry.load_defaults()
    assert count > 200, f"Expected 200+ tools, got {count}"


def test_tool_categories():
    """Test tools span all categories."""
    registry = ToolRegistry(sandbox_mode=False)
    registry.load_defaults()

    categories_found = set()
    for tool_info in registry.list_available():
        categories_found.add(tool_info["category"])

    expected = {"recon", "vuln_scan", "web", "exploit", "network", "post_exploit",
                "code_analysis", "crypto", "osint", "fuzzing", "wireless", "cloud",
                "forensics", "reporting", "misc"}
    assert expected.issubset(categories_found), f"Missing categories: {expected - categories_found}"


def test_tool_availability_check():
    """Test that at least some tools are detected as available."""
    registry = ToolRegistry(sandbox_mode=False)
    registry.load_defaults()
    # At minimum, basic tools like curl, git, grep should be available
    available = registry.count_available()
    assert available > 0, "No tools detected as available"


def test_custom_tool_add():
    """Test adding a custom tool at runtime."""
    registry = ToolRegistry(sandbox_mode=False)
    registry.load_defaults()
    initial_count = registry.count()

    registry.add_custom_tool(
        name="my-test-tool",
        binary="echo",
        category="misc",
        description="A test tool",
        install_cmd="",
    )

    assert registry.count() == initial_count + 1
    tool = registry.get("my-test-tool")
    assert tool is not None
    assert tool.name == "my-test-tool"


def test_vulnerability_model():
    """Test Vulnerability data model."""
    vuln = Vulnerability(
        title="SQL Injection in login form",
        severity=Severity.CRITICAL,
        description="The login form is vulnerable to SQL injection",
        evidence="sqlmap confirmed injection point",
        affected_component="/api/login",
        confidence=0.95,
    )
    assert vuln.severity == Severity.CRITICAL
    assert vuln.confidence == 0.95
    assert vuln.id  # Auto-generated


def test_agent_task_model():
    """Test AgentTask data model."""
    task = AgentTask(
        agent_role=AgentRole.RECON,
        objective="Scan target for open ports",
        target=Target(name="test", value="192.168.1.1", target_type="host"),
    )
    assert task.agent_role == AgentRole.RECON
    assert task.target.value == "192.168.1.1"
    assert task.depth == 0
    assert task.step_count == 0


def test_config_defaults():
    """Test default config generation."""
    cfg = RecurSecConfig()
    assert cfg.agent.max_steps == 50
    assert cfg.agent.max_depth == 5
    assert cfg.dashboard.port == 8080
    assert cfg.tools.sandbox_mode is True


def test_tool_llm_schema():
    """Test that tools generate valid LLM function-calling schemas."""
    registry = ToolRegistry(sandbox_mode=False)
    registry.load_defaults()

    tool = registry.get("nmap")
    assert tool is not None
    schema = tool.to_llm_schema()
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "nmap"
    assert "parameters" in schema["function"]
