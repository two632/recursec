"""Tests for new modules: parsers, attack_chain, safety, embeddings."""

import pytest

from recursec.core.attack_chain import AttackChainBuilder, ChainStep, _compute_impact, _infer_phase
from recursec.core.models import Severity, Vulnerability
from recursec.llm.safety import SafetyGuard
from recursec.memory.embeddings import EmbeddingClient, VectorMemory, _cosine_similarity
from recursec.tools.parsers import (
    _parse_credential_brute,
    _parse_directory_bruteforce,
    _parse_masscan,
    _parse_nmap,
    _parse_nuclei,
    _parse_semgrep,
    _parse_sqlmap,
    _parse_subdomain_enum,
    parse_tool_output,
)


# ── Parser Tests ─────────────────────────────────────────

def test_parse_nmap_text():
    output = """Starting Nmap 7.94
Nmap scan report for 192.168.1.1
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2
80/tcp   open  http     Apache httpd 2.4.41
443/tcp  open  https    nginx 1.18
3306/tcp closed mysql
"""
    result = _parse_nmap(output)
    assert result["host_count"] == 1
    assert result["port_count"] == 3
    assert len(result["open_ports"]) == 3
    assert result["open_ports"][0]["port"] == 22
    assert result["open_ports"][0]["service"] == "ssh"


def test_parse_nuclei_json():
    output = '{"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical","description":"Apache Log4j2 RCE"},"host":"http://target.com","matched-at":"http://target.com/"}'
    result = _parse_nuclei(output)
    assert result["total"] == 1
    assert result["severity_counts"]["critical"] == 1
    assert result["findings"][0]["name"] == "Log4j RCE"


def test_parse_nuclei_text():
    output = """[critical] [cve-2021-44228] [http] http://target.com
[high] [cve-2023-1234] [http] http://target.com/admin
[info] [tech-detect:nginx] [http] http://target.com"""
    result = _parse_nuclei(output)
    assert result["total"] == 3
    assert result["severity_counts"]["critical"] == 1
    assert result["severity_counts"]["high"] == 1
    assert result["severity_counts"]["info"] == 1


def test_parse_sqlmap():
    output = """[INFO] testing 'AND boolean-based blind'
[INFO] parameter 'id' is vulnerable
[INFO] testing 'time-based blind'
[INFO] back-end DBMS: MySQL >= 5.0
available databases:
[*] information_schema
[*] myapp_db
[*] test_db"""
    result = _parse_sqlmap(output)
    assert result["is_vulnerable"]
    assert "id" in result["injectable_params"]
    assert "MySQL" in result["dbms"]
    assert "boolean-based" in result["techniques"]
    assert "information_schema" in result["databases"]


def test_parse_credential_brute():
    output = """[80][http] host: 192.168.1.1   login: admin   password: admin123
[80][http] host: 192.168.1.1   login: root   password: toor"""
    result = _parse_credential_brute(output)
    assert result["total"] == 2
    assert result["credentials"][0]["username"] == "admin"


def test_parse_subdomain_enum():
    output = """mail.example.com
admin.example.com
api.example.com
test.example.com
# This is a comment
[INFO] Something"""
    result = _parse_subdomain_enum(output)
    assert result["total"] == 4
    assert "mail.example.com" in result["subdomains"]


def test_parse_directory_bruteforce():
    output = """/admin (Status: 200) [Size: 1234]
/login (Status: 301) [Size: 0]
/api (Status: 403) [Size: 567]"""
    result = _parse_directory_bruteforce(output)
    assert result["total"] == 3


def test_parse_semgrep_json():
    output = '{"results":[{"check_id":"python.security.eval","path":"app.py","start":{"line":10},"end":{"line":10},"extra":{"message":"Use of eval()","severity":"WARNING"}}],"errors":[]}'
    result = _parse_semgrep(output)
    assert result["total"] == 1
    assert result["findings"][0]["rule_id"] == "python.security.eval"


def test_parse_masscan_text():
    output = """Discovered open port 80/tcp on 192.168.1.1
Discovered open port 443/tcp on 192.168.1.1
Discovered open port 22/tcp on 192.168.1.2"""
    result = _parse_masscan(output)
    assert result["host_count"] == 2
    assert result["total_ports"] == 3


def test_parse_tool_output_unknown():
    result = parse_tool_output("unknown_tool", "some output")
    assert "raw" in result


# ── Attack Chain Tests ───────────────────────────────────

def test_chain_step():
    step = ChainStep(
        phase="recon",
        description="Port scan",
        tool="nmap",
        command="nmap -sV target",
    )
    d = step.to_dict()
    assert d["phase"] == "recon"
    assert d["tool"] == "nmap"


def test_attack_chain_builder():
    builder = AttackChainBuilder()

    vuln1 = Vulnerability(
        title="SQL Injection",
        severity=Severity.CRITICAL,
        description="SQLi in login",
        affected_component="web-login",
        validated=True,
    )
    vuln2 = Vulnerability(
        title="XSS",
        severity=Severity.MEDIUM,
        description="Reflected XSS",
        affected_component="web-login",
    )

    builder.add_finding(vuln1, agent_role="web_scanner")
    builder.add_finding(vuln2, agent_role="web_scanner")
    builder.add_tool_result("nmap", "nmap -sV target", "22/tcp open ssh", agent_role="recon")

    chains = builder.build_chains()
    assert len(chains) >= 1

    summary = builder.get_summary()
    assert summary["total_findings"] >= 2


def test_compute_impact():
    critical = [Vulnerability(title="t", severity=Severity.CRITICAL, description="d")]
    assert "CRITICAL" in _compute_impact(critical)

    low = [Vulnerability(title="t", severity=Severity.LOW, description="d")]
    assert "LOW" in _compute_impact(low)


def test_infer_phase():
    assert _infer_phase("recon") == "recon"
    assert _infer_phase("exploit") == "exploitation"
    assert _infer_phase("post_exploit") == "post_exploit"
    assert _infer_phase("unknown") == "unknown"


# ── Safety Tests ─────────────────────────────────────────

def test_safety_guard_init():
    guard = SafetyGuard(enabled=True)
    assert guard.enabled
    stats = guard.stats()
    assert stats["total_checks"] == 0
    assert stats["blocked"] == 0


@pytest.mark.asyncio
async def test_safety_guard_disabled():
    guard = SafetyGuard(enabled=False)
    safe, reason = await guard.check_prompt("any content")
    assert safe
    assert reason == ""


@pytest.mark.asyncio
async def test_safety_guard_tool_check_disabled():
    guard = SafetyGuard(enabled=False)
    safe, reason = await guard.check_tool_command("nmap", "nmap -sV target", "192.168.1.1")
    assert safe


# ── Embedding Tests ──────────────────────────────────────

def test_cosine_similarity():
    assert _cosine_similarity([1, 0, 0], [1, 0, 0]) == pytest.approx(1.0)
    assert _cosine_similarity([1, 0, 0], [0, 1, 0]) == pytest.approx(0.0)
    assert _cosine_similarity([], []) == 0.0
    assert _cosine_similarity([1, 2, 3], [1, 2, 3]) == pytest.approx(1.0)


def test_embedding_client_init():
    client = EmbeddingClient(base_url="http://localhost:8115")
    assert client.model_id == "nomic-embed-text"


def test_vector_memory_init():
    client = EmbeddingClient()
    vm = VectorMemory(client)
    assert vm.count() == 0


def test_report_data():
    builder = AttackChainBuilder()
    vuln = Vulnerability(
        title="Test Vuln",
        severity=Severity.HIGH,
        description="test",
        affected_component="comp",
        validated=True,
    )
    builder.add_finding(vuln)
    report = builder.generate_report_data()
    assert report["severity_summary"]["high"] >= 1
    assert report["validated_count"] >= 1
