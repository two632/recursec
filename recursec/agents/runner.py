"""RecurSec Runner — the REAL end-to-end autonomous pipeline.

This is the module that makes "recursec run --target example.com" actually work.
It connects LLM servers, runs real tools, parses real output, and finds real vulns.

Pipeline:
1. Detect target type (URL, IP, domain, CIDR)
2. Health-check LLM servers, pick the best available
3. Recon phase: DNS, subdomains, port scan, web probing
4. LLM analysis: feed recon data to LLM for attack planning
5. Active scan phase: nuclei, nikto, sqlmap, ffuf based on LLM plan
6. LLM analysis: analyze scan results, identify vulns
7. Deep dive: follow-up scans on interesting findings
8. Correlate, deduplicate, validate findings
9. Generate report

Everything runs synchronously with subprocess for tools
and urllib for LLM calls. No async, no external deps beyond
structlog and whatever tools are installed on the system.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

from recursec.agents.llm_client import LLMClient

logger = structlog.get_logger()


class TargetType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    UNKNOWN = "unknown"


class ScanPhase(str, Enum):
    INIT = "init"
    RECON = "recon"
    ANALYSIS = "analysis"
    ACTIVE_SCAN = "active_scan"
    DEEP_DIVE = "deep_dive"
    REPORT = "report"
    DONE = "done"


@dataclass
class ScanFinding:
    """A real vulnerability finding."""
    title: str = ""
    severity: str = "info"
    vuln_type: str = ""
    target: str = ""
    url: str = ""
    evidence: str = ""
    tool: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "type": self.vuln_type,
            "target": self.target,
            "url": self.url,
            "evidence": self.evidence[:200],
            "tool": self.tool,
            "cwe": self.cwe,
            "confidence": self.confidence,
        }


@dataclass
class ToolOutput:
    """Output from running a tool."""
    tool: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_s: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "ok": self.success,
            "duration": f"{self.duration_s:.1f}s",
            "output_len": len(self.stdout),
        }


@dataclass
class ScanConfig:
    """Configuration for a scan run."""
    target: str = ""
    goal: str = ""
    max_time_s: float = 3600.0
    max_findings: int = 500
    max_iterations: int = 100
    stealth: bool = False
    deep_scan: bool = True
    autonomous: bool = True
    llm_model: str = ""
    tool_timeout_s: int = 300
    output_dir: str = ""
    verbose: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "max_time": self.max_time_s,
            "stealth": self.stealth,
            "deep": self.deep_scan,
        }


# ── Model preferences by task ─────────────────────────────────

MODEL_PREFERENCES: dict[str, list[str]] = {
    "security_analysis": ["whiterabbitneo", "dolphin", "hermes-4-14b", "qwen-coder-14b"],
    "code_review": ["qwen-coder-14b", "qwen-coder-7b", "codellama-13b", "codellama-7b"],
    "planning": ["deepseek-r1", "hermes-4-14b", "qwen-coder-14b"],
    "recon_analysis": ["whiterabbitneo", "mistral", "llama-3.1-8b"],
    "exploit_analysis": ["whiterabbitneo", "dolphin", "deepseek-r1"],
    "general": ["mistral", "llama-3.1-8b", "phi-3.5-mini"],
    "fast": ["phi-3.5-mini", "functiongemma"],
}

# ── System prompts ─────────────────────────────────────────────

SECURITY_SYSTEM_PROMPT = """You are RecurSec, an expert autonomous security assessment agent.
You analyze tool outputs, identify vulnerabilities, plan attacks, and suggest next steps.
You MUST be specific and actionable. Do NOT hallucinate findings — only report what the evidence shows.
When analyzing tool output, extract:
- Vulnerabilities (with severity: critical/high/medium/low/info)
- Open ports and services
- Interesting endpoints or parameters
- Misconfigurations
- Information disclosure
For each finding, provide: title, severity, evidence, and remediation.
Respond in JSON format when asked for structured output."""

PLANNING_SYSTEM_PROMPT = """You are a security assessment planner. Given recon data about a target,
create a specific attack plan. List the exact tools and commands to run next.
Format your response as a JSON list of objects with keys: tool, args, reason.
Only suggest tools that actually exist (nmap, nuclei, nikto, sqlmap, ffuf, gobuster, subfinder, httpx, etc.).
Be specific with arguments — include the actual target, ports, and options."""

AUTONOMOUS_SYSTEM_PROMPT = """You are RecurSec, a fully autonomous security assessment agent.
You have access to 300+ pentesting tools. Your job is to find vulnerabilities, exploits, and security issues in the target.

AVAILABLE TOOLS (only use ones that exist on the system):
{available_tools}

RULES:
1. Output EXACTLY ONE shell command to execute next. Nothing else.
2. The command must be a real tool invocation (nmap, nuclei, sqlmap, ffuf, curl, dig, etc.)
3. Include the actual target/URL/IP in the command.
4. Use appropriate flags for machine-readable output when possible (-oN, -json, --json, -silent, etc.)
5. Do NOT use pipes, semicolons, or chain commands. One single command only.
6. If you believe the assessment is complete, output exactly: DONE
7. Do NOT repeat commands you've already run.
8. Prioritize: recon first, then vuln scanning, then exploitation verification.
9. Be creative — try different attack vectors, not just the obvious ones.
10. For web targets: check headers, directories, parameters, injection points, misconfigs.
11. For network targets: enumerate services, check for default creds, known CVEs.

IMPORTANT: Output the raw command only. No explanation, no markdown, no backticks. Just the command."""

ANALYSIS_SYSTEM_PROMPT = """You are a security analyst. Analyze the following tool output and extract security findings.
For each finding provide: title, severity (critical/high/medium/low/info), type, evidence, cwe, remediation.
If there are no findings, return an empty findings list.
Be precise — only report what the evidence shows. Do NOT hallucinate.
Respond as JSON: {{"findings": [{{"title":"...", "severity":"...", "type":"...", "evidence":"...", "cwe":"...", "remediation":"..."}}]}}"""


class Runner:
    """The real end-to-end autonomous security scanner."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self._config = config or ScanConfig()
        self._llm = LLMClient()
        self._findings: list[ScanFinding] = []
        self._tool_outputs: list[ToolOutput] = []
        self._phase = ScanPhase.INIT
        self._start_time = time.time()
        self._healthy_models: list[str] = []
        self._primary_model: str = ""
        self._log = logger.bind(component="runner")
        self._output_dir = self._config.output_dir or f"output/{int(time.time())}"
        self._executed_commands: list[str] = []
        self._memory: list[dict[str, str]] = []

    def run(self, target: str, goal: str = "") -> dict[str, Any]:
        """Run a full autonomous security assessment."""
        self._config.target = target
        self._config.goal = goal or f"Find all vulnerabilities in {target}"
        os.makedirs(self._output_dir, exist_ok=True)

        self._print(f"\n{'='*60}")
        self._print("  RecurSec Autonomous Security Assessment")
        self._print(f"  Target: {target}")
        self._print(f"  Goal: {self._config.goal}")
        self._print(f"{'='*60}\n")

        # Step 1: Detect target type
        target_type = self._detect_target_type(target)
        self._print(f"[*] Target type: {target_type.value}")

        # Step 2: Check LLM servers
        self._phase = ScanPhase.INIT
        self._print("[*] Checking LLM servers...")
        self._healthy_models = self._llm.get_healthy_models()
        if self._healthy_models:
            self._print(f"[+] {len(self._healthy_models)} models online: {', '.join(self._healthy_models)}")
            self._primary_model = self._select_model("security_analysis")
            self._print(f"[+] Primary model: {self._primary_model}")
        else:
            self._print("[!] No LLM servers online — running tools-only mode")

        # Step 3: Recon
        self._phase = ScanPhase.RECON
        self._print("\n[*] Phase 1: RECONNAISSANCE")
        recon_data = self._run_recon(target, target_type)

        # Step 4: LLM analysis of recon
        self._phase = ScanPhase.ANALYSIS
        attack_plan = []
        if self._primary_model:
            self._print("\n[*] Phase 2: LLM ANALYSIS")
            attack_plan = self._llm_analyze_recon(recon_data, target)

        # Step 5: Active scanning
        self._phase = ScanPhase.ACTIVE_SCAN
        self._print("\n[*] Phase 3: ACTIVE SCANNING")
        scan_data = self._run_active_scans(target, target_type, attack_plan)

        # Step 6: LLM analysis of scan results
        if self._primary_model and scan_data:
            self._print("\n[*] Phase 4: FINDING ANALYSIS")
            self._llm_analyze_scans(scan_data, target)

        # Step 7: Deep dive on interesting findings
        if self._config.deep_scan and self._findings:
            self._phase = ScanPhase.DEEP_DIVE
            self._print("\n[*] Phase 5: DEEP DIVE")
            self._run_deep_dive(target, target_type)

        # Step 7.5: Autonomous think-act loop (LLM decides what to run next)
        if self._primary_model and self._config.autonomous:
            self._phase = ScanPhase.ACTIVE_SCAN
            self._print("\n[*] Phase 6: AUTONOMOUS AGENT LOOP")
            self._run_autonomous_loop(target, target_type)

        # Step 8: Report
        self._phase = ScanPhase.REPORT
        report = self._generate_report(target)

        self._phase = ScanPhase.DONE
        elapsed = time.time() - self._start_time

        self._print(f"\n{'='*60}")
        self._print("  ASSESSMENT COMPLETE")
        self._print(f"  Duration: {elapsed:.1f}s")
        self._print(f"  Findings: {len(self._findings)}")
        self._print(f"  Tools run: {len(self._tool_outputs)}")
        sev_counts = self._count_severities()
        self._print(f"  Critical: {sev_counts.get('critical', 0)}, High: {sev_counts.get('high', 0)}, Medium: {sev_counts.get('medium', 0)}, Low: {sev_counts.get('low', 0)}")
        self._print(f"  Report: {self._output_dir}/report.json")
        self._print(f"{'='*60}\n")

        return report

    # ── Target detection ───────────────────────────────────────

    def _detect_target_type(self, target: str) -> TargetType:
        if target.startswith(("http://", "https://")):
            return TargetType.URL
        if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", target):
            return TargetType.CIDR
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            return TargetType.IP
        if "." in target:
            return TargetType.DOMAIN
        return TargetType.UNKNOWN

    def _extract_domain(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            target = target.split("://", 1)[1]
        return target.split("/")[0].split(":")[0]

    # ── Tool execution ─────────────────────────────────────────

    def _run_tool(self, name: str, cmd: list[str], timeout_s: int = 0) -> ToolOutput:
        """Run a tool via subprocess and capture output."""
        timeout = timeout_s or self._config.tool_timeout_s
        cmd_str = " ".join(cmd)
        self._print(f"  [>] {name}: {cmd_str[:80]}")

        start = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "TERM": "dumb"},
            )
            output = ToolOutput(
                tool=name,
                command=cmd_str,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_s=time.time() - start,
            )
        except subprocess.TimeoutExpired:
            output = ToolOutput(
                tool=name,
                command=cmd_str,
                stderr=f"Timeout after {timeout}s",
                exit_code=-1,
                duration_s=time.time() - start,
            )
        except FileNotFoundError:
            output = ToolOutput(
                tool=name,
                command=cmd_str,
                stderr=f"Tool not found: {cmd[0]}",
                exit_code=-1,
                duration_s=0.0,
            )

        self._tool_outputs.append(output)

        if output.success:
            self._print(f"  [+] {name}: done ({output.duration_s:.1f}s, {len(output.stdout)} bytes)")
        else:
            self._print(f"  [-] {name}: failed ({output.stderr[:60]})")

        # Save raw output
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
        out_path = os.path.join(self._output_dir, f"{safe_name}.txt")
        with open(out_path, "w") as f:
            f.write(f"Command: {cmd_str}\nExit: {output.exit_code}\n\n{output.stdout}\n\nSTDERR:\n{output.stderr}")

        return output

    def _has_tool(self, name: str) -> bool:
        return shutil.which(name) is not None

    # ── Recon phase ────────────────────────────────────────────

    def _run_recon(self, target: str, target_type: TargetType) -> dict[str, ToolOutput]:
        results: dict[str, ToolOutput] = {}
        domain = self._extract_domain(target)

        # DNS lookup
        if self._has_tool("dig"):
            results["dig_a"] = self._run_tool("dig-A", ["dig", "+short", domain, "A"])
            results["dig_mx"] = self._run_tool("dig-MX", ["dig", "+short", domain, "MX"])
            results["dig_txt"] = self._run_tool("dig-TXT", ["dig", "+short", domain, "TXT"])
            results["dig_ns"] = self._run_tool("dig-NS", ["dig", "+short", domain, "NS"])

        # WHOIS
        if self._has_tool("whois"):
            results["whois"] = self._run_tool("whois", ["whois", domain], timeout_s=30)

        # Subdomain enumeration
        if self._has_tool("subfinder"):
            results["subfinder"] = self._run_tool("subfinder", [
                "subfinder", "-d", domain, "-silent", "-timeout", "30",
            ], timeout_s=60)

        # Port scan
        if target_type in (TargetType.IP, TargetType.DOMAIN, TargetType.CIDR):
            if self._has_tool("nmap"):
                nmap_args = ["nmap", "-sV", "-sC", "--top-ports", "1000", "-T4", "--open"]
                if self._config.stealth:
                    nmap_args = ["nmap", "-sS", "-T2", "--top-ports", "100"]
                nmap_args.append(domain)
                results["nmap"] = self._run_tool("nmap", nmap_args, timeout_s=600)

        # HTTP probing
        if target_type == TargetType.URL:
            if self._has_tool("curl"):
                results["curl_headers"] = self._run_tool("curl-headers", [
                    "curl", "-sI", "-L", "--max-time", "15", target,
                ])

        # Use curl for basic HTTP probing (more reliable than httpx which may be python version)
        if self._has_tool("curl") and target_type in (TargetType.DOMAIN, TargetType.URL):
            probe_url = target if target.startswith("http") else f"https://{domain}"
            results["curl_probe"] = self._run_tool("curl-probe", [
                "curl", "-sI", "-L", "--max-time", "15", "-o", "/dev/null",
                "-w", "HTTP/%{http_version} %{http_code} %{redirect_url}\\nIP: %{remote_ip}\\nSize: %{size_download}\\nTime: %{time_total}s\\nSSL: %{ssl_verify_result}\\n",
                probe_url,
            ], timeout_s=20)

        # Extract basic findings from recon
        self._extract_recon_findings(results, target)

        return results

    def _extract_recon_findings(self, results: dict[str, ToolOutput], target: str) -> None:
        """Extract obvious findings from recon data."""
        # Check for missing security headers
        curl_out = results.get("curl_headers")
        if curl_out and curl_out.success:
            headers_lower = curl_out.stdout.lower()
            header_checks = [
                ("x-frame-options", "Missing X-Frame-Options header", "low", "CWE-1021"),
                ("content-security-policy", "Missing Content-Security-Policy header", "medium", "CWE-693"),
                ("strict-transport-security", "Missing HSTS header", "medium", "CWE-319"),
                ("x-content-type-options", "Missing X-Content-Type-Options header", "low", "CWE-693"),
            ]
            for header, title, sev, cwe in header_checks:
                if header not in headers_lower:
                    self._add_finding(ScanFinding(
                        title=title, severity=sev, vuln_type="missing_header",
                        target=target, evidence=f"Header '{header}' not present in response",
                        tool="curl", cwe=cwe, confidence="high",
                    ))

            # Check for server version disclosure
            for line in curl_out.stdout.splitlines():
                if line.lower().startswith("server:"):
                    server_val = line.split(":", 1)[1].strip()
                    if re.search(r"\d+\.\d+", server_val):
                        self._add_finding(ScanFinding(
                            title=f"Server version disclosure: {server_val}",
                            severity="low", vuln_type="info_disclosure",
                            target=target, evidence=line.strip(),
                            tool="curl", cwe="CWE-200", confidence="high",
                        ))

        # Check nmap for interesting findings
        nmap_out = results.get("nmap")
        if nmap_out and nmap_out.success:
            nmap_text = nmap_out.stdout
            # Look for potentially dangerous open services
            dangerous_services = {
                "21/": ("FTP service exposed", "medium"),
                "23/": ("Telnet service exposed", "high"),
                "445/": ("SMB service exposed", "medium"),
                "3389/": ("RDP service exposed", "medium"),
                "6379/": ("Redis exposed", "high"),
                "27017/": ("MongoDB exposed", "high"),
                "9200/": ("Elasticsearch exposed", "high"),
                "5432/": ("PostgreSQL exposed", "medium"),
                "3306/": ("MySQL exposed", "medium"),
            }
            for port_prefix, (title, sev) in dangerous_services.items():
                if f"{port_prefix}" in nmap_text and "open" in nmap_text:
                    self._add_finding(ScanFinding(
                        title=title, severity=sev, vuln_type="exposed_service",
                        target=target, evidence=f"Port {port_prefix.rstrip('/')} open",
                        tool="nmap", confidence="high",
                    ))

    # ── LLM analysis ───────────────────────────────────────────

    def _select_model(self, task_type: str) -> str:
        """Select best available model for a task."""
        preferences = MODEL_PREFERENCES.get(task_type, MODEL_PREFERENCES["general"])
        for model in preferences:
            if model in self._healthy_models:
                return model
        return self._healthy_models[0] if self._healthy_models else ""

    def _llm_query(self, system_prompt: str, user_prompt: str, model_id: str = "", max_tokens: int = 2048) -> str:
        """Send a query to an LLM and return the text response."""
        model = model_id or self._primary_model
        if not model:
            return ""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        self._print(f"  [>] LLM query to {model} ({len(user_prompt)} chars)")
        resp = self._llm.chat(model, messages, temperature=0.3, max_tokens=max_tokens)

        if resp.success and resp.content:
            self._print(f"  [+] LLM response: {len(resp.content)} chars, {resp.latency_ms:.0f}ms")
            return resp.content
        else:
            self._print(f"  [-] LLM error: {resp.error[:60]}")
            # Fallback to another model
            fallback = self._select_model("general")
            if fallback and fallback != model:
                self._print(f"  [>] Fallback to {fallback}")
                resp = self._llm.chat(fallback, messages, temperature=0.3, max_tokens=max_tokens)
                if resp.success:
                    return resp.content
            return ""

    def _llm_analyze_recon(self, recon_data: dict[str, ToolOutput], target: str) -> list[dict[str, Any]]:
        """Have LLM analyze recon data and generate attack plan."""
        # Build context from recon results
        context_parts = []
        for name, output in recon_data.items():
            if output.success and output.stdout.strip():
                context_parts.append(f"=== {name} ===\n{output.stdout[:2000]}")

        if not context_parts:
            return []

        context = "\n\n".join(context_parts)
        prompt = (
            f"Target: {target}\n\n"
            f"Here is the reconnaissance data:\n\n{context}\n\n"
            "Based on this recon data:\n"
            "1. Identify all interesting findings (open ports, services, subdomains, technologies)\n"
            "2. Create an attack plan — list specific tools and commands to run next\n"
            "3. Prioritize by likelihood of finding vulnerabilities\n\n"
            'Respond as JSON: {{"findings": [...], "plan": [{{"tool": "...", "args": "...", "reason": "..."}}]}}'
        )

        model = self._select_model("planning")
        response = self._llm_query(PLANNING_SYSTEM_PROMPT, prompt, model_id=model, max_tokens=4096)

        # Parse attack plan from LLM response
        plan = self._extract_json(response)
        if isinstance(plan, dict) and "plan" in plan:
            return plan["plan"]
        return []

    def _llm_analyze_scans(self, scan_data: dict[str, ToolOutput], target: str) -> None:
        """Have LLM analyze scan results to extract findings."""
        for name, output in scan_data.items():
            if not output.success or not output.stdout.strip():
                continue
            if len(output.stdout) < 50:
                continue

            prompt = (
                f"Target: {target}\nTool: {name}\n\n"
                f"Tool output:\n{output.stdout[:4000]}\n\n"
                "Analyze this output and extract ALL security findings.\n"
                "For each finding, provide:\n"
                "- title: specific description\n"
                "- severity: critical/high/medium/low/info\n"
                "- type: vuln category (xss, sqli, ssrf, etc.)\n"
                "- evidence: the specific evidence from the output\n"
                "- cwe: CWE ID if applicable\n"
                "- remediation: how to fix it\n\n"
                'Respond as JSON: {{"findings": [{{"title":"...", "severity":"...", "type":"...", "evidence":"...", "cwe":"...", "remediation":"..."}}]}}'
            )

            model = self._select_model("security_analysis")
            response = self._llm_query(SECURITY_SYSTEM_PROMPT, prompt, model_id=model, max_tokens=4096)

            parsed = self._extract_json(response)
            if isinstance(parsed, dict) and "findings" in parsed:
                for f in parsed["findings"]:
                    if isinstance(f, dict) and f.get("title"):
                        self._add_finding(ScanFinding(
                            title=f.get("title", ""),
                            severity=f.get("severity", "medium"),
                            vuln_type=f.get("type", ""),
                            target=target,
                            evidence=f.get("evidence", ""),
                            tool=name,
                            cwe=f.get("cwe", ""),
                            remediation=f.get("remediation", ""),
                            confidence="medium",
                        ))

    # ── Active scanning ────────────────────────────────────────

    def _run_active_scans(self, target: str, target_type: TargetType, attack_plan: list[dict[str, Any]]) -> dict[str, ToolOutput]:
        results: dict[str, ToolOutput] = {}
        domain = self._extract_domain(target)
        url = target if target_type == TargetType.URL else f"http://{domain}"

        # Default scans (always run if tools available)
        if self._has_tool("nuclei"):
            results["nuclei"] = self._run_tool("nuclei", [
                "nuclei", "-u", url, "-severity", "critical,high,medium",
                "-silent", "-no-color", "-timeout", "10",
            ], timeout_s=600)

        if self._has_tool("nikto") and target_type in (TargetType.URL, TargetType.DOMAIN):
            results["nikto"] = self._run_tool("nikto", [
                "nikto", "-h", url, "-Tuning", "123bde", "-maxtime", "120s",
            ], timeout_s=180)

        if self._has_tool("ffuf") and target_type in (TargetType.URL, TargetType.DOMAIN):
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            if os.path.exists(wordlist):
                results["ffuf"] = self._run_tool("ffuf", [
                    "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
                    "-mc", "200,201,301,302,403", "-t", "20",
                    "-timeout", "10", "-s",
                ], timeout_s=120)

        # Execute LLM-suggested tools
        for step in attack_plan[:5]:
            tool = step.get("tool", "")
            args_str = step.get("args", "")
            if not tool or not self._has_tool(tool):
                continue
            if tool in results:
                continue

            # Build command from LLM suggestion
            cmd = self._build_tool_command(tool, args_str, target, domain, url)
            if cmd:
                results[f"llm_{tool}"] = self._run_tool(f"llm-{tool}", cmd, timeout_s=self._config.tool_timeout_s)

        return results

    def _build_tool_command(self, tool: str, args_str: str, target: str, domain: str, url: str) -> list[str]:
        """Build a safe tool command from LLM suggestion."""
        # Sanitize — only allow known-safe tools
        allowed = {"nmap", "nuclei", "nikto", "ffuf", "gobuster", "sqlmap", "subfinder",
                    "httpx", "curl", "dig", "whois", "wpscan", "dalfox", "arjun",
                    "testssl.sh", "sslyze", "feroxbuster", "dnsrecon", "whatweb"}
        if tool not in allowed:
            return []

        # Parse args string into list, replacing placeholders
        args = args_str.replace("{target}", target).replace("{domain}", domain).replace("{url}", url)
        parts = args.split()

        # If the tool binary isn't the first arg, prepend it
        if parts and parts[0] != tool:
            parts = [tool] + parts
        elif not parts:
            parts = [tool, target]

        # Block dangerous patterns
        dangerous = ["rm", "dd", "mkfs", "chmod", "|", ";", "&&", "$(", "`"]
        cmd_str = " ".join(parts)
        for d in dangerous:
            if d in cmd_str:
                return []

        return parts

    # ── Deep dive ──────────────────────────────────────────────

    def _run_deep_dive(self, target: str, target_type: TargetType) -> None:
        """Run follow-up scans on interesting findings."""
        url = target if target_type == TargetType.URL else f"http://{self._extract_domain(target)}"

        # If we found SQL injection hints, run sqlmap
        sqli_findings = [f for f in self._findings if "sql" in f.vuln_type.lower() or "sql" in f.title.lower()]
        if sqli_findings and self._has_tool("sqlmap"):
            for finding in sqli_findings[:2]:
                target_url = finding.url or url
                self._run_tool("sqlmap-deep", [
                    "sqlmap", "-u", target_url, "--batch", "--level=2",
                    "--risk=2", "--timeout=10", "--retries=1",
                ], timeout_s=120)

        # If we found XSS hints, run dalfox
        xss_findings = [f for f in self._findings if "xss" in f.vuln_type.lower() or "xss" in f.title.lower()]
        if xss_findings and self._has_tool("dalfox"):
            for finding in xss_findings[:2]:
                target_url = finding.url or url
                self._run_tool("dalfox-deep", [
                    "dalfox", "url", target_url, "--silence",
                ], timeout_s=120)

        # Ask LLM for deep dive suggestions
        if self._primary_model and self._findings:
            findings_summary = json.dumps([f.to_dict() for f in self._findings[:10]], indent=2)
            prompt = (
                f"Target: {target}\n\nFindings so far:\n{findings_summary}\n\n"
                "Based on these findings, suggest 3 specific follow-up investigations.\n"
                "What additional tools/commands would reveal deeper vulnerabilities?\n"
                'Respond as JSON: {{"followups": [{{"tool": "...", "args": "...", "reason": "..."}}]}}'
            )
            response = self._llm_query(SECURITY_SYSTEM_PROMPT, prompt, max_tokens=2048)
            parsed = self._extract_json(response)
            if isinstance(parsed, dict) and "followups" in parsed:
                for step in parsed["followups"][:3]:
                    tool = step.get("tool", "")
                    if tool and self._has_tool(tool):
                        domain = self._extract_domain(target)
                        cmd = self._build_tool_command(tool, step.get("args", ""), target, domain, target)
                        if cmd:
                            self._run_tool(f"deep-{tool}", cmd)

    # ── Autonomous think-act loop ────────────────────────────────

    def _get_available_tools_text(self) -> str:
        """Build a concise list of tools available on this system."""
        from recursec.agents.tool_executor import TOOL_REGISTRY
        available = []
        for tool_def in TOOL_REGISTRY:
            binary = tool_def.get("binary", tool_def["name"])
            if shutil.which(binary):
                available.append(f"{tool_def['name']} ({tool_def['desc']})")
        return ", ".join(available) if available else "curl, nmap, dig, whois (basic set)"

    def _run_autonomous_loop(self, target: str, target_type: TargetType) -> None:
        """Run the LLM-driven autonomous think-act loop.

        The LLM sees what tools are available, what has been done so far,
        and decides what command to run next. It keeps going until it
        says DONE, hits the iteration limit, or runs out of time.
        """
        max_iterations = self._config.max_iterations
        available_tools = self._get_available_tools_text()
        system_prompt = AUTONOMOUS_SYSTEM_PROMPT.format(available_tools=available_tools)

        # Build initial memory from what we've already done
        for out in self._tool_outputs:
            if out.success:
                summary = out.stdout[:300] if out.stdout else "(no output)"
                self._memory.append({"command": out.command, "output": summary})
                self._executed_commands.append(out.command)

        findings_so_far = [f.to_dict() for f in self._findings[:10]]

        for iteration in range(max_iterations):
            elapsed = time.time() - self._start_time
            if elapsed > self._config.max_time_s:
                self._print(f"  [!] Time limit reached ({elapsed:.0f}s)")
                break

            # Build the user prompt with full context
            recent_memory = self._memory[-8:]
            memory_text = ""
            for m in recent_memory:
                memory_text += f"\nCommand: {m['command']}\nOutput: {m['output'][:200]}\n"

            user_prompt = (
                f"Target: {target}\n"
                f"Target type: {target_type.value}\n"
                f"Iteration: {iteration + 1}/{max_iterations}\n"
                f"Findings so far: {len(self._findings)}\n"
                f"Tools run: {len(self._tool_outputs)}\n"
                f"Time elapsed: {elapsed:.0f}s / {self._config.max_time_s:.0f}s\n"
            )
            if findings_so_far:
                user_prompt += f"\nCurrent findings:\n{json.dumps(findings_so_far[:5], indent=1)}\n"
            if memory_text:
                user_prompt += f"\nRecent actions:\n{memory_text}\n"
            user_prompt += "\nWhat command should I run next?"

            # Ask the LLM
            model = self._select_model("security_analysis")
            command_text = self._llm_query(system_prompt, user_prompt, model_id=model, max_tokens=256)

            if not command_text:
                self._print("  [!] LLM returned empty response, stopping loop")
                break

            # Clean up the command
            command_text = command_text.strip()
            # Remove markdown code fences if present
            if command_text.startswith("```"):
                lines = command_text.split("\n")
                command_text = "\n".join(ln for ln in lines if not ln.startswith("```")).strip()
            # Take only the first line (should be one command)
            command_text = command_text.split("\n")[0].strip()

            # Check if LLM says we're done
            if command_text.upper() in ("DONE", "DONE.", "ASSESSMENT COMPLETE", "COMPLETE"):
                self._print(f"  [*] LLM says assessment is complete after {iteration + 1} iterations")
                break

            # Validate the command
            if not self._is_safe_command(command_text):
                self._print(f"  [!] Blocked unsafe command: {command_text[:60]}")
                self._memory.append({"command": command_text, "output": "BLOCKED: unsafe command"})
                continue

            # Skip if we already ran this exact command
            if command_text in self._executed_commands:
                self._memory.append({"command": command_text, "output": "SKIPPED: already executed"})
                continue

            # Execute the command
            self._print(f"  [{iteration + 1}] Agent: {command_text[:80]}")
            output = self._run_shell_command(command_text)
            self._executed_commands.append(command_text)

            if output.success and output.stdout:
                summary = output.stdout[:500]
                self._memory.append({"command": command_text, "output": summary})

                # Have LLM analyze the output for findings
                if len(output.stdout) > 50:
                    self._llm_extract_findings(output, target)
            else:
                err_msg = output.stderr[:200] if output.stderr else "no output"
                self._memory.append({"command": command_text, "output": f"ERROR: {err_msg}"})

            # Update findings list for next iteration context
            findings_so_far = [f.to_dict() for f in self._findings[:10]]

        self._print(f"  [*] Autonomous loop completed: {len(self._executed_commands)} commands, {len(self._findings)} findings")

    def _run_shell_command(self, command: str) -> ToolOutput:
        """Run a shell command safely and capture output."""
        # Extract tool name from command
        parts = command.split()
        tool_name = parts[0] if parts else "unknown"

        start = time.time()
        try:
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=self._config.tool_timeout_s,
                env={**os.environ, "TERM": "dumb"},
            )
            output = ToolOutput(
                tool=tool_name,
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_s=time.time() - start,
            )
        except subprocess.TimeoutExpired:
            output = ToolOutput(
                tool=tool_name, command=command,
                stderr=f"Timeout after {self._config.tool_timeout_s}s",
                exit_code=-1, duration_s=time.time() - start,
            )
        except FileNotFoundError:
            output = ToolOutput(
                tool=tool_name, command=command,
                stderr=f"Tool not found: {tool_name}",
                exit_code=-1, duration_s=0.0,
            )
        except OSError as exc:
            output = ToolOutput(
                tool=tool_name, command=command,
                stderr=str(exc), exit_code=-1, duration_s=0.0,
            )

        self._tool_outputs.append(output)

        if output.success:
            self._print(f"       OK ({output.duration_s:.1f}s, {len(output.stdout)} bytes)")
        else:
            self._print(f"       FAIL: {output.stderr[:60]}")

        # Save raw output
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", f"auto_{len(self._executed_commands)}_{tool_name}")
        out_path = os.path.join(self._output_dir, f"{safe_name}.txt")
        with open(out_path, "w") as f:
            f.write(f"Command: {command}\nExit: {output.exit_code}\n\n{output.stdout}\n\nSTDERR:\n{output.stderr}")

        return output

    def _is_safe_command(self, command: str) -> bool:
        """Check if a command is safe to execute."""
        cmd_lower = command.lower()

        # Block destructive patterns
        blocked = [
            "rm -rf", "rm -r /", "mkfs", "dd if=", "chmod -R 777 /",
            ":(){:|:&};:", "fork", "> /dev/sd", "mv / ", "shutdown",
            "reboot", "halt", "poweroff", "init 0", "init 6",
            "wget -O- | sh", "curl | sh", "eval ", "exec ",
        ]
        for b in blocked:
            if b in cmd_lower:
                return False

        # Block shell metacharacters (prevent injection)
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", ">"]
        for ch in dangerous_chars:
            if ch in command:
                return False

        # Must start with a known binary
        parts = command.split()
        if not parts:
            return False
        binary = parts[0]
        if not shutil.which(binary):
            return False

        return True

    def _llm_extract_findings(self, output: ToolOutput, target: str) -> None:
        """Have LLM analyze tool output and extract findings."""
        prompt = (
            f"Target: {target}\nTool: {output.tool}\nCommand: {output.command}\n\n"
            f"Tool output:\n{output.stdout[:4000]}\n\n"
            "Extract ALL security findings from this output."
        )

        model = self._select_model("security_analysis")
        response = self._llm_query(ANALYSIS_SYSTEM_PROMPT, prompt, model_id=model, max_tokens=4096)

        parsed = self._extract_json(response)
        if isinstance(parsed, dict) and "findings" in parsed:
            for f in parsed["findings"]:
                if isinstance(f, dict) and f.get("title"):
                    self._add_finding(ScanFinding(
                        title=f.get("title", ""),
                        severity=f.get("severity", "medium"),
                        vuln_type=f.get("type", ""),
                        target=target,
                        evidence=f.get("evidence", ""),
                        tool=output.tool,
                        cwe=f.get("cwe", ""),
                        remediation=f.get("remediation", ""),
                        confidence="medium",
                    ))

    # ── Finding management ─────────────────────────────────────

    def _add_finding(self, finding: ScanFinding) -> None:
        """Add a finding, deduplicating by title+target."""
        key = f"{finding.title}:{finding.target}"
        existing_keys = {f"{f.title}:{f.target}" for f in self._findings}
        if key not in existing_keys:
            self._findings.append(finding)

    def _count_severities(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    # ── Report generation ──────────────────────────────────────

    def _generate_report(self, target: str) -> dict[str, Any]:
        """Generate the final report."""
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self._findings, key=lambda f: severity_order.get(f.severity, 5))

        report = {
            "target": target,
            "goal": self._config.goal,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "duration_s": round(time.time() - self._start_time, 1),
            "summary": {
                "total_findings": len(self._findings),
                "severities": self._count_severities(),
                "tools_run": len(self._tool_outputs),
                "models_used": self._healthy_models,
            },
            "findings": [f.to_dict() for f in sorted_findings],
            "tool_results": [t.to_dict() for t in self._tool_outputs],
        }

        # Save report
        report_path = os.path.join(self._output_dir, "report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        # Generate markdown report
        md = self._build_markdown_report(target, sorted_findings)
        md_path = os.path.join(self._output_dir, "report.md")
        with open(md_path, "w") as f:
            f.write(md)

        return report

    def _build_markdown_report(self, target: str, findings: list[ScanFinding]) -> str:
        lines = [f"# RecurSec Security Assessment: {target}"]
        lines.append(f"\nDate: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}")
        lines.append(f"Duration: {time.time() - self._start_time:.1f}s")
        lines.append(f"Findings: {len(findings)}")
        sev = self._count_severities()
        lines.append("\n## Summary\n| Severity | Count |\n|----------|-------|")
        for s in ["critical", "high", "medium", "low", "info"]:
            if sev.get(s, 0) > 0:
                lines.append(f"| {s.upper()} | {sev[s]} |")

        lines.append("\n## Findings\n")
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. [{f.severity.upper()}] {f.title}")
            if f.vuln_type:
                lines.append(f"**Type:** {f.vuln_type}")
            if f.cwe:
                lines.append(f"**CWE:** {f.cwe}")
            if f.evidence:
                lines.append(f"**Evidence:** `{f.evidence[:200]}`")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}")
            lines.append(f"**Tool:** {f.tool} | **Confidence:** {f.confidence}\n")

        lines.append("\n## Tools Executed\n")
        for t in self._tool_outputs:
            status = "OK" if t.success else "FAIL"
            lines.append(f"- {t.tool}: {status} ({t.duration_s:.1f}s)")

        return "\n".join(lines)

    # ── Helpers ─────────────────────────────────────────────────

    def _extract_json(self, text: str) -> Any:
        """Extract JSON from LLM response text."""
        if not text:
            return {}
        # Try to find JSON block
        json_match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if json_match:
            text = json_match.group(1)
        else:
            # Try to find { ... } block
            brace_match = re.search(r"\{.*\}", text, re.DOTALL)
            if brace_match:
                text = brace_match.group(0)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}

    def _print(self, msg: str) -> None:
        """Print with optional verbose control."""
        print(msg)

    def get_stats(self) -> dict[str, Any]:
        return {
            "phase": self._phase.value,
            "findings": len(self._findings),
            "tools_run": len(self._tool_outputs),
            "elapsed": f"{time.time() - self._start_time:.1f}s",
            "models": self._healthy_models,
        }
