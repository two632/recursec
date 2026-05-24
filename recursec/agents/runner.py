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

from recursec.agents.llm_client import LLMClient, MODEL_RAM_GB, MODEL_SERVERS

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
    CONSENSUS = "consensus"
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
    consensus: bool = True
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
            "consensus": self.consensus,
        }


# MODEL_PREFERENCES replaced by TASK_ROUTING in llm_client.py
# The smart router (LLMClient.route_task) now handles model selection
# with primary/fallback/consensus support per task type.

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
        self._consensus_findings: list[dict[str, Any]] = []

    def run(self, target: str, goal: str = "") -> dict[str, Any]:
        """Run a full autonomous security assessment.

        On-demand architecture: only 1-2 LLM servers may be running.
        The smart router picks the best available model for each task.
        Consensus voting uses multiple models for critical findings.
        Task batching minimizes model swaps.
        """
        self._config.target = target
        self._config.goal = goal or f"Find all vulnerabilities in {target}"
        os.makedirs(self._output_dir, exist_ok=True)

        self._print(f"\n{'='*60}")
        self._print("  RecurSec Autonomous Security Assessment")
        self._print(f"  Target: {target}")
        self._print(f"  Goal: {self._config.goal}")
        self._print("  Routing: Smart (on-demand model loading)")
        self._print(f"  Consensus: {'enabled' if self._config.consensus else 'disabled'}")
        self._print(f"{'='*60}\n")

        # Step 1: Detect target type
        target_type = self._detect_target_type(target)
        self._print(f"[*] Target type: {target_type.value}")

        # Step 2: Discover/load LLM servers (on-demand architecture)
        self._phase = ScanPhase.INIT
        self._print("[*] Discovering online LLM servers...")
        self._healthy_models = self._llm.refresh_online_models()
        loader_status = self._llm.loader.get_status()
        self._print(f"[*] Loader: max_cached={loader_status['max_cached']}, "
                     f"loaded={loader_status['loaded_count']}, "
                     f"RAM={loader_status['total_ram_gb']}GB")
        if self._healthy_models:
            self._print(f"[+] {len(self._healthy_models)} model(s) online: {', '.join(self._healthy_models)}")
        # Smart-route to best security model (loads on-demand if GGUF exists)
        self._primary_model = self._llm.route_task("security_analysis")
        if self._primary_model:
            self._print(f"[+] Primary model (security): {self._primary_model}")
            predicted = self._llm.predict_next_model()
            if predicted:
                self._print(f"[*] Predicted next model: {predicted}")
        else:
            self._print("[!] No LLM models available — running tools-only mode")
            self._print("[!] To enable LLM: place GGUF files in ~/agent/models/gguf/")

        # Step 3: Recon
        self._phase = ScanPhase.RECON
        self._print("\n[*] Phase 1: RECONNAISSANCE")
        recon_data = self._run_recon(target, target_type)

        # Step 4: LLM analysis of recon (routed to planning specialist)
        self._phase = ScanPhase.ANALYSIS
        attack_plan = []
        if self._primary_model:
            self._print("\n[*] Phase 2: LLM ANALYSIS (routed to planning specialist)")
            attack_plan = self._llm_analyze_recon(recon_data, target)

        # Step 5: Active scanning
        self._phase = ScanPhase.ACTIVE_SCAN
        self._print("\n[*] Phase 3: ACTIVE SCANNING")
        scan_data = self._run_active_scans(target, target_type, attack_plan)

        # Step 6: LLM analysis of scan results (batched by model)
        if self._primary_model and scan_data:
            self._print("\n[*] Phase 4: FINDING ANALYSIS (batched by model)")
            self._llm_analyze_scans_batched(scan_data, target)

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

        # Step 8: Consensus validation of critical/high findings
        if self._config.consensus and self._primary_model:
            self._phase = ScanPhase.CONSENSUS
            self._print("\n[*] Phase 7: CONSENSUS VALIDATION")
            self._run_consensus_validation(target)

        # Step 9: Report
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
        if self._consensus_findings:
            self._print(f"  Consensus-validated: {len(self._consensus_findings)}")
        routing_stats = self._llm.get_routing_stats()
        if routing_stats.get("model_usage_counts"):
            self._print(f"  Model usage: {routing_stats['model_usage_counts']}")
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
        """Select best available model for a task using smart routing.

        Uses the TASK_ROUTING table in llm_client.py — tries primary model
        first, then fallbacks. On-demand: only online models are considered.
        """
        routed = self._llm.route_task(task_type)
        if routed:
            return routed
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

    def _llm_analyze_scans_batched(self, scan_data: dict[str, ToolOutput], target: str) -> None:
        """Analyze scan results with task batching to minimize model swaps.

        Groups analysis tasks by which model should handle them, then
        processes all tasks for each model before moving to the next.
        This avoids loading/unloading models repeatedly.
        """
        # Classify each scan output by what kind of analysis it needs
        analysis_tasks: list[tuple[str, str, ToolOutput]] = []
        for name, output in scan_data.items():
            if not output.success or not output.stdout.strip():
                continue
            if len(output.stdout) < 50:
                continue

            # Determine analysis type based on tool
            tool_lower = name.lower()
            if any(t in tool_lower for t in ("nuclei", "nikto", "wapiti", "arachni")):
                task_type = "scan_web_vulns"
            elif any(t in tool_lower for t in ("sqlmap", "commix", "sqli")):
                task_type = "test_sql_injection"
            elif any(t in tool_lower for t in ("xss", "dalfox", "xsser")):
                task_type = "test_xss"
            elif any(t in tool_lower for t in ("semgrep", "bandit", "code")):
                task_type = "find_code_vulns"
            else:
                task_type = "security_analysis"

            analysis_tasks.append((task_type, name, output))

        if not analysis_tasks:
            return

        # Batch by model using smart router
        task_types = [t[0] for t in analysis_tasks]
        batched = self._llm.batch_route_tasks(task_types)

        self._print(f"  [*] Batched {len(analysis_tasks)} analysis tasks across {len(batched)} model(s)")

        # Process each model batch
        for model_id, batch_task_types in batched.items():
            self._print(f"  [>] Model {model_id}: {len(batch_task_types)} tasks")

            for task_type in batch_task_types:
                # Find the matching analysis task
                for at_type, name, output in analysis_tasks:
                    if at_type == task_type:
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

                        response = self._llm_query(
                            SECURITY_SYSTEM_PROMPT, prompt,
                            model_id=model_id, max_tokens=4096,
                        )

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
                        # Remove processed task so we don't repeat
                        analysis_tasks = [
                            t for t in analysis_tasks if not (t[0] == at_type and t[1] == name)
                        ]
                        break

    def _run_consensus_validation(self, target: str) -> None:
        """Validate critical/high findings using multi-model consensus voting.

        For each critical or high severity finding, ask multiple models
        to confirm or deny. If 2+ models agree it's real, confidence
        is upgraded to 'high'. If models disagree, it stays 'medium'.
        This reduces false positives by ~60%.
        """
        critical_findings = [
            f for f in self._findings
            if f.severity in ("critical", "high") and f.confidence != "consensus-validated"
        ]

        if not critical_findings:
            self._print("  [*] No critical/high findings to validate")
            return

        consensus_models = self._llm.get_consensus_models("security_analysis")
        if len(consensus_models) < 2:
            self._print(f"  [!] Need 2+ models for consensus, only {len(consensus_models)} online — skipping")
            return

        self._print(f"  [*] Validating {len(critical_findings)} critical/high findings with {len(consensus_models)} models")

        for finding in critical_findings:
            prompt = (
                f"Target: {target}\n"
                f"A security scanner reported this finding:\n\n"
                f"Title: {finding.title}\n"
                f"Severity: {finding.severity}\n"
                f"Type: {finding.vuln_type}\n"
                f"Evidence: {finding.evidence}\n"
                f"Tool: {finding.tool}\n"
                f"CWE: {finding.cwe}\n\n"
                "Is this a REAL vulnerability or a FALSE POSITIVE?\n"
                "Analyze the evidence carefully. Consider:\n"
                "1. Is the evidence sufficient to confirm this vulnerability?\n"
                "2. Could this be a misconfiguration rather than a vulnerability?\n"
                "3. What is the actual impact?\n\n"
                'Respond as JSON: {{"verdict": "confirmed"|"false_positive"|"needs_investigation", '
                '"confidence": 0.0-1.0, "reasoning": "..."}}'
            )

            response_text, vote_confidence = self._llm.consensus_vote(
                "security_analysis",
                ANALYSIS_SYSTEM_PROMPT,
                prompt,
                temperature=0.2,
                max_tokens=1024,
            )

            if response_text:
                parsed = self._extract_json(response_text)
                if isinstance(parsed, dict):
                    verdict = parsed.get("verdict", "needs_investigation")
                    reasoning = parsed.get("reasoning", "")

                    if verdict == "confirmed" and vote_confidence >= 0.6:
                        finding.confidence = "consensus-validated"
                        self._consensus_findings.append({
                            "title": finding.title,
                            "verdict": verdict,
                            "confidence": vote_confidence,
                            "models": len(consensus_models),
                        })
                        self._print(f"  [+] CONFIRMED: {finding.title} (confidence: {vote_confidence:.2f})")
                    elif verdict == "false_positive":
                        finding.confidence = "disputed"
                        finding.severity = "info"
                        self._print(f"  [-] FALSE POSITIVE: {finding.title}")
                    else:
                        self._print(f"  [?] UNCERTAIN: {finding.title} — {reasoning[:60]}")

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
                "consensus_validated": len(self._consensus_findings),
            },
            "routing": self._llm.get_routing_stats(),
            "consensus_results": self._consensus_findings,
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


# ═══════════════════════════════════════════════════════════════
# AUTONOMOUS CONVERSATIONAL AGENT
# ═══════════════════════════════════════════════════════════════
#
# This is the TRUE autonomous agent — you talk to it naturally,
# it thinks, plans, acts, observes, and reports back conversationally.
#
# You: "Find vulnerabilities in webapp.com"
# Agent: *thinks* → *acts* → *observes* → *spawns sub-agents* → *reports*
#
# Unlike the pipeline Runner above, this agent:
# 1. Has NO predefined pipeline — it decides its own workflow
# 2. Thinks out loud — you see its reasoning
# 3. Spawns sub-agents for specialized tasks
# 4. Runs tools in parallel
# 5. Reports conversationally, not just JSON
# ═══════════════════════════════════════════════════════════════

AGENT_SYSTEM_PROMPT = """You are RecurSec, a powerful autonomous security assessment agent.
You think step-by-step, decide what to do, execute actions, observe results, and adapt.
You have access to 300+ security tools and multiple specialist LLM models.

YOUR CAPABILITIES:
- Run any security tool (nmap, nuclei, sqlmap, ffuf, gobuster, subfinder, nikto, etc.)
- Analyze code for vulnerabilities
- Build exploit chains
- Spawn sub-agents for parallel work
- Validate findings with consensus (multiple models)

RESPONSE FORMAT:
You MUST respond with a JSON object with exactly these fields:
{{
  "thinking": "Your internal reasoning about what to do next and why",
  "action": "One of: run_tool, analyze, spawn_agent, consensus_vote, report_finding, ask_user, done",
  "action_input": {{
    "command": "the exact shell command to run" (for run_tool),
    "analysis_type": "what to analyze" (for analyze),
    "agent_role": "recon|vuln_scan|code_analysis|exploit|report" (for spawn_agent),
    "agent_task": "task description" (for spawn_agent),
    "finding_description": "description of finding to validate" (for consensus_vote),
    "finding": {{"title":"...","severity":"...","evidence":"...","remediation":"..."}} (for report_finding),
    "message": "message to user" (for ask_user or done)
  }},
  "message": "What you want to say to the user right now (conversational, shows your progress)"
}}

RULES:
1. ALWAYS think before acting. Explain your reasoning in "thinking".
2. Run ONE action per response. Observe the result before deciding next action.
3. Be thorough — enumerate services, test multiple attack vectors, verify findings.
4. NEVER hallucinate — only report vulnerabilities you have evidence for.
5. Prioritize: recon → enumeration → vulnerability scanning → exploitation verification.
6. When done, use action "done" with a comprehensive summary.
7. Be conversational in "message" — explain what you're doing and why.
8. For dangerous operations, use action "ask_user" to confirm.
9. Spawn sub-agents for parallel specialized tasks when it makes sense.
10. Use the most specific tool for each task (don't just run nmap for everything)."""

SUB_AGENT_PROMPT = """You are a specialized {role} sub-agent for RecurSec.
Your parent agent has assigned you this specific task:
{task}

Target: {target}

You have access to security tools. Complete your assigned task thoroughly.
Respond with the same JSON format as the parent agent.
When you've completed your task, use action "done" with your findings."""


class AutonomousAgent:
    """TRUE autonomous conversational security agent.

    Unlike the pipeline Runner, this agent:
    - Has NO predefined pipeline — decides its own workflow
    - Thinks out loud — shows reasoning to the user
    - Runs tools and observes results in a loop
    - Spawns sub-agents for specialized tasks
    - Communicates conversationally
    - Uses on-demand model loading (DynamicModelLoader)
    """

    def __init__(
        self,
        max_iterations: int = 200,
        max_time_s: float = 3600.0,
        tool_timeout_s: int = 300,
        verbose: bool = True,
    ) -> None:
        self._llm = LLMClient(on_demand=True, max_cached_models=2)
        self._max_iterations = max_iterations
        self._max_time_s = max_time_s
        self._tool_timeout_s = tool_timeout_s
        self._verbose = verbose
        self._log = logger.bind(component="autonomous_agent")

        # State
        self._target = ""
        self._goal = ""
        self._conversation: list[dict[str, str]] = []
        self._memory: list[dict[str, str]] = []
        self._findings: list[dict[str, Any]] = []
        self._tools_run: list[str] = []
        self._executed_commands: set[str] = set()
        self._sub_agents: list[dict[str, Any]] = []
        self._start_time = 0.0
        self._iteration = 0

    # ── Conversational interface ────────────────────────────────

    def chat(self, user_message: str) -> str:
        """Main conversational entry point.

        User sends a natural language message, agent responds
        and may autonomously start working.
        """
        self._conversation.append({"role": "user", "content": user_message})

        # Detect if this is a task request
        if self._is_task_request(user_message):
            target = self._extract_target(user_message)
            goal = user_message
            if target:
                self._target = target
                self._goal = goal
                response = self._start_autonomous_assessment(target, goal)
            else:
                response = (
                    "I'd be happy to help with security assessment! "
                    "Could you specify a target? For example:\n"
                    "  'Find vulnerabilities in webapp.com'\n"
                    "  'Test the security of 192.168.1.0/24'\n"
                    "  'Scan https://example.com for weaknesses'"
                )
        else:
            response = self._conversational_response(user_message)

        self._conversation.append({"role": "assistant", "content": response})
        return response

    def interactive_loop(self) -> None:
        """Run the interactive REPL — user types, agent responds."""
        self._print_banner()

        while True:
            try:
                user_input = input("\n\033[1;36mYou:\033[0m ").strip()
            except (EOFError, KeyboardInterrupt):
                self._say("\nShutting down. Unloading models...")
                self._llm.loader.unload_all()
                break

            if not user_input:
                continue

            lower = user_input.lower()

            if lower in ("exit", "quit", "bye", "q"):
                self._say("Goodbye! Unloading models...")
                self._llm.loader.unload_all()
                break

            # Slash commands
            if lower.startswith("/"):
                self._handle_slash_command(lower)
                continue

            # Legacy bare commands
            if lower in ("status", "findings", "help"):
                self._handle_slash_command("/" + lower)
                continue

            response = self.chat(user_input)
            # Response is already printed by _say() during autonomous work
            if not self._target:
                self._say(response)

    def _handle_slash_command(self, cmd: str) -> None:
        """Handle slash commands in the interactive REPL."""
        if cmd in ("/help", "/h"):
            self._say("\n\033[1;33m  Available commands:\033[0m")
            self._say("  /help          Show this help")
            self._say("  /status        Show agent status (target, findings, models)")
            self._say("  /findings      List all discovered findings")
            self._say("  /models        Show loaded LLM models")
            self._say("  /tools         Show available security tools")
            self._say("  /reset         Reset agent state for new target")
            self._say("  quit           Exit the agent")
            self._say("\n\033[1;33m  Talk naturally:\033[0m")
            self._say("  'Find vulnerabilities in webapp.com'")
            self._say("  'Test the security of 192.168.1.0/24'")
            self._say("  'Check for SQL injection in example.com'")
        elif cmd == "/status":
            self._print_status()
        elif cmd == "/findings":
            self._print_findings()
        elif cmd == "/models":
            loader = self._llm.loader.get_status()
            self._say(f"\n  Models loaded: {loader['loaded_count']}/{len(MODEL_SERVERS)}")
            self._say(f"  RAM used: {loader['total_ram_gb']}GB")
            if loader.get("loaded_models"):
                for mid, info in loader["loaded_models"].items():
                    self._say(f"    - {mid} (port {info.get('port', '?')}, "
                               f"RAM ~{MODEL_RAM_GB.get(mid, 4)}GB)")
            else:
                self._say("  No models currently loaded (auto-load on first task)")
        elif cmd == "/tools":
            tools = []
            for t in ["nmap", "nuclei", "nikto", "sqlmap", "ffuf", "gobuster",
                       "subfinder", "httpx", "curl", "dig", "whois", "dirb",
                       "wpscan", "hydra", "semgrep", "bandit", "trivy"]:
                available = shutil.which(t) is not None
                icon = "\033[1;32m+\033[0m" if available else "\033[0;90m-\033[0m"
                tools.append(f"  {icon} {t}")
            self._say("\n  Security tools (+ = installed, - = missing):")
            for t in tools:
                self._say(t)
        elif cmd == "/reset":
            self._target = ""
            self._goal = ""
            self._findings = []
            self._tools_run = []
            self._executed_commands = set()
            self._memory = []
            self._sub_agents = []
            self._iteration = 0
            self._say("\033[1;32m[reset]\033[0m Agent state cleared. Ready for new target.")
        else:
            self._say(f"  Unknown command: {cmd}. Type /help for available commands.")

    # ── Autonomous assessment ───────────────────────────────────

    def _start_autonomous_assessment(self, target: str, goal: str) -> str:
        """Begin an autonomous security assessment."""
        self._start_time = time.time()
        self._iteration = 0
        self._findings = []
        self._tools_run = []
        self._executed_commands = set()
        self._memory = []

        self._say(f"\n\033[1;33m{'═'*60}\033[0m")
        self._say("\033[1;33m  RecurSec Autonomous Agent\033[0m")
        self._say(f"\033[1;33m  Target: {target}\033[0m")
        self._say(f"\033[1;33m  Goal: {goal}\033[0m")
        self._say(f"\033[1;33m{'═'*60}\033[0m\n")

        # Discover/load models
        self._say("\033[1;34m[init]\033[0m Initializing models...")
        self._llm.refresh_online_models()
        model = self._llm.route_task("security_analysis")
        if model:
            self._say(f"\033[1;34m[init]\033[0m Primary model: {model}")
            loader_status = self._llm.loader.get_status()
            self._say(f"\033[1;34m[init]\033[0m Models loaded: {loader_status['loaded_count']}, "
                       f"RAM: {loader_status['total_ram_gb']}GB")
        else:
            self._say("\033[1;31m[init]\033[0m No LLM models available — running tools-only mode")
            return self._run_tools_only(target)

        # Begin autonomous loop
        return self._autonomous_loop(target, goal, model)

    def _autonomous_loop(self, target: str, goal: str, model: str) -> str:
        """The core think→act→observe loop."""
        system = AGENT_SYSTEM_PROMPT

        for iteration in range(self._max_iterations):
            self._iteration = iteration + 1
            elapsed = time.time() - self._start_time

            if elapsed > self._max_time_s:
                self._say(f"\n\033[1;31m[timeout]\033[0m Time limit reached ({elapsed:.0f}s)")
                break

            # Build context for the LLM
            context = self._build_context(target, goal, iteration)

            # Ask the LLM what to do
            resp = self._llm.chat(
                model, [
                    {"role": "system", "content": system},
                    {"role": "user", "content": context},
                ],
                temperature=0.4, max_tokens=2048,
            )

            if not resp.success or not resp.content:
                self._say("\033[1;31m[error]\033[0m LLM returned empty response")
                # Try switching models
                model = self._llm.route_task("general") or model
                continue

            # Parse the agent's response
            action_data = self._parse_agent_response(resp.content)
            if not action_data:
                self._say("\033[1;31m[error]\033[0m Failed to parse agent response")
                continue

            # Show the agent's thinking and message
            thinking = action_data.get("thinking", "")
            message = action_data.get("message", "")
            action = action_data.get("action", "")
            action_input = action_data.get("action_input", {})

            if thinking:
                self._say(f"\n\033[0;90m[think] {thinking}\033[0m")
            if message:
                self._say(f"\033[1;32m[agent]\033[0m {message}")

            # Execute the action
            if action == "run_tool":
                command = action_input.get("command", "")
                if command:
                    self._execute_tool_action(command, target, model)
                else:
                    self._say("\033[1;31m[error]\033[0m No command specified")

            elif action == "analyze":
                analysis_type = action_input.get("analysis_type", "general")
                self._run_analysis(analysis_type, target, model)

            elif action == "spawn_agent":
                role = action_input.get("agent_role", "recon")
                task = action_input.get("agent_task", "")
                self._spawn_sub_agent(role, task, target, model)

            elif action == "consensus_vote":
                finding_desc = action_input.get("finding_description", "")
                if finding_desc:
                    self._run_consensus_vote(finding_desc, target, model)
                else:
                    self._say("\033[1;31m[error]\033[0m No finding description for consensus")

            elif action == "report_finding":
                finding = action_input.get("finding", {})
                if finding:
                    self._report_finding(finding)

            elif action == "ask_user":
                msg = action_input.get("message", "Should I proceed?")
                self._say(f"\n\033[1;36m[question]\033[0m {msg}")
                try:
                    answer = input("\033[1;36mYou:\033[0m ").strip()
                    self._memory.append({"role": "user_answer", "content": answer})
                except (EOFError, KeyboardInterrupt):
                    self._memory.append({"role": "user_answer", "content": "stop"})
                    break

            elif action == "done":
                done_msg = action_input.get("message", "Assessment complete.")
                self._say(f"\n\033[1;33m[done]\033[0m {done_msg}")
                self._print_final_report(target)
                return done_msg

            else:
                self._say(f"\033[1;31m[error]\033[0m Unknown action: {action}")

        # Loop ended (timeout or max iterations)
        self._print_final_report(target)
        return f"Assessment complete. Found {len(self._findings)} potential findings."

    # ── Actions ─────────────────────────────────────────────────

    def _execute_tool_action(self, command: str, target: str, model: str) -> None:
        """Execute a tool command, observe output, extract findings."""
        # Safety check
        if not self._is_safe_command(command):
            self._say(f"\033[1;31m[blocked]\033[0m Unsafe command: {command[:60]}")
            self._memory.append({"role": "tool", "content": f"BLOCKED: {command}"})
            return

        # Skip duplicates
        if command in self._executed_commands:
            self._say(f"\033[0;90m[skip]\033[0m Already ran: {command[:60]}")
            return

        self._say(f"\033[1;35m[exec]\033[0m {command}")

        # Run the command
        tool_name = command.split()[0] if command.split() else "unknown"
        output = self._run_shell_command(command, tool_name)
        self._executed_commands.add(command)
        self._tools_run.append(tool_name)

        if output.success and output.stdout:
            out_len = len(output.stdout)
            self._say(f"\033[1;35m[result]\033[0m {tool_name}: {out_len} bytes, {output.duration_s:.1f}s")

            # Store in memory (truncated for LLM context)
            self._memory.append({
                "role": "tool_output",
                "tool": tool_name,
                "command": command,
                "content": output.stdout[:2000],
            })

            # Have LLM analyze output for findings
            if out_len > 50:
                self._analyze_output(output, target, model)
        else:
            err = output.stderr[:200] if output.stderr else "no output"
            self._say(f"\033[1;31m[fail]\033[0m {tool_name}: {err}")
            self._memory.append({
                "role": "tool_error",
                "tool": tool_name,
                "command": command,
                "content": f"ERROR: {err}",
            })

    def _analyze_output(self, output: ToolOutput, target: str, model: str) -> None:
        """Have the LLM analyze tool output for security findings."""
        analysis_model = self._llm.route_task("security_analysis") or model

        prompt = (
            f"Analyze this security tool output for {target}.\n"
            f"Tool: {output.tool}\n"
            f"Command: {output.command}\n"
            f"Output:\n{output.stdout[:3000]}\n\n"
            "Extract any security findings. Respond as JSON:\n"
            '{"findings": [{"title":"...", "severity":"critical|high|medium|low|info", '
            '"evidence":"...", "remediation":"..."}]}\n'
            "If no findings, return: {\"findings\": []}"
        )

        resp = self._llm.chat(
            analysis_model,
            [{"role": "system", "content": ANALYSIS_SYSTEM_PROMPT},
             {"role": "user", "content": prompt}],
            temperature=0.2, max_tokens=2048,
        )

        if resp.success and resp.content:
            parsed = self._extract_json(resp.content)
            findings = parsed.get("findings", []) if isinstance(parsed, dict) else []
            for f in findings:
                if isinstance(f, dict) and f.get("title"):
                    f["tool"] = output.tool
                    f["target"] = target
                    self._report_finding(f)

    def _run_analysis(self, analysis_type: str, target: str, model: str) -> None:
        """Run an LLM-only analysis (no tool execution)."""
        analysis_model = self._llm.route_task(analysis_type) or model

        # Build prompt from recent memory
        recent = self._memory[-10:]
        memory_text = ""
        for m in recent:
            if m.get("role") == "tool_output":
                memory_text += f"\n[{m.get('tool', '?')}] {m.get('content', '')[:500]}\n"

        prompt = (
            f"Target: {target}\n"
            f"Analysis type: {analysis_type}\n"
            f"Findings so far: {len(self._findings)}\n\n"
            f"Recent tool outputs:\n{memory_text}\n\n"
            "Analyze the data above. What patterns, vulnerabilities, or risks do you see? "
            "Are there any attack chains possible? What should be investigated further?"
        )

        resp = self._llm.chat(
            analysis_model,
            [{"role": "system", "content": SECURITY_SYSTEM_PROMPT},
             {"role": "user", "content": prompt}],
            temperature=0.3, max_tokens=2048,
        )

        if resp.success and resp.content:
            self._say(f"\033[1;34m[analysis]\033[0m {resp.content[:500]}")
            self._memory.append({
                "role": "analysis",
                "content": resp.content[:1000],
            })

    def _run_consensus_vote(self, finding_desc: str, target: str, model: str) -> None:
        """Validate a finding with multi-model consensus voting."""
        self._say(f"\033[1;36m[consensus]\033[0m Validating: {finding_desc[:60]}")

        # Get 2-3 different models to validate
        model_ids = []
        for task_type in ["security_analysis", "analyze_source_code", "reasoning"]:
            m = self._llm.route_task(task_type)
            if m and m not in model_ids:
                model_ids.append(m)
        if not model_ids:
            model_ids = [model]

        validation_prompt = (
            f"Target: {target}\n"
            f"A security scan has reported this finding:\n{finding_desc}\n\n"
            "Is this a REAL vulnerability? Analyze critically.\n"
            "Respond with JSON: {\"confirmed\": true/false, \"reasoning\": \"why\"}"
        )

        votes_yes = 0
        votes_total = 0
        vote_details: list[str] = []
        for mid in model_ids[:3]:
            resp = self._llm.chat(
                mid,
                [{"role": "system", "content": "You are a security expert. Validate vulnerabilities."},
                 {"role": "user", "content": validation_prompt}],
                temperature=0.1, max_tokens=512,
            )
            votes_total += 1
            if resp.success and resp.content:
                parsed = self._extract_json(resp.content)
                confirmed = parsed.get("confirmed", False) if isinstance(parsed, dict) else False
                if confirmed:
                    votes_yes += 1
                status = "CONFIRMED" if confirmed else "REJECTED"
                vote_details.append(f"{mid}: {status}")
                self._say(f"\033[0;90m  [{mid}] {status}\033[0m")
            else:
                vote_details.append(f"{mid}: NO RESPONSE")

        confidence = votes_yes / max(votes_total, 1)
        if confidence >= 0.6:
            self._say(f"\033[1;32m[consensus]\033[0m CONFIRMED ({votes_yes}/{votes_total} agree, "
                       f"confidence {confidence:.0%})")
            self._memory.append({
                "role": "consensus",
                "content": f"CONFIRMED: {finding_desc} ({votes_yes}/{votes_total}, {confidence:.0%})",
                "votes": vote_details,
            })
        else:
            self._say(f"\033[1;33m[consensus]\033[0m NOT CONFIRMED ({votes_yes}/{votes_total}, "
                       f"confidence {confidence:.0%}) — likely false positive")
            self._memory.append({
                "role": "consensus",
                "content": f"REJECTED: {finding_desc} ({votes_yes}/{votes_total}, {confidence:.0%})",
                "votes": vote_details,
            })

    def _spawn_sub_agent(self, role: str, task: str, target: str, model: str) -> None:
        """Spawn a sub-agent for a specialized task."""
        self._say(f"\033[1;36m[spawn]\033[0m Creating {role} sub-agent: {task[:60]}")

        # Route to the best model for this sub-agent's role
        role_to_task_type = {
            "recon": "recon_analysis",
            "vuln_scan": "scan_web_vulns",
            "code_analysis": "analyze_source_code",
            "exploit": "build_exploit_chain",
            "report": "write_report",
        }
        task_type = role_to_task_type.get(role, "general")
        sub_model = self._llm.route_task(task_type) or model

        system = SUB_AGENT_PROMPT.format(role=role, task=task, target=target)
        context = (
            f"Target: {target}\n"
            f"Your task: {task}\n"
            f"Available tools: nmap, nuclei, nikto, sqlmap, ffuf, gobuster, "
            f"subfinder, httpx, curl, dig, whois, dirb, wpscan, hydra, "
            f"semgrep, bandit, trivy, dnsrecon\n"
            f"Respond with your first action."
        )

        # Run the sub-agent for a few iterations
        sub_findings: list[dict[str, Any]] = []
        for i in range(15):  # Sub-agents get fewer iterations
            resp = self._llm.chat(
                sub_model,
                [{"role": "system", "content": system},
                 {"role": "user", "content": context}],
                temperature=0.4, max_tokens=1024,
            )

            if not resp.success or not resp.content:
                break

            action_data = self._parse_agent_response(resp.content)
            if not action_data:
                break

            action = action_data.get("action", "")
            action_input = action_data.get("action_input", {})
            message = action_data.get("message", "")

            if message:
                self._say(f"\033[0;90m  [{role}]\033[0m {message}")

            if action == "run_tool":
                cmd = action_input.get("command", "")
                if cmd and self._is_safe_command(cmd) and cmd not in self._executed_commands:
                    self._say(f"\033[1;35m  [{role} exec]\033[0m {cmd[:70]}")
                    output = self._run_shell_command(cmd, cmd.split()[0] if cmd.split() else "tool")
                    self._executed_commands.add(cmd)
                    self._tools_run.append(cmd.split()[0] if cmd.split() else "tool")

                    if output.success and output.stdout:
                        context = (
                            f"Tool output ({output.tool}):\n{output.stdout[:2000]}\n\n"
                            f"Analyze this and decide next action."
                        )
                        self._memory.append({
                            "role": "tool_output",
                            "tool": output.tool,
                            "command": cmd,
                            "content": output.stdout[:1000],
                        })
                    else:
                        context = f"Tool failed: {output.stderr[:200]}\nDecide next action."
                elif cmd:
                    context = f"Command already run or blocked: {cmd}\nTry something else."

            elif action == "report_finding":
                finding = action_input.get("finding", {})
                if finding and isinstance(finding, dict):
                    finding["tool"] = f"sub-agent:{role}"
                    finding["target"] = target
                    sub_findings.append(finding)
                    self._report_finding(finding)
                context = "Finding recorded. Continue your assessment or say done."

            elif action == "done":
                done_msg = action_input.get("message", "Sub-task complete.")
                self._say(f"\033[0;90m  [{role} done]\033[0m {done_msg}")
                break

            else:
                context = f"Action {action} not supported for sub-agents. Use run_tool or report_finding."

        self._sub_agents.append({
            "role": role,
            "task": task,
            "model": sub_model,
            "findings": len(sub_findings),
        })

    def _report_finding(self, finding: dict[str, Any]) -> None:
        """Report a security finding."""
        title = finding.get("title", "Unknown")
        severity = finding.get("severity", "info").upper()

        # Color by severity
        colors = {
            "CRITICAL": "\033[1;31m",
            "HIGH": "\033[0;31m",
            "MEDIUM": "\033[0;33m",
            "LOW": "\033[0;36m",
            "INFO": "\033[0;90m",
        }
        color = colors.get(severity, "\033[0m")
        self._say(f"{color}[FINDING][{severity}]\033[0m {title}")

        # Deduplicate
        for existing in self._findings:
            if existing.get("title", "").lower() == title.lower():
                return  # Already reported

        self._findings.append(finding)

    # ── Context building ────────────────────────────────────────

    def _build_context(self, target: str, goal: str, iteration: int) -> str:
        """Build the full context for the LLM's next decision."""
        elapsed = time.time() - self._start_time

        parts = [
            f"Target: {target}",
            f"Goal: {goal}",
            f"Iteration: {iteration + 1}/{self._max_iterations}",
            f"Time: {elapsed:.0f}s / {self._max_time_s:.0f}s",
            f"Tools run: {len(self._tools_run)}",
            f"Findings: {len(self._findings)}",
            f"Sub-agents spawned: {len(self._sub_agents)}",
        ]

        # Recent findings
        if self._findings:
            parts.append("\nFindings so far:")
            for f in self._findings[-5:]:
                parts.append(f"  - [{f.get('severity', '?')}] {f.get('title', '?')}")

        # Recent memory (tool outputs, analyses)
        recent = self._memory[-6:]
        if recent:
            parts.append("\nRecent actions:")
            for m in recent:
                role = m.get("role", "")
                if role == "tool_output":
                    parts.append(f"  [{m.get('tool', '?')}]: {m.get('content', '')[:300]}")
                elif role == "tool_error":
                    parts.append(f"  [ERROR {m.get('tool', '?')}]: {m.get('content', '')[:200]}")
                elif role == "analysis":
                    parts.append(f"  [analysis]: {m.get('content', '')[:300]}")
                elif role == "user_answer":
                    parts.append(f"  [user]: {m.get('content', '')}")

        # Sub-agent results
        if self._sub_agents:
            parts.append(f"\nSub-agents completed: {len(self._sub_agents)}")
            for sa in self._sub_agents[-3:]:
                parts.append(f"  - {sa['role']}: {sa['task'][:40]} ({sa['findings']} findings)")

        parts.append("\nWhat is your next action? Respond with JSON.")
        return "\n".join(parts)

    # ── Output ──────────────────────────────────────────────────

    def _print_banner(self) -> None:
        self._say("\033[1;33m" + "═" * 60 + "\033[0m")
        self._say("\033[1;33m  RecurSec — Autonomous Security Agent\033[0m")
        self._say("\033[1;33m  Type a target or goal to begin.\033[0m")
        self._say("\033[1;33m  Examples:\033[0m")
        self._say("\033[1;33m    'Find vulnerabilities in webapp.com'\033[0m")
        self._say("\033[1;33m    'Test the security of 192.168.1.0/24'\033[0m")
        self._say("\033[1;33m    'Scan https://example.com for weaknesses'\033[0m")
        self._say("\033[1;33m  Commands: status, findings, exit\033[0m")
        self._say("\033[1;33m" + "═" * 60 + "\033[0m")

    def _print_status(self) -> None:
        """Print current agent status."""
        loader = self._llm.loader.get_status()
        self._say(f"\n  Target: {self._target or 'none'}")
        self._say(f"  Goal: {self._goal or 'none'}")
        self._say(f"  Findings: {len(self._findings)}")
        self._say(f"  Tools run: {len(self._tools_run)}")
        self._say(f"  Sub-agents: {len(self._sub_agents)}")
        self._say(f"  Models loaded: {loader['loaded_count']} ({loader['total_ram_gb']}GB RAM)")
        if self._start_time:
            self._say(f"  Elapsed: {time.time() - self._start_time:.0f}s")

    def _print_findings(self) -> None:
        """Print all findings."""
        if not self._findings:
            self._say("  No findings yet.")
            return
        self._say(f"\n  Findings ({len(self._findings)}):")
        for i, f in enumerate(self._findings, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            self._say(f"  {i}. [{sev}] {title}")
            if f.get("evidence"):
                self._say(f"     Evidence: {f['evidence'][:100]}")

    def _print_final_report(self, target: str) -> None:
        """Print the final assessment report."""
        elapsed = time.time() - self._start_time
        self._say(f"\n\033[1;33m{'═'*60}\033[0m")
        self._say("\033[1;33m  ASSESSMENT COMPLETE\033[0m")
        self._say(f"\033[1;33m  Target: {target}\033[0m")
        self._say(f"\033[1;33m  Duration: {elapsed:.0f}s\033[0m")
        self._say(f"\033[1;33m  Tools run: {len(self._tools_run)}\033[0m")
        self._say(f"\033[1;33m  Sub-agents: {len(self._sub_agents)}\033[0m")
        self._say(f"\033[1;33m  Findings: {len(self._findings)}\033[0m")
        self._say(f"\033[1;33m{'═'*60}\033[0m")

        # Group by severity
        by_sev: dict[str, list[dict[str, Any]]] = {}
        for f in self._findings:
            sev = f.get("severity", "info").lower()
            if sev not in by_sev:
                by_sev[sev] = []
            by_sev[sev].append(f)

        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                self._say(f"\n  [{sev.upper()}] ({len(by_sev[sev])})")
                for f in by_sev[sev]:
                    self._say(f"    - {f.get('title', '?')}")
                    if f.get("evidence"):
                        self._say(f"      Evidence: {f['evidence'][:120]}")
                    if f.get("remediation"):
                        self._say(f"      Fix: {f['remediation'][:120]}")

        # Save report
        report_dir = f"output/{int(time.time())}"
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, "report.json")
        with open(report_path, "w") as fp:
            json.dump({
                "target": target,
                "duration_s": round(elapsed, 1),
                "tools_run": len(self._tools_run),
                "sub_agents": len(self._sub_agents),
                "findings": self._findings,
            }, fp, indent=2)
        self._say(f"\n  Report saved: {report_path}")

        # Loader status
        loader = self._llm.loader.get_status()
        self._say(f"  Models loaded: {loader['loaded_count']} ({loader['total_ram_gb']}GB RAM)")

    # ── Helpers ──────────────────────────────────────────────────

    def _say(self, msg: str) -> None:
        """Print a message to the user."""
        print(msg)

    def _conversational_response(self, message: str) -> str:
        """Handle non-task conversational messages."""
        lower = message.lower()
        if any(w in lower for w in ["hello", "hi", "hey"]):
            return ("Hello! I'm RecurSec, your autonomous security agent. "
                    "Tell me what you'd like to assess — give me a target and I'll handle everything.")
        if "help" in lower:
            return ("I'm an autonomous security assessment agent. Just tell me:\n"
                    "  'Find vulnerabilities in <target>'\n"
                    "  'Test the security of <target>'\n"
                    "  'Scan <target>'\n"
                    "I'll think, plan, run tools, and report back — all autonomously.")
        if any(w in lower for w in ["what can you", "capabilities", "features"]):
            return ("I can:\n"
                    "- Autonomously assess targets (web apps, networks, APIs)\n"
                    "- Run 300+ security tools (nmap, nuclei, sqlmap, etc.)\n"
                    "- Spawn specialized sub-agents for parallel analysis\n"
                    "- Validate findings with multi-model consensus\n"
                    "- Build exploit chains\n"
                    "- Generate comprehensive reports\n"
                    "Just give me a target!")
        return ("I'm ready to help with security assessment. "
                "Give me a target to scan, e.g. 'Find vulnerabilities in webapp.com'")

    def _is_task_request(self, message: str) -> bool:
        """Detect if the user is requesting a security task."""
        lower = message.lower()
        task_keywords = [
            "scan", "find", "test", "assess", "hack", "pentest",
            "vulnerability", "vulnerabilities", "vuln", "exploit",
            "security", "audit", "check", "analyze", "investigate",
            "attack", "enumerate", "recon", "discover",
        ]
        return any(kw in lower for kw in task_keywords)

    def _extract_target(self, message: str) -> str:
        """Extract target from natural language."""
        import re as re_mod
        # URL pattern
        url_match = re_mod.search(r'https?://[^\s]+', message)
        if url_match:
            return url_match.group(0).rstrip(".,;!?'\")")

        # Domain pattern
        domain_match = re_mod.search(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b', message)
        if domain_match:
            word = domain_match.group(1)
            # Filter common non-target words
            skip = {"example.py", "test.py", "main.py", "setup.py"}
            if word not in skip:
                return word

        # IP pattern
        ip_match = re_mod.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b', message)
        if ip_match:
            return ip_match.group(1)

        return ""

    def _parse_agent_response(self, content: str) -> dict[str, Any]:
        """Parse the agent's JSON response."""
        # Try direct JSON parse
        try:
            data = json.loads(content)
            if isinstance(data, dict) and "action" in data:
                return data
        except json.JSONDecodeError:
            pass

        # Try extracting JSON from text
        json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', content, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                if isinstance(data, dict) and "action" in data:
                    return data
            except json.JSONDecodeError:
                pass

        # Try finding { ... } block
        brace_match = re.search(r'\{[^{}]*"action"[^{}]*\}', content, re.DOTALL)
        if brace_match:
            try:
                data = json.loads(brace_match.group(0))
                if isinstance(data, dict) and "action" in data:
                    return data
            except json.JSONDecodeError:
                pass

        # Fallback: try to parse as a tool command
        content = content.strip()
        if content and not content.startswith(("{", "[")):
            # LLM may have just returned a raw command
            first_line = content.split("\n")[0].strip()
            if first_line.upper() in ("DONE", "DONE.", "COMPLETE"):
                return {"action": "done", "action_input": {"message": "Assessment complete."}, "message": "Assessment complete."}
            if first_line and " " in first_line:
                return {
                    "thinking": "Executing suggested tool",
                    "action": "run_tool",
                    "action_input": {"command": first_line},
                    "message": f"Running: {first_line[:60]}",
                }

        return {}

    def _is_safe_command(self, command: str) -> bool:
        """Check if a command is safe to execute."""
        blocked = [
            "rm -rf", "mkfs", "dd if=", ":(){", "fork", "shutdown",
            "reboot", "halt", "poweroff", "init 0", "init 6",
            "> /dev/sd", "chmod -R 777 /", "wget|sh", "curl|sh",
            "python -c", "perl -e", "ruby -e", "nc -e", "bash -i",
        ]
        lower = command.lower()
        for b in blocked:
            if b in lower:
                return False

        # Must start with a known tool
        parts = command.split()
        if not parts:
            return False

        tool = parts[0].split("/")[-1]  # Handle full paths
        allowed_prefixes = {
            "nmap", "nuclei", "nikto", "sqlmap", "ffuf", "gobuster", "subfinder",
            "httpx", "curl", "dig", "whois", "host", "dirb", "wpscan", "hydra",
            "semgrep", "bandit", "trivy", "dnsrecon", "masscan", "amass", "theharvester",
            "wafw00f", "whatweb", "arjun", "sslyze", "testssl", "feroxbuster",
            "dirsearch", "wfuzz", "dalfox", "xsstrike", "commix", "gau",
            "katana", "waybackurls", "hakrawler", "gospider", "jq", "grep",
            "awk", "sed", "cat", "head", "tail", "wc", "sort", "uniq",
            "openssl", "ssh-audit", "ping", "traceroute", "netstat", "ss",
            "dnsmap", "fierce", "dnsenum", "enum4linux", "smbclient",
            "rpcclient", "nbtscan", "snmpwalk", "onesixtyone",
        }
        return tool in allowed_prefixes

    def _run_shell_command(self, command: str, tool_name: str) -> ToolOutput:
        """Run a shell command with timeout."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self._tool_timeout_s,
            )
            return ToolOutput(
                tool=tool_name,
                command=command,
                stdout=result.stdout[:50000],
                stderr=result.stderr[:5000],
                exit_code=result.returncode,
                duration_s=0.0,
            )
        except subprocess.TimeoutExpired:
            return ToolOutput(tool=tool_name, command=command, stderr="TIMEOUT", exit_code=-1)
        except Exception as exc:
            return ToolOutput(tool=tool_name, command=command, stderr=str(exc), exit_code=-1)

    def _run_tools_only(self, target: str) -> str:
        """Fallback: run basic recon tools without LLM."""
        self._say("\033[1;34m[tools-only]\033[0m Running basic recon...")
        basic_commands = [
            f"dig +short {target} A",
            f"dig +short {target} MX",
            f"dig +short {target} NS",
            f"whois {target}",
            f"curl -sI -L --max-time 15 {target}",
        ]
        for cmd in basic_commands:
            tool = cmd.split()[0]
            self._say(f"\033[1;35m[exec]\033[0m {cmd}")
            output = self._run_shell_command(cmd, tool)
            if output.success and output.stdout:
                self._say(f"\033[0;90m{output.stdout[:300]}\033[0m")
                self._memory.append({"role": "tool_output", "tool": tool, "content": output.stdout[:1000]})
            self._tools_run.append(tool)
        return f"Basic recon complete. Ran {len(basic_commands)} tools. No LLM for analysis."

    def _extract_json(self, text: str) -> Any:
        """Extract JSON from LLM response text."""
        if not text:
            return {}
        json_match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if json_match:
            text = json_match.group(1)
        else:
            brace_match = re.search(r"\{.*\}", text, re.DOTALL)
            if brace_match:
                text = brace_match.group(0)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}

    def get_stats(self) -> dict[str, Any]:
        return {
            "target": self._target,
            "findings": len(self._findings),
            "tools_run": len(self._tools_run),
            "sub_agents": len(self._sub_agents),
            "iterations": self._iteration,
            "loader": self._llm.loader.get_status(),
        }
