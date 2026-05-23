"""Code analysis tool wrappers — semgrep, bandit, trivy, grype, snyk, trufflehog.

Static analysis and dependency auditing tools for source code review
and supply chain security.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from recursec.core.models import ToolResult
from recursec.tools.parsers import parse_semgrep, parse_bandit, parse_trivy


async def _run_command(cmd: list[str], timeout: float = 300.0, cwd: str = "") -> tuple[str, str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd or None,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            stdout.decode(errors="replace") if stdout else "",
            stderr.decode(errors="replace") if stderr else "",
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return "", "Command timed out", 1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127


def _check_tool(name: str) -> bool:
    return shutil.which(name) is not None


# ── Semgrep ────────────────────────────────────────────────

class SemgrepWrapper:
    """Wrapper for semgrep — code scanning with custom rules."""

    @staticmethod
    async def scan(
        target_dir: str,
        config: str = "auto",
        severity: list[str] | None = None,
        lang: str = "",
        exclude: list[str] | None = None,
        timeout: float = 600.0,
    ) -> ToolResult:
        if not _check_tool("semgrep"):
            return ToolResult(tool_name="semgrep", command="semgrep", stderr="semgrep not installed", exit_code=127)

        cmd = ["semgrep", "--json", "--config", config]
        if severity:
            for s in severity:
                cmd.extend(["--severity", s.upper()])
        if lang:
            cmd.extend(["--lang", lang])
        if exclude:
            for e in exclude:
                cmd.extend(["--exclude", e])
        cmd.append(target_dir)

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_semgrep(stdout) if stdout else {}

        return ToolResult(
            tool_name="semgrep", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )

    @staticmethod
    async def scan_with_rules(
        target_dir: str,
        rules_file: str,
        timeout: float = 600.0,
    ) -> ToolResult:
        if not _check_tool("semgrep"):
            return ToolResult(tool_name="semgrep", command="semgrep", stderr="semgrep not installed", exit_code=127)

        cmd = ["semgrep", "--json", "--config", rules_file, target_dir]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_semgrep(stdout) if stdout else {}

        return ToolResult(
            tool_name="semgrep", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── Bandit ─────────────────────────────────────────────────

class BanditWrapper:
    """Wrapper for bandit — Python security linter."""

    @staticmethod
    async def scan(
        target_dir: str,
        severity: str = "",
        confidence: str = "",
        recursive: bool = True,
        timeout: float = 120.0,
    ) -> ToolResult:
        if not _check_tool("bandit"):
            return ToolResult(tool_name="bandit", command="bandit", stderr="bandit not installed", exit_code=127)

        cmd = ["bandit", "-f", "json"]
        if recursive:
            cmd.append("-r")
        if severity:
            cmd.extend(["-ll" if severity == "medium" else "-lll" if severity == "high" else "-l"])
        if confidence:
            cmd.extend(["-ii" if confidence == "medium" else "-iii" if confidence == "high" else "-i"])
        cmd.append(target_dir)

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_bandit(stdout) if stdout else {}

        return ToolResult(
            tool_name="bandit", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── Trivy ──────────────────────────────────────────────────

class TrivyWrapper:
    """Wrapper for trivy — vulnerability scanner for containers, filesystems, repos."""

    @staticmethod
    async def scan_fs(
        target_dir: str,
        severity: str = "CRITICAL,HIGH,MEDIUM",
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("trivy"):
            return ToolResult(tool_name="trivy", command="trivy", stderr="trivy not installed", exit_code=127)

        cmd = ["trivy", "fs", "--format", "json", "--severity", severity, target_dir]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_trivy(stdout) if stdout else {}

        return ToolResult(
            tool_name="trivy", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )

    @staticmethod
    async def scan_image(
        image: str,
        severity: str = "CRITICAL,HIGH,MEDIUM",
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("trivy"):
            return ToolResult(tool_name="trivy", command="trivy", stderr="trivy not installed", exit_code=127)

        cmd = ["trivy", "image", "--format", "json", "--severity", severity, image]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_trivy(stdout) if stdout else {}

        return ToolResult(
            tool_name="trivy", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )

    @staticmethod
    async def scan_repo(
        repo_url: str,
        severity: str = "CRITICAL,HIGH,MEDIUM",
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("trivy"):
            return ToolResult(tool_name="trivy", command="trivy", stderr="trivy not installed", exit_code=127)

        cmd = ["trivy", "repo", "--format", "json", "--severity", severity, repo_url]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_trivy(stdout) if stdout else {}

        return ToolResult(
            tool_name="trivy", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── Grype ──────────────────────────────────────────────────

class GrypeWrapper:
    """Wrapper for grype — vulnerability scanner for SBOMs and container images."""

    @staticmethod
    async def scan(
        target: str,
        severity: str = "",
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("grype"):
            return ToolResult(tool_name="grype", command="grype", stderr="grype not installed", exit_code=127)

        cmd = ["grype", target, "-o", "json"]
        if severity:
            cmd.extend(["--fail-on", severity.lower()])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        parsed: dict[str, Any] = {}
        if stdout:
            try:
                data = json.loads(stdout)
                matches = data.get("matches", [])
                parsed = {
                    "vulnerabilities": [
                        {
                            "id": m.get("vulnerability", {}).get("id", ""),
                            "severity": m.get("vulnerability", {}).get("severity", ""),
                            "package": m.get("artifact", {}).get("name", ""),
                            "version": m.get("artifact", {}).get("version", ""),
                            "fix_version": ", ".join(m.get("vulnerability", {}).get("fix", {}).get("versions", [])),
                            "description": m.get("vulnerability", {}).get("description", "")[:200],
                        }
                        for m in matches
                    ],
                    "total": len(matches),
                }
            except json.JSONDecodeError:
                pass

        return ToolResult(
            tool_name="grype", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── TruffleHog ─────────────────────────────────────────────

class TrufflehogWrapper:
    """Wrapper for trufflehog — secret detection in code."""

    @staticmethod
    async def scan_directory(
        target_dir: str,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("trufflehog"):
            return ToolResult(tool_name="trufflehog", command="trufflehog", stderr="trufflehog not installed", exit_code=127)

        cmd = ["trufflehog", "filesystem", "--json", target_dir]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        secrets = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        secrets.append({
                            "detector": data.get("DetectorType", ""),
                            "verified": data.get("Verified", False),
                            "source": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                            "redacted": data.get("Redacted", ""),
                        })
                    except json.JSONDecodeError:
                        pass

        return ToolResult(
            tool_name="trufflehog", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"secrets": secrets, "total": len(secrets)},
        )

    @staticmethod
    async def scan_git(
        repo_url: str,
        timeout: float = 600.0,
    ) -> ToolResult:
        if not _check_tool("trufflehog"):
            return ToolResult(tool_name="trufflehog", command="trufflehog", stderr="trufflehog not installed", exit_code=127)

        cmd = ["trufflehog", "git", "--json", repo_url]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        secrets = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        secrets.append({
                            "detector": data.get("DetectorType", ""),
                            "verified": data.get("Verified", False),
                            "commit": data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit", ""),
                            "file": data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
                        })
                    except json.JSONDecodeError:
                        pass

        return ToolResult(
            tool_name="trufflehog", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"secrets": secrets, "total": len(secrets)},
        )


# ── Gitleaks ──────────────────────────────────────────────

class GitleaksWrapper:
    """Wrapper for gitleaks — Git repo secret scanner."""

    @staticmethod
    async def detect(
        target: str,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("gitleaks"):
            return ToolResult(tool_name="gitleaks", command="gitleaks", stderr="gitleaks not installed", exit_code=127)

        report = tempfile.mktemp(suffix=".json")
        cmd = ["gitleaks", "detect", "--source", target, "--report-format", "json", "--report-path", report]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        findings = []
        report_path = Path(report)
        if report_path.exists():
            try:
                data = json.loads(report_path.read_text())
                if isinstance(data, list):
                    findings = [
                        {
                            "rule": f.get("RuleID", ""),
                            "match": f.get("Match", "")[:100],
                            "file": f.get("File", ""),
                            "line": f.get("StartLine", 0),
                            "commit": f.get("Commit", "")[:8],
                        }
                        for f in data
                    ]
            except json.JSONDecodeError:
                pass
            report_path.unlink(missing_ok=True)

        return ToolResult(
            tool_name="gitleaks", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"findings": findings, "total": len(findings)},
        )
