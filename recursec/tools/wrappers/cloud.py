"""Cloud security tool wrappers — AWS, GCP, Azure testing.

Integrates:
- ScoutSuite (multi-cloud audit)
- Prowler (AWS security)
- CloudMapper (AWS visualization)
- enumerate-iam (AWS IAM enumeration)
- Pacu (AWS exploitation)
- S3Scanner (S3 bucket discovery)
- CloudBrute (cloud enumeration)
"""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

import structlog

from recursec.core.models import ToolResult

logger = structlog.get_logger()


async def _run(cmd: list[str], timeout: float = 600.0, env: dict[str, str] | None = None) -> ToolResult:
    tool_name = cmd[0] if cmd else "unknown"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
        stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
        return ToolResult(
            tool_name=tool_name, command=" ".join(cmd),
            stdout=stdout, stderr=stderr,
            return_code=proc.returncode or 0, parsed_data={},
        )
    except asyncio.TimeoutError:
        return ToolResult(tool_name=tool_name, command=" ".join(cmd),
                          stdout="", stderr="Timed out", return_code=1, parsed_data={})
    except FileNotFoundError:
        return ToolResult(tool_name=tool_name, command=" ".join(cmd),
                          stdout="", stderr=f"{tool_name} not found", return_code=127, parsed_data={})


class ScoutSuiteWrapper:
    """Wrapper for ScoutSuite multi-cloud security auditing."""

    def __init__(self) -> None:
        self.available = shutil.which("scout") is not None

    async def audit_aws(self, profile: str = "", regions: list[str] | None = None) -> ToolResult:
        """Run ScoutSuite AWS audit."""
        cmd = ["scout", "aws", "--force", "--no-browser"]
        if profile:
            cmd.extend(["--profile", profile])
        if regions:
            cmd.extend(["--regions"] + regions)
        result = await _run(cmd, timeout=1800.0)
        result.parsed_data = self._parse_scoutsuite_report()
        return result

    async def audit_gcp(self, project_id: str = "") -> ToolResult:
        """Run ScoutSuite GCP audit."""
        cmd = ["scout", "gcp", "--force", "--no-browser"]
        if project_id:
            cmd.extend(["--project-id", project_id])
        return await _run(cmd, timeout=1800.0)

    async def audit_azure(self) -> ToolResult:
        """Run ScoutSuite Azure audit."""
        cmd = ["scout", "azure", "--force", "--no-browser"]
        return await _run(cmd, timeout=1800.0)

    def _parse_scoutsuite_report(self) -> dict[str, Any]:
        """Parse ScoutSuite JSON report."""
        import glob
        import os
        report_files = glob.glob(os.path.expanduser("~/.local/share/scoutsuite-report/*.json"))
        if not report_files:
            return {}
        latest = max(report_files, key=os.path.getmtime)
        try:
            with open(latest) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}


class ProwlerWrapper:
    """Wrapper for Prowler AWS security assessment."""

    def __init__(self) -> None:
        self.available = shutil.which("prowler") is not None

    async def audit(
        self,
        provider: str = "aws",
        checks: list[str] | None = None,
        severity: str = "",
        profile: str = "",
    ) -> ToolResult:
        """Run Prowler security audit."""
        cmd = ["prowler", provider, "--output-formats", "json"]
        if checks:
            cmd.extend(["--checks"] + checks)
        if severity:
            cmd.extend(["--severity", severity])
        if profile:
            cmd.extend(["--profile", profile])

        result = await _run(cmd, timeout=3600.0)
        result.parsed_data = self._parse_output(result.stdout)
        return result

    async def list_checks(self, provider: str = "aws") -> ToolResult:
        """List available Prowler checks."""
        cmd = ["prowler", provider, "--list-checks"]
        return await _run(cmd, timeout=60.0)

    def _parse_output(self, output: str) -> dict[str, Any]:
        """Parse Prowler JSON output."""
        findings = []
        for line in output.splitlines():
            try:
                finding = json.loads(line)
                findings.append(finding)
            except json.JSONDecodeError:
                pass
        return {
            "findings": findings,
            "total": len(findings),
            "by_severity": self._count_severities(findings),
        }

    def _count_severities(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("Severity", f.get("severity", "unknown"))
            counts[sev] = counts.get(sev, 0) + 1
        return counts


class S3ScannerWrapper:
    """Wrapper for S3 bucket discovery and testing."""

    def __init__(self) -> None:
        self.available = shutil.which("s3scanner") is not None

    async def scan_bucket(self, bucket_name: str) -> ToolResult:
        """Scan a specific S3 bucket."""
        cmd = ["s3scanner", "scan", "--bucket", bucket_name]
        result = await _run(cmd)
        result.parsed_data = self._parse_output(result.stdout)
        return result

    async def scan_list(self, wordlist: str) -> ToolResult:
        """Scan multiple buckets from wordlist."""
        cmd = ["s3scanner", "scan", "--buckets-file", wordlist]
        result = await _run(cmd, timeout=600.0)
        result.parsed_data = self._parse_output(result.stdout)
        return result

    def _parse_output(self, output: str) -> dict[str, Any]:
        """Parse S3Scanner output."""
        buckets = []
        for line in output.splitlines():
            if "exists" in line.lower() or "open" in line.lower():
                buckets.append({
                    "bucket": line.split()[0] if line.split() else "",
                    "status": "accessible" if "open" in line.lower() else "exists",
                    "raw": line.strip(),
                })
        return {"buckets": buckets, "found": len(buckets)}


class EnumerateIAMWrapper:
    """Wrapper for AWS IAM enumeration."""

    def __init__(self) -> None:
        self.available = shutil.which("enumerate-iam") is not None or shutil.which("enumerate-iam.py") is not None
        self._cmd = "enumerate-iam" if shutil.which("enumerate-iam") else "enumerate-iam.py"

    async def enumerate(self, access_key: str, secret_key: str, region: str = "us-east-1") -> ToolResult:
        """Enumerate IAM permissions for given credentials."""
        import os
        env = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": access_key,
            "AWS_SECRET_ACCESS_KEY": secret_key,
            "AWS_DEFAULT_REGION": region,
        }
        cmd = [self._cmd]
        result = await _run(cmd, timeout=300.0, env=env)
        result.parsed_data = self._parse_permissions(result.stdout)
        return result

    def _parse_permissions(self, output: str) -> dict[str, Any]:
        """Parse enumerated permissions."""
        permissions: list[str] = []
        for line in output.splitlines():
            if line.strip().startswith("--"):
                continue
            if "." in line and "::" not in line:
                permissions.append(line.strip())
        return {"permissions": permissions, "count": len(permissions)}


class CloudBruteWrapper:
    """Wrapper for CloudBrute multi-cloud enumeration."""

    def __init__(self) -> None:
        self.available = shutil.which("cloudbrute") is not None

    async def enumerate(self, domain: str, wordlist: str = "", providers: str = "aws,gcp,azure") -> ToolResult:
        """Enumerate cloud resources for a domain."""
        cmd = ["cloudbrute", "-d", domain, "-k", domain.split(".")[0]]
        if wordlist:
            cmd.extend(["-w", wordlist])
        result = await _run(cmd, timeout=600.0)
        result.parsed_data = self._parse_output(result.stdout)
        return result

    def _parse_output(self, output: str) -> dict[str, Any]:
        """Parse CloudBrute output."""
        resources: list[dict[str, str]] = []
        for line in output.splitlines():
            if line.strip() and not line.startswith("["):
                parts = line.strip().split()
                if len(parts) >= 2:
                    resources.append({
                        "provider": parts[0],
                        "resource": parts[1] if len(parts) > 1 else "",
                        "url": parts[2] if len(parts) > 2 else "",
                    })
        return {"resources": resources, "count": len(resources)}


class AWSEnumerator:
    """AWS resource enumeration using AWS CLI."""

    def __init__(self) -> None:
        self.available = shutil.which("aws") is not None

    async def list_s3_buckets(self) -> ToolResult:
        """List S3 buckets."""
        cmd = ["aws", "s3api", "list-buckets", "--output", "json"]
        result = await _run(cmd)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def list_ec2_instances(self, region: str = "") -> ToolResult:
        """List EC2 instances."""
        cmd = ["aws", "ec2", "describe-instances", "--output", "json"]
        if region:
            cmd.extend(["--region", region])
        result = await _run(cmd)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def list_iam_users(self) -> ToolResult:
        """List IAM users."""
        cmd = ["aws", "iam", "list-users", "--output", "json"]
        result = await _run(cmd)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def list_security_groups(self, region: str = "") -> ToolResult:
        """List security groups."""
        cmd = ["aws", "ec2", "describe-security-groups", "--output", "json"]
        if region:
            cmd.extend(["--region", region])
        result = await _run(cmd)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def check_public_access_block(self, bucket: str) -> ToolResult:
        """Check S3 bucket public access block."""
        cmd = ["aws", "s3api", "get-public-access-block", "--bucket", bucket, "--output", "json"]
        result = await _run(cmd)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result
