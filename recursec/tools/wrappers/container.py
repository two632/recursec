"""Container and Kubernetes security tool wrappers.

Integrates:
- Trivy (container/IaC scanning)
- Grype (vulnerability scanning)
- Syft (SBOM generation)
- kube-bench (CIS benchmarks)
- kube-hunter (Kubernetes pentesting)
- Falco (runtime security)
- Docker Bench Security
"""

from __future__ import annotations

import asyncio
import json
import shutil

import structlog

from recursec.core.models import ToolResult

logger = structlog.get_logger()


async def _run(cmd: list[str], timeout: float = 300.0) -> ToolResult:
    tool_name = cmd[0] if cmd else "unknown"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
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


class TrivyWrapper:
    """Wrapper for Trivy vulnerability scanner."""

    def __init__(self) -> None:
        self.available = shutil.which("trivy") is not None

    async def scan_image(self, image: str, severity: str = "CRITICAL,HIGH") -> ToolResult:
        """Scan container image for vulnerabilities."""
        cmd = [
            "trivy", "image", "--format", "json",
            "--severity", severity,
            image,
        ]
        result = await _run(cmd, timeout=600.0)
        if result.return_code == 0 and result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def scan_filesystem(self, path: str, severity: str = "CRITICAL,HIGH") -> ToolResult:
        """Scan filesystem for vulnerabilities."""
        cmd = [
            "trivy", "fs", "--format", "json",
            "--severity", severity,
            path,
        ]
        result = await _run(cmd, timeout=600.0)
        if result.return_code == 0 and result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def scan_config(self, path: str) -> ToolResult:
        """Scan IaC/config files for misconfigurations."""
        cmd = ["trivy", "config", "--format", "json", path]
        result = await _run(cmd, timeout=300.0)
        if result.return_code == 0 and result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def generate_sbom(self, image: str) -> ToolResult:
        """Generate Software Bill of Materials."""
        cmd = ["trivy", "image", "--format", "cyclonedx", image]
        return await _run(cmd, timeout=600.0)


class GrypeWrapper:
    """Wrapper for Grype vulnerability scanner."""

    def __init__(self) -> None:
        self.available = shutil.which("grype") is not None

    async def scan(self, target: str, severity: str = "critical,high") -> ToolResult:
        """Scan target (image, directory, SBOM) for vulnerabilities."""
        cmd = ["grype", target, "-o", "json", "--fail-on", severity]
        result = await _run(cmd, timeout=600.0)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def scan_sbom(self, sbom_path: str) -> ToolResult:
        """Scan SBOM for vulnerabilities."""
        cmd = ["grype", f"sbom:{sbom_path}", "-o", "json"]
        result = await _run(cmd, timeout=300.0)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result


class SyftWrapper:
    """Wrapper for Syft SBOM generator."""

    def __init__(self) -> None:
        self.available = shutil.which("syft") is not None

    async def generate_sbom(self, target: str, output_format: str = "json") -> ToolResult:
        """Generate SBOM for target."""
        cmd = ["syft", target, "-o", output_format]
        result = await _run(cmd, timeout=600.0)
        if output_format == "json" and result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result


class KubeBenchWrapper:
    """Wrapper for kube-bench CIS benchmark testing."""

    def __init__(self) -> None:
        self.available = shutil.which("kube-bench") is not None

    async def run(self, target: str = "") -> ToolResult:
        """Run CIS Kubernetes benchmark."""
        cmd = ["kube-bench", "--json"]
        if target:
            cmd.extend(["--targets", target])
        result = await _run(cmd, timeout=600.0)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def run_node(self) -> ToolResult:
        """Run node-specific benchmarks."""
        return await self.run(target="node")

    async def run_master(self) -> ToolResult:
        """Run master-specific benchmarks."""
        return await self.run(target="master")


class KubeHunterWrapper:
    """Wrapper for kube-hunter Kubernetes pentesting."""

    def __init__(self) -> None:
        self.available = shutil.which("kube-hunter") is not None

    async def scan_remote(self, target: str) -> ToolResult:
        """Scan remote Kubernetes cluster."""
        cmd = ["kube-hunter", "--remote", target, "--report", "json"]
        result = await _run(cmd, timeout=600.0)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def scan_internal(self) -> ToolResult:
        """Scan from within the cluster."""
        cmd = ["kube-hunter", "--internal", "--report", "json"]
        result = await _run(cmd, timeout=600.0)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result

    async def scan_cidr(self, cidr: str) -> ToolResult:
        """Scan CIDR range for Kubernetes clusters."""
        cmd = ["kube-hunter", "--cidr", cidr, "--report", "json"]
        result = await _run(cmd, timeout=600.0)
        if result.stdout:
            try:
                result.parsed_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return result


class DockerBenchWrapper:
    """Wrapper for Docker Bench for Security."""

    def __init__(self) -> None:
        self.available = shutil.which("docker-bench-security") is not None

    async def run(self) -> ToolResult:
        """Run Docker Bench for Security."""
        cmd = ["docker-bench-security", "-l", "/tmp/docker-bench.log"]
        result = await _run(cmd, timeout=600.0)

        # Parse output for findings
        warnings = []
        passes = []
        for line in result.stdout.splitlines():
            if "[WARN]" in line:
                warnings.append(line.strip())
            elif "[PASS]" in line:
                passes.append(line.strip())

        result.parsed_data = {
            "warnings": warnings,
            "passes": passes,
            "warn_count": len(warnings),
            "pass_count": len(passes),
        }
        return result


class FalcoWrapper:
    """Wrapper for Falco runtime security."""

    def __init__(self) -> None:
        self.available = shutil.which("falco") is not None

    async def run_rules(self, rules_path: str, duration: int = 60) -> ToolResult:
        """Run Falco with custom rules for specified duration."""
        cmd = ["falco", "-r", rules_path, "-o", "json_output=true"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.sleep(duration)
            proc.terminate()
            stdout_bytes, stderr_bytes = await proc.communicate()
            stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""

            alerts = []
            for line in stdout.splitlines():
                try:
                    alert = json.loads(line)
                    alerts.append(alert)
                except json.JSONDecodeError:
                    pass

            return ToolResult(
                tool_name="falco", command=" ".join(cmd),
                stdout=stdout, stderr=stderr,
                return_code=proc.returncode or 0,
                parsed_data={"alerts": alerts, "count": len(alerts)},
            )
        except (FileNotFoundError, asyncio.TimeoutError) as e:
            return ToolResult(
                tool_name="falco", command=" ".join(cmd),
                stdout="", stderr=str(e), return_code=1, parsed_data={},
            )
