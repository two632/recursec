"""Network tool wrappers — nmap, masscan, netcat, hping3, tcpdump, arp-scan.

Each wrapper:
1. Builds the CLI command from structured parameters
2. Executes with timeout and resource limits
3. Parses output into structured data
4. Returns ToolResult for agent consumption
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

from recursec.core.models import ToolResult
from recursec.tools.parsers import parse_nmap, parse_masscan


async def _run_command(cmd: list[str], timeout: float = 300.0) -> tuple[str, str, int]:
    """Run a shell command and return (stdout, stderr, returncode)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
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
    """Check if a tool is installed."""
    return shutil.which(name) is not None


# ── Nmap ───────────────────────────────────────────────────

class NmapWrapper:
    """Wrapper for nmap — the network mapper."""

    @staticmethod
    async def scan(
        target: str,
        ports: str = "",
        scan_type: str = "default",
        scripts: list[str] | None = None,
        timing: int = 3,
        os_detection: bool = False,
        service_version: bool = True,
        top_ports: int | None = None,
        output_format: str = "xml",
        extra_args: list[str] | None = None,
        timeout: float = 600.0,
    ) -> ToolResult:
        """Run an nmap scan."""
        if not _check_tool("nmap"):
            return ToolResult(tool_name="nmap", command="nmap", stderr="nmap not installed", exit_code=127)

        cmd = ["nmap"]

        # Scan type
        scan_types = {
            "default": [],
            "syn": ["-sS"],
            "connect": ["-sT"],
            "udp": ["-sU"],
            "ack": ["-sA"],
            "window": ["-sW"],
            "null": ["-sN"],
            "fin": ["-sF"],
            "xmas": ["-sX"],
            "ping": ["-sn"],
            "version": ["-sV"],
            "aggressive": ["-A"],
            "vuln": ["--script", "vuln"],
        }
        cmd.extend(scan_types.get(scan_type, []))

        # Ports
        if ports:
            cmd.extend(["-p", ports])
        elif top_ports:
            cmd.extend(["--top-ports", str(top_ports)])

        # Timing
        cmd.append(f"-T{timing}")

        # Service version detection
        if service_version and scan_type not in ("version", "aggressive"):
            cmd.append("-sV")

        # OS detection
        if os_detection:
            cmd.append("-O")

        # Scripts
        if scripts:
            cmd.extend(["--script", ",".join(scripts)])

        # Output
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        cmd.extend(["-oX", xml_path])

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        cmd.append(target)

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        # Parse XML output
        parsed = {}
        try:
            xml_content = Path(xml_path).read_text()
            parsed = parse_nmap(xml_content, is_xml=True)
        except Exception:
            if stdout:
                parsed = parse_nmap(stdout)
        finally:
            Path(xml_path).unlink(missing_ok=True)

        return ToolResult(
            tool_name="nmap",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            parsed_data=parsed,
        )


# ── Masscan ────────────────────────────────────────────────

class MasscanWrapper:
    """Wrapper for masscan — ultra-fast port scanner."""

    @staticmethod
    async def scan(
        target: str,
        ports: str = "0-65535",
        rate: int = 10000,
        banner: bool = False,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("masscan"):
            return ToolResult(tool_name="masscan", command="masscan", stderr="masscan not installed", exit_code=127)

        cmd = ["masscan", target, "-p", ports, "--rate", str(rate)]
        if banner:
            cmd.append("--banners")
        cmd.extend(["--open", "-oJ", "-"])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_masscan(stdout) if stdout else {}

        return ToolResult(
            tool_name="masscan",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            parsed_data=parsed,
        )


# ── Netcat ─────────────────────────────────────────────────

class NetcatWrapper:
    """Wrapper for netcat/ncat — TCP/UDP swiss army knife."""

    @staticmethod
    async def banner_grab(
        host: str,
        port: int,
        timeout: float = 5.0,
        send_data: str = "",
    ) -> ToolResult:
        nc = "ncat" if _check_tool("ncat") else "nc"
        if not _check_tool(nc):
            return ToolResult(tool_name="netcat", command=nc, stderr="netcat not installed", exit_code=127)

        cmd = [nc, "-w", str(int(timeout)), host, str(port)]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdin_data = send_data.encode() if send_data else b"\r\n"
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(stdin_data), timeout=timeout + 2
            )
            return ToolResult(
                tool_name="netcat",
                command=" ".join(cmd),
                stdout=stdout.decode(errors="replace") if stdout else "",
                stderr=stderr.decode(errors="replace") if stderr else "",
                exit_code=proc.returncode or 0,
            )
        except asyncio.TimeoutError:
            return ToolResult(tool_name="netcat", command=" ".join(cmd), stderr="Timeout", exit_code=1)

    @staticmethod
    async def port_check(host: str, port: int, timeout: float = 3.0) -> ToolResult:
        nc = "ncat" if _check_tool("ncat") else "nc"
        cmd = [nc, "-z", "-w", str(int(timeout)), host, str(port)]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout + 2)
        return ToolResult(
            tool_name="netcat",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            parsed_data={"open": rc == 0, "host": host, "port": port},
        )


# ── Hping3 ─────────────────────────────────────────────────

class Hping3Wrapper:
    """Wrapper for hping3 — packet crafting and SYN scanning."""

    @staticmethod
    async def syn_scan(
        target: str,
        port: int = 80,
        count: int = 3,
        timeout: float = 10.0,
    ) -> ToolResult:
        if not _check_tool("hping3"):
            return ToolResult(tool_name="hping3", command="hping3", stderr="hping3 not installed", exit_code=127)

        cmd = ["hping3", "-S", "-p", str(port), "-c", str(count), target]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        return ToolResult(
            tool_name="hping3",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
        )

    @staticmethod
    async def traceroute(target: str, max_hops: int = 30, timeout: float = 30.0) -> ToolResult:
        if not _check_tool("hping3"):
            return ToolResult(tool_name="hping3", command="hping3", stderr="hping3 not installed", exit_code=127)

        cmd = ["hping3", "--traceroute", "-S", "-p", "80", "-t", str(max_hops), target]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        return ToolResult(
            tool_name="hping3",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
        )


# ── Tcpdump ────────────────────────────────────────────────

class TcpdumpWrapper:
    """Wrapper for tcpdump — packet capture and analysis."""

    @staticmethod
    async def capture(
        interface: str = "any",
        filter_expr: str = "",
        count: int = 100,
        output_file: str = "",
        timeout: float = 30.0,
    ) -> ToolResult:
        if not _check_tool("tcpdump"):
            return ToolResult(tool_name="tcpdump", command="tcpdump", stderr="tcpdump not installed", exit_code=127)

        cmd = ["tcpdump", "-i", interface, "-c", str(count), "-nn"]
        if filter_expr:
            cmd.extend(filter_expr.split())
        if output_file:
            cmd.extend(["-w", output_file])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        return ToolResult(
            tool_name="tcpdump",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
        )


# ── ARP-scan ──────────────────────────────────────────────

class ArpScanWrapper:
    """Wrapper for arp-scan — layer 2 network discovery."""

    @staticmethod
    async def scan(
        target: str = "--localnet",
        interface: str = "",
        timeout: float = 30.0,
    ) -> ToolResult:
        if not _check_tool("arp-scan"):
            return ToolResult(tool_name="arp-scan", command="arp-scan", stderr="arp-scan not installed", exit_code=127)

        cmd = ["arp-scan"]
        if interface:
            cmd.extend(["-I", interface])
        cmd.append(target)

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        # Parse output
        hosts = []
        if stdout:
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    ip = parts[0].strip()
                    mac = parts[1].strip()
                    vendor = parts[2].strip() if len(parts) > 2 else ""
                    if ip and "." in ip:
                        hosts.append({"ip": ip, "mac": mac, "vendor": vendor})

        return ToolResult(
            tool_name="arp-scan",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            parsed_data={"hosts": hosts, "total": len(hosts)},
        )


# ── Traceroute ─────────────────────────────────────────────

class TracerouteWrapper:
    """Wrapper for traceroute."""

    @staticmethod
    async def trace(
        target: str,
        max_hops: int = 30,
        timeout: float = 30.0,
    ) -> ToolResult:
        tool = "traceroute" if _check_tool("traceroute") else "tracert"
        if not _check_tool(tool):
            return ToolResult(tool_name="traceroute", command=tool, stderr=f"{tool} not installed", exit_code=127)

        cmd = [tool, "-m", str(max_hops), target]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        # Parse hops
        hops = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and line[0].isdigit():
                    parts = line.split()
                    hop_num = parts[0] if parts else ""
                    hops.append({"hop": hop_num, "raw": line})

        return ToolResult(
            tool_name="traceroute",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            parsed_data={"hops": hops, "total_hops": len(hops)},
        )
