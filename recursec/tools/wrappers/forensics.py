"""Forensics tool wrappers — memory, disk, and malware analysis.

Integrates:
- Volatility3 (memory forensics)
- Binwalk (firmware analysis)
- Foremost (file carving)
- YARA (pattern matching)
- strings/file/objdump (basic binary analysis)
- Autopsy/Sleuthkit (disk forensics)
"""

from __future__ import annotations

import asyncio
import re
import shutil
from typing import Any

import structlog

from recursec.tools.tool_runner import ToolResult

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


class VolatilityWrapper:
    """Wrapper for Volatility3 memory forensics framework."""

    def __init__(self) -> None:
        self.available = shutil.which("vol") is not None or shutil.which("vol3") is not None
        self._cmd = "vol3" if shutil.which("vol3") else "vol"

    async def list_processes(self, memory_dump: str) -> ToolResult:
        """List processes from memory dump."""
        cmd = [self._cmd, "-f", memory_dump, "windows.pslist.PsList"]
        result = await _run(cmd, timeout=600.0)
        result.parsed_data = self._parse_pslist(result.stdout)
        return result

    async def network_connections(self, memory_dump: str) -> ToolResult:
        """Extract network connections from memory."""
        cmd = [self._cmd, "-f", memory_dump, "windows.netscan.NetScan"]
        result = await _run(cmd, timeout=600.0)
        result.parsed_data = self._parse_netscan(result.stdout)
        return result

    async def dump_hashes(self, memory_dump: str) -> ToolResult:
        """Extract password hashes from memory."""
        cmd = [self._cmd, "-f", memory_dump, "windows.hashdump.Hashdump"]
        return await _run(cmd, timeout=600.0)

    async def malfind(self, memory_dump: str) -> ToolResult:
        """Detect potentially injected code in memory."""
        cmd = [self._cmd, "-f", memory_dump, "windows.malfind.Malfind"]
        result = await _run(cmd, timeout=600.0)
        result.parsed_data = self._parse_malfind(result.stdout)
        return result

    async def command_history(self, memory_dump: str) -> ToolResult:
        """Extract command history from memory."""
        cmd = [self._cmd, "-f", memory_dump, "windows.cmdline.CmdLine"]
        return await _run(cmd, timeout=600.0)

    async def registry_hives(self, memory_dump: str) -> ToolResult:
        """List registry hives from memory."""
        cmd = [self._cmd, "-f", memory_dump, "windows.registry.hivelist.HiveList"]
        return await _run(cmd, timeout=600.0)

    async def dll_list(self, memory_dump: str) -> ToolResult:
        """List loaded DLLs from memory."""
        cmd = [self._cmd, "-f", memory_dump, "windows.dlllist.DllList"]
        return await _run(cmd, timeout=600.0)

    async def file_scan(self, memory_dump: str) -> ToolResult:
        """Scan for file objects in memory."""
        cmd = [self._cmd, "-f", memory_dump, "windows.filescan.FileScan"]
        return await _run(cmd, timeout=600.0)

    def _parse_pslist(self, output: str) -> dict[str, Any]:
        """Parse process list output."""
        processes = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[0].isdigit():
                processes.append({
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]) if parts[1].isdigit() else 0,
                    "name": parts[2],
                    "threads": int(parts[3]) if parts[3].isdigit() else 0,
                })
        return {"processes": processes, "count": len(processes)}

    def _parse_netscan(self, output: str) -> dict[str, Any]:
        """Parse network scan output."""
        connections = []
        for line in output.splitlines():
            if "ESTABLISHED" in line or "LISTENING" in line or "CLOSED" in line:
                parts = line.split()
                if len(parts) >= 5:
                    connections.append({
                        "local": parts[1] if len(parts) > 1 else "",
                        "remote": parts[3] if len(parts) > 3 else "",
                        "state": parts[4] if len(parts) > 4 else "",
                        "pid": parts[-1] if parts[-1].isdigit() else "",
                    })
        return {"connections": connections, "count": len(connections)}

    def _parse_malfind(self, output: str) -> dict[str, Any]:
        """Parse malfind output for suspicious injections."""
        injections = []
        current: dict[str, Any] = {}
        for line in output.splitlines():
            pid_match = re.match(r"PID:\s+(\d+)", line)
            if pid_match:
                if current:
                    injections.append(current)
                current = {"pid": int(pid_match.group(1))}
            protection_match = re.search(r"Protection:\s+(.+)", line)
            if protection_match and current:
                current["protection"] = protection_match.group(1).strip()
        if current:
            injections.append(current)
        return {"injections": injections, "count": len(injections)}


class BinwalkWrapper:
    """Wrapper for Binwalk firmware analysis."""

    def __init__(self) -> None:
        self.available = shutil.which("binwalk") is not None

    async def scan(self, filepath: str) -> ToolResult:
        """Scan file for embedded files and signatures."""
        cmd = ["binwalk", filepath]
        result = await _run(cmd)
        result.parsed_data = self._parse_scan(result.stdout)
        return result

    async def extract(self, filepath: str, output_dir: str = "") -> ToolResult:
        """Extract embedded files."""
        cmd = ["binwalk", "-e", filepath]
        if output_dir:
            cmd.extend(["-C", output_dir])
        return await _run(cmd, timeout=600.0)

    async def entropy(self, filepath: str) -> ToolResult:
        """Calculate entropy analysis."""
        cmd = ["binwalk", "-E", filepath]
        return await _run(cmd)

    def _parse_scan(self, output: str) -> dict[str, Any]:
        """Parse binwalk scan output."""
        entries = []
        for line in output.splitlines():
            match = re.match(r"(\d+)\s+0x[0-9A-Fa-f]+\s+(.*)", line)
            if match:
                entries.append({
                    "offset": int(match.group(1)),
                    "description": match.group(2).strip(),
                })
        return {"entries": entries, "count": len(entries)}


class ForemostWrapper:
    """Wrapper for Foremost file carving."""

    def __init__(self) -> None:
        self.available = shutil.which("foremost") is not None

    async def carve(self, filepath: str, output_dir: str, file_types: str = "") -> ToolResult:
        """Carve files from disk image or file."""
        cmd = ["foremost", "-i", filepath, "-o", output_dir]
        if file_types:
            cmd.extend(["-t", file_types])
        return await _run(cmd, timeout=1800.0)


class YARAWrapper:
    """Wrapper for YARA pattern matching."""

    def __init__(self) -> None:
        self.available = shutil.which("yara") is not None

    async def scan_file(self, rules_path: str, target_path: str) -> ToolResult:
        """Scan file with YARA rules."""
        cmd = ["yara", "-s", rules_path, target_path]
        result = await _run(cmd, timeout=300.0)
        result.parsed_data = self._parse_matches(result.stdout)
        return result

    async def scan_directory(self, rules_path: str, target_dir: str) -> ToolResult:
        """Scan directory recursively with YARA rules."""
        cmd = ["yara", "-r", "-s", rules_path, target_dir]
        result = await _run(cmd, timeout=600.0)
        result.parsed_data = self._parse_matches(result.stdout)
        return result

    def _parse_matches(self, output: str) -> dict[str, Any]:
        """Parse YARA match output."""
        matches = []
        current_rule = ""
        for line in output.splitlines():
            if not line.startswith("0x"):
                parts = line.split()
                if len(parts) >= 2:
                    current_rule = parts[0]
                    filepath = parts[1]
                    matches.append({"rule": current_rule, "file": filepath, "strings": []})
            elif matches:
                matches[-1]["strings"].append(line.strip())
        return {"matches": matches, "count": len(matches)}


class SleuthkitWrapper:
    """Wrapper for Sleuthkit disk forensics tools."""

    def __init__(self) -> None:
        self.available = shutil.which("fls") is not None

    async def list_files(self, image_path: str, offset: int = 0) -> ToolResult:
        """List files in disk image."""
        cmd = ["fls", "-r"]
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.append(image_path)
        return await _run(cmd, timeout=300.0)

    async def file_info(self, image_path: str) -> ToolResult:
        """Get filesystem info from image."""
        cmd = ["fsstat", image_path]
        return await _run(cmd)

    async def timeline(self, image_path: str) -> ToolResult:
        """Generate filesystem timeline."""
        cmd = ["fls", "-r", "-m", "/", image_path]
        return await _run(cmd, timeout=600.0)

    async def recover_file(self, image_path: str, inode: str, output_path: str) -> ToolResult:
        """Recover a specific file by inode."""
        cmd = ["icat", image_path, inode]
        result = await _run(cmd)
        if result.return_code == 0 and result.stdout:
            try:
                with open(output_path, "wb") as f:
                    f.write(result.stdout.encode("latin-1"))
            except OSError as e:
                result.stderr = str(e)
        return result


class StringsWrapper:
    """Wrapper for strings/file utilities."""

    def __init__(self) -> None:
        self.available = shutil.which("strings") is not None

    async def extract_strings(self, filepath: str, min_length: int = 6) -> ToolResult:
        """Extract printable strings from binary."""
        cmd = ["strings", f"-n{min_length}", filepath]
        result = await _run(cmd)

        # Categorize interesting strings
        urls = []
        ips = []
        emails = []
        paths = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if re.match(r"https?://", line):
                urls.append(line)
            elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line):
                ips.append(line)
            elif "@" in line and "." in line:
                emails.append(line)
            elif line.startswith("/") or line.startswith("C:\\"):
                paths.append(line)

        result.parsed_data = {
            "total_strings": len(result.stdout.splitlines()),
            "urls": urls[:100],
            "ips": ips[:100],
            "emails": emails[:100],
            "paths": paths[:100],
        }
        return result

    async def file_type(self, filepath: str) -> ToolResult:
        """Identify file type."""
        cmd = ["file", "-b", filepath]
        return await _run(cmd)

    async def objdump_headers(self, filepath: str) -> ToolResult:
        """Dump binary headers."""
        if not shutil.which("objdump"):
            return ToolResult(tool_name="objdump", command="", stdout="", stderr="not found",
                              return_code=127, parsed_data={})
        cmd = ["objdump", "-f", "-h", filepath]
        return await _run(cmd)
