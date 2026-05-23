"""OSINT tool wrappers — spiderfoot, recon-ng, sherlock, holehe, photon.

Open-source intelligence gathering tools — all run locally.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from recursec.core.models import ToolResult


async def _run_command(cmd: list[str], timeout: float = 300.0) -> tuple[str, str, int]:
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
    return shutil.which(name) is not None


# ── SpiderFoot ─────────────────────────────────────────────

class SpiderFootWrapper:
    """Wrapper for SpiderFoot — comprehensive OSINT automation."""

    @staticmethod
    async def scan(
        target: str,
        modules: list[str] | None = None,
        timeout: float = 600.0,
    ) -> ToolResult:
        if not _check_tool("spiderfoot"):
            return ToolResult(tool_name="spiderfoot", command="spiderfoot", stderr="spiderfoot not installed", exit_code=127)

        cmd = ["spiderfoot", "-s", target, "-q"]
        if modules:
            cmd.extend(["-m", ",".join(modules)])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        return ToolResult(
            tool_name="spiderfoot", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
        )


# ── Recon-ng ──────────────────────────────────────────────

class ReconNGWrapper:
    """Wrapper for recon-ng — OSINT framework."""

    @staticmethod
    async def run_module(
        module: str,
        source: str = "",
        options: dict[str, str] | None = None,
        timeout: float = 120.0,
    ) -> ToolResult:
        if not _check_tool("recon-ng"):
            return ToolResult(tool_name="recon-ng", command="recon-ng", stderr="recon-ng not installed", exit_code=127)

        # Build recon-ng commands
        commands = [f"modules load {module}"]
        if source:
            commands.append(f"options set SOURCE {source}")
        if options:
            for key, val in options.items():
                commands.append(f"options set {key} {val}")
        commands.append("run")
        commands.append("exit")

        rc_content = "\n".join(commands)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
            f.write(rc_content)
            rc_file = f.name

        cmd = ["recon-ng", "-r", rc_file]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        Path(rc_file).unlink(missing_ok=True)

        return ToolResult(
            tool_name="recon-ng", command=f"recon-ng module={module}",
            stdout=stdout, stderr=stderr, exit_code=rc,
        )


# ── Sherlock ──────────────────────────────────────────────

class SherlockWrapper:
    """Wrapper for sherlock — username enumeration across social networks."""

    @staticmethod
    async def search(
        username: str,
        timeout: float = 120.0,
    ) -> ToolResult:
        if not _check_tool("sherlock"):
            return ToolResult(tool_name="sherlock", command="sherlock", stderr="sherlock not installed", exit_code=127)

        output_file = tempfile.mktemp(suffix=".json")
        cmd = ["sherlock", username, "--json", output_file, "--timeout", "10"]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        profiles = []
        output_path = Path(output_file)
        if output_path.exists():
            try:
                data = json.loads(output_path.read_text())
                if isinstance(data, dict):
                    for site, info in data.items():
                        if isinstance(info, dict) and info.get("status") == "Claimed":
                            profiles.append({
                                "site": site,
                                "url": info.get("url_user", ""),
                            })
            except (json.JSONDecodeError, OSError):
                pass
            output_path.unlink(missing_ok=True)

        return ToolResult(
            tool_name="sherlock", command=f"sherlock {username}",
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"profiles": profiles, "total": len(profiles)},
        )


# ── Holehe ─────────────────────────────────────────────────

class HoleheWrapper:
    """Wrapper for holehe — email account discovery."""

    @staticmethod
    async def check(
        email: str,
        timeout: float = 120.0,
    ) -> ToolResult:
        if not _check_tool("holehe"):
            return ToolResult(tool_name="holehe", command="holehe", stderr="holehe not installed", exit_code=127)

        cmd = ["holehe", email, "--no-color"]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        accounts = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if "[+]" in line:
                    parts = line.split("[+]")
                    if len(parts) > 1:
                        service = parts[1].strip().split()[0] if parts[1].strip() else ""
                        accounts.append({"service": service, "exists": True})

        return ToolResult(
            tool_name="holehe", command=f"holehe {email}",
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"accounts": accounts, "total": len(accounts)},
        )


# ── Photon ─────────────────────────────────────────────────

class PhotonWrapper:
    """Wrapper for photon — web crawler for OSINT."""

    @staticmethod
    async def crawl(
        url: str,
        depth: int = 2,
        threads: int = 10,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("photon"):
            return ToolResult(tool_name="photon", command="photon", stderr="photon not installed", exit_code=127)

        output_dir = tempfile.mkdtemp(prefix="photon_")
        cmd = ["photon", "-u", url, "-l", str(depth), "-t", str(threads), "-o", output_dir]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        results: dict[str, Any] = {}
        out_path = Path(output_dir)
        for file_type in ["urls.txt", "internal.txt", "external.txt", "scripts.txt", "forms.txt", "params.txt", "files.txt"]:
            fp = out_path / file_type
            if fp.exists():
                items = [line.strip() for line in fp.read_text().splitlines() if line.strip()]
                results[file_type.replace(".txt", "")] = items

        return ToolResult(
            tool_name="photon", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data=results,
        )


# ── Waybackurls ────────────────────────────────────────────

class WaybackurlsWrapper:
    """Wrapper for waybackurls — fetch URLs from Wayback Machine."""

    @staticmethod
    async def fetch(
        domain: str,
        timeout: float = 120.0,
    ) -> ToolResult:
        if not _check_tool("waybackurls"):
            return ToolResult(tool_name="waybackurls", command="waybackurls", stderr="waybackurls not installed", exit_code=127)

        cmd = ["sh", "-c", f"echo {domain} | waybackurls"]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        urls = []
        if stdout:
            urls = [u.strip() for u in stdout.splitlines() if u.strip()]

        return ToolResult(
            tool_name="waybackurls", command=f"waybackurls {domain}",
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"urls": urls[:1000], "total": len(urls)},
        )


# ── GAU (Get All URLs) ────────────────────────────────────

class GAUWrapper:
    """Wrapper for gau — fetch all known URLs."""

    @staticmethod
    async def fetch(
        domain: str,
        providers: list[str] | None = None,
        timeout: float = 120.0,
    ) -> ToolResult:
        if not _check_tool("gau"):
            return ToolResult(tool_name="gau", command="gau", stderr="gau not installed", exit_code=127)

        cmd_str = f"echo {domain} | gau"
        if providers:
            cmd_str += f" --providers {','.join(providers)}"

        cmd = ["sh", "-c", cmd_str]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        urls = []
        if stdout:
            urls = [u.strip() for u in stdout.splitlines() if u.strip()]

        return ToolResult(
            tool_name="gau", command=f"gau {domain}",
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"urls": urls[:1000], "total": len(urls)},
        )


# ── CertSpotter / CRT.sh ─────────────────────────────────

class CertSearchWrapper:
    """Search certificate transparency logs locally via crt.sh data or certspotter."""

    @staticmethod
    async def search(
        domain: str,
        timeout: float = 30.0,
    ) -> ToolResult:
        # Use curl to query crt.sh locally (it's a free API, no key needed)
        if not _check_tool("curl"):
            return ToolResult(tool_name="cert_search", command="curl", stderr="curl not installed", exit_code=127)

        cmd = ["curl", "-s", f"https://crt.sh/?q=%25.{domain}&output=json", "--max-time", str(int(timeout))]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout + 5)

        subdomains: set[str] = set()
        if stdout:
            try:
                data = json.loads(stdout)
                if isinstance(data, list):
                    for entry in data:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            if n and not n.startswith("*"):
                                subdomains.add(n)
            except json.JSONDecodeError:
                pass

        sorted_subs = sorted(subdomains)
        return ToolResult(
            tool_name="cert_search", command=f"crt.sh query for {domain}",
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"subdomains": sorted_subs, "total": len(sorted_subs)},
        )
