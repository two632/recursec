"""Fuzzing tool wrappers — afl++, honggfuzz, boofuzz, schemathesis, restler.

Fuzzing tools for binary, protocol, and API testing.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Any

from recursec.core.models import ToolResult


async def _run_command(cmd: list[str], timeout: float = 600.0) -> tuple[str, str, int]:
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


# ── AFL++ ──────────────────────────────────────────────────

class AFLPlusWrapper:
    """Wrapper for AFL++ — coverage-guided fuzzer."""

    @staticmethod
    async def fuzz(
        target_binary: str,
        input_dir: str,
        output_dir: str = "",
        timeout_per_run: int = 1000,
        memory_limit: int = 512,
        dictionary: str = "",
        extra_args: list[str] | None = None,
        duration_s: int = 300,
    ) -> ToolResult:
        afl = "afl-fuzz" if _check_tool("afl-fuzz") else "AFL_FUZZ"
        if not _check_tool(afl):
            return ToolResult(tool_name="afl++", command=afl, stderr="afl-fuzz not installed", exit_code=127)

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="afl_output_")

        cmd = [afl, "-i", input_dir, "-o", output_dir, "-t", str(timeout_per_run), "-m", str(memory_limit)]
        if dictionary:
            cmd.extend(["-x", dictionary])
        if extra_args:
            cmd.extend(extra_args)
        cmd.extend(["--", target_binary])

        stdout, stderr, rc = await _run_command(cmd, timeout=float(duration_s) + 30)

        # Parse AFL stats
        stats: dict[str, Any] = {}
        stats_file = Path(output_dir) / "default" / "fuzzer_stats"
        if stats_file.exists():
            for line in stats_file.read_text().splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    stats[key.strip()] = val.strip()

        # Count crashes
        crash_dir = Path(output_dir) / "default" / "crashes"
        crashes = list(crash_dir.glob("id:*")) if crash_dir.exists() else []

        return ToolResult(
            tool_name="afl++", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={
                "stats": stats,
                "crashes_found": len(crashes),
                "output_dir": output_dir,
                "execs_per_sec": stats.get("execs_per_sec", "0"),
                "total_paths": stats.get("paths_total", "0"),
            },
        )


# ── Honggfuzz ──────────────────────────────────────────────

class HonggfuzzWrapper:
    """Wrapper for honggfuzz — security-oriented fuzzer."""

    @staticmethod
    async def fuzz(
        target_binary: str,
        input_dir: str = "",
        output_dir: str = "",
        threads: int = 4,
        timeout_per_run: int = 10,
        duration_s: int = 300,
    ) -> ToolResult:
        if not _check_tool("honggfuzz"):
            return ToolResult(tool_name="honggfuzz", command="honggfuzz", stderr="honggfuzz not installed", exit_code=127)

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="hfuzz_")

        cmd = ["honggfuzz", "--threads", str(threads), "--timeout", str(timeout_per_run)]
        cmd.extend(["--output", output_dir, "--run_time", str(duration_s)])
        if input_dir:
            cmd.extend(["--input", input_dir])
        cmd.extend(["--", target_binary])

        stdout, stderr, rc = await _run_command(cmd, timeout=float(duration_s) + 30)

        return ToolResult(
            tool_name="honggfuzz", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"output_dir": output_dir},
        )


# ── Boofuzz ────────────────────────────────────────────────

class BoofuzzWrapper:
    """Wrapper for boofuzz — network protocol fuzzer."""

    @staticmethod
    async def fuzz_tcp(
        target_host: str,
        target_port: int,
        protocol_script: str = "",
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("boo"):
            # boofuzz is typically used as a Python library
            return ToolResult(tool_name="boofuzz", command="boofuzz", stderr="boofuzz not installed", exit_code=127)

        cmd = ["python3", "-m", "boofuzz", "--host", target_host, "--port", str(target_port)]
        if protocol_script:
            cmd.extend(["--script", protocol_script])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        return ToolResult(
            tool_name="boofuzz", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
        )


# ── Schemathesis ──────────────────────────────────────────

class SchemathesisWrapper:
    """Wrapper for schemathesis — API schema-based fuzzer."""

    @staticmethod
    async def fuzz_api(
        schema_url: str,
        base_url: str = "",
        checks: list[str] | None = None,
        hypothesis_max_examples: int = 100,
        workers: int = 4,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("st"):
            return ToolResult(tool_name="schemathesis", command="st", stderr="schemathesis not installed", exit_code=127)

        cmd = ["st", "run", schema_url]
        if base_url:
            cmd.extend(["--base-url", base_url])
        if checks:
            for check in checks:
                cmd.extend(["--checks", check])
        else:
            cmd.extend(["--checks", "all"])
        cmd.extend(["--hypothesis-max-examples", str(hypothesis_max_examples)])
        cmd.extend(["--workers", str(workers)])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        # Parse schemathesis output
        failures = []
        if stdout:
            current_failure: dict[str, str] = {}
            for line in stdout.splitlines():
                if "FAILED" in line:
                    if current_failure:
                        failures.append(current_failure)
                    current_failure = {"endpoint": line.strip()}
                elif "Check" in line and current_failure:
                    current_failure["check"] = line.strip()

            if current_failure:
                failures.append(current_failure)

        return ToolResult(
            tool_name="schemathesis", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"failures": failures, "total_failures": len(failures)},
        )


# ── Radamsa ────────────────────────────────────────────────

class RadamsaWrapper:
    """Wrapper for radamsa — general-purpose mutation fuzzer."""

    @staticmethod
    async def mutate(
        input_file: str,
        count: int = 100,
        output_dir: str = "",
        seed: int = 0,
        timeout: float = 60.0,
    ) -> ToolResult:
        if not _check_tool("radamsa"):
            return ToolResult(tool_name="radamsa", command="radamsa", stderr="radamsa not installed", exit_code=127)

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="radamsa_")

        cmd = ["radamsa", "-n", str(count), "-o", f"{output_dir}/%n.fuzz"]
        if seed:
            cmd.extend(["-s", str(seed)])
        cmd.append(input_file)

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        # Count generated files
        out_path = Path(output_dir)
        generated = list(out_path.glob("*.fuzz"))

        return ToolResult(
            tool_name="radamsa", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"output_dir": output_dir, "files_generated": len(generated)},
        )
