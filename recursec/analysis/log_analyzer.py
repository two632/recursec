"""Log analysis engine — parses and analyzes security-relevant logs.

Supports:
- Apache/Nginx access/error logs
- Auth/syslog logs
- SSH auth logs
- Windows event logs (exported as text)
- Application logs
- Pattern-based anomaly detection
- Brute force attempt identification
- Path traversal / injection detection in URLs
- Suspicious user-agent detection
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class LogEntry:
    """A parsed log entry."""
    timestamp: str = ""
    source_ip: str = ""
    method: str = ""
    path: str = ""
    status_code: int = 0
    size: int = 0
    user_agent: str = ""
    referer: str = ""
    user: str = ""
    raw_line: str = ""
    log_type: str = "unknown"


@dataclass
class LogAnomaly:
    """A detected log anomaly."""
    anomaly_type: str
    severity: str
    description: str
    count: int = 1
    source_ips: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "count": self.count,
            "source_ips": self.source_ips[:10],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class LogAnalysisResult:
    """Results of log analysis."""
    total_lines: int = 0
    total_entries: int = 0
    anomalies: list[LogAnomaly] = field(default_factory=list)
    status_distribution: dict[int, int] = field(default_factory=dict)
    top_ips: list[dict[str, Any]] = field(default_factory=list)
    top_paths: list[dict[str, Any]] = field(default_factory=list)
    suspicious_user_agents: list[str] = field(default_factory=list)
    injection_attempts: list[dict[str, str]] = field(default_factory=list)
    brute_force_ips: list[dict[str, Any]] = field(default_factory=list)
    error_summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "total_entries": self.total_entries,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "status_distribution": self.status_distribution,
            "top_ips": self.top_ips[:10],
            "injection_attempts": len(self.injection_attempts),
            "brute_force_ips": len(self.brute_force_ips),
        }


# ── Log Parsing Patterns ──────────────────────────────────

# Apache/Nginx combined log format
APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# Nginx error log
NGINX_ERROR_PATTERN = re.compile(
    r'(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\].*?client:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

# SSH auth log
SSH_AUTH_PATTERN = re.compile(
    r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+).*?(?:sshd|ssh).*?(?:Failed|Accepted|Invalid)\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

# Syslog auth
SYSLOG_AUTH_PATTERN = re.compile(
    r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+).*?(?:authentication failure|pam_unix.*authentication).*?rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)(?:.*user=(?P<user>\S+))?'
)

# ── Suspicious Patterns ───────────────────────────────────

INJECTION_PATTERNS = [
    (re.compile(r"(?:union|select|insert|update|delete|drop|alter|create)\s", re.IGNORECASE), "sql_injection"),
    (re.compile(r"(?:script|alert|onerror|onload|javascript:)", re.IGNORECASE), "xss"),
    (re.compile(r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f", re.IGNORECASE), "path_traversal"),
    (re.compile(r"(?:;|&&|\|\|)\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|nc|python)", re.IGNORECASE), "command_injection"),
    (re.compile(r"\{\{.*\}\}|<%.*%>|\$\{.*\}", re.IGNORECASE), "template_injection"),
    (re.compile(r"(?:etc/passwd|etc/shadow|proc/self|win\.ini)", re.IGNORECASE), "lfi"),
    (re.compile(r"(?:SLEEP|BENCHMARK|WAITFOR)\s*\(", re.IGNORECASE), "sql_time_blind"),
    (re.compile(r"(?:base64_decode|eval|exec|system|passthru)\s*\(", re.IGNORECASE), "code_injection"),
    (re.compile(r"(?:xml|DOCTYPE|ENTITY|SYSTEM)", re.IGNORECASE), "xxe"),
    (re.compile(r"(?:ldap|jndi)://", re.IGNORECASE), "ldap_injection"),
]

SUSPICIOUS_UA_PATTERNS = [
    re.compile(r"(?:sqlmap|nikto|nmap|nuclei|dirbuster|gobuster|wfuzz|ffuf|burp)", re.IGNORECASE),
    re.compile(r"(?:masscan|zgrab|curl|wget|python-requests|httpx)", re.IGNORECASE),
    re.compile(r"(?:bot|crawler|spider|scan)", re.IGNORECASE),
]

SENSITIVE_PATHS = [
    re.compile(r"(?:/admin|/wp-admin|/phpmyadmin|/cpanel|/manager)", re.IGNORECASE),
    re.compile(r"(?:\.env|\.git|\.svn|\.htaccess|\.htpasswd)", re.IGNORECASE),
    re.compile(r"(?:/api/|/graphql|/swagger|/openapi)", re.IGNORECASE),
    re.compile(r"(?:backup|dump|export|database|sql)", re.IGNORECASE),
]


class LogAnalyzer:
    """Analyzes security logs for threats and anomalies."""

    def __init__(self) -> None:
        self._ip_counts: dict[str, int] = defaultdict(int)
        self._ip_4xx: dict[str, int] = defaultdict(int)
        self._ip_paths: dict[str, set[str]] = defaultdict(set)
        self._path_counts: dict[str, int] = defaultdict(int)
        self._failed_auth: dict[str, int] = defaultdict(int)

    def analyze(self, log_content: str, log_type: str = "auto") -> LogAnalysisResult:
        """Analyze log content and return security findings."""
        result = LogAnalysisResult()

        lines = log_content.splitlines()
        result.total_lines = len(lines)

        for line in lines:
            line = line.strip()
            if not line:
                continue

            entry = self._parse_line(line, log_type)
            if entry:
                result.total_entries += 1
                self._process_entry(entry, result)

        # Post-analysis
        self._detect_brute_force(result)
        self._detect_scanning(result)
        self._build_summaries(result)

        return result

    def _parse_line(self, line: str, log_type: str) -> LogEntry | None:
        """Parse a log line into a LogEntry."""
        # Try Apache/Nginx format first
        match = APACHE_LOG_PATTERN.match(line)
        if match:
            g = match.groupdict()
            return LogEntry(
                timestamp=g.get("time", ""),
                source_ip=g.get("ip", ""),
                method=g.get("method", ""),
                path=g.get("path", ""),
                status_code=int(g.get("status", 0)),
                size=int(g["size"]) if g.get("size", "-") != "-" else 0,
                user_agent=g.get("ua", ""),
                referer=g.get("referer", ""),
                raw_line=line,
                log_type="access",
            )

        # Try SSH auth log
        match = SSH_AUTH_PATTERN.search(line)
        if match:
            g = match.groupdict()
            failed = "Failed" in line or "Invalid" in line
            return LogEntry(
                timestamp=g.get("time", ""),
                source_ip=g.get("ip", ""),
                user=g.get("user", ""),
                status_code=401 if failed else 200,
                raw_line=line,
                log_type="ssh_auth",
            )

        # Try syslog auth
        match = SYSLOG_AUTH_PATTERN.search(line)
        if match:
            g = match.groupdict()
            return LogEntry(
                timestamp=g.get("time", ""),
                source_ip=g.get("ip", ""),
                user=g.get("user", ""),
                status_code=401,
                raw_line=line,
                log_type="syslog_auth",
            )

        # Try nginx error
        match = NGINX_ERROR_PATTERN.search(line)
        if match:
            g = match.groupdict()
            return LogEntry(
                timestamp=g.get("time", ""),
                source_ip=g.get("ip", ""),
                raw_line=line,
                log_type="nginx_error",
            )

        return None

    def _process_entry(self, entry: LogEntry, result: LogAnalysisResult) -> None:
        """Process a single log entry for anomalies."""
        ip = entry.source_ip

        # Track IP activity
        if ip:
            self._ip_counts[ip] += 1
            if entry.status_code >= 400:
                self._ip_4xx[ip] += 1
            if entry.path:
                self._ip_paths[ip].add(entry.path)

        # Track status codes
        if entry.status_code > 0:
            result.status_distribution[entry.status_code] = result.status_distribution.get(entry.status_code, 0) + 1

        # Track paths
        if entry.path:
            self._path_counts[entry.path] += 1

        # Track failed auth
        if entry.log_type in ("ssh_auth", "syslog_auth") and entry.status_code >= 400:
            self._failed_auth[ip] += 1

        # Check for injection attempts
        if entry.path:
            for pattern, inj_type in INJECTION_PATTERNS:
                if pattern.search(entry.path):
                    result.injection_attempts.append({
                        "type": inj_type,
                        "path": entry.path[:200],
                        "source_ip": ip,
                        "method": entry.method,
                    })
                    break

        # Check for suspicious user agents
        if entry.user_agent:
            for pattern in SUSPICIOUS_UA_PATTERNS:
                if pattern.search(entry.user_agent):
                    if entry.user_agent not in result.suspicious_user_agents:
                        result.suspicious_user_agents.append(entry.user_agent[:200])
                    break

    def _detect_brute_force(self, result: LogAnalysisResult) -> None:
        """Detect brute force attempts."""
        for ip, count in self._failed_auth.items():
            if count >= 5:
                result.brute_force_ips.append({
                    "ip": ip,
                    "attempts": count,
                    "severity": "critical" if count > 50 else "high" if count > 20 else "medium",
                })
                result.anomalies.append(LogAnomaly(
                    anomaly_type="brute_force",
                    severity="critical" if count > 50 else "high",
                    description=f"Brute force detected from {ip}: {count} failed auth attempts",
                    count=count,
                    source_ips=[ip],
                    confidence=min(1.0, count / 30.0),
                ))

    def _detect_scanning(self, result: LogAnalysisResult) -> None:
        """Detect scanning activity."""
        for ip, error_count in self._ip_4xx.items():
            path_count = len(self._ip_paths.get(ip, set()))
            if error_count > 50 and path_count > 20:
                result.anomalies.append(LogAnomaly(
                    anomaly_type="directory_scanning",
                    severity="high",
                    description=f"Directory scanning from {ip}: {error_count} 4xx errors across {path_count} unique paths",
                    count=error_count,
                    source_ips=[ip],
                    confidence=min(1.0, error_count / 100.0),
                ))

        # Injection attempt summary
        if result.injection_attempts:
            by_type: dict[str, int] = defaultdict(int)
            by_ip: dict[str, int] = defaultdict(int)
            for attempt in result.injection_attempts:
                by_type[attempt["type"]] += 1
                by_ip[attempt["source_ip"]] += 1

            for inj_type, count in by_type.items():
                result.anomalies.append(LogAnomaly(
                    anomaly_type=f"injection_{inj_type}",
                    severity="critical" if inj_type in ("sql_injection", "command_injection", "code_injection") else "high",
                    description=f"{count} {inj_type.replace('_', ' ')} attempts detected",
                    count=count,
                    source_ips=list(by_ip.keys())[:10],
                    confidence=0.8,
                ))

    def _build_summaries(self, result: LogAnalysisResult) -> None:
        """Build summary statistics."""
        # Top IPs
        sorted_ips = sorted(self._ip_counts.items(), key=lambda x: x[1], reverse=True)
        result.top_ips = [
            {"ip": ip, "requests": count, "errors": self._ip_4xx.get(ip, 0)}
            for ip, count in sorted_ips[:20]
        ]

        # Top paths
        sorted_paths = sorted(self._path_counts.items(), key=lambda x: x[1], reverse=True)
        result.top_paths = [
            {"path": path, "count": count}
            for path, count in sorted_paths[:20]
        ]
