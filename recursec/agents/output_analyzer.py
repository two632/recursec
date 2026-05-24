"""Output analyzer — parses and analyzes tool outputs.

Handles:
1. Multi-format parsing (JSON, XML, text, JSONL)
2. Finding extraction from raw output
3. Severity classification
4. Deduplication
5. Enrichment with context
6. False positive scoring
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OutputFormat(str, Enum):
    JSON = "json"
    JSONL = "jsonl"
    XML = "xml"
    TEXT = "text"
    CSV = "csv"
    NMAP = "nmap"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ParsedFinding:
    """A finding extracted from tool output."""
    finding_id: str = ""
    title: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    description: str = ""
    evidence: str = ""
    target: str = ""
    tool: str = ""
    confidence: float = 0.5
    cve: str = ""
    cwe: str = ""
    remediation: str = ""
    false_positive_score: float = 0.0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:8],
            "title": self.title[:30],
            "severity": self.severity.value[:4],
            "confidence": f"{self.confidence:.2f}",
            "fp_score": f"{self.false_positive_score:.2f}",
            "tool": self.tool[:12],
        }


# Severity keywords for text-based classification
SEVERITY_KEYWORDS: dict[FindingSeverity, list[str]] = {
    FindingSeverity.CRITICAL: ["critical", "rce", "remote code execution", "unauthenticated", "0-day", "zero-day", "command injection", "sql injection", "pre-auth"],
    FindingSeverity.HIGH: ["high", "xss", "ssrf", "idor", "privilege escalation", "authentication bypass", "path traversal", "deserialization", "xxe"],
    FindingSeverity.MEDIUM: ["medium", "csrf", "clickjacking", "open redirect", "information disclosure", "cors", "directory listing", "verbose error"],
    FindingSeverity.LOW: ["low", "cookie", "header missing", "hsts", "x-frame", "content-type", "server version"],
    FindingSeverity.INFO: ["info", "informational", "note", "technology detected"],
}

# False positive patterns — common FP indicators
FP_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"could not connect", "fp_boost": 0.8, "reason": "Connection failed"},
    {"pattern": r"timed out", "fp_boost": 0.6, "reason": "Timeout"},
    {"pattern": r"access denied", "fp_boost": 0.3, "reason": "Access denied"},
    {"pattern": r"404 not found", "fp_boost": 0.5, "reason": "Resource not found"},
    {"pattern": r"false positive", "fp_boost": 0.9, "reason": "Self-identified FP"},
    {"pattern": r"informational", "fp_boost": 0.4, "reason": "Info only"},
]


class OutputAnalyzer:
    """Analyzes tool outputs and extracts findings."""

    def __init__(self) -> None:
        self._finding_counter = 0
        self._all_findings: list[ParsedFinding] = []
        self._log = logger.bind(component="output_analyzer")

    def parse_json_output(self, raw: str) -> list[dict[str, Any]]:
        """Parse JSON output."""
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass
        return []

    def parse_jsonl_output(self, raw: str) -> list[dict[str, Any]]:
        """Parse JSON Lines output."""
        results = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    def parse_nmap_text(self, raw: str) -> list[dict[str, Any]]:
        """Parse nmap text output."""
        findings = []
        port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)")
        for line in raw.split("\n"):
            match = port_pattern.search(line)
            if match:
                findings.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4),
                    "version": match.group(5).strip(),
                })
        return findings

    def classify_severity(self, text: str) -> FindingSeverity:
        """Classify severity from text."""
        text_lower = text.lower()
        for severity, keywords in SEVERITY_KEYWORDS.items():
            for kw in keywords:
                if kw in text_lower:
                    return severity
        return FindingSeverity.INFO

    def score_false_positive(self, finding: ParsedFinding) -> float:
        """Score likelihood of false positive (0=real, 1=likely FP)."""
        fp_score = 0.0
        text = (finding.title + " " + finding.description + " " + finding.evidence).lower()

        for pattern_info in FP_PATTERNS:
            if re.search(pattern_info["pattern"], text, re.IGNORECASE):
                fp_score = max(fp_score, pattern_info["fp_boost"])

        # Low confidence = higher FP likelihood
        if finding.confidence < 0.3:
            fp_score = max(fp_score, 0.6)

        return min(fp_score, 1.0)

    def extract_findings(
        self,
        raw_output: str,
        tool_name: str,
        target: str,
        output_format: OutputFormat = OutputFormat.TEXT,
    ) -> list[ParsedFinding]:
        """Extract findings from raw tool output."""
        findings: list[ParsedFinding] = []

        if output_format == OutputFormat.JSON:
            parsed = self.parse_json_output(raw_output)
        elif output_format == OutputFormat.JSONL:
            parsed = self.parse_jsonl_output(raw_output)
        elif output_format == OutputFormat.NMAP:
            parsed = self.parse_nmap_text(raw_output)
        else:
            parsed = [{"raw": raw_output}]

        for item in parsed:
            self._finding_counter += 1
            title = item.get("info", {}).get("name", "") or item.get("title", "") or item.get("name", "") or f"{tool_name} finding #{self._finding_counter}"
            description = item.get("info", {}).get("description", "") or item.get("description", "") or ""
            severity_str = item.get("info", {}).get("severity", "") or item.get("severity", "") or ""

            severity = self.classify_severity(severity_str or title or description)

            finding = ParsedFinding(
                finding_id=f"f-{self._finding_counter}",
                title=title,
                severity=severity,
                description=description,
                evidence=str(item)[:500],
                target=target,
                tool=tool_name,
                confidence=0.7 if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) else 0.5,
                cve=item.get("info", {}).get("classification", {}).get("cve-id", "") or item.get("cve", "") or "",
            )

            finding.false_positive_score = self.score_false_positive(finding)
            findings.append(finding)
            self._all_findings.append(finding)

        return findings

    def deduplicate(self, findings: list[ParsedFinding]) -> list[ParsedFinding]:
        """Remove duplicate findings."""
        seen: set[str] = set()
        unique: list[ParsedFinding] = []
        for f in findings:
            key = f"{f.title}:{f.target}:{f.severity.value}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def get_findings_by_severity(self) -> dict[str, list[ParsedFinding]]:
        """Group all findings by severity."""
        groups: dict[str, list[ParsedFinding]] = {}
        for f in self._all_findings:
            groups.setdefault(f.severity.value, []).append(f)
        return groups

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = {}
        for f in self._all_findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        return {
            "total_findings": len(self._all_findings),
            "by_severity": sev_counts,
            "avg_confidence": sum(f.confidence for f in self._all_findings) / max(len(self._all_findings), 1),
            "avg_fp_score": sum(f.false_positive_score for f in self._all_findings) / max(len(self._all_findings), 1),
        }

    def build_analyzer_prompt(self) -> str:
        """Build LLM prompt with finding summary."""
        stats = self.get_stats()
        lines = ["## Finding Analysis Summary"]
        lines.append(f"Total: {stats['total_findings']}")
        for sev, count in sorted(stats.get("by_severity", {}).items()):
            lines.append(f"  {sev}: {count}")
        lines.append(f"Avg confidence: {stats['avg_confidence']:.2f}")
        lines.append(f"Avg FP score: {stats['avg_fp_score']:.2f}")
        return "\n".join(lines)
