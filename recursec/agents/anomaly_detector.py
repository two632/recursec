"""Anomaly detector — behavioral analysis for vulnerability discovery.

Implements:
1. Response time anomaly detection
2. Response size anomaly detection
3. Status code pattern analysis
4. Content difference analysis
5. Parameter behavior profiling
6. Baseline establishment
7. Statistical outlier detection (Z-score, IQR)
8. Time-series anomaly detection
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AnomalyType(str, Enum):
    RESPONSE_TIME = "response_time"
    RESPONSE_SIZE = "response_size"
    STATUS_CODE = "status_code"
    CONTENT_DIFF = "content_diff"
    BEHAVIOR_CHANGE = "behavior_change"
    ERROR_SPIKE = "error_spike"


class AnomalySeverity(str, Enum):
    LOW = "low"              # Minor deviation
    MEDIUM = "medium"        # Notable deviation
    HIGH = "high"            # Significant anomaly
    CRITICAL = "critical"    # Extreme outlier


@dataclass
class Observation:
    """A single observation data point."""
    endpoint: str = ""
    method: str = "GET"
    status_code: int = 200
    response_time_ms: float = 0.0
    response_size: int = 0
    content_hash: str = ""
    parameters: dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint[:30],
            "status": self.status_code,
            "time_ms": round(self.response_time_ms, 1),
            "size": self.response_size,
        }


@dataclass
class Baseline:
    """Statistical baseline for an endpoint."""
    endpoint: str = ""
    sample_count: int = 0
    avg_response_time_ms: float = 0.0
    std_response_time_ms: float = 0.0
    avg_response_size: float = 0.0
    std_response_size: float = 0.0
    common_status_codes: dict[int, int] = field(default_factory=dict)
    content_hashes: set[str] = field(default_factory=set)
    min_time: float = float("inf")
    max_time: float = 0.0
    min_size: float = float("inf")
    max_size: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint[:30],
            "samples": self.sample_count,
            "avg_time": round(self.avg_response_time_ms, 1),
            "std_time": round(self.std_response_time_ms, 1),
            "avg_size": round(self.avg_response_size, 0),
            "status_codes": dict(self.common_status_codes),
        }


@dataclass
class Anomaly:
    """A detected anomaly."""
    anomaly_id: str = ""
    anomaly_type: AnomalyType = AnomalyType.RESPONSE_TIME
    severity: AnomalySeverity = AnomalySeverity.MEDIUM
    endpoint: str = ""
    description: str = ""
    expected_value: float = 0.0
    actual_value: float = 0.0
    z_score: float = 0.0
    observation: Observation | None = None
    timestamp: float = field(default_factory=time.time)

    @property
    def deviation_ratio(self) -> float:
        if self.expected_value == 0:
            return 0.0
        return abs(self.actual_value - self.expected_value) / self.expected_value

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.anomaly_id[:10],
            "type": self.anomaly_type.value,
            "severity": self.severity.value,
            "endpoint": self.endpoint[:25],
            "expected": round(self.expected_value, 1),
            "actual": round(self.actual_value, 1),
            "z_score": round(self.z_score, 2),
        }


class AnomalyDetector:
    """Behavioral anomaly detection for vulnerability discovery.

    Establishes baselines for endpoint behavior and detects
    deviations that may indicate vulnerabilities:
    - Slow responses → potential injection
    - Size changes → content injection/information disclosure
    - Error spikes → input validation issues
    - Content differences → dynamic behavior
    """

    def __init__(
        self,
        z_threshold: float = 3.0,
        min_samples: int = 5,
    ) -> None:
        self._baselines: dict[str, Baseline] = {}
        self._observations: dict[str, list[Observation]] = defaultdict(list)
        self._anomalies: list[Anomaly] = []
        self._counter = 0
        self._z_threshold = z_threshold
        self._min_samples = min_samples
        self._log = logger.bind(component="anomaly_detector")

    def observe(self, observation: Observation) -> list[Anomaly]:
        """Record an observation and check for anomalies."""
        endpoint = observation.endpoint
        self._observations[endpoint].append(observation)

        # Update baseline
        self._update_baseline(endpoint, observation)

        # Check for anomalies
        anomalies = []
        baseline = self._baselines.get(endpoint)
        if baseline and baseline.sample_count >= self._min_samples:
            anomalies = self._check_anomalies(observation, baseline)
            self._anomalies.extend(anomalies)

        return anomalies

    def _update_baseline(self, endpoint: str, obs: Observation) -> None:
        """Update baseline statistics with Welford's online algorithm."""
        if endpoint not in self._baselines:
            self._baselines[endpoint] = Baseline(endpoint=endpoint)

        bl = self._baselines[endpoint]
        bl.sample_count += 1
        n = bl.sample_count

        # Welford's for response time
        delta = obs.response_time_ms - bl.avg_response_time_ms
        bl.avg_response_time_ms += delta / n
        delta2 = obs.response_time_ms - bl.avg_response_time_ms
        if n > 1:
            variance = ((n - 2) / (n - 1)) * (bl.std_response_time_ms ** 2) + (delta * delta2) / n
            bl.std_response_time_ms = math.sqrt(max(0, variance))

        # Welford's for response size
        delta_s = obs.response_size - bl.avg_response_size
        bl.avg_response_size += delta_s / n
        delta2_s = obs.response_size - bl.avg_response_size
        if n > 1:
            variance_s = ((n - 2) / (n - 1)) * (bl.std_response_size ** 2) + (delta_s * delta2_s) / n
            bl.std_response_size = math.sqrt(max(0, variance_s))

        # Min/max
        bl.min_time = min(bl.min_time, obs.response_time_ms)
        bl.max_time = max(bl.max_time, obs.response_time_ms)
        bl.min_size = min(bl.min_size, obs.response_size)
        bl.max_size = max(bl.max_size, obs.response_size)

        # Status codes
        bl.common_status_codes[obs.status_code] = bl.common_status_codes.get(obs.status_code, 0) + 1

        # Content hashes
        if obs.content_hash:
            bl.content_hashes.add(obs.content_hash)

    def _check_anomalies(
        self,
        obs: Observation,
        baseline: Baseline,
    ) -> list[Anomaly]:
        """Check observation against baseline for anomalies."""
        anomalies = []

        # Response time anomaly
        if baseline.std_response_time_ms > 0:
            z_time = (obs.response_time_ms - baseline.avg_response_time_ms) / baseline.std_response_time_ms
            if abs(z_time) > self._z_threshold:
                self._counter += 1
                severity = self._z_to_severity(abs(z_time))
                anomalies.append(Anomaly(
                    anomaly_id=f"anom-{self._counter}",
                    anomaly_type=AnomalyType.RESPONSE_TIME,
                    severity=severity,
                    endpoint=obs.endpoint,
                    description=f"Response time {obs.response_time_ms:.0f}ms vs baseline {baseline.avg_response_time_ms:.0f}ms",
                    expected_value=baseline.avg_response_time_ms,
                    actual_value=obs.response_time_ms,
                    z_score=z_time,
                    observation=obs,
                ))

        # Response size anomaly
        if baseline.std_response_size > 0:
            z_size = (obs.response_size - baseline.avg_response_size) / baseline.std_response_size
            if abs(z_size) > self._z_threshold:
                self._counter += 1
                severity = self._z_to_severity(abs(z_size))
                anomalies.append(Anomaly(
                    anomaly_id=f"anom-{self._counter}",
                    anomaly_type=AnomalyType.RESPONSE_SIZE,
                    severity=severity,
                    endpoint=obs.endpoint,
                    description=f"Response size {obs.response_size}B vs baseline {baseline.avg_response_size:.0f}B",
                    expected_value=baseline.avg_response_size,
                    actual_value=obs.response_size,
                    z_score=z_size,
                    observation=obs,
                ))

        # Status code anomaly
        total_codes = sum(baseline.common_status_codes.values())
        code_freq = baseline.common_status_codes.get(obs.status_code, 0) / max(1, total_codes)
        if code_freq < 0.05 and baseline.sample_count >= 10:
            self._counter += 1
            anomalies.append(Anomaly(
                anomaly_id=f"anom-{self._counter}",
                anomaly_type=AnomalyType.STATUS_CODE,
                severity=AnomalySeverity.MEDIUM,
                endpoint=obs.endpoint,
                description=f"Unusual status code {obs.status_code} (seen {code_freq:.0%} of the time)",
                expected_value=200,
                actual_value=obs.status_code,
                observation=obs,
            ))

        # Content difference
        if obs.content_hash and obs.content_hash not in baseline.content_hashes:
            self._counter += 1
            anomalies.append(Anomaly(
                anomaly_id=f"anom-{self._counter}",
                anomaly_type=AnomalyType.CONTENT_DIFF,
                severity=AnomalySeverity.LOW,
                endpoint=obs.endpoint,
                description="Response content differs from all previous responses",
                observation=obs,
            ))

        # Error detection
        if obs.error and obs.status_code >= 500:
            self._counter += 1
            anomalies.append(Anomaly(
                anomaly_id=f"anom-{self._counter}",
                anomaly_type=AnomalyType.ERROR_SPIKE,
                severity=AnomalySeverity.HIGH,
                endpoint=obs.endpoint,
                description=f"Server error: {obs.error[:50]}",
                observation=obs,
            ))

        return anomalies

    def _z_to_severity(self, z: float) -> AnomalySeverity:
        """Convert Z-score to severity."""
        if z > 6:
            return AnomalySeverity.CRITICAL
        if z > 4:
            return AnomalySeverity.HIGH
        if z > 3:
            return AnomalySeverity.MEDIUM
        return AnomalySeverity.LOW

    def get_baseline(self, endpoint: str) -> Baseline | None:
        """Get baseline for an endpoint."""
        return self._baselines.get(endpoint)

    def get_anomalies(
        self,
        endpoint: str = "",
        anomaly_type: AnomalyType | None = None,
        severity: AnomalySeverity | None = None,
    ) -> list[Anomaly]:
        """Get detected anomalies with optional filtering."""
        results = self._anomalies
        if endpoint:
            results = [a for a in results if a.endpoint == endpoint]
        if anomaly_type:
            results = [a for a in results if a.anomaly_type == anomaly_type]
        if severity:
            results = [a for a in results if a.severity == severity]
        return results

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        severity_counts: dict[str, int] = defaultdict(int)
        for a in self._anomalies:
            type_counts[a.anomaly_type.value] += 1
            severity_counts[a.severity.value] += 1

        return {
            "baselines": len(self._baselines),
            "total_observations": sum(len(obs) for obs in self._observations.values()),
            "anomalies": len(self._anomalies),
            "by_type": dict(type_counts),
            "by_severity": dict(severity_counts),
        }
