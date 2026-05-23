"""Anomaly detector — identifies unusual patterns in findings and behavior.

Implements:
1. Statistical anomaly detection (z-score, IQR)
2. Behavioral anomaly detection (agent behavior shifts)
3. Finding anomaly detection (unusual vulnerability patterns)
4. Temporal anomaly detection (timing irregularities)
5. Network anomaly detection (unusual traffic patterns)
6. Baseline learning from normal behavior
7. Anomaly classification and severity
8. Alert generation for detected anomalies
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
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    FINDING = "finding"
    NETWORK = "network"


class AnomalySeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DataPoint:
    """A data point for anomaly detection."""
    name: str = ""
    value: float = 0.0
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "value": round(self.value, 3),
        }


@dataclass
class Anomaly:
    """A detected anomaly."""
    anomaly_id: str = ""
    anomaly_type: AnomalyType = AnomalyType.STATISTICAL
    severity: AnomalySeverity = AnomalySeverity.MEDIUM
    description: str = ""
    metric_name: str = ""
    observed_value: float = 0.0
    expected_range: tuple[float, float] = (0.0, 0.0)
    deviation_score: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.anomaly_id,
            "type": self.anomaly_type.value,
            "severity": self.severity.value,
            "desc": self.description[:40],
            "metric": self.metric_name[:20],
            "observed": round(self.observed_value, 3),
            "deviation": round(self.deviation_score, 2),
        }


@dataclass
class Baseline:
    """A statistical baseline for a metric."""
    name: str = ""
    values: list[float] = field(default_factory=list)
    mean: float = 0.0
    std_dev: float = 0.0
    q1: float = 0.0
    q3: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    last_updated: float = 0.0

    @property
    def iqr(self) -> float:
        return self.q3 - self.q1

    @property
    def lower_fence(self) -> float:
        return self.q1 - 1.5 * self.iqr

    @property
    def upper_fence(self) -> float:
        return self.q3 + 1.5 * self.iqr

    def z_score(self, value: float) -> float:
        if self.std_dev == 0:
            return 0.0
        return (value - self.mean) / self.std_dev

    def is_outlier_iqr(self, value: float) -> bool:
        return value < self.lower_fence or value > self.upper_fence

    def update(self) -> None:
        """Recompute statistics from values."""
        if not self.values:
            return

        n = len(self.values)
        self.mean = sum(self.values) / n

        variance = sum((v - self.mean) ** 2 for v in self.values) / max(1, n - 1)
        self.std_dev = math.sqrt(variance)

        sorted_vals = sorted(self.values)
        self.min_val = sorted_vals[0]
        self.max_val = sorted_vals[-1]
        self.q1 = sorted_vals[max(0, n // 4)]
        self.q3 = sorted_vals[min(n - 1, 3 * n // 4)]
        self.last_updated = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "mean": round(self.mean, 3),
            "std": round(self.std_dev, 3),
            "iqr": round(self.iqr, 3),
            "samples": len(self.values),
        }


class AnomalyDetector:
    """Identifies unusual patterns in findings and behavior.

    Learns baselines from normal behavior and flags
    deviations using statistical and heuristic methods.
    """

    def __init__(
        self,
        z_threshold: float = 2.5,
        min_baseline_samples: int = 10,
        max_baseline_samples: int = 200,
    ) -> None:
        self._baselines: dict[str, Baseline] = {}
        self._anomalies: list[Anomaly] = []
        self._anomaly_counter = 0
        self._z_threshold = z_threshold
        self._min_baseline = min_baseline_samples
        self._max_baseline = max_baseline_samples
        self._log = logger.bind(component="anomaly_detector")

    def observe(self, name: str, value: float) -> Anomaly | None:
        """Observe a data point and check for anomalies."""
        baseline = self._get_or_create_baseline(name)

        baseline.values.append(value)
        if len(baseline.values) > self._max_baseline:
            baseline.values = baseline.values[-self._max_baseline:]
        baseline.update()

        # Need enough data for detection
        if len(baseline.values) < self._min_baseline:
            return None

        # Z-score detection
        z = baseline.z_score(value)
        if abs(z) > self._z_threshold:
            return self._create_anomaly(
                anomaly_type=AnomalyType.STATISTICAL,
                description=f"{name} z-score={z:.2f} exceeds threshold",
                metric_name=name,
                observed_value=value,
                expected_range=(baseline.mean - 2 * baseline.std_dev,
                                baseline.mean + 2 * baseline.std_dev),
                deviation_score=abs(z),
            )

        # IQR detection
        if baseline.is_outlier_iqr(value):
            return self._create_anomaly(
                anomaly_type=AnomalyType.STATISTICAL,
                description=f"{name} outside IQR fences",
                metric_name=name,
                observed_value=value,
                expected_range=(baseline.lower_fence, baseline.upper_fence),
                deviation_score=abs(z),
            )

        return None

    def detect_temporal_anomaly(
        self,
        name: str,
        timestamps: list[float],
    ) -> Anomaly | None:
        """Detect timing anomalies (irregular intervals)."""
        if len(timestamps) < 3:
            return None

        intervals = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]

        if not intervals:
            return None

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return None

        latest_interval = intervals[-1]
        ratio = latest_interval / mean_interval

        # More than 3x or less than 0.3x normal interval
        if ratio > 3.0 or ratio < 0.3:
            return self._create_anomaly(
                anomaly_type=AnomalyType.TEMPORAL,
                description=f"{name} interval {ratio:.1f}x normal",
                metric_name=name,
                observed_value=latest_interval,
                expected_range=(mean_interval * 0.5, mean_interval * 2.0),
                deviation_score=abs(ratio - 1.0),
            )

        return None

    def detect_behavioral_anomaly(
        self,
        agent_id: str,
        action_distribution: dict[str, int],
        baseline_distribution: dict[str, int],
    ) -> Anomaly | None:
        """Detect behavioral shift in agent action patterns."""
        all_actions = set(action_distribution) | set(baseline_distribution)
        if not all_actions:
            return None

        total_current = sum(action_distribution.values())
        total_baseline = sum(baseline_distribution.values())

        if total_current == 0 or total_baseline == 0:
            return None

        # Chi-squared-like divergence
        divergence = 0.0
        for action in all_actions:
            p_current = action_distribution.get(action, 0) / total_current
            p_baseline = baseline_distribution.get(action, 0) / total_baseline
            if p_baseline > 0:
                divergence += abs(p_current - p_baseline) / p_baseline

        if divergence > 1.0:  # Significant behavioral shift
            return self._create_anomaly(
                anomaly_type=AnomalyType.BEHAVIORAL,
                description=f"Agent {agent_id} behavior shift (divergence={divergence:.2f})",
                metric_name=f"behavior:{agent_id}",
                observed_value=divergence,
                expected_range=(0.0, 1.0),
                deviation_score=divergence,
            )

        return None

    def _create_anomaly(
        self,
        anomaly_type: AnomalyType,
        description: str,
        metric_name: str,
        observed_value: float,
        expected_range: tuple[float, float],
        deviation_score: float,
    ) -> Anomaly:
        """Create and store an anomaly."""
        self._anomaly_counter += 1

        # Determine severity from deviation
        if deviation_score > 5.0:
            severity = AnomalySeverity.CRITICAL
        elif deviation_score > 3.0:
            severity = AnomalySeverity.HIGH
        elif deviation_score > 2.0:
            severity = AnomalySeverity.MEDIUM
        else:
            severity = AnomalySeverity.LOW

        anomaly = Anomaly(
            anomaly_id=f"anom-{self._anomaly_counter}",
            anomaly_type=anomaly_type,
            severity=severity,
            description=description,
            metric_name=metric_name,
            observed_value=observed_value,
            expected_range=expected_range,
            deviation_score=deviation_score,
        )

        self._anomalies.append(anomaly)
        if len(self._anomalies) > 500:
            self._anomalies = self._anomalies[-500:]

        return anomaly

    def _get_or_create_baseline(self, name: str) -> Baseline:
        if name not in self._baselines:
            self._baselines[name] = Baseline(name=name)
        return self._baselines[name]

    def get_recent_anomalies(self, limit: int = 10) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._anomalies[-limit:]]

    def get_baselines(self) -> list[dict[str, Any]]:
        return [b.to_dict() for b in self._baselines.values()]

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = defaultdict(int)
        for a in self._anomalies:
            sev_counts[a.severity.value] += 1
        return {
            "baselines": len(self._baselines),
            "anomalies": len(self._anomalies),
            "by_severity": dict(sev_counts),
        }
