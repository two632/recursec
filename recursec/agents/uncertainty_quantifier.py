"""Uncertainty quantifier — estimates and propagates uncertainty in agent outputs.

Implements:
1. Confidence calibration (predicted vs actual accuracy)
2. Epistemic uncertainty (model doesn't know)
3. Aleatoric uncertainty (inherent noise)
4. Monte Carlo dropout-style estimation
5. Ensemble disagreement as uncertainty
6. Uncertainty propagation through reasoning chains
7. Calibration curve computation
8. Selective prediction (abstain when uncertain)
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class UncertaintyEstimate:
    """An uncertainty estimate for a prediction."""
    estimate_id: str = ""
    source: str = ""              # What produced this estimate
    predicted_confidence: float = 0.5
    epistemic: float = 0.0        # How much we don't know
    aleatoric: float = 0.0        # Inherent randomness
    total_uncertainty: float = 0.0
    should_abstain: bool = False
    timestamp: float = field(default_factory=time.time)

    @property
    def is_reliable(self) -> bool:
        return self.total_uncertainty < 0.4 and not self.should_abstain

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.estimate_id,
            "source": self.source[:15],
            "confidence": round(self.predicted_confidence, 3),
            "epistemic": round(self.epistemic, 3),
            "aleatoric": round(self.aleatoric, 3),
            "total": round(self.total_uncertainty, 3),
            "reliable": self.is_reliable,
        }


@dataclass
class CalibrationBin:
    """A bin for calibration curve computation."""
    bin_start: float = 0.0
    bin_end: float = 0.1
    predictions: int = 0
    correct: int = 0

    @property
    def accuracy(self) -> float:
        if self.predictions == 0:
            return 0.0
        return self.correct / self.predictions

    @property
    def avg_confidence(self) -> float:
        return (self.bin_start + self.bin_end) / 2

    @property
    def calibration_error(self) -> float:
        return abs(self.accuracy - self.avg_confidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "range": f"{self.bin_start:.1f}-{self.bin_end:.1f}",
            "predictions": self.predictions,
            "accuracy": round(self.accuracy, 3),
            "error": round(self.calibration_error, 3),
        }


@dataclass
class PredictionRecord:
    """A recorded prediction for calibration."""
    predicted_confidence: float = 0.5
    was_correct: bool = False
    task_type: str = ""
    model_id: str = ""
    timestamp: float = field(default_factory=time.time)


class UncertaintyQuantifier:
    """Estimates and propagates uncertainty in agent outputs.

    Tracks prediction accuracy, computes calibration curves,
    and helps agents know when they don't know.
    """

    def __init__(
        self,
        num_bins: int = 10,
        abstain_threshold: float = 0.6,
    ) -> None:
        self._records: list[PredictionRecord] = []
        self._bins: list[CalibrationBin] = []
        self._estimate_counter = 0
        self._abstain_threshold = abstain_threshold
        self._model_calibration: dict[str, float] = {}
        self._task_uncertainty: dict[str, list[float]] = defaultdict(list)
        self._log = logger.bind(component="uncertainty_quantifier")

        # Initialize calibration bins
        for i in range(num_bins):
            self._bins.append(CalibrationBin(
                bin_start=i / num_bins,
                bin_end=(i + 1) / num_bins,
            ))

    def estimate(
        self,
        source: str,
        predicted_confidence: float,
        model_outputs: list[float] | None = None,
        task_type: str = "",
    ) -> UncertaintyEstimate:
        """Estimate uncertainty for a prediction."""
        self._estimate_counter += 1

        # Epistemic uncertainty from ensemble disagreement
        epistemic = 0.0
        if model_outputs and len(model_outputs) > 1:
            mean_out = sum(model_outputs) / len(model_outputs)
            variance = sum((x - mean_out) ** 2 for x in model_outputs) / len(model_outputs)
            epistemic = math.sqrt(variance)

        # Aleatoric uncertainty from task difficulty history
        aleatoric = 0.0
        task_history = self._task_uncertainty.get(task_type, [])
        if task_history:
            aleatoric = sum(task_history[-20:]) / len(task_history[-20:])

        # Calibration adjustment
        calibration_offset = self._model_calibration.get(source, 0.0)
        adjusted_confidence = max(0.01, min(0.99,
            predicted_confidence - calibration_offset
        ))

        total = math.sqrt(epistemic ** 2 + aleatoric ** 2)
        effective_uncertainty = total + (1.0 - adjusted_confidence) * 0.5

        should_abstain = effective_uncertainty > self._abstain_threshold

        return UncertaintyEstimate(
            estimate_id=f"ue-{self._estimate_counter}",
            source=source,
            predicted_confidence=adjusted_confidence,
            epistemic=epistemic,
            aleatoric=aleatoric,
            total_uncertainty=effective_uncertainty,
            should_abstain=should_abstain,
        )

    def record_outcome(
        self,
        predicted_confidence: float,
        was_correct: bool,
        task_type: str = "",
        model_id: str = "",
    ) -> None:
        """Record prediction outcome for calibration."""
        record = PredictionRecord(
            predicted_confidence=predicted_confidence,
            was_correct=was_correct,
            task_type=task_type,
            model_id=model_id,
        )
        self._records.append(record)

        if len(self._records) > 2000:
            self._records = self._records[-2000:]

        # Update calibration bin
        for cal_bin in self._bins:
            if cal_bin.bin_start <= predicted_confidence < cal_bin.bin_end:
                cal_bin.predictions += 1
                if was_correct:
                    cal_bin.correct += 1
                break

        # Update task uncertainty
        uncertainty_val = 0.0 if was_correct else 1.0
        self._task_uncertainty[task_type].append(uncertainty_val)
        if len(self._task_uncertainty[task_type]) > 100:
            self._task_uncertainty[task_type] = self._task_uncertainty[task_type][-100:]

        # Update model calibration offset
        self._update_model_calibration(model_id)

    def _update_model_calibration(self, model_id: str) -> None:
        """Update calibration offset for a model."""
        model_records = [r for r in self._records[-200:] if r.model_id == model_id]
        if len(model_records) < 10:
            return

        # Compute average overconfidence
        overconfidence = sum(
            r.predicted_confidence - (1.0 if r.was_correct else 0.0)
            for r in model_records
        ) / len(model_records)

        self._model_calibration[model_id] = overconfidence

    def propagate_uncertainty(
        self,
        uncertainties: list[float],
        method: str = "product",
    ) -> float:
        """Propagate uncertainty through a chain of reasoning steps."""
        if not uncertainties:
            return 0.0

        if method == "product":
            # Each step multiplies reliability
            reliability = 1.0
            for u in uncertainties:
                reliability *= (1.0 - u)
            return 1.0 - reliability

        if method == "max":
            return max(uncertainties)

        if method == "average":
            return sum(uncertainties) / len(uncertainties)

        return max(uncertainties)

    def get_calibration_curve(self) -> list[dict[str, Any]]:
        """Get calibration curve data."""
        return [b.to_dict() for b in self._bins if b.predictions > 0]

    def get_expected_calibration_error(self) -> float:
        """Compute Expected Calibration Error (ECE)."""
        total_predictions = sum(b.predictions for b in self._bins)
        if total_predictions == 0:
            return 0.0

        ece = sum(
            b.predictions / total_predictions * b.calibration_error
            for b in self._bins
        )
        return ece

    def get_model_calibration(self) -> dict[str, float]:
        """Get calibration offsets per model."""
        return {k: round(v, 3) for k, v in self._model_calibration.items()}

    def get_stats(self) -> dict[str, Any]:
        return {
            "records": len(self._records),
            "estimates": self._estimate_counter,
            "ece": round(self.get_expected_calibration_error(), 4),
            "model_calibrations": len(self._model_calibration),
            "task_types": len(self._task_uncertainty),
        }
