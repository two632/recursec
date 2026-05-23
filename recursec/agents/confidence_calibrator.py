"""Confidence calibrator — calibrates and adjusts confidence scores.

Implements:
1. Model-specific calibration curves
2. Task-type calibration adjustments
3. Historical accuracy tracking
4. Overconfidence detection and correction
5. Underconfidence detection and correction
6. Cross-model confidence normalization
7. Calibration metrics (ECE, MCE, Brier score)
8. Adaptive calibration based on validation feedback
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CalibrationBucket:
    """A bucket for calibration measurement."""
    predicted_confidence: float = 0.0
    actual_accuracy: float = 0.0
    count: int = 0
    total_predicted: float = 0.0
    total_correct: int = 0

    def update(self, predicted: float, correct: bool) -> None:
        self.count += 1
        self.total_predicted += predicted
        if correct:
            self.total_correct += 1
        self.predicted_confidence = self.total_predicted / max(1, self.count)
        self.actual_accuracy = self.total_correct / max(1, self.count)


@dataclass
class ModelCalibration:
    """Calibration data for a specific model."""
    model_name: str = ""
    buckets: list[CalibrationBucket] = field(default_factory=list)
    total_predictions: int = 0
    total_correct: int = 0
    calibration_factor: float = 1.0     # Multiplier to adjust confidence
    offset: float = 0.0                  # Additive offset

    @property
    def accuracy(self) -> float:
        if self.total_predictions == 0:
            return 0.0
        return self.total_correct / self.total_predictions

    @property
    def ece(self) -> float:
        """Expected Calibration Error."""
        if not self.buckets:
            return 0.0
        total = sum(b.count for b in self.buckets)
        if total == 0:
            return 0.0
        weighted_error = sum(
            b.count * abs(b.predicted_confidence - b.actual_accuracy)
            for b in self.buckets
        )
        return weighted_error / total

    @property
    def mce(self) -> float:
        """Maximum Calibration Error."""
        if not self.buckets:
            return 0.0
        return max(
            abs(b.predicted_confidence - b.actual_accuracy)
            for b in self.buckets
            if b.count > 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_name,
            "predictions": self.total_predictions,
            "accuracy": round(self.accuracy, 3),
            "ece": round(self.ece, 3),
            "mce": round(self.mce, 3),
            "factor": round(self.calibration_factor, 3),
        }


@dataclass
class CalibrationRecord:
    """A record of a prediction and its outcome."""
    model: str = ""
    task_type: str = ""
    predicted_confidence: float = 0.0
    was_correct: bool = False
    timestamp: float = field(default_factory=time.time)


class ConfidenceCalibrator:
    """Calibrates confidence scores from LLM outputs.

    Tracks model accuracy over time and applies
    calibration adjustments to produce reliable
    confidence estimates.
    """

    def __init__(self, num_buckets: int = 10) -> None:
        self._num_buckets = num_buckets
        self._model_calibrations: dict[str, ModelCalibration] = {}
        self._task_calibrations: dict[str, float] = {}     # task_type -> adjustment factor
        self._records: list[CalibrationRecord] = []
        self._log = logger.bind(component="confidence_calibrator")

    def calibrate(
        self,
        raw_confidence: float,
        model: str = "",
        task_type: str = "",
    ) -> float:
        """Calibrate a raw confidence score."""
        calibrated = raw_confidence

        # Model-specific calibration
        model_cal = self._model_calibrations.get(model)
        if model_cal:
            calibrated = calibrated * model_cal.calibration_factor + model_cal.offset

        # Task-type adjustment
        task_factor = self._task_calibrations.get(task_type, 1.0)
        calibrated *= task_factor

        # Clamp to [0.01, 0.99]
        return max(0.01, min(0.99, calibrated))

    def record_outcome(
        self,
        model: str,
        task_type: str,
        predicted_confidence: float,
        was_correct: bool,
    ) -> None:
        """Record a prediction outcome for calibration."""
        record = CalibrationRecord(
            model=model,
            task_type=task_type,
            predicted_confidence=predicted_confidence,
            was_correct=was_correct,
        )
        self._records.append(record)

        if len(self._records) > 10000:
            self._records = self._records[-10000:]

        # Update model calibration
        self._update_model_calibration(model, predicted_confidence, was_correct)

        # Update task calibration
        self._update_task_calibration(task_type, predicted_confidence, was_correct)

    def _update_model_calibration(
        self,
        model: str,
        predicted: float,
        correct: bool,
    ) -> None:
        """Update calibration data for a model."""
        if model not in self._model_calibrations:
            cal = ModelCalibration(
                model_name=model,
                buckets=[CalibrationBucket() for _ in range(self._num_buckets)],
            )
            self._model_calibrations[model] = cal

        cal = self._model_calibrations[model]
        cal.total_predictions += 1
        if correct:
            cal.total_correct += 1

        # Update bucket
        bucket_idx = min(self._num_buckets - 1, int(predicted * self._num_buckets))
        cal.buckets[bucket_idx].update(predicted, correct)

        # Recalculate calibration factor
        if cal.total_predictions >= 10:
            self._fit_calibration(cal)

    def _update_task_calibration(
        self,
        task_type: str,
        predicted: float,
        correct: bool,
    ) -> None:
        """Update task-type calibration."""
        # Collect records for this task type
        task_records = [r for r in self._records[-500:] if r.task_type == task_type]

        if len(task_records) < 5:
            return

        avg_predicted = sum(r.predicted_confidence for r in task_records) / len(task_records)
        actual_accuracy = sum(1 for r in task_records if r.was_correct) / len(task_records)

        if avg_predicted > 0:
            self._task_calibrations[task_type] = actual_accuracy / avg_predicted
        else:
            self._task_calibrations[task_type] = 1.0

    def _fit_calibration(self, cal: ModelCalibration) -> None:
        """Fit calibration parameters for a model."""
        # Simple linear calibration: calibrated = raw * factor + offset
        # Minimize difference between predicted confidence and actual accuracy

        points = [
            (b.predicted_confidence, b.actual_accuracy)
            for b in cal.buckets
            if b.count > 0
        ]

        if len(points) < 2:
            return

        # Linear regression
        n = len(points)
        sum_x = sum(p[0] for p in points)
        sum_y = sum(p[1] for p in points)
        sum_xy = sum(p[0] * p[1] for p in points)
        sum_x2 = sum(p[0] ** 2 for p in points)

        denom = n * sum_x2 - sum_x ** 2
        if abs(denom) < 1e-10:
            return

        slope = (n * sum_xy - sum_x * sum_y) / denom
        intercept = (sum_y - slope * sum_x) / n

        cal.calibration_factor = max(0.1, min(3.0, slope))
        cal.offset = max(-0.5, min(0.5, intercept))

    def compute_brier_score(self, model: str = "") -> float:
        """Compute Brier score (lower is better, 0 is perfect)."""
        records = self._records[-1000:]
        if model:
            records = [r for r in records if r.model == model]

        if not records:
            return 1.0

        total = sum(
            (r.predicted_confidence - (1.0 if r.was_correct else 0.0)) ** 2
            for r in records
        )
        return total / len(records)

    def detect_overconfidence(self, model: str) -> bool:
        """Check if a model is systematically overconfident."""
        cal = self._model_calibrations.get(model)
        if not cal or cal.total_predictions < 20:
            return False

        # Overconfident if predicted confidence > actual accuracy by > 0.15
        for bucket in cal.buckets:
            if bucket.count >= 5:
                gap = bucket.predicted_confidence - bucket.actual_accuracy
                if gap > 0.15:
                    return True
        return False

    def detect_underconfidence(self, model: str) -> bool:
        """Check if a model is systematically underconfident."""
        cal = self._model_calibrations.get(model)
        if not cal or cal.total_predictions < 20:
            return False

        for bucket in cal.buckets:
            if bucket.count >= 5:
                gap = bucket.actual_accuracy - bucket.predicted_confidence
                if gap > 0.15:
                    return True
        return False

    def normalize_across_models(
        self,
        scores: dict[str, float],
    ) -> dict[str, float]:
        """Normalize confidence scores across multiple models."""
        if not scores:
            return {}

        # Apply model-specific calibration
        calibrated = {}
        for model, score in scores.items():
            calibrated[model] = self.calibrate(score, model=model)

        # Normalize to sum to 1.0 (useful for voting)
        total = sum(calibrated.values())
        if total > 0:
            return {k: v / total for k, v in calibrated.items()}

        return calibrated

    def get_model_report(self, model: str) -> dict[str, Any]:
        """Get detailed calibration report for a model."""
        cal = self._model_calibrations.get(model)
        if not cal:
            return {"model": model, "status": "no_data"}

        return {
            "model": model,
            "predictions": cal.total_predictions,
            "accuracy": round(cal.accuracy, 3),
            "ece": round(cal.ece, 3),
            "mce": round(cal.mce, 3),
            "brier": round(self.compute_brier_score(model), 3),
            "overconfident": self.detect_overconfidence(model),
            "underconfident": self.detect_underconfidence(model),
            "calibration_factor": round(cal.calibration_factor, 3),
            "offset": round(cal.offset, 3),
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "models_tracked": len(self._model_calibrations),
            "task_types": len(self._task_calibrations),
            "total_records": len(self._records),
            "brier_score": round(self.compute_brier_score(), 3),
        }
