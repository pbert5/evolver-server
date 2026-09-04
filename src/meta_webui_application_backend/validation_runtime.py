"""Side-effect-free generic run runtime for temperature hold and cycling."""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from statistics import mean
from typing import Any, Mapping, Sequence

from .validation_artifact import (AcceptanceCriterion, CriterionOutcome, CriterionResult,
                                  Comparator, ValidationArtifact, ValidationOutcome)


@dataclass(frozen=True)
class TemperatureHold:
    target: float
    tolerance: float
    duration_seconds: float

    def __post_init__(self) -> None:
        if not isfinite(self.target) or not isfinite(self.tolerance) or self.tolerance < 0:
            raise ValueError("temperature target and non-negative tolerance are required")
        if not isfinite(self.duration_seconds) or self.duration_seconds <= 0:
            raise ValueError("hold duration_seconds must be positive")


@dataclass(frozen=True)
class TemperatureCycle:
    targets: tuple[float, ...]
    tolerance: float
    hold_seconds: float
    cycles: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.targets, tuple) or not self.targets or any(not isfinite(target) for target in self.targets):
            raise ValueError("temperature cycle requires finite targets")
        if not isfinite(self.tolerance) or self.tolerance < 0:
            raise ValueError("temperature cycle requires a non-negative tolerance")
        if not isfinite(self.hold_seconds) or self.hold_seconds <= 0 or not isinstance(self.cycles, int) or isinstance(self.cycles, bool) or self.cycles <= 0:
            raise ValueError("cycle hold_seconds and cycles must be positive")


def temperature_phase(protocol: TemperatureHold | TemperatureCycle, elapsed_seconds: float) -> dict[str, Any]:
    """Return the phase for a durable run projection without mutating it.

    Lifecycle and observations belong to the edge ``ExperimentRun`` store;
    this helper only interprets an elapsed-time value for validation/UI code.
    """
    if isinstance(elapsed_seconds, bool) or not isfinite(elapsed_seconds) or elapsed_seconds < 0:
        raise ValueError("elapsed_seconds must be finite and non-negative")
    if isinstance(protocol, TemperatureHold):
        return {"target": protocol.target, "phase_index": 0,
                "completed_cycles": 0, "complete": elapsed_seconds >= protocol.duration_seconds}
    phase_count = len(protocol.targets)
    phase_number = min(int(elapsed_seconds // protocol.hold_seconds), phase_count * protocol.cycles - 1)
    return {"target": protocol.targets[phase_number % phase_count],
            "phase_index": phase_number % phase_count,
            "completed_cycles": phase_number // phase_count,
            "complete": elapsed_seconds >= phase_count * protocol.cycles * protocol.hold_seconds}


def _metric_value(observation: Mapping[str, Any], metric: str) -> float | None:
    value: Any = observation.get(metric)
    if value is None and metric == "temperature.absolute_error":
        value = observation.get("absolute_error")
    if value is None and metric in {"temperature", "temperature_c"}:
        value = observation.get("temperature_c", observation.get("temperature"))
    if value is None and isinstance(observation.get("payload"), Mapping):
        return _metric_value(observation["payload"], metric)
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and isfinite(float(value)) else None


def evaluate_criterion(criterion: AcceptanceCriterion, observations: Sequence[Mapping[str, Any] | float]) -> CriterionResult:
    if criterion.aggregation not in {"mean", "min", "max", "last"}:
        raise ValueError(f"unsupported aggregation: {criterion.aggregation}")
    values = [_metric_value(item, criterion.metric) if isinstance(item, Mapping) else
              float(item) if isinstance(item, (int, float)) and not isinstance(item, bool) else None
              for item in observations]
    values = [value for value in values if value is not None and isfinite(value)]
    if not values:
        return CriterionResult(criterion.id, criterion.metric, CriterionOutcome.INCONCLUSIVE, reason="no observations")
    observed = {"mean": mean(values), "min": min(values), "max": max(values), "last": values[-1]}[criterion.aggregation]
    comparator = criterion.comparator if isinstance(criterion.comparator, Comparator) else Comparator(criterion.comparator)
    if comparator is Comparator.BETWEEN:
        if criterion.lower_bound is None or criterion.upper_bound is None:
            raise ValueError("between requires lower_bound and upper_bound")
        passed = criterion.lower_bound <= observed <= criterion.upper_bound
    else:
        if criterion.threshold is None:
            raise ValueError(f"{comparator.value} requires threshold")
        passed = {Comparator.EQ: observed == criterion.threshold, Comparator.LT: observed < criterion.threshold,
                  Comparator.LTE: observed <= criterion.threshold, Comparator.GT: observed > criterion.threshold,
                  Comparator.GTE: observed >= criterion.threshold}[comparator]
    return CriterionResult(criterion.id, criterion.metric, CriterionOutcome.PASS if passed else CriterionOutcome.FAIL, observed)


def evaluate_criteria(criteria: Sequence[AcceptanceCriterion], observations: Sequence[Mapping[str, Any] | float]) -> tuple[tuple[CriterionResult, ...], ValidationOutcome]:
    results = tuple(evaluate_criterion(c, observations) for c in criteria)
    if any(r.outcome is CriterionOutcome.FAIL and c.required for r, c in zip(results, criteria)):
        overall = ValidationOutcome.FAIL
    elif any(r.outcome is CriterionOutcome.INCONCLUSIVE and c.required for r, c in zip(results, criteria)):
        overall = ValidationOutcome.INCONCLUSIVE
    elif any(r.outcome is CriterionOutcome.FAIL for r in results):
        overall = ValidationOutcome.DEGRADED
    else:
        overall = ValidationOutcome.PASS
    return results, overall


def build_validation_artifact(*, target_resource: str, source_run_id: str, protocol_id: str, protocol_version: str,
                              criteria: Sequence[AcceptanceCriterion], observations: Sequence[Mapping[str, Any] | float],
                              created_at: str, created_by: str, calibration_artifacts: Sequence[Mapping[str, Any]] = (),
                              raw_evidence_references: Sequence[str] = ()) -> ValidationArtifact:
    results, overall = evaluate_criteria(criteria, observations)
    return ValidationArtifact(target_resource, source_run_id, protocol_id, protocol_version, results, overall,
                              created_at, created_by, tuple(calibration_artifacts), tuple(raw_evidence_references))
