"""Side-effect-free generic run runtime for temperature hold and cycling."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from math import isfinite
from statistics import mean
from typing import Any, Generic, Mapping, Sequence, TypeVar

from .validation_artifact import (AcceptanceCriterion, CriterionOutcome, CriterionResult,
                                  Comparator, ValidationArtifact, ValidationOutcome)


class RunState(StrEnum):
    READY = "ready"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


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
        if not self.targets or any(not isfinite(target) for target in self.targets):
            raise ValueError("temperature cycle requires finite targets")
        if not isfinite(self.tolerance) or self.tolerance < 0:
            raise ValueError("temperature cycle requires a non-negative tolerance")
        if not isfinite(self.hold_seconds) or self.hold_seconds <= 0 or self.cycles <= 0:
            raise ValueError("cycle hold_seconds and cycles must be positive")


ProtocolT = TypeVar("ProtocolT", TemperatureHold, TemperatureCycle)


@dataclass
class ExperimentRun(Generic[ProtocolT]):
    """Generic clock-driven run; the protocol only supplies target phases."""
    run_id: str
    protocol: ProtocolT
    elapsed_seconds: float = 0.0
    state: RunState = RunState.READY
    samples: list[float] = field(default_factory=list)
    phase_index: int = 0
    completed_cycles: int = 0

    def start(self) -> None:
        if self.state is not RunState.READY:
            raise RuntimeError("run can only be started once")
        self.state = RunState.RUNNING

    @property
    def target(self) -> float:
        if isinstance(self.protocol, TemperatureHold):
            return self.protocol.target
        return self.protocol.targets[self.phase_index % len(self.protocol.targets)]

    @property
    def tolerance(self) -> float:
        return self.protocol.tolerance

    def record_temperature(self, value: float, elapsed_seconds: float) -> None:
        if self.state is not RunState.RUNNING:
            raise RuntimeError("temperature can only be recorded while running")
        if isinstance(value, bool) or not isfinite(value) or elapsed_seconds < self.elapsed_seconds:
            raise ValueError("temperature and elapsed_seconds must be finite and monotonic")
        self.elapsed_seconds = elapsed_seconds
        self.samples.append(float(value))
        if isinstance(self.protocol, TemperatureHold):
            if elapsed_seconds >= self.protocol.duration_seconds:
                self.state = RunState.COMPLETE
            return
        if elapsed_seconds >= (self.completed_cycles * len(self.protocol.targets) + self.phase_index + 1) * self.protocol.hold_seconds:
            self.phase_index += 1
            if self.phase_index == len(self.protocol.targets):
                self.phase_index = 0
                self.completed_cycles += 1
            if self.completed_cycles >= self.protocol.cycles:
                self.state = RunState.COMPLETE

    def fail(self) -> None:
        if self.state is RunState.RUNNING:
            self.state = RunState.FAILED


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
    values = [float(item) for item in observations if isinstance(item, (int, float)) and not isinstance(item, bool)] if observations and not isinstance(observations[0], Mapping) else [_metric_value(item, criterion.metric) for item in observations]  # type: ignore[arg-type]
    values = [value for value in values if value is not None and isfinite(value)]
    if not values:
        return CriterionResult(criterion.id, criterion.metric, CriterionOutcome.INCONCLUSIVE, reason="no observations")
    observed = {"mean": mean(values), "min": min(values), "max": max(values), "last": values[-1]}.get(criterion.aggregation)
    if observed is None:
        raise ValueError(f"unsupported aggregation: {criterion.aggregation}")
    if criterion.comparator is Comparator.BETWEEN:
        if criterion.lower_bound is None or criterion.upper_bound is None:
            raise ValueError("between requires lower_bound and upper_bound")
        passed = criterion.lower_bound <= observed <= criterion.upper_bound
    else:
        if criterion.threshold is None:
            raise ValueError(f"{criterion.comparator.value} requires threshold")
        passed = {Comparator.EQ: observed == criterion.threshold, Comparator.LT: observed < criterion.threshold,
                  Comparator.LTE: observed <= criterion.threshold, Comparator.GT: observed > criterion.threshold,
                  Comparator.GTE: observed >= criterion.threshold}[criterion.comparator]
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
