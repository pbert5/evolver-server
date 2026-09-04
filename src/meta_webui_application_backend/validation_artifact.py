"""Typed, immutable validation results.

This module is deliberately independent of persistence and instrument control.
It turns an evaluated validation plan into evidence that can safely be passed
between the runtime and a caller without exposing mutable nested dictionaries.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class Comparator(str, Enum):
    EQ = "eq"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    BETWEEN = "between"


class CriterionOutcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    NOT_EVALUATED = "not_evaluated"


class ValidationOutcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    DEGRADED = "degraded"


class CriterionSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class AcceptanceCriterion:
    id: str
    metric: str
    comparator: Comparator
    threshold: float | None = None
    lower_bound: float | None = None
    upper_bound: float | None = None
    aggregation: str = "mean"
    unit: str | None = None
    severity: CriterionSeverity = CriterionSeverity.ERROR
    required: bool = True


@dataclass(frozen=True)
class CriterionResult:
    criterion_id: str
    metric: str
    outcome: CriterionOutcome
    observed_value: float | None = None
    evidence_reference: str | None = None
    reason: str | None = None


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(k): _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    if isinstance(value, (frozenset, set)):
        return sorted(_plain(item) for item in value)
    if isinstance(value, Enum):
        return value.value
    return value


@dataclass(frozen=True)
class ValidationArtifact:
    target_resource: str
    source_run_id: str
    protocol_id: str
    protocol_version: str
    criterion_results: tuple[CriterionResult, ...]
    overall_result: ValidationOutcome
    created_at: str
    created_by: str
    calibration_artifacts: tuple[Mapping[str, Any], ...] = ()
    raw_evidence_references: tuple[str, ...] = ()
    digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "criterion_results", tuple(self.criterion_results))
        object.__setattr__(self, "calibration_artifacts", tuple(_freeze(x) for x in self.calibration_artifacts))
        object.__setattr__(self, "raw_evidence_references", tuple(self.raw_evidence_references))
        if not self.digest:
            object.__setattr__(self, "digest", self.compute_digest())
        elif self.digest != self.compute_digest():
            raise ValueError("digest does not match validation artifact content")

    def _content(self) -> dict[str, Any]:
        return {"target_resource": self.target_resource, "source_run_id": self.source_run_id,
                "protocol_id": self.protocol_id, "protocol_version": self.protocol_version,
                "criterion_results": [_plain(result.__dict__) for result in self.criterion_results],
                "overall_result": self.overall_result.value, "created_at": self.created_at,
                "created_by": self.created_by, "calibration_artifacts": _plain(self.calibration_artifacts),
                "raw_evidence_references": list(self.raw_evidence_references)}

    def compute_digest(self) -> str:
        encoded = json.dumps(self._content(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def to_dict(self) -> dict[str, Any]:
        result = self._content()
        result["digest"] = self.digest
        return result
