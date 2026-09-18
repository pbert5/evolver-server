"""Small, side-effect-free helpers for eVOLVER calibration evidence.

Blank readings are evidence emitted by an edge.  They are deliberately not a
calibration artifact: a blank can be reviewed later, but it cannot establish an
OD600 transform or be distributed as one.
"""
from __future__ import annotations

import math
from statistics import mean, pstdev
from typing import Any, Mapping, Sequence


PUMP_COMPONENTS = tuple(f"P{index}" for index in range(6))


def pump_component(value: Any) -> str:
    if not isinstance(value, str) or value not in PUMP_COMPONENTS:
        raise ValueError("pump component_id must be one of P0-P5")
    return value


def blank_record(record: Mapping[str, Any], *, controller_id: str, controller_generation: int) -> dict[str, Any]:
    """Validate and normalize one edge-owned, read-only OD blank observation."""
    if not isinstance(record, Mapping):
        raise ValueError("OD blank record must be an object")
    instrument_id = record.get("instrument_id")
    if not isinstance(instrument_id, str) or not instrument_id:
        raise ValueError("OD blank record requires instrument_id")
    channel = record.get("channel_index", record.get("channel"))
    if not isinstance(channel, int) or isinstance(channel, bool) or not 0 <= channel <= 5:
        raise ValueError("OD blank channel_index must be an integer from 0 to 5")
    raw_adc = record.get("raw_adc", record.get("raw_value"))
    if not isinstance(raw_adc, (int, float)) or isinstance(raw_adc, bool) or not math.isfinite(float(raw_adc)):
        raise ValueError("OD blank record requires finite raw_adc")
    identity = record.get("blank_id", record.get("sample_id", record.get("id")))
    if not isinstance(identity, str) or not identity.strip():
        raise ValueError("OD blank record requires blank_id, sample_id, or id")
    captured_at = record.get("captured_at", record.get("timestamp"))
    if not isinstance(captured_at, str) or not captured_at:
        raise ValueError("OD blank record requires captured_at")
    result = dict(record)
    result.update({
        "record_id": str(record.get("record_id", record.get("id", f"{identity}:{channel}:{captured_at}"))),
        "blank_id": identity,
        "instrument_id": instrument_id,
        "channel_index": channel,
        "raw_adc": raw_adc,
        "captured_at": captured_at,
        "controller_id": controller_id,
        "controller_generation": controller_generation,
        "evidence_type": "od_blank",
        "read_only": True,
    })
    return result


def blank_statistics(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return deterministic replicate statistics grouped by blank identity."""
    groups: dict[tuple[str, int, str], list[float]] = {}
    for record in records:
        key = (str(record["instrument_id"]), int(record["channel_index"]), str(record["blank_id"]))
        groups.setdefault(key, []).append(float(record["raw_adc"]))
    result = []
    for (instrument_id, channel_index, blank_id), values in sorted(groups.items()):
        result.append({
            "instrument_id": instrument_id,
            "channel_index": channel_index,
            "blank_id": blank_id,
            "replicates": len(values),
            "raw_adc_values": values,
            "raw_adc_mean": mean(values),
            "raw_adc_stddev": pstdev(values) if len(values) > 1 else 0.0,
            "raw_adc_min": min(values),
            "raw_adc_max": max(values),
        })
    return result
