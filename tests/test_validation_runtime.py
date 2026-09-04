import pytest

from meta_webui_application_backend.evolver_edge import EdgeStore, canonical_digest
from meta_webui_application_backend.validation_artifact import (AcceptanceCriterion, Comparator, CriterionOutcome,
                                                                 ValidationOutcome)
from meta_webui_application_backend.validation_runtime import (TemperatureCycle, TemperatureHold,
                                                               build_validation_artifact, evaluate_criterion,
                                                               temperature_phase)


def test_temperature_phase_is_pure_for_hold_and_cycle():
    hold = TemperatureHold(30, .5, 20)
    assert temperature_phase(hold, 20) == {"target": 30, "phase_index": 0, "completed_cycles": 0, "complete": True}
    cycle = TemperatureCycle((20, 30), .5, 10, cycles=2)
    assert temperature_phase(cycle, 0)["target"] == 20
    assert temperature_phase(cycle, 10)["target"] == 30
    assert temperature_phase(cycle, 20) == {"target": 20, "phase_index": 0, "completed_cycles": 1, "complete": False}
    assert temperature_phase(cycle, 40)["complete"] is True
    with pytest.raises(ValueError): temperature_phase(cycle, -1)


def test_durable_edge_experiment_run_is_canonical(tmp_path):
    bundle = {"id": "temperature-hold", "name": "temperature hold", "purpose": "validation",
              "schema_version": "1", "execution_mode": "declarative_state_machine",
              "source": {"experiment_id": "temperature-hold", "dataset_revision": "1",
                          "created_at": "2026-09-04T00:00:00Z"},
              "resolved_definition": {"content": {}, "media_type": "application/json"},
              "execution_plan": {"content": {"target": 30}, "media_type": "application/json"},
              "runtime_parameters": [], "source_metadata": []}
    bundle["digest"] = canonical_digest(bundle)
    with EdgeStore(tmp_path) as edge:
        edge.put_bundle(bundle)
        edge.create_run(run_id="hold", bundle_id="temperature-hold", instrument_ids=["instrument-a"])
        run = edge.transition_run(run_id="hold", state="running", based_on_revision=0)
        assert run["state"] == "running" and run["current_revision"] == 1
    with EdgeStore(tmp_path) as restarted:
        assert restarted.run("hold")["current_revision"] == 1
        assert restarted.events_after("hold")[-1]["event_type"] == "run_started"


def test_typed_criteria_aggregate_and_report_missing_evidence():
    criterion = AcceptanceCriterion("mean", "temperature_c", Comparator.LTE, threshold=30.5)
    result = evaluate_criterion(criterion, [{"temperature_c": 30}, {"temperature_c": 31}])
    assert result.outcome is CriterionOutcome.PASS and result.observed_value == 30.5
    assert evaluate_criterion(criterion, []).outcome is CriterionOutcome.INCONCLUSIVE
    mixed = evaluate_criterion(criterion, [{"temperature_c": 30}, "bad", 31])
    assert mixed.observed_value == 30.5
    with pytest.raises(ValueError):
        evaluate_criterion(AcceptanceCriterion("bad", "temperature_c", Comparator.LTE,
                                                threshold=30, aggregation="median"), [])


def test_validation_artifact_is_deeply_immutable_and_digest_stable():
    calibration = {"id": "cal", "meta": {"valid": True}}
    artifact = build_validation_artifact(target_resource="instrument-a", source_run_id="run-a", protocol_id="hold",
        protocol_version="1", criteria=[AcceptanceCriterion("c", "temperature_c", Comparator.GTE, threshold=30)],
        observations=[{"temperature_c": 31}], created_at="2026-09-04T00:00:00Z", created_by="test",
        calibration_artifacts=[calibration])
    assert artifact.overall_result is ValidationOutcome.PASS
    try:
        artifact.calibration_artifacts[0]["meta"]["valid"] = False
    except TypeError:
        pass
    else:
        raise AssertionError("artifact evidence is mutable")
    calibration["meta"]["valid"] = False
    assert artifact.calibration_artifacts[0]["meta"]["valid"] is True
    assert artifact.digest == artifact.compute_digest()
