from meta_webui_application_backend.validation_artifact import (AcceptanceCriterion, Comparator, CriterionOutcome,
                                                                 ValidationOutcome)
from meta_webui_application_backend.validation_runtime import (ExperimentRun, TemperatureCycle, TemperatureHold,
                                                               build_validation_artifact, evaluate_criterion)


def test_generic_run_completes_temperature_hold_and_cycle():
    hold = ExperimentRun("hold", TemperatureHold(30, .5, 20))
    hold.start(); hold.record_temperature(30.1, 20)
    assert hold.state.value == "complete" and hold.target == 30
    cycle = ExperimentRun("cycle", TemperatureCycle((20, 30), .5, 10, cycles=2))
    cycle.start()
    for second in (10, 20, 30, 40): cycle.record_temperature(cycle.target, second)
    assert cycle.state.value == "complete" and cycle.completed_cycles == 2


def test_typed_criteria_aggregate_and_report_missing_evidence():
    criterion = AcceptanceCriterion("mean", "temperature_c", Comparator.LTE, threshold=30.5)
    result = evaluate_criterion(criterion, [{"temperature_c": 30}, {"temperature_c": 31}])
    assert result.outcome is CriterionOutcome.PASS and result.observed_value == 30.5
    assert evaluate_criterion(criterion, []).outcome is CriterionOutcome.INCONCLUSIVE


def test_validation_artifact_is_deeply_immutable_and_digest_stable():
    artifact = build_validation_artifact(target_resource="instrument-a", source_run_id="run-a", protocol_id="hold",
        protocol_version="1", criteria=[AcceptanceCriterion("c", "temperature_c", Comparator.GTE, threshold=30)],
        observations=[{"temperature_c": 31}], created_at="2026-09-04T00:00:00Z", created_by="test",
        calibration_artifacts=[{"id": "cal", "meta": {"valid": True}}])
    assert artifact.overall_result is ValidationOutcome.PASS
    try:
        artifact.calibration_artifacts[0]["meta"]["valid"] = False
    except TypeError:
        pass
    else:
        raise AssertionError("artifact evidence is mutable")
    assert artifact.digest == artifact.compute_digest()
