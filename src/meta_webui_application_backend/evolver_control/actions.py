"""Central eVOLVER action adapter.

This is the application boundary for named central actions.  It deliberately
contains no state or policy of its own: action handlers call the existing
``evolver_controller`` routes/functions, which remain authoritative for
authorization, fencing, idempotency, audit facts, and queued-vs-applied
semantics.
"""
from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from typing import Any, Mapping

from .. import evolver_controller


class UnknownAction(ValueError):
    """Raised when a caller supplies an action outside this adapter contract."""


# Stable catalog ids are the trusted adapter registry.  Values are translated
# to existing domain seams below; no catalog string is imported or evaluated.
ACTION_ADAPTERS = {
    "evolver.edge.status": "controllers",
    "evolver.edge.controllers": "controllers",
    "evolver.edge.instruments": "instruments",
    "evolver.edge.runs": "runs",
    "evolver.controllers.list": "controllers",
    "evolver.controllers.show": "controllers",
    "evolver.controllers.freshness": "controller_freshness",
    "evolver.controllers.add": "enrollment_token",
    "evolver.controllers.refresh": "refresh",
    "evolver.controllers.rescan": "hardware_rescan",
    "evolver.controllers.archive": "archive_controller",
    "evolver.controllers.restore": "restore_controller",
    "evolver.controllers.release.set": "desired_release",
    "evolver.controllers.commands.list": "commands",
    "evolver.controllers.commands.show": "commands",
    "evolver.controllers.recovery.request": "recovery",
    "evolver.controllers.recovery.status": "recovery",
    "evolver.controllers.recovery.diff": "recovery_diff",
    "evolver.instruments.list": "instruments",
    "evolver.instruments.show": "instruments",
    "evolver.runs.list": "runs",
    "evolver.runs.show": "runs",
    "evolver.runs.pause": "pause_run",
    "evolver.runs.resume": "resume_run",
    "evolver.runs.stop": "stop_run",
    "evolver.experiments.validate": "experiment_validate",
    "evolver.experiments.describe": "experiment_describe",
    "evolver.experiments.plan": "experiment_plan",
    "evolver.release.build": "release_build",
}


def _body(parameters: Mapping[str, Any]) -> dict[str, Any]:
    return dict(parameters)


def _operator_required(operator: evolver_controller.OperatorIdentity | None,
                       permission: str) -> tuple[HTTPStatus, dict[str, Any]] | None:
    # A small explicit check is needed only for controller functions whose
    # public route adds the authorization gate before calling the function.
    return evolver_controller._require_operator(operator, permission)


def dispatch(action: str, parameters: Mapping[str, Any] | None = None, *,
             operator: evolver_controller.OperatorIdentity | None = None,
             state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Dispatch one named central action to the existing controller seam.

    ``parameters`` is request data, not executable code.  Responses preserve
    the controller's status and payload so callers can distinguish accepted
    (queued intent) from completed/applied evidence.
    """
    if not isinstance(action, str) or not action:
        raise UnknownAction("action must be a non-empty string")
    action = ACTION_ADAPTERS.get(action, action)
    params = parameters if isinstance(parameters, Mapping) else {}
    body = _body(params)

    # Read projections and durable command facts.
    if action in {"controllers", "evolver.controllers"}:
        return evolver_controller.controllers(controller_id=params.get("controller_id"), state_root=state_root)
    if action in {"instruments", "evolver.instruments"}:
        return evolver_controller.instruments(instrument_id=params.get("instrument_id"), state_root=state_root)
    if action in {"runs", "evolver.runs"}:
        return evolver_controller.runs(run_id=params.get("run_id"), state_root=state_root)
    if action in {"commands", "command", "evolver.commands"}:
        return evolver_controller.command_projection(str(params.get("controller_id", "")), params.get("command_id"), state_root=state_root)
    if action in {"controller_freshness", "evolver.controller_freshness"}:
        return evolver_controller.controller_freshness(controller_id=params.get("controller_id"), state_root=state_root)
    if action in {"recovery", "recovery_manifest", "evolver.recovery"}:
        controller_id = str(params.get("controller_id", ""))
        if params.get("request") is True:
            denied = _operator_required(operator, "recover_controller")
            if denied:
                return denied
            return evolver_controller.request_recovery_manifest(
                controller_id, requested_by=operator.subject, auth_source=operator.source, state_root=state_root)
        status, projection = evolver_controller.controllers(controller_id=controller_id, state_root=state_root)
        if status is not HTTPStatus.OK:
            return status, projection
        manifest = projection["controller"].get("recovery_manifest")
        return HTTPStatus.OK, {"controller_id": controller_id, "recovery_manifest": manifest,
                               "webui_controller": projection["webui_controller"]}

    # Enrollment is split between operator-issued tokens and machine enrollment.
    if action in {"enrollment_token", "create_enrollment_token", "evolver.enrollment_token"}:
        denied = _operator_required(operator, "manage_controller")
        if denied:
            return denied
        return evolver_controller.create_enrollment_token(
            server_url=body.get("server_url", ""),
            ttl_seconds=body.get("ttl_seconds", evolver_controller.DEFAULT_TOKEN_TTL_SECONDS),
            purpose=body.get("purpose", "enrollment"), release_binding=body.get("release_binding"),
            state_root=state_root)
    if action in {"enroll", "evolver.enroll"}:
        return evolver_controller.enroll(body, state_root=state_root)

    controller_id = params.get("controller_id")
    if action in {"refresh", "controller_refresh", "evolver.controller_refresh"}:
        return evolver_controller.request_controller_refresh(str(controller_id), body, operator=operator, state_root=state_root)
    if action in {"hardware_rescan", "controller_hardware_rescan", "evolver.controller_hardware_rescan"}:
        return evolver_controller.request_controller_refresh(str(controller_id), body, operator=operator, hardware=True, state_root=state_root)
    if action in {"assign_endpoint", "assign_controller_endpoint", "evolver.assign_controller_endpoint"}:
        return evolver_controller.assign_controller_endpoint(str(controller_id), body, operator=operator, state_root=state_root)
    if action in {"desired_release", "controller_set_desired_release", "evolver.controller_set_desired_release"}:
        return evolver_controller.set_desired_release(str(controller_id), body, operator=operator, state_root=state_root)
    if action in {"archive_controller", "evolver.archive_controller"}:
        return evolver_controller.archive_controller(str(controller_id), operator=operator, state_root=state_root)
    if action in {"restore_controller", "evolver.restore_controller"}:
        return evolver_controller.archive_controller(str(controller_id), operator=operator, state_root=state_root, restore=True)
    if action in {"rollback", "controller_rollback", "evolver.controller_rollback"}:
        return evolver_controller.request_rollback(str(controller_id), body, operator=operator, state_root=state_root)

    if action in {"lease", "manual_control_lease", "evolver.manual_control_lease"}:
        return evolver_controller.manual_control_lease(str(controller_id), body, operator=operator,
                                                       action=str(params.get("lease_action", "acquire")), state_root=state_root)
    if action in {"manual_command", "instrument_manual_command", "evolver.instrument_manual_command"}:
        return evolver_controller.manual_control_command(str(controller_id), body, operator=operator, state_root=state_root)

    if action in {"run_command", "evolver.run_command", "pause_run", "resume_run", "stop_run"}:
        run_id = str(params.get("run_id", ""))
        command_body = dict(body)
        if action in {"pause_run", "resume_run", "stop_run"}:
            command_body.setdefault("action", action.removesuffix("_run"))
        denied = _operator_required(operator, "operate_run")
        if denied:
            return denied
        return evolver_controller.mutate_run(run_id, command_body, requested_by=operator.subject,
                                             auth_source=operator.source, state_root=state_root)
    if action in {"run_resources", "evolver.run_resources"}:
        return evolver_controller.run_resources(str(params.get("run_id", "")), state_root=state_root)
    if action in {"add_run_resource", "release_run_resource", "replace_run_resource", "confirm_run_move"}:
        operation = {"add_run_resource": "add", "release_run_resource": "release",
                     "replace_run_resource": "replace", "confirm_run_move": "confirm_move"}[action]
        return evolver_controller.mutate_run_resource(
            str(params.get("run_id", "")), body, operator=operator,
            assignment_id=params.get("assignment_id"), action=operation, state_root=state_root)
    if action in {"recovery_diff", "evolver.recovery_diff"}:
        return evolver_controller.recovery_diff(str(controller_id), state_root=state_root)
    if action in {"recovery_import", "evolver.recovery_import"}:
        denied = _operator_required(operator, "recover_controller")
        if denied:
            return denied
        return evolver_controller.import_recovery_snapshot(str(controller_id), body, state_root=state_root)

    if action == "experiment_validate":
        if not isinstance(body.get("definition"), dict):
            return HTTPStatus.BAD_REQUEST, {"error": "definition must be a JSON object", "kind": "BadRequest"}
        from ..experiment_actions import validate_experiment
        return HTTPStatus.OK, validate_experiment(body["definition"], body.get("selected_calibration_artifacts", []), resolved_at=str(body.get("resolved_at", "")))
    if action == "experiment_describe":
        if not isinstance(body.get("definition"), dict):
            return HTTPStatus.BAD_REQUEST, {"error": "definition must be a JSON object", "kind": "BadRequest"}
        from ..experiment_actions import describe_experiment
        return HTTPStatus.OK, describe_experiment(body["definition"])
    if action == "experiment_plan":
        if not isinstance(body.get("bundle"), dict):
            return HTTPStatus.BAD_REQUEST, {"error": "bundle must be a JSON object", "kind": "BadRequest"}
        from ..experiment_actions import plan_experiment
        return HTTPStatus.OK, plan_experiment(body["bundle"], state=body.get("state"), run_id=body.get("run_id"), target_temperature=body.get("target_temperature"), required_capabilities=body.get("required_capabilities"))
    if action == "release_build":
        from ..server_release_actions import release_build
        return release_build(body, operator=operator)

    raise UnknownAction(f"unknown central eVOLVER action: {action}")


class CentralEvolverActionAdapter:
    """Injectable adapter for application callers and focused contract tests."""

    def __init__(self, *, state_root: Path | None = None) -> None:
        self.state_root = state_root

    def dispatch(self, action: str, parameters: Mapping[str, Any] | None = None, *,
                 operator: evolver_controller.OperatorIdentity | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
        return dispatch(action, parameters, operator=operator, state_root=self.state_root)
