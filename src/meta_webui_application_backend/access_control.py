"""Application-wide authentication, roles, permissions, and runtime overrides.

The authored session YAML is the baseline. PostgreSQL stores only runtime
materialization, overrides, audit facts, and opaque development sessions.
Nothing in this module trusts a browser-selected username as authentication.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from .db import DatabaseUnavailableError, connection

SESSION_COOKIE = "meta_webui_session"
SESSION_TTL = timedelta(hours=8)
TRUSTED_PROXY_SECRET_HEADER = "X-Meta-Webui-Trusted-Proxy-Secret"
PERMISSIONS = ("view", "operate_run", "manage_controller", "manage_calibration", "recover_controller", "update_controller", "hardware_maintenance", "manage_access", "view_runtime_debug")


@dataclass(frozen=True)
class AuthenticatedIdentity:
    username: str
    source: str
    permissions: frozenset[str]


def _root() -> Path:
    return Path(os.environ.get("META_WEBUI_REPOSITORY_ROOT", Path.cwd()))


def baseline() -> dict[str, Any]:
    root = _root()
    # Deployment composition owns the application-wide session contract. Keep
    # the old singular path as a compatibility fallback for standalone legacy
    # layouts, but never let it shadow the current authoritative file.
    paths = (
        root / "applications" / "deployment" / "webui" / "session.yaml",
        root / "application" / "webui" / "session.yaml",
    )
    path = next((candidate for candidate in paths if candidate.is_file()), None)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path else {}
    session = raw.get("session", {}) if isinstance(raw, dict) else {}
    return session if isinstance(session, dict) else {}


def development_auth_enabled() -> bool:
    profile = os.environ.get("META_WEBUI_PROFILE", "").strip().lower()
    if profile not in {"development", "test"}:
        return False
    value = os.environ.get("META_WEBUI_DEVELOPMENT_AUTH", "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def request_is_trusted_proxy(headers: Any) -> bool:
    """Prove that a request came through the configured identity perimeter."""
    expected = os.environ.get("META_WEBUI_TRUSTED_PROXY_SECRET", "")
    supplied = headers.get(TRUSTED_PROXY_SECRET_HEADER, "") if hasattr(headers, "get") else ""
    return bool(expected and isinstance(supplied, str) and secrets.compare_digest(supplied, expected))


def _effective_for_user(row: dict[str, Any], configured: dict[str, Any], override: dict[str, Any] | None, role_map: dict[str, dict[str, Any]], permission_map: dict[str, dict[str, Any]]) -> dict[str, Any]:
    username = str(row["username"])
    configured_user = configured.get(username) if isinstance(configured.get(username), dict) else None
    configured_role = str((configured_user or {}).get("role") or row.get("configured_role") or row.get("role") or "guest")
    effective_role = str((override or {}).get("role_name_override") or configured_role)
    configured_active = bool((configured_user or {}).get("active", True))
    effective_active = bool((override or {}).get("active_override")) if override and override.get("active_override") is not None else configured_active if configured_user else bool(row.get("is_active", True))
    role_definition = role_map.get(effective_role, {})
    configured_role_definition = role_map.get(configured_role, {})
    configured_permissions = list((configured_role_definition or {}).get("permissions", []))
    effective_permissions = list((role_definition or {}).get("permissions", []))
    role_override = row.get("role_override") if isinstance(row.get("role_override"), dict) else None
    role_runtime_override = role_definition.get("runtime_override") if isinstance(role_definition.get("runtime_override"), dict) else None
    for permission_override in (role_runtime_override, role_override):
        if permission_override:
            disabled = set(permission_override.get("disabled_permissions") or [])
            effective_permissions = [permission for permission in effective_permissions if permission not in disabled]
            effective_permissions.extend(permission for permission in permission_override.get("added_permissions") or [] if permission not in effective_permissions)
    return {
        "id": username,
        "name": (override or {}).get("display_name_override") or row.get("display_name") or username,
        "configured": {"name": (configured_user or {}).get("name"), "role": configured_role, "active": configured_active} if configured_user else None,
        "runtime_override": override,
        "effective": {"name": (override or {}).get("display_name_override") or row.get("display_name") or username, "role": effective_role, "roles": [effective_role], "active": effective_active, "permissions": effective_permissions},
        "source": "configured_with_runtime_override" if configured_user and (override or (role_override and (role_override.get("disabled_permissions") or role_override.get("added_permissions"))) or (role_runtime_override and (role_runtime_override.get("disabled_permissions") or role_runtime_override.get("added_permissions")))) else "configured" if configured_user else "runtime",
        "permissions": [{"id": permission, "label": permission_map.get(permission, {}).get("label", permission), "configured": permission in configured_permissions, "effective": permission in effective_permissions, "disabled_locally": permission in configured_permissions and permission not in effective_permissions} for permission in permission_map],
    }


def access_snapshot() -> dict[str, Any]:
    config = baseline()
    configured_users = config.get("users", {}) if isinstance(config.get("users"), dict) else {}
    configured_roles = config.get("roles", {}) if isinstance(config.get("roles"), dict) else {}
    configured_permissions = config.get("permissions", {}) if isinstance(config.get("permissions"), dict) else {}
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, username, display_name, is_active FROM core.users ORDER BY username")
        users = {str(row["username"]): dict(row) for row in cur.fetchall()}
        cur.execute("SELECT id, name, description FROM core.roles ORDER BY name")
        roles = {str(row["name"]): dict(row) for row in cur.fetchall()}
        cur.execute("SELECT user_id, role_id FROM core.user_roles")
        role_ids = {str(row["user_id"]): str(row["role_id"]) for row in cur.fetchall()}
        cur.execute("SELECT role_id, disabled_permissions, added_permissions FROM core.role_runtime_overrides")
        role_overrides = {str(row["role_id"]): dict(row) for row in cur.fetchall()}
        cur.execute("SELECT user_id, active_override, display_name_override, role_name_override FROM core.user_runtime_overrides")
        overrides = {str(row["user_id"]): {"active_override": row.get("active_override"), "display_name_override": row.get("display_name_override"), "role_name_override": row.get("role_name_override")} for row in cur.fetchall()}
        cur.execute("SELECT id, label, description, category FROM core.permissions ORDER BY id")
        permission_map = {str(row["id"]): dict(row) for row in cur.fetchall()}
    role_map: dict[str, dict[str, Any]] = {}
    for role_name, role in roles.items():
        configured = configured_roles.get(role_name, {}) if isinstance(configured_roles.get(role_name), dict) else {}
        role_map[role_name] = {"label": configured.get("label") or role.get("name"), "permissions": list(configured.get("permissions", [])), "configured_permissions": list(configured.get("permissions", []))}
        if role_name == "admin" and not role_map[role_name]["permissions"]:
            role_map[role_name]["permissions"] = list(PERMISSIONS)
        if role_name == "guest" and not role_map[role_name]["permissions"]:
            role_map[role_name]["permissions"] = ["view"]
        role_id = str(role["id"])
        if role_id in role_overrides:
            role_map[role_name]["runtime_override"] = {"disabled_permissions": list(role_overrides[role_id].get("disabled_permissions") or []), "added_permissions": list(role_overrides[role_id].get("added_permissions") or [])}
    for username, configured_user in configured_users.items():
        if username not in users:
            # A configured identity is visible even before a materialization
            # migration has copied it to core.users.
            users[username] = {"username": username, "display_name": configured_user.get("name", username), "is_active": True, "id": None}
    result_users = []
    for username, row in users.items():
        user_id = str(row["id"]) if row.get("id") else ""
        override = overrides.get(user_id)
        configured_user = configured_users.get(username) if isinstance(configured_users.get(username), dict) else None
        if configured_user and override is None and user_id and username in configured_users:
            # The baseline role is authoritative when no runtime override is
            # present, so repository changes take effect without DB reset.
            pass
        role_id = role_ids.get(user_id)
        if role_id and role_id in role_overrides:
            row = {**row, "role_override": role_map.get(next((name for name, item in roles.items() if str(item["id"]) == role_id), ""), {}).get("runtime_override")}
        result_users.append(_effective_for_user(row, configured_users, override, role_map, permission_map))
    result_roles = []
    for name, role in role_map.items():
        effective_permissions = list(role["permissions"])
        runtime_override = role.get("runtime_override") if isinstance(role.get("runtime_override"), dict) else None
        if runtime_override:
            effective_permissions = [permission for permission in effective_permissions if permission not in set(runtime_override.get("disabled_permissions") or [])]
            effective_permissions.extend(permission for permission in runtime_override.get("added_permissions") or [] if permission not in effective_permissions)
        result_roles.append({"id": name, "label": role["label"], "description": roles[name].get("description"), "configured": name in configured_roles, "runtime_override": runtime_override, "permissions": [{"id": permission, "label": permission_map.get(permission, {}).get("label", permission), "configured": permission in role.get("configured_permissions", []), "effective": permission in effective_permissions, "disabled_locally": permission in role.get("configured_permissions", []) and permission not in effective_permissions} for permission in permission_map]})
    return {"users": sorted(result_users, key=lambda item: item["id"]), "roles": result_roles, "permissions": list(permission_map.values()), "development_auth_enabled": development_auth_enabled(), "reset_semantics": "Runtime users and overrides are database state; authored YAML becomes effective again after a runtime database reset."}


def _user_by_username(cur: Any, username: str) -> dict[str, Any] | None:
    cur.execute("SELECT id, username, display_name, is_active FROM core.users WHERE username = %s", (username,))
    row = cur.fetchone()
    return dict(row) if row else None


def create_development_session(username: str) -> tuple[str, dict[str, Any]]:
    if not development_auth_enabled():
        raise PermissionError("development authentication is disabled")
    snapshot = access_snapshot()
    user = next((item for item in snapshot["users"] if item["id"] == username), None)
    if not user or not user["effective"]["active"]:
        raise PermissionError("user is not active")
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + SESSION_TTL
    with connection() as conn, conn.cursor() as cur:
        row = _user_by_username(cur, username)
        if not row:
            raise PermissionError("user is not materialized in the application database")
        cur.execute("INSERT INTO core.auth_sessions(session_digest, user_id, expires_at) VALUES (%s, %s, %s)", (_digest(token), row["id"], expires))
    return token, user


def identity_for_request(headers: Any, cookies: dict[str, str] | None = None, *, trusted_proxy: bool = False) -> AuthenticatedIdentity | None:
    cookies = cookies or {}
    token = cookies.get(SESSION_COOKIE)
    username: str | None = None
    source = ""
    try:
        with connection() as conn, conn.cursor() as cur:
            if token:
                cur.execute("SELECT u.username FROM core.auth_sessions s JOIN core.users u ON u.id = s.user_id WHERE s.session_digest = %s AND s.expires_at > now() AND u.is_active", (_digest(token),))
                row = cur.fetchone()
                if row:
                    username, source = str(row["username"]), "development_session"
                    cur.execute("UPDATE core.auth_sessions SET last_seen_at = now() WHERE session_digest = %s", (_digest(token),))
            if username is None and trusted_proxy:
                header_name = (os.environ.get("META_WEBUI_TRUSTED_OPERATOR_HEADER") or os.environ.get("META_WEBUI_EVOLVER_TRUSTED_OPERATOR_HEADER", "")).strip()
                subject = headers.get(header_name) if header_name and hasattr(headers, "get") else None
                if isinstance(subject, str) and subject.strip():
                    username, source = subject.strip(), f"trusted_header:{header_name}"
    except DatabaseUnavailableError:
        # Test/deployment compatibility adapter only. It is intentionally
        # ignored whenever PostgreSQL is available; the general RBAC database
        # is authoritative in real deployments.
        header_name = (os.environ.get("META_WEBUI_TRUSTED_OPERATOR_HEADER") or os.environ.get("META_WEBUI_EVOLVER_TRUSTED_OPERATOR_HEADER", "")).strip() if trusted_proxy else ""
        raw_roles = os.environ.get("META_WEBUI_EVOLVER_OPERATOR_ROLES", "")
        subject = headers.get(header_name) if header_name and hasattr(headers, "get") else None
        try:
            role_map = json.loads(raw_roles) if raw_roles else {}
        except json.JSONDecodeError:
            role_map = {}
        permissions = role_map.get(subject, []) if isinstance(role_map, dict) and isinstance(subject, str) else []
        if isinstance(permissions, list) and isinstance(subject, str) and subject.strip():
            return AuthenticatedIdentity(username=subject.strip(), source=f"trusted_header:{header_name}", permissions=frozenset(str(item) for item in permissions))
        return None
    if username is None:
        return None
    try:
        snapshot = access_snapshot()
    except DatabaseUnavailableError:
        return AuthenticatedIdentity(username=username, source=source, permissions=frozenset()) if username and source.startswith("trusted_header:") else None
    user = next((item for item in snapshot["users"] if item["id"] == username), None)
    if not user or not user["effective"]["active"]:
        return None
    return AuthenticatedIdentity(username=username, source=source, permissions=frozenset(permission["id"] for permission in user["permissions"] if permission["effective"]))


def parse_cookie_header(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    result: dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            key, raw = part.strip().split("=", 1)
            result[key] = raw
    return result


def audit(cur: Any, actor_username: str | None, operation: str, target: str, previous: Any, new: Any) -> None:
    actor_id = None
    if actor_username:
        cur.execute("SELECT id FROM core.users WHERE username = %s", (actor_username,))
        row = cur.fetchone()
        actor_id = row["id"] if row else None
    cur.execute("INSERT INTO audit.events(event_type, actor_user_id, entity_schema, entity_table, event_json) VALUES (%s, %s, 'core', %s, %s::jsonb)", ("access_control." + operation, actor_id, target, json.dumps({"previous": previous, "new": new, "source": "runtime_override"}, default=str)))


def _require_access_admin(actor: str) -> None:
    identity = next((item for item in access_snapshot()["users"] if item["id"] == actor), None)
    if not identity or "manage_access" not in {permission["id"] for permission in identity["permissions"] if permission["effective"]}:
        raise PermissionError("access administration permission is required")


def mutate_user(actor: str, username: str, body: dict[str, Any], *, delete: bool = False) -> dict[str, Any]:
    _require_access_admin(actor)
    before = access_snapshot()
    target = next((item for item in before["users"] if item["id"] == username), None)
    configured = target and target["configured"] is not None
    if not target and not delete:
        display_name = str(body.get("name") or username)
        role_name = str(body.get("role") or "guest")
        if role_name not in {item["id"] for item in before["roles"]}:
            raise ValueError("unknown role")
        with connection() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO core.users(username, display_name, is_active) VALUES (%s, %s, true) RETURNING id", (username, display_name))
            user_id = cur.fetchone()["id"]
            cur.execute("SELECT id FROM core.roles WHERE name = %s", (role_name,))
            role_id = cur.fetchone()["id"]
            cur.execute("INSERT INTO core.user_roles(user_id, role_id, granted_by_user_id) SELECT %s, %s, id FROM core.users WHERE username = %s", (user_id, role_id, actor))
            audit(cur, actor, "create_user", "users", None, {"username": username, "role": role_name})
        return next(item for item in access_snapshot()["users"] if item["id"] == username)
    if not target:
        raise KeyError("user not found")
    if delete and configured:
        raise ValueError("configured users are restored, not deleted")
    admin_count = sum(1 for item in before["users"] if item["effective"]["active"] and item["effective"]["role"] == "admin")
    if (delete or body.get("active") is False or (isinstance(body.get("role"), str) and body.get("role") != "admin")) and target["effective"]["role"] == "admin" and admin_count <= 1:
        raise ValueError("cannot remove the last effective Administrator")
    user_id = next((row["id"] for row in _database_users() if row["username"] == username), None)
    if delete:
        with connection() as conn, conn.cursor() as cur:
            audit(cur, actor, "delete_runtime_user", "users", target, None)
            cur.execute("DELETE FROM core.users WHERE id = %s", (user_id,))
        return {"deleted": username}
    with connection() as conn, conn.cursor() as cur:
        if body.get("restore"):
            cur.execute("DELETE FROM core.user_runtime_overrides WHERE user_id = %s", (user_id,))
        else:
            active = body.get("active") if isinstance(body.get("active"), bool) else None
            role_name = body.get("role") if isinstance(body.get("role"), str) else None
            cur.execute("INSERT INTO core.user_runtime_overrides(user_id, active_override, role_name_override, updated_by_user_id) VALUES (%s, %s, %s, (SELECT id FROM core.users WHERE username = %s)) ON CONFLICT (user_id) DO UPDATE SET active_override = COALESCE(EXCLUDED.active_override, core.user_runtime_overrides.active_override), role_name_override = COALESCE(EXCLUDED.role_name_override, core.user_runtime_overrides.role_name_override), updated_at = now(), updated_by_user_id = EXCLUDED.updated_by_user_id", (user_id, active, role_name, actor))
        audit(cur, actor, "restore_user" if body.get("restore") else "override_user", "users", target, body)
    return next(item for item in access_snapshot()["users"] if item["id"] == username)


def mutate_role_permission(actor: str, role_name: str, permission_id: str, enabled: bool) -> dict[str, Any]:
    _require_access_admin(actor)
    before = access_snapshot()
    role = next((item for item in before["roles"] if item["id"] == role_name), None)
    if not role or permission_id not in {item["id"] for item in before["permissions"]}:
        raise KeyError("role or permission not found")
    if role_name == "admin" and permission_id == "manage_access" and enabled is False:
        raise ValueError("Administrator must retain access administration permission")
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, disabled_permissions, added_permissions FROM core.roles r LEFT JOIN core.role_runtime_overrides o ON o.role_id = r.id WHERE r.name = %s", (role_name,))
        row = cur.fetchone()
        if not row:
            raise KeyError("role not found")
        disabled = set(row.get("disabled_permissions") or [])
        added = set(row.get("added_permissions") or [])
        configured_ids = {item["id"] for item in role["permissions"] if item["configured"]}
        if enabled:
            disabled.discard(permission_id)
            if permission_id not in configured_ids:
                added.add(permission_id)
        else:
            if permission_id in role["permissions"]:
                disabled.add(permission_id)
            else:
                added.discard(permission_id)
        cur.execute("INSERT INTO core.role_runtime_overrides(role_id, disabled_permissions, added_permissions, updated_by_user_id) VALUES (%s, %s, %s, (SELECT id FROM core.users WHERE username = %s)) ON CONFLICT (role_id) DO UPDATE SET disabled_permissions = EXCLUDED.disabled_permissions, added_permissions = EXCLUDED.added_permissions, updated_at = now(), updated_by_user_id = EXCLUDED.updated_by_user_id", (row["id"], sorted(disabled), sorted(added), actor))
        audit(cur, actor, "override_role_permission", "roles", role, {"permission": permission_id, "enabled": enabled})
    return next(item for item in access_snapshot()["roles"] if item["id"] == role_name)


def _database_users() -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, username FROM core.users")
        return [dict(row) for row in cur.fetchall()]
