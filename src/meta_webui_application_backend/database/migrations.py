"""Canonical PostgreSQL migration planning and application."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml


_MODULE_ROOT = Path(__file__).resolve().parents[3]
REPOSITORY_ROOT = Path(os.environ.get("META_WEBUI_REPOSITORY_ROOT", _MODULE_ROOT))
HISTORY_TABLE = "system.schema_migrations"
TRANSACTION_CONTROL = re.compile(r"^\s*(BEGIN|COMMIT|ROLLBACK)\b", re.IGNORECASE | re.MULTILINE)


class MigrationError(RuntimeError):
    """Raised when the configured migration contract cannot be satisfied."""


@dataclass(frozen=True)
class Migration:
    identifier: str
    path: Path
    checksum: str
    sql: str


def database_url(environ: dict[str, str] | None = None) -> str:
    environ = os.environ if environ is None else environ
    url = environ.get("META_WEBUI_INTERFACE_DATABASE_URL") or environ.get("DATABASE_URL")
    if not url:
        raise MigrationError(
            "Set META_WEBUI_INTERFACE_DATABASE_URL (or the compatible DATABASE_URL) before applying migrations."
        )
    return url


def runtime_config_path(root: Path = REPOSITORY_ROOT, environ: dict[str, str] | None = None) -> Path:
    environ = os.environ if environ is None else environ
    configured = environ.get("META_WEBUI_INTERFACE_WEBUI_RUNTIME_CONFIG")
    path = Path(configured) if configured else root / "applications" / "deployment" / "runtime.yaml"
    if not path.is_file():
        raise MigrationError(f"Repository runtime config not found: {path}")
    return path


def configured_migrations(root: Path = REPOSITORY_ROOT, environ: dict[str, str] | None = None) -> list[Migration]:
    config_path = runtime_config_path(root, environ)
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise MigrationError(f"Runtime config must be valid YAML: {config_path}: {error}") from error
    entries = config.get("database", {}).get("migrations", []) if isinstance(config, dict) else []
    if not isinstance(entries, list):
        raise MigrationError(f"database.migrations must be a list in {config_path}")

    migrations: list[Migration] = []
    identifiers: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not isinstance(entry.get("path"), str):
            raise MigrationError(f"Invalid database.migrations entry {index} in {config_path}")
        identifier = entry["id"]
        if identifier in identifiers:
            raise MigrationError(f"Duplicate configured migration identifier: {identifier}")
        identifiers.add(identifier)
        raw_path = Path(entry["path"])
        candidates = [raw_path] if raw_path.is_absolute() else [config_path.parent / raw_path, root / raw_path, root / "src" / raw_path]
        path = next((candidate for candidate in candidates if candidate.is_file()), None)
        if path is None:
            raise MigrationError(f"Configured database migration not found: {entry['path']}")
        sql = path.read_text(encoding="utf-8")
        if TRANSACTION_CONTROL.search(sql):
            raise MigrationError(
                f"Migration {identifier} contains transaction control. The canonical runner owns transactions: {path}"
            )
        migrations.append(Migration(identifier, path, hashlib.sha256(sql.encode()).hexdigest(), sql))
    return migrations


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _source_revision() -> str:
    """Return the build provenance supplied to the migration container."""
    return os.environ.get("META_WEBUI_BUILD_REVISION") or "unknown"


def _psql(url: str, *, sql: str | None = None, input_sql: str | None = None) -> str:
    command = ["psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "-X", "-At", "-d", url]
    if sql is not None:
        command.extend(["-c", sql])
    completed = subprocess.run(command, input=input_sql, text=True, capture_output=True, check=False)
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise MigrationError(f"PostgreSQL migration command failed: {detail}")
    return completed.stdout


def apply_migrations(
    url: str,
    migrations: list[Migration],
    *,
    execute: Callable[..., str] = _psql,
    log: Callable[[str], None] | None = None,
) -> None:
    log = (lambda message: print(message, file=sys.stderr)) if log is None else log
    execute(url, sql="CREATE SCHEMA IF NOT EXISTS system; CREATE TABLE IF NOT EXISTS system.schema_migrations (migration_id text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());")
    applied_rows = execute(url, sql="SELECT migration_id || E'\\t' || checksum FROM system.schema_migrations ORDER BY migration_id;")
    applied = dict(line.split("\t", 1) for line in applied_rows.splitlines() if "\t" in line)
    for migration in migrations:
        previous = applied.get(migration.identifier)
        if previous is not None:
            if previous != migration.checksum:
                message = f"Checksum mismatch for applied migration {migration.identifier}: {migration.path}"
                log(message)
                raise MigrationError(message)
            log(f"Migration already applied: {migration.identifier}")
            continue
        script = (
            "BEGIN;\n"
            "SELECT set_config('meta_webui.source_revision', "
            f"{_sql_literal(_source_revision())}, true);\n"
            f"{migration.sql}\n"
            "INSERT INTO system.schema_migrations (migration_id, checksum) VALUES "
            f"({_sql_literal(migration.identifier)}, {_sql_literal(migration.checksum)});\nCOMMIT;\n"
        )
        try:
            execute(url, input_sql=script)
        except MigrationError:
            log(f"Migration failed: {migration.identifier}")
            raise
        log(f"Migration applied: {migration.identifier}")


def main() -> int:
    try:
        migrations = configured_migrations()
        apply_migrations(database_url(), migrations)
    except MigrationError as error:
        print(f"Migration error: {error}", file=sys.stderr)
        return 1
    return 0
