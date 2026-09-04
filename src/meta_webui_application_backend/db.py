"""Runtime PostgreSQL access for request handlers.

The migration runner shells out to `psql`; this module is the app's first
actual runtime consumer of the database, per db/README.md's intended
`UI -> API/application layer -> PostgreSQL` flow. One dependency (psycopg),
one place a caller gets a connection.
"""
from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row

from meta_webui_application_backend.database.migrations import MigrationError, database_url


class DatabaseUnavailableError(RuntimeError):
    """No database URL is configured, or the database could not be reached."""


@contextmanager
def connection() -> Generator[psycopg.Connection[dict[str, Any]], None, None]:
    """A connection with dict-shaped rows, opened and closed per call.

    Short-lived by design: this server is a `ThreadingHTTPServer` with no
    pool, and request volume here is low (dataset management, not a hot
    path). Raises `DatabaseUnavailableError` rather than letting a caller
    trip over a raw psycopg exception, matching how `dc_proxy` turns a
    missing Data Catalog token into a clean 503 instead of a stack trace.
    """
    try:
        url = database_url()
    except MigrationError as error:
        raise DatabaseUnavailableError(str(error)) from error
    try:
        with psycopg.connect(url, row_factory=dict_row) as conn:
            yield conn
    except psycopg.OperationalError as error:
        raise DatabaseUnavailableError(f"could not connect to the database: {error}") from error
