"""Production persistence and explicit legacy migration boundaries."""

from .legacy_import import LegacyImportConflict, import_legacy_state

__all__ = ["LegacyImportConflict", "import_legacy_state"]
