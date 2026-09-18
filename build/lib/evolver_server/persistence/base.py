"""Small persistence contracts shared by native repositories."""
from __future__ import annotations

from typing import Any, Protocol


class Repository(Protocol):
    def load(self) -> tuple[dict[str, Any], int]: ...
    def save(self, state: dict[str, Any], revision: int) -> None: ...
