"""Release-manifest validation and safe file routing for eVOLVER artifacts.

Release files are deliberately outside the application source tree.  An
operator publishes a generated directory and selects one immutable release
using environment configuration; this server never turns a request path into
an arbitrary filesystem path.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any


RELEASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CANONICAL_TARGET_RE = re.compile(r"linux-(x86_64|aarch64)-(glibc|nixos)\Z")
LEGACY_TARGET_RE = re.compile(r"linux-(x86_64|aarch64)\Z")


class ReleaseError(ValueError):
    pass


def release_root(repository_root: Path) -> Path:
    """Return the separately-managed release directory, without creating it."""
    return Path(os.environ.get("META_WEBUI_EVOLVER_RELEASE_ROOT", repository_root / "releases" / "evolver"))


def current_release() -> str:
    release = os.environ.get("META_WEBUI_EVOLVER_RELEASE", "")
    if not RELEASE_ID_RE.fullmatch(release):
        raise ReleaseError("no valid current eVOLVER release is configured")
    return release


def _safe_child(root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise ReleaseError("invalid release artifact path")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    if resolved_root not in resolved.parents and resolved != resolved_root:
        raise ReleaseError("invalid release artifact path")
    return resolved


def release_file(repository_root: Path, release: str, relative: str) -> Path:
    if not RELEASE_ID_RE.fullmatch(release):
        raise ReleaseError("invalid release identifier")
    path = _safe_child(release_root(repository_root) / release, relative)
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def manifest(repository_root: Path, release: str) -> dict[str, Any]:
    path = release_file(repository_root, release, "manifest.json")
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseError("release manifest is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ReleaseError("release manifest must be an object")
    if parsed.get("version") != release or not isinstance(parsed.get("git_revision"), str):
        raise ReleaseError("release manifest identity does not match its route")
    if not re.fullmatch(r"[0-9a-f]{7,64}", parsed["git_revision"]):
        raise ReleaseError("release manifest has invalid git_revision")
    if not isinstance(parsed.get("protocol_version"), str) or not parsed["protocol_version"]:
        raise ReleaseError("release manifest has no protocol_version")
    artifacts = parsed.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ReleaseError("release manifest has no artifacts")
    for platform, artifact in artifacts.items():
        if not isinstance(platform, str) or not (CANONICAL_TARGET_RE.fullmatch(platform) or LEGACY_TARGET_RE.fullmatch(platform)):
            raise ReleaseError("release manifest has invalid artifact platform")
        if not isinstance(artifact, dict) or not isinstance(artifact.get("url"), str):
            raise ReleaseError("release manifest has invalid artifact")
        if CANONICAL_TARGET_RE.fullmatch(platform):
            _, architecture, runtime = platform.split("-")
            expected = {"target": platform, "platform": "linux", "architecture": architecture, "runtime": runtime}
            if any(artifact.get(key) != value for key, value in expected.items()):
                raise ReleaseError("release manifest target metadata disagrees with artifact key")
        if not artifact["url"].startswith(f"/releases/evolver/{release}/"):
            raise ReleaseError("release artifact URL must be local and versioned")
        if not isinstance(artifact.get("sha256"), str) or not SHA256_RE.fullmatch(artifact["sha256"]):
            raise ReleaseError("release manifest has invalid artifact SHA-256")
        if not isinstance(artifact.get("size"), int) or artifact["size"] < 1:
            raise ReleaseError("release manifest has invalid artifact size")
    firmware = parsed.get("firmware")
    if firmware is not None:
        if not isinstance(firmware, dict) or firmware.get("variant") != "samd21-minievolver":
            raise ReleaseError("release manifest has invalid firmware variant")
        if not isinstance(firmware.get("version"), str) or not firmware["version"]:
            raise ReleaseError("release manifest has invalid firmware version")
        if not isinstance(firmware.get("url"), str) or not firmware["url"].startswith(f"/releases/evolver/{release}/"):
            raise ReleaseError("release firmware URL must be local and versioned")
        if not isinstance(firmware.get("sha256"), str) or not SHA256_RE.fullmatch(firmware["sha256"]):
            raise ReleaseError("release manifest has invalid firmware SHA-256")
        if not isinstance(firmware.get("size"), int) or firmware["size"] < 1:
            raise ReleaseError("release manifest has invalid firmware size")
    signature = parsed.get("signature")
    if signature is not None and not isinstance(signature, dict):
        raise ReleaseError("release manifest signature must be an object")
    return parsed


def artifact_matches(path: Path, expected_sha256: str) -> bool:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest() == expected_sha256


def release_readiness(repository_root: Path, release: str, *, expected_manifest_digest: str | None = None,
                      expected_source_revision: str | None = None) -> dict[str, Any]:
    """Validate one immutable release, including every referenced payload."""
    manifest_path = release_file(repository_root, release, "manifest.json")
    parsed = manifest(repository_root, release)
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if expected_manifest_digest is not None and manifest_digest != expected_manifest_digest:
        raise ReleaseError("release manifest digest does not match immutable binding")
    if expected_source_revision is not None and parsed["git_revision"] != expected_source_revision:
        raise ReleaseError("release source revision does not match immutable binding")
    entries = list(parsed["artifacts"].values())
    firmware = parsed.get("firmware")
    if not isinstance(firmware, dict):
        raise ReleaseError("selected release has no required firmware artifact")
    entries.append(firmware)
    for entry in entries:
        relative = entry["url"].removeprefix(f"/releases/evolver/{release}/")
        path = release_file(repository_root, release, relative)
        if path.stat().st_size != entry["size"]:
            raise ReleaseError(f"release artifact size does not match manifest: {relative}")
        if not artifact_matches(path, entry["sha256"]):
            raise ReleaseError(f"release artifact checksum failed: {relative}")
    return {"release": release, "manifest": parsed, "manifest_sha256": manifest_digest}


def selected_release_readiness(repository_root: Path) -> dict[str, Any]:
    """Validate the release consumed by the server-hosted installer."""
    return release_readiness(repository_root, current_release())
