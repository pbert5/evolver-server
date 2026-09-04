"""Physical USB evidence and bounded firmware identity aliases."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

SAMD21_USB_SERIAL_RE = re.compile(r"^[0-9A-F]{32}$")
ALIAS_SCHEME = "samd21-usb-serial-sha256-v1"

def canonical_samd21_usb_serial(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("USB serial must be a string")
    serial = value.strip().upper()
    if not SAMD21_USB_SERIAL_RE.fullmatch(serial):
        raise ValueError("SAMD21 USB serial must be exactly 32 hexadecimal characters")
    return serial

def firmware_alias_for_usb_serial(value: str) -> str:
    digest = hashlib.sha256(canonical_samd21_usb_serial(value).encode("ascii")).hexdigest()
    return f"MEV-{digest[:27]}"

def samd21_hardware_fingerprint(*, vid: int, pid: int, usb_serial: str,
                                manufacturer: str | None = None,
                                product: str | None = None) -> dict[str, Any]:
    serial = canonical_samd21_usb_serial(usb_serial)
    result: dict[str, Any] = {"scheme": ALIAS_SCHEME, "usb_vid": f"0x{vid:04x}",
                              "usb_pid": f"0x{pid:04x}", "usb_serial": serial,
                              "serial_sha256": hashlib.sha256(serial.encode("ascii")).hexdigest()}
    if manufacturer is not None: result["manufacturer"] = manufacturer
    if product is not None: result["product"] = product
    return result

def validate_usb_match(info: Mapping[str, Any], *, expected_vid: int, expected_pid: int,
                       expected_serial: str) -> dict[str, Any]:
    serial = canonical_samd21_usb_serial(expected_serial)
    if info.get("vid") != expected_vid or info.get("pid") != expected_pid:
        raise ValueError("USB VID/PID mismatch")
    if not isinstance(info.get("serial_number"), str):
        raise ValueError("USB serial metadata is missing")
    if canonical_samd21_usb_serial(info["serial_number"]) != serial:
        raise ValueError("USB serial mismatch")
    return samd21_hardware_fingerprint(vid=expected_vid, pid=expected_pid,
                                       usb_serial=serial, manufacturer=info.get("manufacturer"),
                                       product=info.get("product"))
