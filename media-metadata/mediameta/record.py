"""The in-memory representation of one file's metadata."""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path

from .fields import COMMON_FIELDS, FIELDS_BY_NAME


def _jsonable(value):
    """Make datetimes, bytes and paths survive a JSON round trip."""
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return f"<{len(value)} bytes>"
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


@dataclass
class MetadataRecord:
    """Everything a backend could tell us about a single file.

    ``common`` holds canonical fields (see :mod:`mediameta.fields`) and
    ``raw`` holds the backend's own namespaced tags, e.g. ``EXIF:Artist``
    or ``QuickTime:\\xa9nam``.
    """

    path: Path
    kind: str = "unknown"
    format: str = ""
    backend: str = ""
    writable: bool = False
    common: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

    def get(self, name: str, default=None):
        """Read a canonical field, falling back to a raw tag of that name."""
        if name in self.common:
            return self.common[name]
        return self.raw.get(name, default)

    def set_common(self, name: str, value) -> None:
        """Store a canonical value, dropping empty ones."""
        if value is None or value == "" or value == []:
            self.common.pop(name, None)
        else:
            self.common[name] = value

    def ordered_common(self) -> dict:
        """Canonical fields in the declared order, which reads better."""
        ordered = {}
        for spec in COMMON_FIELDS:
            if spec.name in self.common:
                ordered[spec.name] = self.common[spec.name]
        for name, value in self.common.items():
            ordered.setdefault(name, value)
        return ordered

    def to_dict(self, include_raw: bool = True) -> dict:
        data = {
            "path": str(self.path),
            "kind": self.kind,
            "format": self.format,
            "backend": self.backend,
            "writable": self.writable,
            "common": _jsonable(self.ordered_common()),
        }
        if include_raw:
            data["raw"] = _jsonable(self.raw)
        if self.warnings:
            data["warnings"] = list(self.warnings)
        return data

    def to_json(self, include_raw: bool = True, indent: int = 2) -> str:
        return json.dumps(
            self.to_dict(include_raw), indent=indent, ensure_ascii=False, sort_keys=False
        )

    def render(self, include_raw: bool = False, width: int = 22) -> str:
        """Human-readable dump used by ``mediameta show``."""
        lines = [f"{self.path}"]
        header = f"  {self.format or '?'} · {self.kind} · backend={self.backend}"
        if not self.writable:
            header += " · read-only"
        lines.append(header)

        common = self.ordered_common()
        if common:
            lines.append("  metadata:")
            for name, value in common.items():
                lines.append(f"    {name:<{width}} {_render_value(value)}")
        else:
            lines.append("  metadata:            (none)")

        if include_raw and self.raw:
            lines.append("  raw tags:")
            for name in sorted(self.raw):
                lines.append(f"    {name:<{width}} {_render_value(self.raw[name])}")

        for warning in self.warnings:
            lines.append(f"  ! {warning}")
        return "\n".join(lines)


def _render_value(value) -> str:
    if isinstance(value, _dt.datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return f"<{len(value)} bytes>"
    text = str(value)
    return text if len(text) <= 300 else text[:297] + "..."


def describe_fields() -> str:
    """Pretty list of every canonical field, for ``mediameta fields``."""
    lines = ["Canonical fields (usable with --set NAME=VALUE):", ""]
    for spec in COMMON_FIELDS:
        flags = []
        if not spec.writable:
            flags.append("read-only")
        if spec.media != ("image", "video", "audio"):
            flags.append("/".join(spec.media))
        if spec.aliases:
            flags.append("aliases: " + ", ".join(spec.aliases))
        suffix = f"  [{'; '.join(flags)}]" if flags else ""
        lines.append(f"  {spec.name:<20} {spec.type:<10} {spec.help}{suffix}")
    lines.append("")
    lines.append("  gps                  shorthand   --set gps=55.7558,37.6176[,altitude]")
    return "\n".join(lines)


__all__ = ["MetadataRecord", "describe_fields", "FIELDS_BY_NAME"]
