"""The library API: read, write, remove and copy metadata."""

from __future__ import annotations

from pathlib import Path

from .backends import select_backend
from .errors import FieldError, MediaMetaError
from .fields import FIELDS_BY_NAME, normalize, resolve_field
from .record import MetadataRecord
from .utils import make_backup

#: Fields that describe the pixels rather than the metadata; never copied.
TECHNICAL_FIELDS = {"width", "height", "duration", "mime_type"}


def read_metadata(path, backend: str = "auto") -> MetadataRecord:
    """Read everything known about one file."""
    path = Path(path)
    if not path.exists():
        raise MediaMetaError(f"{path} does not exist")
    if path.is_dir():
        raise MediaMetaError(f"{path} is a directory")
    return select_backend(path, backend).read(path)


def write_metadata(
    path,
    changes: dict | None = None,
    raw: dict | None = None,
    backend: str = "auto",
    output=None,
    backup: bool = False,
) -> MetadataRecord:
    """Apply canonical ``changes`` (``None`` as a value deletes the field).

    ``raw`` passes backend-specific tags straight through, for example
    ``{"EXIF:ISOSpeedRatings": 400}`` or ``{"iTunes:\\xa9wrt": "K"}``.
    """
    path = Path(path)
    if not path.exists():
        raise MediaMetaError(f"{path} does not exist")
    if not changes and not raw:
        raise FieldError("nothing to write: no fields given")

    normalized = _normalize_changes(changes or {})
    chosen = select_backend(path, backend, for_write=True)

    if backup and output is None:
        make_backup(path)
    return chosen.write(path, normalized, raw or {}, output=output)


def remove_metadata(
    path,
    fields=None,
    backend: str = "auto",
    output=None,
    backup: bool = False,
) -> MetadataRecord:
    """Delete ``fields``, or every metadata block when ``fields`` is empty."""
    path = Path(path)
    if not path.exists():
        raise MediaMetaError(f"{path} does not exist")

    chosen = select_backend(path, backend, for_write=True)
    if backup and output is None:
        make_backup(path)

    if not fields:
        return chosen.clear(path, output=output)

    changes = {}
    for name in fields:
        spec = resolve_field(name)
        if not spec.writable:
            raise FieldError(f"{spec.name} is read-only")
        changes[spec.name] = None
    return chosen.write(path, changes, {}, output=output)


def copy_metadata(
    source,
    destination,
    fields=None,
    backend: str = "auto",
    output=None,
    backup: bool = False,
) -> MetadataRecord:
    """Copy canonical metadata from one file to another, across formats."""
    source_record = read_metadata(source, backend=backend)

    if fields:
        wanted = {resolve_field(name).name for name in fields}
    else:
        wanted = {
            name for name, spec in FIELDS_BY_NAME.items()
            if spec.writable and name not in TECHNICAL_FIELDS
        }

    changes = {
        name: value
        for name, value in source_record.common.items()
        if name in wanted and name not in TECHNICAL_FIELDS
    }
    if not changes:
        raise FieldError(f"{Path(source).name} has no metadata worth copying")

    return write_metadata(
        destination, changes, backend=backend, output=output, backup=backup
    )


def _normalize_changes(changes: dict) -> dict:
    normalized = {}
    for name, value in changes.items():
        spec = resolve_field(name)
        if not spec.writable:
            raise FieldError(f"{spec.name} is read-only")
        normalized[spec.name] = None if value is None else normalize(spec, value)
    return normalized
