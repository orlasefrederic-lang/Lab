"""mediameta - read and edit metadata of photos and videos.

    from mediameta import read_metadata, write_metadata

    record = read_metadata("IMG_0001.jpg")
    print(record.common["datetime_original"])

    write_metadata("IMG_0001.jpg", {"title": "Sunset", "gps_latitude": 55.75})
"""

from __future__ import annotations

from .api import copy_metadata, read_metadata, remove_metadata, write_metadata
from .backends import available_backends, backend_status, select_backend
from .errors import (
    BackendUnavailableError,
    CorruptFileError,
    FieldError,
    MediaMetaError,
    ReadOnlyFormatError,
    UnsupportedFormatError,
)
from .fields import COMMON_FIELDS, FIELDS_BY_NAME, FieldSpec
from .record import MetadataRecord, describe_fields

__version__ = "1.0.0"

__all__ = [
    "read_metadata",
    "write_metadata",
    "remove_metadata",
    "copy_metadata",
    "MetadataRecord",
    "describe_fields",
    "COMMON_FIELDS",
    "FIELDS_BY_NAME",
    "FieldSpec",
    "available_backends",
    "backend_status",
    "select_backend",
    "MediaMetaError",
    "UnsupportedFormatError",
    "ReadOnlyFormatError",
    "BackendUnavailableError",
    "FieldError",
    "CorruptFileError",
    "__version__",
]
