"""Optional backend that shells out to Phil Harvey's ExifTool.

It is not required for the common cases, but when the binary is installed
it unlocks everything the pure-Python backends cannot do: HEIC, RAW, MKV,
AVI, writing TIFF, and XMP sidecars.
"""

from __future__ import annotations

import datetime as _dt
import json
import shutil
import subprocess
from pathlib import Path

from ..errors import FieldError, MediaMetaError
from ..fields import normalize, resolve_field, split_list
from ..record import MetadataRecord
from ..utils import (
    MEDIA_SUFFIXES,
    MIME_TYPES,
    effective_suffix,
    guess_format,
    guess_kind,
    staged_write,
)
from .base import Backend

#: canonical field -> tag names to read, best source first.
READ_TAGS = {
    "title": ("Title", "ObjectName", "XPTitle", "DisplayName"),
    "description": ("Description", "ImageDescription", "Caption-Abstract", "XPSubject"),
    "comment": ("UserComment", "Comment", "XPComment"),
    "artist": ("Artist", "Creator", "By-line", "XPAuthor", "Author"),
    "copyright": ("Copyright", "Rights", "CopyrightNotice"),
    "keywords": ("Keywords", "Subject", "XPKeywords", "Category"),
    "software": ("Software", "CreatorTool", "Encoder", "EncodingTool"),
    "datetime_original": ("DateTimeOriginal", "CreateDate", "CreationDate", "MediaCreateDate", "DateCreated"),
    "camera_make": ("Make",),
    "camera_model": ("Model", "CameraModelName"),
    "lens": ("LensModel", "Lens", "LensID"),
    "orientation": ("Orientation",),
    "rating": ("Rating", "RatingPercent"),
    "gps_latitude": ("GPSLatitude",),
    "gps_longitude": ("GPSLongitude",),
    "gps_altitude": ("GPSAltitude",),
    "album": ("Album",),
    "genre": ("Genre",),
    "duration": ("Duration", "MediaDuration", "TrackDuration"),
    "width": ("ImageWidth", "ExifImageWidth"),
    "height": ("ImageHeight", "ExifImageHeight"),
    "mime_type": ("MIMEType",),
}

#: canonical field -> tags to write. ``AllDates`` covers the three EXIF dates.
WRITE_TAGS = {
    "title": ("Title",),
    "description": ("Description",),
    "comment": ("UserComment", "Comment"),
    "artist": ("Artist", "Creator"),
    "copyright": ("Copyright",),
    "keywords": ("Keywords", "Subject"),
    "software": ("Software",),
    "datetime_original": ("AllDates", "CreationDate"),
    "camera_make": ("Make",),
    "camera_model": ("Model",),
    "lens": ("LensModel",),
    "orientation": ("Orientation",),
    "rating": ("Rating",),
    "gps_latitude": ("GPSLatitude",),
    "gps_longitude": ("GPSLongitude",),
    "gps_altitude": ("GPSAltitude",),
    "album": ("Album",),
    "genre": ("Genre",),
}

LIST_FIELDS = {"keywords"}
SKIP_GROUPS = ("ExifTool:",)
SKIP_TAGS = {
    "SourceFile", "File:FileName", "File:Directory", "File:FileSize",
    "File:FileModifyDate", "File:FileAccessDate", "File:FileInodeChangeDate",
    "File:FilePermissions", "File:FileType", "File:FileTypeExtension",
}


class ExifToolBackend(Backend):
    """Universal backend; only active when ``exiftool`` is on PATH."""

    name = "exiftool"
    #: Lower than the native backends, so they stay the default when both work.
    priority = 10
    read_suffixes = frozenset(MEDIA_SUFFIXES)
    write_suffixes = frozenset(MEDIA_SUFFIXES)

    def __init__(self, executable: str | None = None):
        self.executable = executable or shutil.which("exiftool") or "exiftool"

    def is_available(self) -> tuple:
        if shutil.which(self.executable) is None:
            return False, "exiftool is not installed (apt install libimage-exiftool-perl / brew install exiftool)"
        return True, ""

    def supports(self, path, suffix: str | None = None) -> bool:
        # ExifTool knows more formats than our suffix table, so accept anything
        # that looks like a media file plus the sidecar formats it owns.
        suffix = suffix or effective_suffix(path)
        return suffix in self.read_suffixes or suffix in {".xmp", ".heic", ".heif", ".avif"}

    def can_write(self, path, suffix: str | None = None) -> bool:
        return self.supports(path, suffix)

    # -- process plumbing ---------------------------------------------

    def _run(self, arguments, check: bool = True) -> subprocess.CompletedProcess:
        available, reason = self.is_available()
        if not available:
            raise MediaMetaError(reason)
        try:
            result = subprocess.run(
                [self.executable, *arguments],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise MediaMetaError(f"could not run exiftool: {exc}") from exc

        if check and result.returncode != 0:
            message = (result.stderr or result.stdout or "").strip()
            raise MediaMetaError(f"exiftool failed: {message}")
        return result

    # -- reading ------------------------------------------------------

    def read(self, path) -> MetadataRecord:
        path = Path(path)
        result = self._run(["-j", "-G", "-n", "-charset", "UTF8", "-api", "largefilesupport=1", str(path)])
        try:
            payload = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise MediaMetaError(f"could not parse exiftool output: {exc}") from exc
        if not payload:
            raise MediaMetaError(f"exiftool returned nothing for {path}")

        tags = payload[0]
        record = MetadataRecord(
            path=path,
            kind=guess_kind(path),
            format=str(tags.get("File:FileType") or guess_format(path)),
            backend=self.name,
            writable=True,
        )
        if result.stderr.strip():
            record.warnings.extend(
                line.strip() for line in result.stderr.splitlines() if line.strip()
            )

        for key, value in tags.items():
            if key in SKIP_TAGS or key.startswith(SKIP_GROUPS):
                continue
            record.raw[key] = value

        self._fill_common(record, tags)
        mime = tags.get("File:MIMEType") or MIME_TYPES.get(record.format)
        if mime:
            record.common["mime_type"] = mime
        return record

    def _fill_common(self, record: MetadataRecord, tags: dict) -> None:
        index: dict = {}
        for key, value in tags.items():
            _, _, bare = key.rpartition(":")
            index.setdefault(bare, value)

        for field_name, candidates in READ_TAGS.items():
            for candidate in candidates:
                if candidate not in index:
                    continue
                value = index[candidate]
                if value in (None, ""):
                    continue
                record.set_common(field_name, self._coerce(field_name, value))
                break

    @staticmethod
    def _coerce(field_name: str, value):
        spec = resolve_field(field_name)
        if field_name in LIST_FIELDS:
            return split_list(value)
        if field_name in ("duration", "width", "height", "mime_type"):
            return value
        try:
            return normalize(spec, value)
        except FieldError:
            return value

    # -- writing ------------------------------------------------------

    def write(self, path, changes: dict, raw_changes: dict | None = None, output=None) -> MetadataRecord:
        path = Path(path)
        target = self._target(path, output)
        arguments = self._build_arguments(changes or {}, raw_changes or {})
        if not arguments:
            return self.read(path)
        return self._apply(path, target, arguments)

    def clear(self, path, output=None) -> MetadataRecord:
        path = Path(path)
        return self._apply(path, self._target(path, output), ["-all="])

    def _apply(self, source: Path, target: Path, arguments) -> MetadataRecord:
        with staged_write(target) as temporary:
            shutil.copyfile(source, temporary)
            result = self._run(
                [
                    "-charset", "UTF8",
                    "-overwrite_original",
                    "-n",
                    *arguments,
                    str(temporary),
                ],
                check=False,
            )
            if result.returncode != 0:
                message = (result.stderr or result.stdout or "").strip()
                raise MediaMetaError(f"exiftool refused the change: {message}")

        record = self.read(target)
        for line in (result.stderr or "").splitlines():
            if line.strip().startswith("Warning"):
                record.warnings.append(line.strip())
        return record

    def _build_arguments(self, changes: dict, raw_changes: dict) -> list:
        arguments: list = []
        for field_name, value in changes.items():
            for tag in WRITE_TAGS.get(field_name, ()):
                arguments.extend(self._tag_arguments(tag, field_name, value))
        for key, value in raw_changes.items():
            arguments.append(f"-{key}=" if value is None else f"-{key}={value}")
        return arguments

    @staticmethod
    def _tag_arguments(tag: str, field_name: str, value) -> list:
        if value is None:
            return [f"-{tag}="]
        if field_name in LIST_FIELDS:
            items = split_list(value)
            return [f"-{tag}="] + [f"-{tag}={item}" for item in items]
        if isinstance(value, _dt.datetime):
            return [f"-{tag}={value.strftime('%Y:%m:%d %H:%M:%S')}"]
        return [f"-{tag}={value}"]
