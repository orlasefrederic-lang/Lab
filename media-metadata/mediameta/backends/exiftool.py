"""Optional backend that shells out to Phil Harvey's ExifTool.

It is not required for the common cases, but when ExifTool is available it
unlocks everything the pure-Python backends cannot do: HEIC, RAW, MKV, AVI,
writing TIFF, and XMP sidecars.

The program is looked up in this order: an explicit path given to the
backend, the ``MEDIAMETA_EXIFTOOL`` environment variable, the private copy
that ``mediameta exiftool install`` downloads, and finally ``PATH``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .. import exiftool_setup
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

    #: ``None`` means "only on Windows"; see :meth:`_run` for why.
    use_argfile = None

    def __init__(self, executable: str | None = None):
        self.executable = executable

    def resolve(self) -> tuple:
        """Return ``(command, source)``; ``command`` is ``None`` if not found."""
        if self.executable:
            return _existing(self.executable), "explicit path"

        configured = os.environ.get("MEDIAMETA_EXIFTOOL")
        if configured:
            return _existing(configured), "MEDIAMETA_EXIFTOOL"

        managed = exiftool_setup.managed_command()
        if managed:
            return managed, "mediameta's own copy"

        found = shutil.which("exiftool")
        if found:
            return [found], "PATH"
        return None, ""

    def is_available(self) -> tuple:
        command, source = self.resolve()
        if command:
            return True, ""
        if source:
            return False, f"exiftool from {source} was not found"
        hint = "run `mediameta exiftool install`"
        if sys.platform.startswith("linux"):
            hint += " or `sudo apt install libimage-exiftool-perl`"
        return False, f"exiftool is not installed: {hint}"

    def supports(self, path, suffix: str | None = None) -> bool:
        # ExifTool knows more formats than our suffix table, so accept anything
        # that looks like a media file plus the sidecar formats it owns.
        suffix = suffix or effective_suffix(path)
        return suffix in self.read_suffixes or suffix in {".xmp", ".heic", ".heif", ".avif"}

    def can_write(self, path, suffix: str | None = None) -> bool:
        return self.supports(path, suffix)

    # -- process plumbing ---------------------------------------------

    def _run(self, arguments, check: bool = True) -> subprocess.CompletedProcess:
        command, _source = self.resolve()
        if not command:
            raise MediaMetaError(self.is_available()[1])

        use_argfile = self.use_argfile
        if use_argfile is None:
            use_argfile = sys.platform == "win32"

        stdin_text = None
        if use_argfile:
            # Windows hands command-line arguments to exiftool in the legacy
            # ANSI code page, so a Cyrillic title would arrive as cp1251 bytes
            # while we promise UTF-8. Arguments read from stdin (-@ -) are
            # taken verbatim, and "filename=utf8" covers the file names too.
            lines = ["-charset", "filename=utf8", *arguments]
            stdin_text = "".join(_argfile_line(argument) + "\n" for argument in lines)
            command = [*command, "-@", "-"]
        else:
            command = [*command, *arguments]

        try:
            result = subprocess.run(
                command,
                input=stdin_text,
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


def _existing(executable: str):
    """A one-element command list if ``executable`` exists, else ``None``."""
    found = shutil.which(executable)
    if found:
        return [found]
    if Path(executable).is_file():
        return [str(executable)]
    return None


def _argfile_line(argument: str) -> str:
    """Encode one argument as a line of an exiftool argument file.

    Plain lines lose surrounding white space and lines starting with ``#``
    are comments, so anything unusual goes through the ``#[CSTR]`` form,
    where C escapes keep newlines and spaces intact.
    """
    unusual = (
        argument != argument.strip()
        or argument.startswith("#")
        or any(character in argument for character in "\r\n\t")
    )
    if not unusual:
        return argument
    escaped = (
        argument.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace('"', '\\"')
    )
    return "#[CSTR]" + escaped
