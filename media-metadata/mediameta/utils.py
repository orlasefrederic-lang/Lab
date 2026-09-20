"""Small helpers shared by the backends: safe file replacement, kind guessing."""

from __future__ import annotations

import glob
import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .errors import MediaMetaError

IMAGE_SUFFIXES = {
    ".jpg": "JPEG", ".jpeg": "JPEG", ".jpe": "JPEG", ".jfif": "JPEG",
    ".png": "PNG", ".tif": "TIFF", ".tiff": "TIFF", ".webp": "WEBP",
    ".heic": "HEIC", ".heif": "HEIF", ".avif": "AVIF", ".gif": "GIF",
    ".bmp": "BMP", ".dng": "DNG", ".cr2": "CR2", ".cr3": "CR3",
    ".nef": "NEF", ".arw": "ARW", ".orf": "ORF", ".rw2": "RW2",
}

VIDEO_SUFFIXES = {
    ".mp4": "MP4", ".m4v": "M4V", ".mov": "MOV", ".qt": "MOV",
    ".3gp": "3GP", ".3g2": "3G2", ".mkv": "MKV", ".webm": "WEBM",
    ".avi": "AVI", ".wmv": "WMV", ".flv": "FLV", ".mts": "MTS",
    ".m2ts": "M2TS", ".mpg": "MPEG", ".mpeg": "MPEG", ".ts": "MPEGTS",
}

AUDIO_SUFFIXES = {
    ".m4a": "M4A", ".mp3": "MP3", ".aac": "AAC", ".flac": "FLAC",
    ".ogg": "OGG", ".opus": "OPUS", ".wav": "WAV", ".aiff": "AIFF",
}

MEDIA_SUFFIXES = set(IMAGE_SUFFIXES) | set(VIDEO_SUFFIXES) | set(AUDIO_SUFFIXES)

MIME_TYPES = {
    "JPEG": "image/jpeg", "PNG": "image/png", "TIFF": "image/tiff",
    "WEBP": "image/webp", "HEIC": "image/heic", "GIF": "image/gif",
    "MP4": "video/mp4", "M4V": "video/x-m4v", "MOV": "video/quicktime",
    "3GP": "video/3gpp", "M4A": "audio/mp4", "MKV": "video/x-matroska",
    "WEBM": "video/webm", "AVI": "video/x-msvideo",
}


#: Leading bytes -> canonical suffix, for files with a missing or wrong name.
MAGIC_NUMBERS = (
    (b"\xff\xd8\xff", ".jpg"),
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"II*\x00", ".tif"),
    (b"MM\x00*", ".tif"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"\x1aE\xdf\xa3", ".mkv"),
    (b"ID3", ".mp3"),
    (b"fLaC", ".flac"),
    (b"OggS", ".ogg"),
)

#: ``ftyp`` brand -> suffix, read at offset 4 of ISO base media files.
FTYP_BRANDS = {
    b"qt  ": ".mov",
    b"heic": ".heic", b"heix": ".heic", b"heim": ".heic", b"mif1": ".heic",
    b"avif": ".avif",
    b"3gp": ".3gp", b"3g2": ".3g2",
    b"M4A ": ".m4a", b"M4V ": ".m4v", b"M4B ": ".m4b",
}


def sniff_suffix(path):
    """Guess the format from the file's own bytes, ignoring its name."""
    try:
        with Path(path).open("rb") as handle:
            head = handle.read(16)
    except OSError:
        return None
    if len(head) < 12:
        return None

    for signature, suffix in MAGIC_NUMBERS:
        if head.startswith(signature):
            return suffix

    if head[:4] == b"RIFF":
        if head[8:12] == b"WEBP":
            return ".webp"
        if head[8:12] == b"AVI ":
            return ".avi"
        if head[8:12] == b"WAVE":
            return ".wav"

    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in FTYP_BRANDS:
            return FTYP_BRANDS[brand]
        if brand[:3] in (b"3gp", b"3g2"):
            return ".3gp"
        return ".mp4"
    return None


#: Suffixes that share a container, where the name is more specific than the
#: bytes: every MP4-family file starts with the same ``ftyp`` header.
CONTAINER_FAMILIES = {
    **{suffix: "jpeg" for suffix in (".jpg", ".jpeg", ".jpe", ".jfif")},
    **{suffix: "tiff" for suffix in (".tif", ".tiff")},
    **{
        suffix: "iso"
        for suffix in (
            ".mp4", ".m4v", ".m4a", ".m4b", ".mp4v", ".mov", ".qt",
            ".3gp", ".3g2", ".heic", ".heif", ".avif",
        )
    },
    **{suffix: "riff" for suffix in (".avi", ".wav", ".webp")},
    **{suffix: "matroska" for suffix in (".mkv", ".webm")},
}


def _family(suffix: str) -> str:
    return CONTAINER_FAMILIES.get(suffix, suffix)


def effective_suffix(path) -> str:
    """The suffix to treat the file as, preferring its content over its name.

    A JPEG named ``.png`` is handled as a JPEG, because writing it back as a
    PNG would silently re-encode the image. When name and content agree on
    the container, the name wins: it distinguishes ``.mov`` from ``.mp4``,
    which share the very same header.
    """
    suffix = Path(path).suffix.lower()
    sniffed = sniff_suffix(path)

    if sniffed is None:
        return suffix
    if suffix not in MEDIA_SUFFIXES:
        return sniffed
    if _family(suffix) == _family(sniffed):
        return suffix
    return sniffed


def guess_kind(path) -> str:
    """Return ``image``, ``video``, ``audio`` or ``unknown`` for a file."""
    suffix = effective_suffix(path)
    if suffix in IMAGE_SUFFIXES:
        return "image"
    if suffix in VIDEO_SUFFIXES:
        return "video"
    if suffix in AUDIO_SUFFIXES:
        return "audio"
    return "unknown"


def guess_format(path) -> str:
    suffix = effective_suffix(path)
    for table in (IMAGE_SUFFIXES, VIDEO_SUFFIXES, AUDIO_SUFFIXES):
        if suffix in table:
            return table[suffix]
    return suffix.lstrip(".").upper()


def is_media_file(path) -> bool:
    """True for files we recognise, by name or - if the name is unhelpful -
    by their first bytes, so ``IMG_0001`` without a suffix still counts."""
    return effective_suffix(path) in MEDIA_SUFFIXES


def _expand_wildcards(entry: Path):
    """Resolve ``*.jpg`` ourselves.

    Unix shells expand wildcards before we ever see them, but the Windows
    command prompt hands the pattern through verbatim, so the same command
    has to work in both places.
    """
    pattern = str(entry)
    if not any(character in pattern for character in "*?[") or entry.exists():
        return [entry]
    return [Path(match) for match in sorted(glob.glob(pattern, recursive=True))]


def iter_media_files(paths, recursive: bool = False):
    """Expand a mix of files, directories and patterns into media files."""
    for raw in paths:
        for entry in _expand_wildcards(Path(raw)):
            if entry.is_dir():
                if not recursive:
                    continue
                for child in sorted(entry.rglob("*")):
                    if child.is_file() and is_media_file(child):
                        yield child
            elif _came_from_a_pattern(raw) and not is_media_file(entry):
                continue  # a broad pattern should not drag in text files
            else:
                yield entry


def _came_from_a_pattern(raw) -> bool:
    return any(character in str(raw) for character in "*?[")


def make_backup(path, suffix: str = ".bak") -> Path:
    """Copy ``path`` next to itself, never overwriting an existing backup."""
    path = Path(path)
    candidate = path.with_name(path.name + suffix)
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}{suffix}{counter}")
        counter += 1
    shutil.copy2(path, candidate)
    return candidate


@contextmanager
def staged_write(target):
    """Write to a temporary file, then move it over ``target`` atomically.

    The original file stays untouched if anything raises, and permissions
    and timestamps of an existing target are preserved.
    """
    target = Path(target)
    directory = target.parent if str(target.parent) else Path(".")
    directory.mkdir(parents=True, exist_ok=True)

    handle, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".mediameta", dir=str(directory)
    )
    os.close(handle)
    temporary = Path(temporary)
    try:
        yield temporary
        if target.exists():
            shutil.copystat(target, temporary)
        try:
            os.replace(temporary, target)
        except PermissionError as exc:
            # Windows refuses to replace a file another program still holds.
            raise MediaMetaError(
                f"{target.name} is locked by another program (a viewer or "
                f"editor with the file open?); close it and try again"
            ) from exc
    finally:
        if temporary.exists():
            temporary.unlink()


def copy_chunks(source, destination, offset: int, length: int, chunk_size: int = 1 << 20) -> None:
    """Stream ``length`` bytes from one open binary file into another."""
    source.seek(offset)
    remaining = length
    while remaining > 0:
        block = source.read(min(chunk_size, remaining))
        if not block:
            raise EOFError(f"unexpected end of file at offset {offset}")
        destination.write(block)
        remaining -= len(block)
