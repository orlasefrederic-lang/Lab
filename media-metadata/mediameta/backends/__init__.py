"""Backend registry and selection."""

from __future__ import annotations

from pathlib import Path

from ..errors import BackendUnavailableError, UnsupportedFormatError
from ..utils import effective_suffix
from .base import Backend
from .exif_image import ExifImageBackend
from .exiftool import ExifToolBackend
from .mp4 import Mp4Backend
from .png_image import PngBackend

#: Instantiated once; backends are stateless apart from the exiftool path.
BACKENDS = (
    ExifImageBackend(),
    PngBackend(),
    Mp4Backend(),
    ExifToolBackend(),
)

BACKENDS_BY_NAME = {backend.name: backend for backend in BACKENDS}


def available_backends() -> list:
    return [backend for backend in BACKENDS if backend.is_available()[0]]


def backend_status() -> list:
    """``[(name, available, reason, formats)]`` for ``mediameta backends``."""
    status = []
    for backend in BACKENDS:
        available, reason = backend.is_available()
        formats = ", ".join(sorted(suffix.lstrip(".") for suffix in backend.read_suffixes))
        status.append((backend.name, available, reason, formats))
    return status


def select_backend(path, preferred: str = "auto", for_write: bool = False) -> Backend:
    """Pick the backend that should handle ``path``.

    ``preferred`` is ``auto``, ``native`` (never shell out), or a backend
    name. For writes, a backend that can only read the format is skipped in
    favour of one that can write it.
    """
    path = Path(path)

    if preferred not in ("auto", "native"):
        backend = BACKENDS_BY_NAME.get(preferred)
        if backend is None:
            known = ", ".join(sorted(BACKENDS_BY_NAME) + ["auto", "native"])
            raise UnsupportedFormatError(f"unknown backend {preferred!r}; choose one of: {known}")
        available, reason = backend.is_available()
        if not available:
            raise BackendUnavailableError(reason)
        return backend

    # Sniffing touches the file, so do it once and share the answer.
    suffix = effective_suffix(path)
    candidates = [backend for backend in BACKENDS if backend.supports(path, suffix)]
    if preferred == "native":
        candidates = [backend for backend in candidates if backend.name != "exiftool"]

    usable = []
    for backend in candidates:
        available, _reason = backend.is_available()
        if available:
            usable.append(backend)

    if not usable:
        raise UnsupportedFormatError(_explain_failure(path, candidates))

    if for_write:
        writers = [backend for backend in usable if backend.can_write(path, suffix)]
        if writers:
            usable = writers

    usable.sort(key=lambda backend: backend.priority, reverse=True)
    return usable[0]


def _explain_failure(path: Path, candidates) -> str:
    if candidates:
        reasons = "; ".join(
            f"{backend.name}: {backend.is_available()[1]}" for backend in candidates
        )
        return f"no usable backend for {path.name} ({reasons})"
    return (
        f"{path.suffix or 'this file'} is not a format mediameta handles natively; "
        "install exiftool to cover HEIC, RAW, MKV, AVI and friends"
    )


__all__ = [
    "Backend",
    "BACKENDS",
    "BACKENDS_BY_NAME",
    "available_backends",
    "backend_status",
    "select_backend",
]
