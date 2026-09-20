"""Backend interface.

A backend knows one family of container formats. It reports which files it
can handle, reads them into a :class:`~mediameta.record.MetadataRecord` and
applies changes expressed in canonical field names.
"""

from __future__ import annotations

from pathlib import Path

from ..errors import ReadOnlyFormatError
from ..record import MetadataRecord
from ..utils import effective_suffix


class Backend:
    """Base class; subclasses override :meth:`read` and usually :meth:`write`."""

    #: Short identifier shown in output and accepted by ``--backend``.
    name = "base"

    #: Higher wins when several backends accept the same file.
    priority = 0

    #: Suffixes this backend can read, lowercase with the dot.
    read_suffixes: frozenset = frozenset()

    #: Subset of :attr:`read_suffixes` this backend can also write.
    write_suffixes: frozenset = frozenset()

    def is_available(self) -> tuple:
        """Return ``(available, reason)``; reason explains a missing dependency."""
        return True, ""

    def supports(self, path, suffix: str | None = None) -> bool:
        return (suffix or effective_suffix(path)) in self.read_suffixes

    def can_write(self, path, suffix: str | None = None) -> bool:
        return (suffix or effective_suffix(path)) in self.write_suffixes

    # -- operations ---------------------------------------------------

    def read(self, path) -> MetadataRecord:
        raise NotImplementedError

    def write(self, path, changes: dict, raw_changes: dict | None = None, output=None) -> MetadataRecord:
        """Apply canonical ``changes`` (``None`` deletes a field).

        ``raw_changes`` carries backend-specific tags. When ``output`` is
        given the original file is left alone and the result is written
        there instead.
        """
        raise ReadOnlyFormatError(
            f"{self.name} cannot write {Path(path).suffix or 'this format'}"
        )

    def clear(self, path, output=None) -> MetadataRecord:
        """Strip every editable metadata block from the file."""
        raise ReadOnlyFormatError(
            f"{self.name} cannot strip metadata from {Path(path).suffix or 'this format'}"
        )

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _target(path, output):
        return Path(path) if output is None else Path(output)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.name}>"
