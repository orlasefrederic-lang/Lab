"""Exception hierarchy for mediameta."""

from __future__ import annotations


class MediaMetaError(Exception):
    """Base class for every error raised by this package."""


class UnsupportedFormatError(MediaMetaError):
    """No backend knows how to handle the given file."""


class ReadOnlyFormatError(MediaMetaError):
    """The format can be inspected but the active backend cannot write it."""


class BackendUnavailableError(MediaMetaError):
    """A backend was requested but its dependency is missing."""


class FieldError(MediaMetaError):
    """A field name or value could not be understood."""


class CorruptFileError(MediaMetaError):
    """The file structure is broken or unexpected."""
