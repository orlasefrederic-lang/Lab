"""PNG metadata: the textual chunks plus the optional ``eXIf`` block.

PNG keeps descriptions in ``tEXt``/``iTXt`` chunks, while cameras and phones
increasingly add a real EXIF block. This backend reads and writes both, so
GPS coordinates or a camera model survive alongside the plain text.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from ..errors import BackendUnavailableError, MediaMetaError
from ..fields import format_exif_datetime, split_list
from ..record import MetadataRecord
from ..utils import MIME_TYPES, guess_format, guess_kind, staged_write
from .exif_image import ExifImageBackend, IFD_ORDER
from .. import xmp as xmp_module

try:
    from PIL import Image, PngImagePlugin

    _PIL_ERROR = ""
except ImportError as exc:  # pragma: no cover - depends on the environment
    Image = None
    PngImagePlugin = None
    _PIL_ERROR = str(exc)

#: canonical field -> PNG text keyword
TEXT_KEYS = {
    "title": "Title",
    "artist": "Author",
    "description": "Description",
    "copyright": "Copyright",
    "software": "Software",
    "comment": "Comment",
    "datetime_original": "Creation Time",
    "keywords": "Keywords",
}
REVERSE_TEXT_KEYS = {value.lower(): key for key, value in TEXT_KEYS.items()}

#: Chunks that are part of the image, not its metadata.
SKIP_INFO_KEYS = {
    "exif", "icc_profile", "dpi", "gamma", "transparency", "aspect",
    "srgb", "chromaticity", "interlace", "compression", "XML:com.adobe.xmp",
}


class PngBackend(ExifImageBackend):
    """Same canonical fields as EXIF, stored the way PNG stores them."""

    name = "png"
    priority = 50
    read_suffixes = frozenset({".png"})
    write_suffixes = frozenset({".png"})

    def is_available(self) -> tuple:
        available, reason = super().is_available()
        if not available:
            return available, reason
        if Image is None:
            return False, "the PNG backend needs Pillow (pip install pillow)"
        return True, ""

    def _require_pillow(self):
        if Image is None:
            raise BackendUnavailableError(
                "the PNG backend needs Pillow: pip install pillow"
                + (f" ({_PIL_ERROR})" if _PIL_ERROR else "")
            )

    # -- reading ------------------------------------------------------

    def read(self, path) -> MetadataRecord:
        self._require_pillow()
        path = Path(path)
        record = MetadataRecord(
            path=path,
            kind=guess_kind(path),
            format=guess_format(path),
            backend=self.name,
            writable=True,
        )

        with Image.open(path) as image:
            info = dict(image.info)
            record.common["width"], record.common["height"] = image.size

        exif = self._exif_from_info(info, record)
        for ifd in IFD_ORDER:
            for tag, value in (exif.get(ifd) or {}).items():
                record.raw[f"EXIF:{self._tag_name(ifd, tag)}"] = self._raw_value(ifd, tag, value)
        self._fill_common(record, exif)

        # Text chunks win: they are what the user sees in file browsers.
        for key, value in info.items():
            if key in SKIP_INFO_KEYS or not isinstance(value, str):
                continue
            record.raw[f"PNG:{key}"] = value
            field_name = REVERSE_TEXT_KEYS.get(key.lower())
            if field_name:
                record.set_common(field_name, self._decode_text_field(field_name, value))

        packet = info.get("XML:com.adobe.xmp") or self._xmp_packet(path)
        properties = xmp_module.parse(packet)
        for key, value in properties.items():
            record.raw[f"XMP:{key}"] = value
        for field_name, value in xmp_module.to_common(properties).items():
            record.common.setdefault(field_name, self._decode_text_field(field_name, value))

        mime = MIME_TYPES.get(record.format)
        if mime:
            record.common["mime_type"] = mime
        return record

    def _exif_from_info(self, info: dict, record: MetadataRecord) -> dict:
        blob = info.get("exif")
        if not blob:
            return {ifd: {} for ifd in IFD_ORDER}
        try:
            import piexif

            return piexif.load(blob)
        except Exception as exc:
            record.warnings.append(f"the eXIf chunk could not be parsed ({exc})")
            return {ifd: {} for ifd in IFD_ORDER}

    def _decode_text_field(self, field_name: str, value):
        if field_name == "keywords":
            return split_list(str(value).replace(";", ","))
        if field_name == "datetime_original":
            try:
                return self._normalize(field_name, value)
            except Exception:
                return value
        if field_name == "rating":
            try:
                return int(value)
            except (TypeError, ValueError):
                return value
        return value

    # -- writing ------------------------------------------------------

    def write(self, path, changes: dict, raw_changes: dict | None = None, output=None) -> MetadataRecord:
        self._require_pillow()
        path = Path(path)
        target = self._target(path, output)
        changes = dict(changes or {})
        raw_changes = dict(raw_changes or {})

        with Image.open(path) as image:
            info = dict(image.info)
            record = MetadataRecord(path=path, backend=self.name)
            exif = self._exif_from_info(info, record)

            exif_changes = {
                name: value for name, value in changes.items()
                if name not in TEXT_KEYS or name in ("datetime_original",)
            }
            self._apply_changes(exif, exif_changes)
            for key, value in raw_changes.items():
                namespace, _, name = key.partition(":")
                if namespace.upper() == "PNG" and name:
                    info[name] = value
                else:
                    self._apply_raw(exif, key, value)

            text = self._text_chunks(info, changes)
            self._save(image, target, text, exif, info)

        return self.read(target)

    def clear(self, path, output=None) -> MetadataRecord:
        self._require_pillow()
        path = Path(path)
        target = self._target(path, output)
        with Image.open(path) as image:
            info = dict(image.info)
            self._save(image, target, {}, None, info, keep_icc=True)
        return self.read(target)

    def _text_chunks(self, info: dict, changes: dict) -> dict:
        """Start from the chunks already in the file, then apply the changes."""
        text = {
            key: value
            for key, value in info.items()
            if isinstance(value, str) and key not in SKIP_INFO_KEYS
        }
        for field_name, value in changes.items():
            key = TEXT_KEYS.get(field_name)
            if key is None:
                continue
            if value is None:
                text.pop(key, None)
            elif field_name == "keywords":
                items = split_list(value)
                if items:
                    text[key] = "; ".join(items)
                else:
                    text.pop(key, None)
            elif isinstance(value, _dt.datetime):
                text[key] = format_exif_datetime(value)
            else:
                text[key] = str(value)
        return text

    def _save(self, image, target, text: dict, exif, info: dict, keep_icc: bool = True) -> None:
        png_info = PngImagePlugin.PngInfo()
        for key, value in text.items():
            png_info.add_text(key, str(value), zip=False)

        save_kwargs = {"pnginfo": png_info}
        if keep_icc and info.get("icc_profile"):
            save_kwargs["icc_profile"] = info["icc_profile"]

        if exif is not None and any(exif.get(ifd) for ifd in IFD_ORDER):
            save_kwargs["exif"] = self._dump(exif)

        try:
            with staged_write(target) as temporary:
                image.save(temporary, format="PNG", **save_kwargs)
        except Exception as exc:
            raise MediaMetaError(f"could not write {Path(target).name}: {exc}") from exc
