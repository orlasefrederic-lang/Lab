"""EXIF metadata for JPEG, WebP and TIFF, on top of ``piexif``.

TIFF and raw files can be read but not written back: for those the
ExifTool backend takes over when it is installed.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from ..errors import BackendUnavailableError, FieldError, MediaMetaError, ReadOnlyFormatError
from ..fields import format_exif_datetime, normalize, resolve_field, split_list
from ..gps import decimal_to_dms, dms_to_decimal, to_rational
from ..jpeg import is_jpeg, strip_metadata
from ..record import MetadataRecord
from ..utils import MIME_TYPES, guess_format, guess_kind, staged_write
from .. import xmp as xmp_module
from .base import Backend

try:  # piexif is pure Python and tiny, but keep the import optional
    import piexif
    import piexif.helper

    _PIEXIF_ERROR = ""
except ImportError as exc:  # pragma: no cover - depends on the environment
    piexif = None
    _PIEXIF_ERROR = str(exc)

IFD_ORDER = ("0th", "Exif", "GPS", "Interop", "1st")

# Tag numbers we care about, spelled out so the mapping below reads clearly.
MAKE = 271
MODEL = 272
ORIENTATION = 274
SOFTWARE = 305
DATETIME = 306
ARTIST = 315
COPYRIGHT = 33432
IMAGE_DESCRIPTION = 270
RATING = 18246
RATING_PERCENT = 18249
XP_TITLE = 40091
XP_COMMENT = 40092
XP_AUTHOR = 40093
XP_KEYWORDS = 40094
XP_SUBJECT = 40095

DATETIME_ORIGINAL = 36867
DATETIME_DIGITIZED = 36868
USER_COMMENT = 37510
LENS_MODEL = 42036
PIXEL_X = 40962
PIXEL_Y = 40963

GPS_VERSION = 0
GPS_LAT_REF = 1
GPS_LAT = 2
GPS_LON_REF = 3
GPS_LON = 4
GPS_ALT_REF = 5
GPS_ALT = 6


def _require_piexif():
    if piexif is None:
        raise BackendUnavailableError(
            "the EXIF backend needs piexif: pip install piexif" + (f" ({_PIEXIF_ERROR})" if _PIEXIF_ERROR else "")
        )


def _decode_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").rstrip("\x00")
    return str(value)


def _decode_xp(value) -> str:
    """XP* tags are UCS-2 little endian stored as a byte string."""
    if isinstance(value, (tuple, list)):
        value = bytes(bytearray(value))
    if not isinstance(value, bytes):
        return str(value)
    return value.decode("utf-16-le", "replace").rstrip("\x00")


def _encode_xp(text: str) -> bytes:
    return str(text).encode("utf-16-le") + b"\x00\x00"


def _rational_to_float(value) -> float:
    if isinstance(value, (tuple, list)) and len(value) == 2:
        numerator, denominator = value
        return float(numerator) / float(denominator or 1)
    return float(value)


class ExifImageBackend(Backend):
    """Canonical fields mapped onto EXIF IFD tags."""

    name = "exif"
    priority = 50
    read_suffixes = frozenset(
        {".jpg", ".jpeg", ".jpe", ".jfif", ".tif", ".tiff", ".webp"}
    )
    write_suffixes = frozenset({".jpg", ".jpeg", ".jpe", ".jfif", ".webp"})

    def is_available(self) -> tuple:
        if piexif is None:
            return False, "piexif is not installed (pip install piexif)"
        return True, ""

    # -- reading ------------------------------------------------------

    def read(self, path) -> MetadataRecord:
        _require_piexif()
        path = Path(path)
        record = MetadataRecord(
            path=path,
            kind=guess_kind(path),
            format=guess_format(path),
            backend=self.name,
            writable=self.can_write(path),
        )

        exif = self._load(path, record)
        for ifd in IFD_ORDER:
            for tag, value in (exif.get(ifd) or {}).items():
                name = self._tag_name(ifd, tag)
                record.raw[f"EXIF:{name}"] = self._raw_value(ifd, tag, value)

        self._fill_common(record, exif)

        properties = xmp_module.parse(self._xmp_packet(path))
        for key, value in properties.items():
            record.raw[f"XMP:{key}"] = value
        for field_name, value in xmp_module.to_common(properties).items():
            if field_name not in record.common:
                record.set_common(field_name, self._normalize(field_name, value))

        self._fill_dimensions(record, exif)
        mime = MIME_TYPES.get(record.format)
        if mime:
            record.common["mime_type"] = mime
        return record

    def _load(self, path: Path, record: MetadataRecord) -> dict:
        try:
            return piexif.load(str(path))
        except Exception as exc:  # piexif raises several unrelated types
            record.warnings.append(f"no readable EXIF block ({exc})")
            return {ifd: {} for ifd in IFD_ORDER}

    @staticmethod
    def _xmp_packet(path: Path, limit: int = 4 << 20):
        try:
            with path.open("rb") as handle:
                return xmp_module.extract_packet(handle.read(limit))
        except OSError:
            return None

    @staticmethod
    def _tag_name(ifd: str, tag: int) -> str:
        info = piexif.TAGS.get(ifd, {}).get(tag)
        if info:
            return info["name"]
        return f"{ifd}:{tag}"

    def _raw_value(self, ifd: str, tag: int, value):
        if tag in (XP_TITLE, XP_COMMENT, XP_AUTHOR, XP_KEYWORDS, XP_SUBJECT):
            return _decode_xp(value)
        if ifd == "Exif" and tag == USER_COMMENT:
            try:
                return piexif.helper.UserComment.load(value)
            except Exception:
                return _decode_text(value)
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8").rstrip("\x00")
            except UnicodeDecodeError:
                return value
        return value

    def _fill_common(self, record: MetadataRecord, exif: dict) -> None:
        zeroth = exif.get("0th") or {}
        exif_ifd = exif.get("Exif") or {}
        gps = exif.get("GPS") or {}

        if XP_TITLE in zeroth:
            record.set_common("title", _decode_xp(zeroth[XP_TITLE]))
        if IMAGE_DESCRIPTION in zeroth:
            record.set_common("description", _decode_text(zeroth[IMAGE_DESCRIPTION]))
        elif XP_SUBJECT in zeroth:
            record.set_common("description", _decode_xp(zeroth[XP_SUBJECT]))

        if USER_COMMENT in exif_ifd:
            record.set_common("comment", self._raw_value("Exif", USER_COMMENT, exif_ifd[USER_COMMENT]))
        elif XP_COMMENT in zeroth:
            record.set_common("comment", _decode_xp(zeroth[XP_COMMENT]))

        if ARTIST in zeroth:
            record.set_common("artist", _decode_text(zeroth[ARTIST]))
        elif XP_AUTHOR in zeroth:
            record.set_common("artist", _decode_xp(zeroth[XP_AUTHOR]))

        for tag, field_name in (
            (COPYRIGHT, "copyright"),
            (SOFTWARE, "software"),
            (MAKE, "camera_make"),
            (MODEL, "camera_model"),
        ):
            if tag in zeroth:
                record.set_common(field_name, _decode_text(zeroth[tag]))

        if XP_KEYWORDS in zeroth:
            record.set_common("keywords", split_list(_decode_xp(zeroth[XP_KEYWORDS]).replace(";", ",")))
        if RATING in zeroth:
            record.set_common("rating", int(zeroth[RATING]))
        if ORIENTATION in zeroth:
            record.set_common("orientation", int(zeroth[ORIENTATION]))
        if LENS_MODEL in exif_ifd:
            record.set_common("lens", _decode_text(exif_ifd[LENS_MODEL]))

        for source in (exif_ifd.get(DATETIME_ORIGINAL), exif_ifd.get(DATETIME_DIGITIZED), zeroth.get(DATETIME)):
            if source:
                try:
                    record.set_common("datetime_original", self._normalize("datetime_original", _decode_text(source)))
                    break
                except FieldError:
                    continue

        if GPS_LAT in gps and GPS_LON in gps:
            record.set_common(
                "gps_latitude", dms_to_decimal(gps[GPS_LAT], _decode_text(gps.get(GPS_LAT_REF, b"N")))
            )
            record.set_common(
                "gps_longitude", dms_to_decimal(gps[GPS_LON], _decode_text(gps.get(GPS_LON_REF, b"E")))
            )
        if GPS_ALT in gps:
            altitude = _rational_to_float(gps[GPS_ALT])
            if gps.get(GPS_ALT_REF) == 1:
                altitude = -altitude
            record.set_common("gps_altitude", altitude)

    def _fill_dimensions(self, record: MetadataRecord, exif: dict) -> None:
        exif_ifd = exif.get("Exif") or {}
        width, height = exif_ifd.get(PIXEL_X), exif_ifd.get(PIXEL_Y)
        if not (width and height):
            width, height = self._dimensions_from_pillow(record.path)
        if width and height:
            record.common["width"] = int(width)
            record.common["height"] = int(height)

    @staticmethod
    def _dimensions_from_pillow(path: Path):
        try:
            from PIL import Image
        except ImportError:
            return None, None
        try:
            with Image.open(path) as image:
                return image.size
        except Exception:
            return None, None

    @staticmethod
    def _normalize(field_name: str, value):
        return normalize(resolve_field(field_name), value)

    # -- writing ------------------------------------------------------

    def write(self, path, changes: dict, raw_changes: dict | None = None, output=None) -> MetadataRecord:
        _require_piexif()
        path = Path(path)
        if not self.can_write(path):
            raise ReadOnlyFormatError(
                f"{path.suffix} can be read but not written by the {self.name} backend; "
                "install exiftool for full write support"
            )
        target = self._target(path, output)

        exif = self._load_for_write(path)
        self._apply_changes(exif, changes or {})
        for key, value in (raw_changes or {}).items():
            self._apply_raw(exif, key, value)

        blob = self._dump(exif)
        data = path.read_bytes()
        with staged_write(target) as temporary:
            temporary.write_bytes(data)
            try:
                piexif.insert(blob, str(temporary))
            except Exception as exc:
                raise MediaMetaError(f"could not write EXIF into {target.name}: {exc}") from exc
        return self.read(target)

    def clear(self, path, output=None) -> MetadataRecord:
        _require_piexif()
        path = Path(path)
        if not self.can_write(path):
            raise ReadOnlyFormatError(f"{path.suffix} cannot be stripped by the {self.name} backend")
        target = self._target(path, output)

        data = path.read_bytes()
        with staged_write(target) as temporary:
            if is_jpeg(data):
                # Removes EXIF, XMP, IPTC and comments in one pass.
                temporary.write_bytes(strip_metadata(data))
            else:
                temporary.write_bytes(data)
                piexif.remove(str(temporary))
        return self.read(target)

    def _load_for_write(self, path: Path) -> dict:
        try:
            exif = piexif.load(str(path))
        except Exception:
            exif = {}
        for ifd in IFD_ORDER:
            exif.setdefault(ifd, {})
        exif.setdefault("thumbnail", None)
        return exif

    def _apply_changes(self, exif: dict, changes: dict) -> None:
        zeroth, exif_ifd, gps = exif["0th"], exif["Exif"], exif["GPS"]

        simple_text = {
            "copyright": (zeroth, COPYRIGHT),
            "software": (zeroth, SOFTWARE),
            "camera_make": (zeroth, MAKE),
            "camera_model": (zeroth, MODEL),
            "description": (zeroth, IMAGE_DESCRIPTION),
            "lens": (exif_ifd, LENS_MODEL),
        }

        for field_name, value in changes.items():
            if field_name in simple_text:
                ifd, tag = simple_text[field_name]
                self._set(ifd, tag, None if value is None else str(value).encode("utf-8"))
            elif field_name == "title":
                self._set(zeroth, XP_TITLE, None if value is None else _encode_xp(value))
            elif field_name == "artist":
                self._set(zeroth, ARTIST, None if value is None else str(value).encode("utf-8"))
                self._set(zeroth, XP_AUTHOR, None if value is None else _encode_xp(value))
            elif field_name == "comment":
                self._set(
                    exif_ifd,
                    USER_COMMENT,
                    None if value is None else piexif.helper.UserComment.dump(str(value), encoding="unicode"),
                )
                self._set(zeroth, XP_COMMENT, None if value is None else _encode_xp(value))
            elif field_name == "keywords":
                items = split_list(value)
                self._set(zeroth, XP_KEYWORDS, _encode_xp("; ".join(items)) if items else None)
            elif field_name == "rating":
                self._set(zeroth, RATING, None if value is None else int(value))
                self._set(zeroth, RATING_PERCENT, None if value is None else int(round(int(value) * 100 / 5)))
            elif field_name == "orientation":
                self._set(zeroth, ORIENTATION, None if value is None else int(value))
            elif field_name == "datetime_original":
                self._set_datetime(exif, value)
            elif field_name.startswith("gps_"):
                continue  # handled together below
            else:
                raise FieldError(f"the {self.name} backend cannot write {field_name}")

        if any(name.startswith("gps_") for name in changes):
            self._apply_gps(gps, changes)

    def _set_datetime(self, exif: dict, value) -> None:
        if value is None:
            self._set(exif["Exif"], DATETIME_ORIGINAL, None)
            self._set(exif["Exif"], DATETIME_DIGITIZED, None)
            self._set(exif["0th"], DATETIME, None)
            return
        if not isinstance(value, _dt.datetime):
            value = self._normalize("datetime_original", value)
        stamp = format_exif_datetime(value).encode("ascii")
        self._set(exif["Exif"], DATETIME_ORIGINAL, stamp)
        self._set(exif["Exif"], DATETIME_DIGITIZED, stamp)
        self._set(exif["0th"], DATETIME, stamp)

    def _apply_gps(self, gps: dict, changes: dict) -> None:
        if "gps_latitude" in changes:
            value = changes["gps_latitude"]
            if value is None:
                gps.pop(GPS_LAT, None)
                gps.pop(GPS_LAT_REF, None)
            else:
                gps[GPS_LAT] = decimal_to_dms(value)
                gps[GPS_LAT_REF] = b"N" if value >= 0 else b"S"

        if "gps_longitude" in changes:
            value = changes["gps_longitude"]
            if value is None:
                gps.pop(GPS_LON, None)
                gps.pop(GPS_LON_REF, None)
            else:
                gps[GPS_LON] = decimal_to_dms(value)
                gps[GPS_LON_REF] = b"E" if value >= 0 else b"W"

        if "gps_altitude" in changes:
            value = changes["gps_altitude"]
            if value is None:
                gps.pop(GPS_ALT, None)
                gps.pop(GPS_ALT_REF, None)
            else:
                gps[GPS_ALT] = to_rational(abs(float(value)))
                gps[GPS_ALT_REF] = 0 if float(value) >= 0 else 1

        if gps:
            gps.setdefault(GPS_VERSION, (2, 3, 0, 0))
        elif GPS_VERSION in gps:
            gps.pop(GPS_VERSION)

    def _apply_raw(self, exif: dict, key: str, value) -> None:
        namespace, _, name = key.partition(":")
        if not name:
            namespace, name = "exif", key
        if namespace.lower() not in ("exif", "tiff"):
            raise FieldError(f"the {self.name} backend only writes EXIF: tags, got {key!r}")

        ifd, tag = self._resolve_tag(name)
        if value is None:
            exif[ifd].pop(tag, None)
            return

        tag_type = piexif.TAGS[ifd][tag]["type"]
        exif[ifd][tag] = self._coerce_raw(tag, tag_type, value)

    @staticmethod
    def _resolve_tag(name: str):
        for ifd in IFD_ORDER:
            for tag, info in piexif.TAGS.get(ifd, {}).items():
                if info["name"].lower() == name.lower():
                    return ifd, tag
        raise FieldError(f"unknown EXIF tag {name!r}")

    @staticmethod
    def _coerce_raw(tag: int, tag_type: int, value):
        if tag in (XP_TITLE, XP_COMMENT, XP_AUTHOR, XP_KEYWORDS, XP_SUBJECT):
            return _encode_xp(value)
        if tag_type == piexif.TYPES.Ascii:
            return str(value).encode("utf-8")
        if tag_type in (piexif.TYPES.Byte, piexif.TYPES.Undefined):
            return value if isinstance(value, bytes) else str(value).encode("utf-8")
        if tag_type in (piexif.TYPES.Short, piexif.TYPES.Long, piexif.TYPES.SLong):
            return int(value)
        if tag_type in (piexif.TYPES.Rational, piexif.TYPES.SRational):
            if isinstance(value, (tuple, list)):
                return tuple(value)
            return to_rational(float(value))
        return value

    @staticmethod
    def _set(ifd: dict, tag: int, value) -> None:
        if value is None:
            ifd.pop(tag, None)
        else:
            ifd[tag] = value

    def _dump(self, exif: dict) -> bytes:
        """Serialise, retrying without tags that piexif refuses to encode."""
        cleaned = {ifd: dict(exif.get(ifd) or {}) for ifd in IFD_ORDER}
        cleaned["thumbnail"] = exif.get("thumbnail")

        for _attempt in range(8):
            try:
                return piexif.dump(cleaned)
            except Exception as exc:
                if not self._drop_offending_tag(cleaned, exc):
                    raise MediaMetaError(f"could not build the EXIF block: {exc}") from exc
        raise MediaMetaError("could not build the EXIF block after dropping broken tags")

    @staticmethod
    def _drop_offending_tag(cleaned: dict, exc: Exception) -> bool:
        """Remove one tag that made ``piexif.dump`` fail, if we can find it."""
        message = str(exc)
        for ifd in IFD_ORDER:
            for tag in list(cleaned.get(ifd, {})):
                name = piexif.TAGS.get(ifd, {}).get(tag, {}).get("name", "")
                if (name and name in message) or str(tag) in message:
                    cleaned[ifd].pop(tag, None)
                    return True
        # Last resort: drop the thumbnail, a frequent source of bad data.
        if cleaned.get("thumbnail") is not None:
            cleaned["thumbnail"] = None
            cleaned["1st"] = {}
            return True
        return False
