"""MP4 / MOV / M4A metadata, built on the box engine in :mod:`mediameta.mp4box`.

Three different tag dialects live in the same container and real files mix
them freely:

* ``moov/udta/meta/ilst`` - the iTunes style atoms (``\\xa9nam``, ``desc``...);
* ``moov/meta`` with ``keys`` + ``ilst`` - Apple's reverse-DNS keys, which is
  what an iPhone writes (``com.apple.quicktime.make``);
* plain text boxes directly under ``moov/udta`` (``\\xa9xyz`` for the GPS fix).

Reading merges all three, writing keeps whatever dialects the file already
uses and adds the iTunes atoms as the common denominator.
"""

from __future__ import annotations

import datetime as _dt
import struct
from pathlib import Path

from .. import mp4box
from ..errors import FieldError
from ..fields import split_list
from ..gps import format_iso6709, parse_iso6709
from ..record import MetadataRecord
from ..utils import MIME_TYPES, guess_format, guess_kind
from .base import Backend

# Apple's epoch for the time fields in mvhd/tkhd/mdhd.
_QT_EPOCH = _dt.datetime(1904, 1, 1)

TYPE_IMPLICIT = 0
TYPE_UTF8 = 1
TYPE_UTF16 = 2
TYPE_JPEG = 13
TYPE_PNG = 14
TYPE_INT = 21
TYPE_FLOAT32 = 22
TYPE_FLOAT64 = 23

#: canonical field -> iTunes-style atom
ITUNES_ATOMS = {
    "title": b"\xa9nam",
    "description": b"desc",
    "comment": b"\xa9cmt",
    "artist": b"\xa9ART",
    "copyright": b"cprt",
    "keywords": b"keyw",
    "software": b"\xa9too",
    "datetime_original": b"\xa9day",
    "album": b"\xa9alb",
    "genre": b"\xa9gen",
}

#: canonical field -> plain QuickTime text box under udta
UDTA_TEXT_ATOMS = {
    "camera_make": b"\xa9mak",
    "camera_model": b"\xa9mod",
    "title": b"\xa9nam",
    "artist": b"\xa9ART",
    "comment": b"\xa9cmt",
    "description": b"\xa9des",
    "copyright": b"\xa9cpy",
    "software": b"\xa9swr",
    "datetime_original": b"\xa9day",
}

#: canonical field -> Apple reverse-DNS key
MDTA_KEYS = {
    "title": "com.apple.quicktime.title",
    "description": "com.apple.quicktime.description",
    "comment": "com.apple.quicktime.comment",
    "artist": "com.apple.quicktime.artist",
    "copyright": "com.apple.quicktime.copyright",
    "software": "com.apple.quicktime.software",
    "camera_make": "com.apple.quicktime.make",
    "camera_model": "com.apple.quicktime.model",
    "datetime_original": "com.apple.quicktime.creationdate",
    "keywords": "com.apple.quicktime.keywords",
    "album": "com.apple.quicktime.album",
    "genre": "com.apple.quicktime.genre",
    "rating": "com.apple.quicktime.rating.user",
}
MDTA_LOCATION_KEY = "com.apple.quicktime.location.ISO6709"

GPS_ATOM = b"\xa9xyz"

LIST_FIELDS = {"keywords"}
INT_FIELDS = {"rating"}


def _atom_name(atom: bytes) -> str:
    return atom.decode("latin-1")


# -- low level atom helpers -------------------------------------------


def _decode_data_box(box: mp4box.Box):
    """Decode an iTunes ``data`` box into a Python value."""
    payload = box.payload
    if len(payload) < 8:
        return None
    type_indicator = struct.unpack_from(">I", payload, 0)[0] & 0x00FFFFFF
    raw = payload[8:]

    if type_indicator == TYPE_UTF8:
        return raw.decode("utf-8", "replace").rstrip("\x00")
    if type_indicator == TYPE_UTF16:
        return raw.decode("utf-16-be", "replace").rstrip("\x00")
    if type_indicator == TYPE_INT:
        return int.from_bytes(raw, "big", signed=True) if raw else 0
    if type_indicator in (TYPE_JPEG, TYPE_PNG):
        return f"<image, {len(raw)} bytes>"
    if type_indicator == TYPE_IMPLICIT:
        try:
            return raw.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return raw
    return raw


def _encode_data_box(value, type_indicator: int | None = None) -> mp4box.Box:
    if type_indicator is None:
        type_indicator = TYPE_INT if isinstance(value, int) and not isinstance(value, bool) else TYPE_UTF8

    if type_indicator == TYPE_INT:
        number = int(value)
        length = 1
        while number < -(1 << (8 * length - 1)) or number >= (1 << (8 * length - 1)):
            length *= 2
        raw = number.to_bytes(max(length, 1), "big", signed=True)
    elif isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8")

    header = struct.pack(">I", type_indicator) + b"\x00\x00\x00\x00"
    return mp4box.Box(b"data", payload=header + raw)


def _decode_qt_text(payload: bytes) -> str:
    """Decode a plain QuickTime text box (``u16 length``, ``u16 language``)."""
    if len(payload) >= 4:
        declared = struct.unpack_from(">H", payload, 0)[0]
        language = struct.unpack_from(">H", payload, 2)[0]
        if declared == len(payload) - 4:
            text = payload[4 : 4 + declared]
            # Language code 0 means the Macintosh encodings; 0x55c4 is UTF-8.
            encoding = "utf-16-be" if language == 0 and declared and text[:1] == b"\x00" else "utf-8"
            return text.decode(encoding, "replace").rstrip("\x00")
    return payload.decode("utf-8", "replace").rstrip("\x00")


def _encode_qt_text(text: str) -> bytes:
    raw = str(text).encode("utf-8")
    return struct.pack(">HH", len(raw), 0x55C4) + raw


def _read_itunes(ilst: mp4box.Box | None) -> dict:
    """Read ``moov/udta/meta/ilst`` into ``{atom_name: value}``."""
    tags: dict = {}
    if ilst is None or not ilst.is_container:
        return tags

    for item in ilst.children:
        if item.type == b"----":
            name = item.find(b"name")
            mean = item.find(b"mean")
            label = (name.payload[4:].decode("utf-8", "replace") if name else "unknown")
            namespace = (mean.payload[4:].decode("utf-8", "replace") if mean else "")
            key = f"----:{namespace}:{label}"
        else:
            key = _atom_name(item.type)

        values = [
            _decode_data_box(child)
            for child in (item.children or [])
            if child.type == b"data"
        ]
        values = [value for value in values if value is not None]
        if values:
            tags[key] = values[0] if len(values) == 1 else values
    return tags


def _parse_keys_box(keys: mp4box.Box) -> list:
    """Parse an Apple ``keys`` box into an ordered list of key strings."""
    payload = keys.payload
    if len(payload) < 8:
        return []
    count = struct.unpack_from(">I", payload, 4)[0]
    names = []
    offset = 8
    for _ in range(count):
        if offset + 8 > len(payload):
            break
        size = struct.unpack_from(">I", payload, offset)[0]
        if size < 8 or offset + size > len(payload):
            break
        names.append(payload[offset + 8 : offset + size].decode("utf-8", "replace"))
        offset += size
    return names


def _build_keys_box(names) -> mp4box.Box:
    entries = b""
    for name in names:
        raw = name.encode("utf-8")
        entries += struct.pack(">I", 8 + len(raw)) + b"mdta" + raw
    payload = b"\x00\x00\x00\x00" + struct.pack(">I", len(names)) + entries
    return mp4box.Box(b"keys", payload=payload)


def _read_mdta(meta: mp4box.Box | None) -> dict:
    """Read the ``keys`` + ``ilst`` pair used by Apple devices."""
    tags: dict = {}
    if meta is None or not meta.is_container:
        return tags
    keys_box = meta.find(b"keys")
    ilst = meta.find(b"ilst")
    if keys_box is None or ilst is None or not ilst.is_container:
        return tags

    names = _parse_keys_box(keys_box)
    for item in ilst.children:
        index = int.from_bytes(item.type, "big")
        if not 1 <= index <= len(names):
            continue
        values = [
            _decode_data_box(child)
            for child in (item.children or [])
            if child.type == b"data"
        ]
        values = [value for value in values if value is not None]
        if values:
            tags[names[index - 1]] = values[0] if len(values) == 1 else values
    return tags


def _write_mdta(meta: mp4box.Box, tags: dict) -> None:
    """Rebuild ``keys`` + ``ilst`` from ``{key: value}``, keeping key order."""
    names = list(tags)
    meta.remove(b"keys")
    meta.remove(b"ilst")
    if not names:
        return

    hdlr = meta.find(b"hdlr")
    if hdlr is None:
        meta.children.insert(
            0,
            mp4box.Box(
                b"hdlr",
                payload=b"\x00\x00\x00\x00" + b"\x00" * 4 + b"mdta" + b"\x00" * 12,
            ),
        )

    items = []
    for index, name in enumerate(names, start=1):
        value = tags[name]
        indicator = TYPE_INT if isinstance(value, int) and not isinstance(value, bool) else TYPE_UTF8
        items.append(
            mp4box.Box(
                index.to_bytes(4, "big"),
                children=[_encode_data_box(value, indicator)],
            )
        )
    meta.children.append(_build_keys_box(names))
    meta.children.append(mp4box.Box(b"ilst", children=items))


def _read_udta_text(udta: mp4box.Box | None) -> dict:
    tags: dict = {}
    if udta is None or not udta.is_container:
        return tags
    for child in udta.children:
        if child.is_container or child.type in (b"meta", b"free", b"skip"):
            continue
        if not child.type.startswith(b"\xa9"):
            continue
        tags[_atom_name(child.type)] = _decode_qt_text(child.payload)
    return tags


# -- movie header helpers ---------------------------------------------


def _read_mvhd(mvhd: mp4box.Box | None) -> dict:
    """Pull timescale, duration and creation time out of ``mvhd``."""
    info: dict = {}
    if mvhd is None or len(mvhd.payload) < 20:
        return info
    version = mvhd.payload[0]
    payload = mvhd.payload
    try:
        if version == 1:
            created, modified, timescale, duration = struct.unpack_from(">QQIQ", payload, 4)
        else:
            created, modified, timescale, duration = struct.unpack_from(">IIII", payload, 4)
    except struct.error:
        return info

    if timescale:
        info["duration"] = round(duration / timescale, 3)
    if created:
        info["created"] = _QT_EPOCH + _dt.timedelta(seconds=created)
    if modified:
        info["modified"] = _QT_EPOCH + _dt.timedelta(seconds=modified)
    return info


def _read_track_dimensions(moov: mp4box.Box) -> dict:
    """Return the pixel size of the first visual track, if there is one."""
    for trak in moov.findall(b"trak"):
        tkhd = trak.find(b"tkhd")
        if tkhd is None:
            continue
        payload = tkhd.payload
        version = payload[0] if payload else 0
        offset = 4 + (32 if version == 1 else 20) + 8 + 2 + 2 + 2 + 2 + 36
        if len(payload) < offset + 8:
            continue
        width, height = struct.unpack_from(">II", payload, offset)
        width, height = width >> 16, height >> 16
        if width and height:
            return {"width": int(width), "height": int(height)}
    return {}


def _set_header_times(moov: mp4box.Box, moment: _dt.datetime) -> None:
    """Update creation/modification time in mvhd, tkhd and mdhd."""
    if moment.tzinfo is not None:
        moment = moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    seconds = int((moment - _QT_EPOCH).total_seconds())
    if seconds < 0:
        return

    for box in moov.walk():
        if box.type not in (b"mvhd", b"tkhd", b"mdhd") or box.is_container:
            continue
        payload = bytearray(box.payload)
        if len(payload) < 20:
            continue
        version = payload[0]
        if version == 1:
            if len(payload) < 20:
                continue
            struct.pack_into(">QQ", payload, 4, seconds, seconds)
        else:
            struct.pack_into(">II", payload, 4, seconds & 0xFFFFFFFF, seconds & 0xFFFFFFFF)
        box.payload = bytes(payload)


def _format_creation_date(value: _dt.datetime) -> str:
    if value.tzinfo is not None:
        return value.isoformat()
    return value.strftime("%Y-%m-%dT%H:%M:%S")


class Mp4Backend(Backend):
    """Reads and writes MP4-family containers with no external dependency."""

    name = "mp4"
    priority = 50
    read_suffixes = frozenset(
        {".mp4", ".m4v", ".m4a", ".m4b", ".mov", ".qt", ".3gp", ".3g2", ".mp4v"}
    )
    write_suffixes = read_suffixes

    # -- reading ------------------------------------------------------

    def read(self, path) -> MetadataRecord:
        path = Path(path)
        moov, _top = mp4box.read_moov(path)

        udta = moov.find(b"udta")
        itunes = _read_itunes(moov.find(b"udta", b"meta", b"ilst"))
        mdta = _read_mdta(moov.find(b"meta"))
        udta_text = _read_udta_text(udta)
        header = _read_mvhd(moov.find(b"mvhd"))

        record = MetadataRecord(
            path=path,
            kind=guess_kind(path),
            format=guess_format(path),
            backend=self.name,
            writable=self.can_write(path),
        )

        for key, value in itunes.items():
            record.raw[f"iTunes:{key}"] = value
        for key, value in mdta.items():
            record.raw[f"QuickTime:{key}"] = value
        for key, value in udta_text.items():
            record.raw[f"udta:{key}"] = value
        if "created" in header:
            record.raw["QuickTime:CreateDate"] = header["created"]
        if "modified" in header:
            record.raw["QuickTime:ModifyDate"] = header["modified"]

        self._fill_common(record, itunes, mdta, udta_text, header)
        record.common.update(_read_track_dimensions(moov))
        if "duration" in header:
            record.common["duration"] = header["duration"]
        mime = MIME_TYPES.get(record.format)
        if mime:
            record.common["mime_type"] = mime
        return record

    def _fill_common(self, record, itunes, mdta, udta_text, header) -> None:
        """Merge the dialects into canonical fields, most specific first."""
        for field_name, key in MDTA_KEYS.items():
            if key in mdta:
                record.set_common(field_name, self._coerce(field_name, mdta[key]))

        for field_name, atom in ITUNES_ATOMS.items():
            if field_name in record.common:
                continue
            value = itunes.get(_atom_name(atom))
            if value is not None:
                record.set_common(field_name, self._coerce(field_name, value))

        for field_name, atom in UDTA_TEXT_ATOMS.items():
            if field_name in record.common:
                continue
            value = udta_text.get(_atom_name(atom))
            if value:
                record.set_common(field_name, self._coerce(field_name, value))

        location = mdta.get(MDTA_LOCATION_KEY) or udta_text.get(_atom_name(GPS_ATOM))
        if location:
            try:
                latitude, longitude, altitude = parse_iso6709(location)
                record.set_common("gps_latitude", latitude)
                record.set_common("gps_longitude", longitude)
                if altitude is not None:
                    record.set_common("gps_altitude", altitude)
            except ValueError:
                record.warnings.append(f"unreadable location string: {location!r}")

        if "datetime_original" not in record.common and header.get("created"):
            record.set_common("datetime_original", header["created"])

    @staticmethod
    def _coerce(field_name: str, value):
        if field_name in LIST_FIELDS:
            return split_list(value)
        if field_name in INT_FIELDS:
            try:
                return int(value)
            except (TypeError, ValueError):
                return value
        if field_name == "datetime_original":
            from ..fields import parse_datetime

            try:
                return parse_datetime(value)
            except FieldError:
                return value
        return value

    # -- writing ------------------------------------------------------

    def write(self, path, changes: dict, raw_changes: dict | None = None, output=None) -> MetadataRecord:
        path = Path(path)
        target = self._target(path, output)
        moov, top = mp4box.read_moov(path)

        self._apply_changes(moov, changes or {}, raw_changes or {})
        mp4box.rewrite_file(path, target, moov, top)
        return self.read(target)

    def clear(self, path, output=None) -> MetadataRecord:
        path = Path(path)
        target = self._target(path, output)
        moov, top = mp4box.read_moov(path)

        moov.remove(b"udta")
        meta = moov.find(b"meta")
        if meta is not None:
            moov.remove(b"meta")
        mp4box.rewrite_file(path, target, moov, top)
        return self.read(target)

    def _apply_changes(self, moov: mp4box.Box, changes: dict, raw_changes: dict) -> None:
        udta = moov.ensure_path(b"udta")
        ilst = moov.ensure_path(b"udta", b"meta", b"ilst")
        meta_iso = moov.find(b"udta", b"meta")
        if not meta_iso.find(b"hdlr"):
            meta_iso.children.insert(
                0,
                mp4box.Box(
                    b"hdlr",
                    payload=b"\x00\x00\x00\x00" + b"\x00" * 4 + b"mdir" + b"appl" + b"\x00" * 9,
                ),
            )

        mdta_meta = moov.find(b"meta")
        mdta_tags = _read_mdta(mdta_meta)

        gps_touched = any(
            key in changes for key in ("gps_latitude", "gps_longitude", "gps_altitude")
        )

        for field_name, value in changes.items():
            if field_name.startswith("gps_"):
                continue
            self._apply_field(udta, ilst, mdta_tags, field_name, value)

        if gps_touched:
            self._apply_gps(udta, mdta_tags, changes)

        if changes.get("datetime_original") is not None:
            _set_header_times(moov, changes["datetime_original"])

        for key, value in raw_changes.items():
            self._apply_raw(udta, ilst, mdta_tags, key, value)

        if mdta_tags or mdta_meta is not None:
            if mdta_meta is None:
                mdta_meta = mp4box.new_container(b"meta")
                moov.children.append(mdta_meta)
            _write_mdta(mdta_meta, mdta_tags)
            if not mdta_tags:
                moov.remove(b"meta")

        if not ilst.children:
            meta_iso_parent = udta
            meta_iso_parent.remove(b"meta")
        if not udta.children:
            moov.remove(b"udta")

    def _apply_field(self, udta, ilst, mdta_tags, field_name: str, value) -> None:
        """Write one canonical field into every dialect the file uses."""
        atom = ITUNES_ATOMS.get(field_name)
        mdta_key = MDTA_KEYS.get(field_name)

        if value is None:
            if atom is not None:
                ilst.remove(atom)
            if field_name in UDTA_TEXT_ATOMS:
                udta.remove(UDTA_TEXT_ATOMS[field_name])
            if mdta_key:
                mdta_tags.pop(mdta_key, None)
            return

        encoded = self._encode_value(field_name, value)

        if atom is not None:
            ilst.remove(atom)
            ilst.children.append(
                mp4box.Box(
                    atom,
                    children=[
                        _encode_data_box(
                            encoded,
                            TYPE_INT if isinstance(encoded, int) else TYPE_UTF8,
                        )
                    ],
                )
            )
        if field_name in UDTA_TEXT_ATOMS:
            udta_atom = UDTA_TEXT_ATOMS[field_name]
            udta.remove(udta_atom)
            udta.children.insert(0, mp4box.Box(udta_atom, payload=_encode_qt_text(encoded)))
        if mdta_key and (mdta_key in mdta_tags or atom is None):
            # Keep Apple's keys in sync, and use them for fields that have no
            # iTunes atom at all (rating, make, model).
            mdta_tags[mdta_key] = encoded

    @staticmethod
    def _encode_value(field_name: str, value):
        if field_name in LIST_FIELDS:
            return ", ".join(split_list(value))
        if isinstance(value, _dt.datetime):
            return _format_creation_date(value)
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)) and field_name in INT_FIELDS:
            return int(value)
        return str(value)

    def _apply_gps(self, udta, mdta_tags, changes: dict) -> None:
        """GPS is one string, so merge the requested parts with what is there."""
        current = mdta_tags.get(MDTA_LOCATION_KEY)
        if current is None:
            existing = _read_udta_text(udta).get(_atom_name(GPS_ATOM))
            current = existing
        latitude = longitude = altitude = None
        if current:
            try:
                latitude, longitude, altitude = parse_iso6709(current)
            except ValueError:
                latitude = longitude = altitude = None

        if "gps_latitude" in changes:
            latitude = changes["gps_latitude"]
        if "gps_longitude" in changes:
            longitude = changes["gps_longitude"]
        if "gps_altitude" in changes:
            altitude = changes["gps_altitude"]

        if latitude is None or longitude is None:
            udta.remove(GPS_ATOM)
            mdta_tags.pop(MDTA_LOCATION_KEY, None)
            return

        location = format_iso6709(latitude, longitude, altitude)
        udta.remove(GPS_ATOM)
        udta.children.insert(0, mp4box.Box(GPS_ATOM, payload=_encode_qt_text(location)))
        if MDTA_LOCATION_KEY in mdta_tags or not mdta_tags:
            mdta_tags[MDTA_LOCATION_KEY] = location

    def _apply_raw(self, udta, ilst, mdta_tags, key: str, value) -> None:
        """Set a backend-specific tag such as ``iTunes:\\xa9nam`` or an mdta key."""
        namespace, _, name = key.partition(":")
        namespace = namespace.lower()
        if not name:
            namespace, name = "itunes", key

        if namespace in ("itunes", "ilst"):
            atom = name.encode("latin-1")
            if len(atom) != 4:
                raise FieldError(f"iTunes atoms are 4 characters, got {name!r}")
            ilst.remove(atom)
            if value is not None:
                ilst.children.append(
                    mp4box.Box(atom, children=[_encode_data_box(value)])
                )
        elif namespace in ("quicktime", "mdta"):
            if value is None:
                mdta_tags.pop(name, None)
            else:
                mdta_tags[name] = value
        elif namespace == "udta":
            atom = name.encode("latin-1")
            udta.remove(atom)
            if value is not None:
                udta.children.insert(0, mp4box.Box(atom, payload=_encode_qt_text(value)))
        else:
            raise FieldError(
                f"unknown tag namespace {namespace!r}; use iTunes:, QuickTime: or udta:"
            )
