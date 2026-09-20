"""The canonical field vocabulary shared by every backend.

Each backend maps these names onto its own tags (EXIF numbers, QuickTime
atoms, PNG text keywords, ExifTool tag names), so ``title`` means the same
thing whether the file is a JPEG or an MP4.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field as _dc_field

from .errors import FieldError
from .gps import parse_coordinate

TEXT = "text"
TEXT_LIST = "text_list"
DATETIME = "datetime"
INT = "int"
FLOAT = "float"
COORD_LAT = "lat"
COORD_LON = "lon"


@dataclass(frozen=True)
class FieldSpec:
    """Describes one canonical field."""

    name: str
    type: str
    help: str
    media: tuple = ("image", "video", "audio")
    writable: bool = True
    choices: tuple = ()
    minimum: float | None = None
    maximum: float | None = None
    aliases: tuple = _dc_field(default=())

    def applies_to(self, kind: str) -> bool:
        return kind in self.media or kind == "unknown"


COMMON_FIELDS: tuple = (
    FieldSpec("title", TEXT, "Short name of the work"),
    FieldSpec("description", TEXT, "Long caption or description", aliases=("caption",)),
    FieldSpec("comment", TEXT, "Free-form user comment"),
    FieldSpec("artist", TEXT, "Author, photographer or creator", aliases=("author", "creator")),
    FieldSpec("copyright", TEXT, "Copyright notice", aliases=("rights",)),
    FieldSpec("keywords", TEXT_LIST, "Comma-separated keywords or tags", aliases=("tags",)),
    FieldSpec("software", TEXT, "Program that produced the file", aliases=("encoder",)),
    FieldSpec(
        "datetime_original",
        DATETIME,
        "Moment the photo or video was captured",
        aliases=("date", "datetime", "taken"),
    ),
    FieldSpec("camera_make", TEXT, "Camera manufacturer", aliases=("make",)),
    FieldSpec("camera_model", TEXT, "Camera model", aliases=("model",)),
    FieldSpec("lens", TEXT, "Lens model", media=("image",)),
    FieldSpec(
        "orientation",
        INT,
        "EXIF orientation, 1-8",
        media=("image",),
        minimum=1,
        maximum=8,
    ),
    FieldSpec("rating", INT, "Rating from 0 to 5", minimum=0, maximum=5),
    FieldSpec("gps_latitude", COORD_LAT, "Latitude in degrees or DMS", aliases=("lat",)),
    FieldSpec("gps_longitude", COORD_LON, "Longitude in degrees or DMS", aliases=("lon", "lng")),
    FieldSpec("gps_altitude", FLOAT, "Altitude in metres", aliases=("alt",)),
    FieldSpec("album", TEXT, "Album or collection", media=("video", "audio")),
    FieldSpec("genre", TEXT, "Genre", media=("video", "audio")),
    FieldSpec("duration", FLOAT, "Length in seconds (read-only)", media=("video", "audio"), writable=False),
    FieldSpec("width", INT, "Pixel width (read-only)", writable=False),
    FieldSpec("height", INT, "Pixel height (read-only)", writable=False),
    FieldSpec("mime_type", TEXT, "Detected media type (read-only)", writable=False),
)

FIELDS_BY_NAME = {spec.name: spec for spec in COMMON_FIELDS}

_ALIASES = {}
for _spec in COMMON_FIELDS:
    for _alias in _spec.aliases:
        _ALIASES[_alias] = _spec.name

#: ``gps`` is a shorthand that expands into latitude/longitude/altitude.
GPS_SHORTHAND = "gps"


def resolve_field(name: str) -> FieldSpec:
    """Look a field up by canonical name or alias."""
    key = str(name).strip().lower().replace("-", "_")
    if key in FIELDS_BY_NAME:
        return FIELDS_BY_NAME[key]
    if key in _ALIASES:
        return FIELDS_BY_NAME[_ALIASES[key]]
    raise FieldError(
        f"unknown field {name!r}; run `mediameta fields` to see the supported ones"
    )


_DATE_FORMATS = (
    "%Y:%m:%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y:%m:%d %H:%M",
    "%Y-%m-%d %H:%M",
    "%Y:%m:%d",
    "%Y-%m-%d",
    "%d.%m.%Y %H:%M:%S",
    "%d.%m.%Y",
)


def parse_datetime(value) -> _dt.datetime:
    """Accept the many date spellings found in metadata and on command lines."""
    if isinstance(value, _dt.datetime):
        return value
    if isinstance(value, _dt.date):
        return _dt.datetime(value.year, value.month, value.day)

    text = str(value).strip().strip("\x00").strip()
    if not text:
        raise FieldError("empty date")
    if text.lower() == "now":
        return _dt.datetime.now()

    # Most files use naive local time; keep an explicit offset when present.
    try:
        return _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass

    normalized = text.replace("Z", "+0000")
    for fmt in _DATE_FORMATS:
        for suffix in ("", "%z"):
            try:
                return _dt.datetime.strptime(normalized, fmt + suffix)
            except ValueError:
                continue
    raise FieldError(f"cannot parse date {value!r}")


def format_exif_datetime(value: _dt.datetime) -> str:
    return value.strftime("%Y:%m:%d %H:%M:%S")


def split_list(value) -> list:
    """Turn ``"a, b; c"`` or a sequence into a clean list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = [str(item).strip() for item in value]
    else:
        text = str(value).replace(";", ",")
        items = [item.strip() for item in text.split(",")]
    return [item for item in items if item]


def normalize(spec: FieldSpec, value):
    """Coerce a user-supplied value into the canonical Python type."""
    if value is None:
        return None

    try:
        if spec.type == TEXT:
            text = value if isinstance(value, str) else str(value)
            return text.strip("\x00")
        if spec.type == TEXT_LIST:
            return split_list(value)
        if spec.type == DATETIME:
            return parse_datetime(value)
        if spec.type == INT:
            number = int(str(value).strip()) if not isinstance(value, int) else value
            _check_range(spec, number)
            return number
        if spec.type == FLOAT:
            number = float(str(value).strip()) if not isinstance(value, float) else value
            _check_range(spec, number)
            return number
        if spec.type == COORD_LAT:
            return parse_coordinate(value, "lat")
        if spec.type == COORD_LON:
            return parse_coordinate(value, "lon")
    except FieldError:
        raise
    except (TypeError, ValueError) as exc:
        raise FieldError(f"invalid value for {spec.name}: {value!r} ({exc})") from exc

    return value


def _check_range(spec: FieldSpec, number) -> None:
    if spec.minimum is not None and number < spec.minimum:
        raise FieldError(f"{spec.name} must be >= {spec.minimum}, got {number}")
    if spec.maximum is not None and number > spec.maximum:
        raise FieldError(f"{spec.name} must be <= {spec.maximum}, got {number}")


def parse_assignments(pairs) -> dict:
    """Parse ``name=value`` strings from the command line into canonical fields.

    An empty value means "delete this field". ``gps=lat,lon[,alt]`` expands
    into the three separate coordinate fields.
    """
    changes: dict = {}
    for pair in pairs:
        if "=" not in pair:
            raise FieldError(f"expected NAME=VALUE, got {pair!r}")
        name, _, raw = pair.partition("=")
        name = name.strip().lower().replace("-", "_")
        raw = raw.strip()

        if name == GPS_SHORTHAND:
            changes.update(_expand_gps(raw))
            continue

        spec = resolve_field(name)
        if not spec.writable:
            raise FieldError(f"{spec.name} is read-only")
        changes[spec.name] = None if raw == "" else normalize(spec, raw)
    return changes


def _expand_gps(raw: str) -> dict:
    if raw == "":
        return {"gps_latitude": None, "gps_longitude": None, "gps_altitude": None}

    parts = [part.strip() for part in raw.split(",") if part.strip()]
    if len(parts) not in (2, 3):
        raise FieldError("gps expects 'lat,lon' or 'lat,lon,altitude'")

    changes = {
        "gps_latitude": parse_coordinate(parts[0], "lat"),
        "gps_longitude": parse_coordinate(parts[1], "lon"),
    }
    if len(parts) == 3:
        changes["gps_altitude"] = float(parts[2])
    return changes
