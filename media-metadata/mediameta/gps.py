"""Conversions between the coordinate notations used by media metadata.

EXIF stores coordinates as three unsigned rationals (degrees, minutes,
seconds) plus a hemisphere reference, QuickTime uses ISO 6709 strings and
humans use decimal degrees or typed DMS such as ``55 deg 45' 20.9" N``.
"""

from __future__ import annotations

import math
import re
from fractions import Fraction

_DMS_RE = re.compile(
    r"""^\s*
    (?P<sign>[-+])?
    (?P<deg>\d+(?:\.\d+)?)\s*(?:[d°]|deg|degrees)?\s*
    (?:(?P<min>\d+(?:\.\d+)?)\s*['′m]?\s*)?
    (?:(?P<sec>\d+(?:\.\d+)?)\s*(?:["″]|''|s)?\s*)?
    (?P<ref>[NSEWnsew])?
    \s*$""",
    re.VERBOSE,
)

_ISO6709_RE = re.compile(
    r"^(?P<lat>[-+]\d{2,6}(?:\.\d+)?)(?P<lon>[-+]\d{3,7}(?:\.\d+)?)"
    r"(?P<alt>[-+]\d+(?:\.\d+)?)?/?$"
)


def parse_coordinate(value, axis: str = "lat") -> float:
    """Parse a coordinate written as a decimal number or as DMS text.

    ``axis`` is ``"lat"`` or ``"lon"``: it decides which hemisphere letters
    are accepted and which range the result must fall into.
    """
    degrees = _to_degrees(value, axis)

    limit = 90.0 if axis == "lat" else 180.0
    if not -limit <= degrees <= limit:
        raise ValueError(f"{degrees} is out of range for {axis}")
    return degrees


def _to_degrees(value, axis: str) -> float:
    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    if not text:
        raise ValueError("empty coordinate")

    try:
        return float(text)
    except ValueError:
        pass

    match = _DMS_RE.match(text)
    if not match:
        raise ValueError(f"cannot parse coordinate: {value!r}")

    degrees = float(match.group("deg"))
    degrees += float(match.group("min") or 0) / 60.0
    degrees += float(match.group("sec") or 0) / 3600.0

    if match.group("sign") == "-":
        degrees = -degrees

    ref = (match.group("ref") or "").upper()
    if ref:
        positive = "N" if axis == "lat" else "E"
        negative = "S" if axis == "lat" else "W"
        if ref not in (positive, negative):
            raise ValueError(f"{ref} is not a valid reference for {axis}")
        degrees = abs(degrees) * (1 if ref == positive else -1)

    return degrees


def decimal_to_dms(value: float, precision: int = 10000):
    """Return ``((deg, 1), (min, 1), (sec_num, precision))`` for EXIF."""
    value = abs(float(value))
    degrees = int(value)
    minutes_float = (value - degrees) * 60
    minutes = int(minutes_float)
    seconds = (minutes_float - minutes) * 60
    seconds_num = int(round(seconds * precision))
    # Rounding may push seconds to exactly 60; carry it over.
    if seconds_num >= 60 * precision:
        seconds_num -= 60 * precision
        minutes += 1
    if minutes >= 60:
        minutes -= 60
        degrees += 1
    return ((degrees, 1), (minutes, 1), (seconds_num, precision))


def dms_to_decimal(dms, ref: str | None = None) -> float:
    """Inverse of :func:`decimal_to_dms`; ``ref`` applies the hemisphere."""
    parts = []
    for component in tuple(dms)[:3]:
        if isinstance(component, (tuple, list)):
            numerator, denominator = component
            parts.append(float(numerator) / float(denominator or 1))
        else:
            parts.append(float(component))
    while len(parts) < 3:
        parts.append(0.0)

    degrees = parts[0] + parts[1] / 60.0 + parts[2] / 3600.0
    if ref and str(ref).upper().strip("\x00 ") in ("S", "W"):
        degrees = -degrees
    return degrees


def to_rational(value: float, max_denominator: int = 1000000):
    """Convert a float to the ``(numerator, denominator)`` pair EXIF wants."""
    fraction = Fraction(float(value)).limit_denominator(max_denominator)
    return (fraction.numerator, fraction.denominator)


def format_iso6709(latitude: float, longitude: float, altitude: float | None = None) -> str:
    """Render coordinates the way QuickTime's ``\\xa9xyz`` atom expects."""
    text = f"{latitude:+09.5f}{longitude:+010.5f}"
    if altitude is not None and not math.isnan(altitude):
        text += f"{altitude:+.3f}"
    return text + "/"


def parse_iso6709(text: str):
    """Parse an ISO 6709 string into ``(lat, lon, alt_or_None)``."""
    cleaned = str(text).strip().strip("\x00")
    match = _ISO6709_RE.match(cleaned)
    if not match:
        raise ValueError(f"not an ISO 6709 location: {text!r}")

    altitude = match.group("alt")
    return (
        float(match.group("lat")),
        float(match.group("lon")),
        float(altitude) if altitude is not None else None,
    )
