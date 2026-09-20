import pytest

from mediameta.gps import (
    decimal_to_dms,
    dms_to_decimal,
    format_iso6709,
    parse_coordinate,
    parse_iso6709,
    to_rational,
)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("55.7558", 55.7558),
        ("-37.6176", -37.6176),
        ("55 deg 45' 20.9\" N", 55.75580),
        ("37°37'3.36\"E", 37.6176),
        ("12 30 30 S", -12.508333),
    ],
)
def test_parse_coordinate(text, expected):
    assert parse_coordinate(text, "lat" if "N" in text or "S" in text else "lon") == pytest.approx(
        expected, abs=1e-5
    )


def test_parse_coordinate_rejects_nonsense():
    with pytest.raises(ValueError):
        parse_coordinate("somewhere nice")


def test_parse_coordinate_rejects_out_of_range():
    with pytest.raises(ValueError):
        parse_coordinate("95.0", "lat")


def test_parse_coordinate_rejects_wrong_hemisphere():
    with pytest.raises(ValueError):
        parse_coordinate("55.5 E", "lat")


@pytest.mark.parametrize("value", [55.755831, -37.61764, 0.0, 89.999999])
def test_dms_roundtrip(value):
    dms = decimal_to_dms(value)
    reference = "N" if value >= 0 else "S"
    assert dms_to_decimal(dms, reference) == pytest.approx(value, abs=1e-6)


def test_decimal_to_dms_carries_rounding():
    # 10.999999999 must not produce 60 seconds.
    degrees, minutes, seconds = decimal_to_dms(10.99999999999)
    assert minutes[0] < 60
    assert seconds[0] / seconds[1] < 60


def test_iso6709_roundtrip():
    text = format_iso6709(55.7558, 37.6176, 140.0)
    latitude, longitude, altitude = parse_iso6709(text)
    assert (latitude, longitude, altitude) == pytest.approx((55.7558, 37.6176, 140.0), abs=1e-4)


def test_iso6709_without_altitude():
    assert parse_iso6709("+55.7558+037.6176/") == (55.7558, 37.6176, None)


def test_to_rational():
    assert to_rational(0.5) == (1, 2)
    assert to_rational(140.0) == (140, 1)
