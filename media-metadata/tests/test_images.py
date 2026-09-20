"""EXIF (JPEG/WebP) and PNG backends."""

import datetime as dt

import pytest

from mediameta import read_metadata, remove_metadata, write_metadata
from mediameta.errors import FieldError, ReadOnlyFormatError
from mediameta.jpeg import find_segment, iter_segments, strip_metadata

FULL_SET = {
    "title": "Закат",
    "description": "Вид на залив",
    "comment": "Снято на ходу",
    "artist": "Костя",
    "copyright": "(c) 2024 Kostya",
    "keywords": ["море", "лето"],
    "software": "mediameta",
    "datetime_original": dt.datetime(2024, 7, 1, 18, 30),
    "camera_make": "Canon",
    "camera_model": "EOS R6",
    "lens": "RF 24-70 F2.8",
    "orientation": 6,
    "rating": 5,
    "gps_latitude": 55.7558,
    "gps_longitude": 37.6176,
    "gps_altitude": 140.0,
}


def test_jpeg_roundtrip(jpeg):
    record = write_metadata(jpeg, FULL_SET)
    for name, expected in FULL_SET.items():
        actual = record.common[name]
        if isinstance(expected, float):
            assert actual == pytest.approx(expected, abs=1e-4)
        else:
            assert actual == expected


def test_jpeg_keeps_pixels(jpeg):
    from PIL import Image

    with Image.open(jpeg) as image:
        before = image.tobytes()
    write_metadata(jpeg, {"title": "x"})
    with Image.open(jpeg) as image:
        assert image.tobytes() == before


def test_reading_reports_dimensions(jpeg):
    record = read_metadata(jpeg)
    assert (record.common["width"], record.common["height"]) == (120, 80)
    assert record.common["mime_type"] == "image/jpeg"


def test_southern_and_western_hemispheres(jpeg):
    record = write_metadata(jpeg, {"gps_latitude": -33.8688, "gps_longitude": -70.6693})
    assert record.common["gps_latitude"] == pytest.approx(-33.8688, abs=1e-5)
    assert record.common["gps_longitude"] == pytest.approx(-70.6693, abs=1e-5)


def test_negative_altitude(jpeg):
    record = write_metadata(jpeg, {"gps_altitude": -412.0})
    assert record.common["gps_altitude"] == pytest.approx(-412.0, abs=0.01)


def test_delete_single_field(jpeg):
    write_metadata(jpeg, FULL_SET)
    record = write_metadata(jpeg, {"title": None})
    assert "title" not in record.common
    assert record.common["artist"] == "Костя"


def test_remove_named_fields(jpeg):
    write_metadata(jpeg, FULL_SET)
    record = remove_metadata(jpeg, ["gps_latitude", "gps_longitude"])
    assert "gps_latitude" not in record.common
    assert "gps_longitude" not in record.common
    assert record.common["title"] == "Закат"


def test_strip_everything(jpeg):
    write_metadata(jpeg, FULL_SET)
    record = remove_metadata(jpeg)
    assert not [name for name in record.common if name not in ("width", "height", "mime_type")]


def test_raw_exif_tag(jpeg):
    record = write_metadata(jpeg, {}, raw={"EXIF:ISOSpeedRatings": 400})
    assert record.raw["EXIF:ISOSpeedRatings"] == 400


def test_unknown_raw_tag_is_rejected(jpeg):
    with pytest.raises(FieldError):
        write_metadata(jpeg, {}, raw={"EXIF:NotARealTag": 1})


def test_webp_roundtrip(webp):
    record = write_metadata(webp, {"title": "Вебпэ", "artist": "Костя"})
    assert record.common["title"] == "Вебпэ"
    assert record.common["artist"] == "Костя"


def test_tiff_is_read_only(tiff):
    record = read_metadata(tiff)
    assert record.writable is False
    with pytest.raises(ReadOnlyFormatError):
        write_metadata(tiff, {"title": "nope"}, backend="native")


def test_png_text_and_exif(png):
    record = write_metadata(
        png,
        {
            "title": "Скриншот",
            "artist": "Костя",
            "keywords": ["ui"],
            "camera_make": "Pixel",
            "gps_latitude": 59.9343,
            "gps_longitude": 30.3351,
            "rating": 4,
        },
    )
    assert record.common["title"] == "Скриншот"
    assert record.raw["PNG:Title"] == "Скриншот"
    assert record.common["camera_make"] == "Pixel"
    assert record.common["gps_latitude"] == pytest.approx(59.9343, abs=1e-4)


def test_png_strip(png):
    write_metadata(png, {"title": "Скриншот", "gps_latitude": 10.0})
    record = remove_metadata(png)
    assert "title" not in record.common
    assert "gps_latitude" not in record.common


def test_png_keeps_pixels(png):
    from PIL import Image

    with Image.open(png) as image:
        before = image.tobytes()
    write_metadata(png, {"title": "x"})
    with Image.open(png) as image:
        assert image.tobytes() == before


def test_jpeg_segments_and_strip(jpeg):
    write_metadata(jpeg, {"title": "Закат"})
    data = jpeg.read_bytes()
    assert find_segment(data, 0xE1, b"Exif\x00\x00") is not None

    stripped = strip_metadata(data)
    assert find_segment(stripped, 0xE1, b"Exif\x00\x00") is None
    assert stripped.startswith(b"\xff\xd8")
    # The scan data must survive untouched.
    assert any(marker == 0xDA for marker, *_ in iter_segments(stripped))


def test_xmp_is_read(jpeg):
    packet = (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">'
        "<dc:title><rdf:Alt><rdf:li>Из Lightroom</rdf:li></rdf:Alt></dc:title>"
        "</rdf:Description></rdf:RDF></x:xmpmeta>"
    ).encode()

    data = bytearray(jpeg.read_bytes())
    signature = b"http://ns.adobe.com/xap/1.0/\x00"
    payload = signature + packet
    segment = b"\xff\xe1" + len(payload).to_bytes(2, "big") + payload
    data[2:2] = segment
    jpeg.write_bytes(bytes(data))

    record = read_metadata(jpeg)
    assert record.common["title"] == "Из Lightroom"
    assert record.raw["XMP:dc:title"] == "Из Lightroom"
