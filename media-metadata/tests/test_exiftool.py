"""ExifTool backend. Skipped entirely when the binary is not installed."""

import shutil

import pytest

from mediameta import read_metadata, write_metadata
from mediameta.backends.exiftool import ExifToolBackend

pytestmark = pytest.mark.skipif(
    shutil.which("exiftool") is None, reason="exiftool is not installed"
)


def test_availability():
    assert ExifToolBackend().is_available()[0] is True


def test_roundtrip_on_jpeg(jpeg):
    record = write_metadata(
        jpeg,
        {"title": "Закат", "artist": "Костя", "gps_latitude": 55.7558, "gps_longitude": 37.6176},
        backend="exiftool",
    )
    assert record.common["title"] == "Закат"
    assert record.common["gps_latitude"] == pytest.approx(55.7558, abs=1e-4)


def test_writes_tiff_which_the_native_backend_cannot(tiff):
    record = write_metadata(tiff, {"artist": "Костя"}, backend="exiftool")
    assert record.common["artist"] == "Костя"


def test_strip(jpeg):
    write_metadata(jpeg, {"title": "Закат"}, backend="exiftool")
    from mediameta import remove_metadata

    record = remove_metadata(jpeg, backend="exiftool")
    assert "title" not in record.common


def test_native_backend_still_reads_what_exiftool_wrote(jpeg):
    write_metadata(jpeg, {"artist": "Костя"}, backend="exiftool")
    assert read_metadata(jpeg, backend="native").common["artist"] == "Костя"


def _exiftool(*arguments):
    import subprocess

    result = subprocess.run(
        ["exiftool", "-charset", "UTF8", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def test_exiftool_reads_what_the_native_backend_wrote(jpeg):
    write_metadata(
        jpeg,
        {"artist": "Костя", "camera_make": "Canon", "gps_latitude": 55.7558,
         "gps_longitude": 37.6176},
        backend="native",
    )
    output = _exiftool("-Artist", "-Make", "-GPSLatitude", "-n", str(jpeg))
    assert "Костя" in output
    assert "Canon" in output
    assert "55.75" in output


def test_exiftool_reads_what_the_mp4_backend_wrote(mp4_faststart):
    write_metadata(
        mp4_faststart,
        {"title": "Клип", "artist": "Костя", "gps_latitude": 55.7558, "gps_longitude": 37.6176},
        backend="native",
    )
    output = _exiftool("-Title", "-Artist", "-GPSCoordinates", str(mp4_faststart))
    assert "Клип" in output
    assert "Костя" in output
    assert "55 deg" in output


def test_edited_mp4_passes_structural_validation(mp4_faststart):
    write_metadata(mp4_faststart, {"title": "Проверка", "comment": "x" * 300}, backend="native")
    output = _exiftool("-validate", "-warning", "-a", str(mp4_faststart))
    assert "Validate" in output and "OK" in output
    assert "Error" not in output


def test_native_backend_reads_xmp_written_by_exiftool(jpeg):
    import subprocess

    subprocess.run(
        ["exiftool", "-charset", "UTF8", "-overwrite_original",
         "-XMP-dc:Title=Из Lightroom", "-XMP-dc:Subject=море", "-XMP-dc:Subject=лето",
         str(jpeg)],
        capture_output=True,
        check=True,
    )
    record = read_metadata(jpeg, backend="native")
    assert record.common["title"] == "Из Lightroom"
    assert record.common["keywords"] == ["море", "лето"]
