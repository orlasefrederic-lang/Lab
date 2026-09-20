"""The library-level API: backups, alternate outputs, copying, error paths."""

import pytest

from mediameta import (
    MediaMetaError,
    copy_metadata,
    read_metadata,
    remove_metadata,
    select_backend,
    write_metadata,
)
from mediameta.errors import BackendUnavailableError, FieldError, UnsupportedFormatError


def test_backup_keeps_the_original(jpeg):
    original = jpeg.read_bytes()
    write_metadata(jpeg, {"title": "Новое"}, backup=True)

    backup = jpeg.with_name(jpeg.name + ".bak")
    assert backup.exists()
    assert backup.read_bytes() == original
    assert read_metadata(jpeg).common["title"] == "Новое"


def test_backups_do_not_overwrite_each_other(jpeg):
    write_metadata(jpeg, {"title": "one"}, backup=True)
    write_metadata(jpeg, {"title": "two"}, backup=True)
    assert jpeg.with_name(jpeg.name + ".bak").exists()
    assert jpeg.with_name(jpeg.name + ".bak1").exists()


def test_output_leaves_the_source_alone(jpeg, tmp_path):
    original = jpeg.read_bytes()
    destination = tmp_path / "copy.jpg"

    record = write_metadata(jpeg, {"title": "Копия"}, output=destination)

    assert jpeg.read_bytes() == original
    assert record.path == destination
    assert read_metadata(destination).common["title"] == "Копия"


def test_copy_between_formats(jpeg, png):
    write_metadata(jpeg, {"title": "Общий", "artist": "Костя", "gps_latitude": 12.5,
                          "gps_longitude": 13.5})
    record = copy_metadata(jpeg, png)
    assert record.common["title"] == "Общий"
    assert record.common["artist"] == "Костя"
    assert record.common["gps_latitude"] == pytest.approx(12.5, abs=1e-4)


def test_copy_image_to_video(jpeg, mp4):
    write_metadata(jpeg, {"title": "Из фото", "artist": "Костя"})
    record = copy_metadata(jpeg, mp4)
    assert record.common["title"] == "Из фото"
    assert record.common["artist"] == "Костя"


def test_copy_selected_fields_only(jpeg, png):
    write_metadata(jpeg, {"title": "Общий", "artist": "Костя"})
    record = copy_metadata(jpeg, png, ["title"])
    assert record.common["title"] == "Общий"
    assert "artist" not in record.common


def test_copy_from_empty_file_fails(jpeg, png):
    with pytest.raises(FieldError):
        copy_metadata(jpeg, png)


def test_copy_does_not_carry_dimensions(jpeg, png):
    write_metadata(jpeg, {"title": "Общий"})
    record = copy_metadata(jpeg, png)
    assert record.common["width"] == 64  # the PNG's own size, not the JPEG's


def test_missing_file(tmp_path):
    with pytest.raises(MediaMetaError):
        read_metadata(tmp_path / "nope.jpg")


def test_directory_is_rejected(tmp_path):
    with pytest.raises(MediaMetaError):
        read_metadata(tmp_path)


def test_unsupported_format(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("hello")
    with pytest.raises(UnsupportedFormatError):
        read_metadata(path)


def test_write_without_changes(jpeg):
    with pytest.raises(FieldError):
        write_metadata(jpeg, {})


def test_read_only_field_is_rejected(jpeg):
    with pytest.raises(FieldError):
        write_metadata(jpeg, {"width": 10})


def test_remove_needs_a_valid_field(jpeg):
    with pytest.raises(FieldError):
        remove_metadata(jpeg, ["nonsense"])


def test_backend_selection(jpeg, png, mp4):
    assert select_backend(jpeg).name == "exif"
    assert select_backend(png).name == "png"
    assert select_backend(mp4).name == "mp4"


def test_explicit_unknown_backend(jpeg):
    with pytest.raises(UnsupportedFormatError):
        select_backend(jpeg, "magic")


def test_unavailable_backend_is_reported(jpeg, monkeypatch):
    from mediameta.backends import BACKENDS_BY_NAME

    monkeypatch.setattr(
        BACKENDS_BY_NAME["exiftool"], "executable", "/nonexistent/exiftool", raising=False
    )
    with pytest.raises(BackendUnavailableError):
        select_backend(jpeg, "exiftool")


def test_failed_write_leaves_the_file_untouched(jpeg, monkeypatch):
    write_metadata(jpeg, {"title": "Цел"})
    before = jpeg.read_bytes()

    import piexif

    def explode(*args, **kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(piexif, "insert", explode)
    with pytest.raises(MediaMetaError):
        write_metadata(jpeg, {"title": "Не должно записаться"})

    assert jpeg.read_bytes() == before
    assert read_metadata(jpeg).common["title"] == "Цел"


def test_no_temporary_files_left_behind(jpeg):
    write_metadata(jpeg, {"title": "Прибрано"})
    leftovers = [item.name for item in jpeg.parent.iterdir() if ".mediameta" in item.name]
    assert leftovers == []


def test_file_without_extension_is_detected(jpeg, tmp_path):
    write_metadata(jpeg, {"title": "Безымянный"})
    plain = tmp_path / "IMG_0001"
    plain.write_bytes(jpeg.read_bytes())

    record = read_metadata(plain)
    assert record.format == "JPEG"
    assert record.common["title"] == "Безымянный"
    assert write_metadata(plain, {"artist": "Костя"}).common["artist"] == "Костя"


def test_video_without_extension_is_detected(mp4, tmp_path):
    plain = tmp_path / "VID_0001"
    plain.write_bytes(mp4.read_bytes())
    record = read_metadata(plain)
    assert record.backend == "mp4"
    assert record.kind == "video"


def test_wrong_extension_follows_the_content(jpeg, tmp_path):
    """A JPEG named .png must not be re-encoded as a PNG."""
    from PIL import Image

    misnamed = tmp_path / "actually_jpeg.png"
    misnamed.write_bytes(jpeg.read_bytes())

    record = write_metadata(misnamed, {"title": "Обманка"})
    assert record.backend == "exif"
    with Image.open(misnamed) as image:
        assert image.format == "JPEG"


def test_extension_still_distinguishes_mov_from_mp4(mp4, tmp_path):
    renamed = tmp_path / "clip.mov"
    renamed.write_bytes(mp4.read_bytes())
    assert read_metadata(renamed).format == "MOV"
