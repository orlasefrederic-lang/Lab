"""Command line behaviour: output shapes and exit codes."""

import json

import pytest

from mediameta import read_metadata, write_metadata
from mediameta.cli import main


def run(*argv):
    return main(list(argv))


def test_show_plain(jpeg, capsys):
    write_metadata(jpeg, {"title": "Закат"})
    assert run("show", str(jpeg)) == 0
    out = capsys.readouterr().out
    assert "Закат" in out
    assert "JPEG" in out


def test_show_json(jpeg, capsys):
    write_metadata(jpeg, {"title": "Закат", "artist": "Костя"})
    assert run("show", str(jpeg), "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["common"]["title"] == "Закат"
    assert payload[0]["backend"] == "exif"


def test_show_selected_fields(jpeg, capsys):
    write_metadata(jpeg, {"title": "Закат", "artist": "Костя"})
    assert run("show", str(jpeg), "-f", "title") == 0
    out = capsys.readouterr().out
    assert "Закат" in out
    assert "Костя" not in out


def test_show_raw_tags(jpeg, capsys):
    write_metadata(jpeg, {"camera_make": "Canon"})
    assert run("show", str(jpeg), "--raw") == 0
    assert "EXIF:Make" in capsys.readouterr().out


def test_show_missing_file(tmp_path, capsys):
    assert run("show", str(tmp_path / "ghost.jpg")) == 1
    assert "does not exist" in capsys.readouterr().err


def test_set_and_read_back(jpeg, capsys):
    code = run(
        "set", str(jpeg),
        "-s", "title=Закат",
        "-s", "date=2024-07-01 18:30",
        "-s", "gps=55.7558,37.6176",
    )
    assert code == 0
    assert "updated" in capsys.readouterr().out

    record = read_metadata(jpeg)
    assert record.common["title"] == "Закат"
    assert record.common["gps_latitude"] == pytest.approx(55.7558, abs=1e-4)


def test_set_empty_value_deletes(jpeg):
    write_metadata(jpeg, {"title": "Закат"})
    assert run("set", str(jpeg), "-s", "title=") == 0
    assert "title" not in read_metadata(jpeg).common


def test_set_requires_an_assignment(jpeg, capsys):
    assert run("set", str(jpeg)) == 2
    assert "nothing to do" in capsys.readouterr().err


def test_set_rejects_bad_value(jpeg, capsys):
    assert run("set", str(jpeg), "-s", "rating=11") == 1
    assert "rating" in capsys.readouterr().err


def test_dry_run_changes_nothing(jpeg, capsys):
    before = jpeg.read_bytes()
    assert run("set", str(jpeg), "-s", "title=Ничего", "--dry-run") == 0
    assert "title = Ничего" in capsys.readouterr().out
    assert jpeg.read_bytes() == before


def test_backup_flag(jpeg):
    assert run("set", str(jpeg), "-s", "title=Копия", "--backup") == 0
    assert jpeg.with_name(jpeg.name + ".bak").exists()


def test_output_flag(jpeg, tmp_path):
    destination = tmp_path / "out.jpg"
    assert run("set", str(jpeg), "-s", "title=Новый", "-o", str(destination)) == 0
    assert read_metadata(destination).common["title"] == "Новый"
    assert "title" not in read_metadata(jpeg).common


def test_output_with_many_files_is_refused(jpeg, png, tmp_path, capsys):
    code = run("set", str(jpeg), str(png), "-s", "title=x", "-o", str(tmp_path / "o.jpg"))
    assert code == 2
    assert "single file" in capsys.readouterr().err


def test_recursive_walk(tmp_path, capsys):
    from PIL import Image
    from mp4_factory import make_mp4

    album = tmp_path / "album"
    (album / "nested").mkdir(parents=True)
    Image.new("RGB", (10, 10)).save(album / "a.jpg")
    Image.new("RGB", (10, 10)).save(album / "nested" / "b.jpg")
    make_mp4(album / "nested" / "c.mp4")
    (album / "notes.txt").write_text("not media")

    assert run("set", str(album), "-r", "-s", "artist=Костя") == 0
    out = capsys.readouterr().out
    assert out.count("updated") == 3
    assert read_metadata(album / "nested" / "b.jpg").common["artist"] == "Костя"
    assert read_metadata(album / "nested" / "c.mp4").common["artist"] == "Костя"


def test_directory_without_recursive_matches_nothing(tmp_path, capsys):
    (tmp_path / "album").mkdir()
    assert run("show", str(tmp_path / "album")) == 1
    assert "no files matched" in capsys.readouterr().err


def test_remove_named_field(jpeg, capsys):
    write_metadata(jpeg, {"title": "Закат", "artist": "Костя"})
    assert run("remove", str(jpeg), "-f", "title") == 0
    assert "removed title" in capsys.readouterr().out
    record = read_metadata(jpeg)
    assert "title" not in record.common
    assert record.common["artist"] == "Костя"


def test_remove_all(jpeg):
    write_metadata(jpeg, {"title": "Закат", "artist": "Костя"})
    assert run("remove", str(jpeg), "--all") == 0
    record = read_metadata(jpeg)
    assert "title" not in record.common and "artist" not in record.common


def test_remove_needs_a_target(jpeg, capsys):
    assert run("remove", str(jpeg)) == 2
    assert "--field" in capsys.readouterr().err


def test_copy_command(jpeg, png, capsys):
    write_metadata(jpeg, {"title": "Общий"})
    assert run("copy", str(jpeg), str(png)) == 0
    assert "copied" in capsys.readouterr().out
    assert read_metadata(png).common["title"] == "Общий"


def test_raw_tag_flag(jpeg):
    assert run("set", str(jpeg), "-t", "EXIF:ISOSpeedRatings=400") == 0
    assert read_metadata(jpeg).raw["EXIF:ISOSpeedRatings"] == 400


def test_fields_listing(capsys):
    assert run("fields") == 0
    out = capsys.readouterr().out
    assert "datetime_original" in out
    assert "gps" in out


def test_backends_listing(capsys):
    assert run("backends") == 0
    out = capsys.readouterr().out
    assert "exif" in out and "mp4" in out


def test_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        run("--version")
    assert excinfo.value.code == 0
    assert "mediameta" in capsys.readouterr().out


def test_video_via_cli(mp4, capsys):
    assert run("set", str(mp4), "-s", "title=Клип", "-s", "album=Отпуск") == 0
    capsys.readouterr()  # drop the "updated" line before reading the JSON
    assert run("show", str(mp4), "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["common"]["title"] == "Клип"
    assert payload[0]["common"]["album"] == "Отпуск"
