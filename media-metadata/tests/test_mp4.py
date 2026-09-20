"""MP4/MOV: tag round trips, and above all keeping the media data valid."""

import datetime as dt

import pytest

from mediameta import mp4box, read_metadata, remove_metadata, write_metadata
from mediameta.errors import CorruptFileError
from mp4_factory import make_mp4, read_samples

EXPECTED_SAMPLES = [b"sample-one", b"sample-two-longer"]

TAGS = {
    "title": "Лето 2024",
    "artist": "Костя",
    "album": "Отпуск",
    "comment": "первый заплыв",
    "genre": "Home video",
    "keywords": ["море", "отпуск"],
    "software": "mediameta",
    "camera_make": "Apple",
    "camera_model": "iPhone 15",
    "rating": 5,
    "datetime_original": dt.datetime(2024, 7, 1, 10, 0, 0),
    "gps_latitude": 55.7558,
    "gps_longitude": 37.6176,
    "gps_altitude": 140.0,
}


@pytest.fixture(params=["mdat-first", "faststart", "padded"])
def video(request, tmp_path):
    """The three layouts that behave differently when moov changes size."""
    if request.param == "faststart":
        return make_mp4(tmp_path / "web.mp4", faststart=True)
    if request.param == "padded":
        return make_mp4(tmp_path / "pad.mp4", faststart=True, free_padding=512)
    return make_mp4(tmp_path / "clip.mp4")


def test_roundtrip_every_field(video):
    record = write_metadata(video, TAGS)
    for name, expected in TAGS.items():
        actual = record.common[name]
        if isinstance(expected, float):
            assert actual == pytest.approx(expected, abs=1e-4)
        else:
            assert actual == expected


def test_media_data_stays_reachable(video):
    """The real risk of editing MP4: stale chunk offsets in stco."""
    write_metadata(video, TAGS)
    assert read_samples(video) == EXPECTED_SAMPLES


def test_repeated_edits_stay_consistent(video):
    for index in range(5):
        write_metadata(video, {"title": f"дубль {index}", "comment": "x" * (index * 40)})
    assert read_samples(video) == EXPECTED_SAMPLES
    assert read_metadata(video).common["title"] == "дубль 4"


def test_silent_video_is_supported(mp4_silent):
    record = write_metadata(mp4_silent, {"title": "Запись экрана"})
    assert record.common["title"] == "Запись экрана"
    assert read_samples(mp4_silent) == EXPECTED_SAMPLES


def test_technical_fields(mp4):
    record = read_metadata(mp4)
    assert record.common["duration"] == pytest.approx(2.0)
    assert (record.common["width"], record.common["height"]) == (640, 480)
    assert record.common["mime_type"] == "video/mp4"


def test_delete_single_field(mp4):
    write_metadata(mp4, TAGS)
    record = write_metadata(mp4, {"album": None})
    assert "album" not in record.common
    assert record.common["title"] == "Лето 2024"


def test_gps_parts_merge(mp4):
    write_metadata(mp4, {"gps_latitude": 10.0, "gps_longitude": 20.0, "gps_altitude": 5.0})
    record = write_metadata(mp4, {"gps_altitude": 99.0})
    assert record.common["gps_latitude"] == pytest.approx(10.0, abs=1e-4)
    assert record.common["gps_altitude"] == pytest.approx(99.0, abs=0.01)


def test_removing_latitude_drops_the_fix(mp4):
    write_metadata(mp4, {"gps_latitude": 10.0, "gps_longitude": 20.0})
    record = remove_metadata(mp4, ["gps_latitude"])
    assert "gps_latitude" not in record.common
    assert "gps_longitude" not in record.common


def test_strip_all(video):
    write_metadata(video, TAGS)
    record = remove_metadata(video)
    assert not [
        name for name in record.common
        if name not in ("width", "height", "duration", "mime_type", "datetime_original")
    ]
    assert read_samples(video) == EXPECTED_SAMPLES


def test_creation_time_reaches_the_movie_header(mp4):
    moment = dt.datetime(2019, 3, 4, 5, 6, 7)
    write_metadata(mp4, {"datetime_original": moment})
    record = read_metadata(mp4)
    assert record.raw["QuickTime:CreateDate"] == moment


def test_raw_itunes_tag(mp4):
    record = write_metadata(mp4, {}, raw={"iTunes:\xa9wrt": "Костя"})
    assert record.raw["iTunes:\xa9wrt"] == "Костя"


def test_raw_quicktime_key(mp4):
    record = write_metadata(mp4, {}, raw={"QuickTime:com.apple.quicktime.location.accuracy.horizontal": "5"})
    assert record.raw["QuickTime:com.apple.quicktime.location.accuracy.horizontal"] == "5"


def test_written_tags_are_readable_by_mutagen(mp4):
    mutagen = pytest.importorskip("mutagen.mp4")
    write_metadata(mp4, {"title": "Проверка", "artist": "Костя"})
    tags = mutagen.MP4(str(mp4)).tags
    assert tags["\xa9nam"] == ["Проверка"]
    assert tags["\xa9ART"] == ["Костя"]


def test_padding_is_used_instead_of_moving_data(tmp_path):
    path = make_mp4(tmp_path / "pad.mp4", faststart=True, free_padding=1024)
    before = [entry.offset for entry in _top_level(path) if entry.type == b"mdat"]
    write_metadata(path, {"title": "не двигай меня"})
    after = [entry.offset for entry in _top_level(path) if entry.type == b"mdat"]
    assert before == after


def test_offsets_move_when_there_is_no_padding(tmp_path):
    path = make_mp4(tmp_path / "web.mp4", faststart=True)
    before = [entry.offset for entry in _top_level(path) if entry.type == b"mdat"]
    write_metadata(path, {"title": "подвинь меня", "comment": "x" * 200})
    after = [entry.offset for entry in _top_level(path) if entry.type == b"mdat"]
    assert after != before
    assert read_samples(path) == EXPECTED_SAMPLES


def test_not_a_container(tmp_path):
    path = tmp_path / "broken.mp4"
    path.write_bytes(b"this is definitely not an mp4 file")
    with pytest.raises(CorruptFileError):
        read_metadata(path)


def test_mov_suffix_is_handled(tmp_path):
    path = make_mp4(tmp_path / "clip.mov")
    record = write_metadata(path, {"title": "Квиктайм"})
    assert record.format == "MOV"
    assert record.common["title"] == "Квиктайм"


def _top_level(path):
    with open(path, "rb") as handle:
        return mp4box.scan_top_level(handle)
