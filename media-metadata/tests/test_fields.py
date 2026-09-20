import datetime as dt

import pytest

from mediameta.errors import FieldError
from mediameta.fields import normalize, parse_assignments, resolve_field, split_list


def test_aliases_resolve():
    assert resolve_field("author").name == "artist"
    assert resolve_field("Date").name == "datetime_original"
    assert resolve_field("lng").name == "gps_longitude"


def test_unknown_field():
    with pytest.raises(FieldError):
        resolve_field("vibe")


@pytest.mark.parametrize(
    "text",
    [
        "2024-07-01 18:30:00",
        "2024:07:01 18:30:00",
        "2024-07-01T18:30:00",
        "01.07.2024 18:30:00",
    ],
)
def test_datetime_spellings(text):
    value = normalize(resolve_field("datetime_original"), text)
    assert value == dt.datetime(2024, 7, 1, 18, 30)


def test_datetime_keeps_offset():
    value = normalize(resolve_field("date"), "2024-07-01T18:30:00+03:00")
    assert value.utcoffset() == dt.timedelta(hours=3)


def test_assignments_expand_gps():
    changes = parse_assignments(["gps=55.7558,37.6176,140"])
    assert changes == {
        "gps_latitude": 55.7558,
        "gps_longitude": 37.6176,
        "gps_altitude": 140.0,
    }


def test_empty_value_means_delete():
    assert parse_assignments(["title="]) == {"title": None}


def test_gps_shorthand_delete():
    assert parse_assignments(["gps="]) == {
        "gps_latitude": None,
        "gps_longitude": None,
        "gps_altitude": None,
    }


def test_rating_range_is_enforced():
    with pytest.raises(FieldError):
        parse_assignments(["rating=7"])


def test_read_only_fields_are_rejected():
    with pytest.raises(FieldError):
        parse_assignments(["width=100"])


def test_assignment_without_equals():
    with pytest.raises(FieldError):
        parse_assignments(["title"])


def test_split_list_handles_both_separators():
    assert split_list("sea; summer, 2024") == ["sea", "summer", "2024"]
