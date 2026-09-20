"""Unit tests for the box engine itself."""

import struct

import pytest

from mediameta import mp4box
from mediameta.errors import CorruptFileError
from mp4_factory import make_mp4


def test_parse_serialize_roundtrip(tmp_path):
    path = make_mp4(tmp_path / "clip.mp4")
    moov, _top = mp4box.read_moov(path)
    assert moov.type == b"moov"
    assert moov.find(b"mvhd") is not None
    assert moov.serialize() == _raw_moov(path)


def test_nested_lookup(tmp_path):
    path = make_mp4(tmp_path / "clip.mp4")
    moov, _ = mp4box.read_moov(path)
    stbl = moov.find(b"trak").find(b"mdia", b"minf", b"stbl")
    assert stbl is not None
    assert stbl.find(b"stco") is not None


def test_ensure_path_creates_containers(tmp_path):
    path = make_mp4(tmp_path / "clip.mp4")
    moov, _ = mp4box.read_moov(path)
    ilst = moov.ensure_path(b"udta", b"meta", b"ilst")
    assert ilst.type == b"ilst"
    assert moov.find(b"udta", b"meta", b"ilst") is ilst


def test_meta_keeps_its_version_prefix():
    meta = mp4box.new_container(b"meta", [mp4box.Box(b"hdlr", payload=b"\x00" * 24)])
    parsed = mp4box.parse_boxes(meta.serialize())[0]
    assert parsed.prefix == b"\x00\x00\x00\x00"
    assert parsed.find(b"hdlr") is not None


def test_shift_chunk_offsets():
    stco = mp4box.Box(
        b"stco", payload=struct.pack(">II", 0, 2) + struct.pack(">II", 100, 5000)
    )
    stbl = mp4box.new_container(b"stbl", [stco])
    moov = mp4box.new_container(b"moov", [stbl])

    moved = mp4box.shift_chunk_offsets(moov, threshold=1000, delta=64)
    assert moved == 1
    values = struct.unpack_from(">II", stco.payload, 8)
    assert values == (100, 5064)


def test_shift_rejects_overflow():
    stco = mp4box.Box(b"stco", payload=struct.pack(">II", 0, 1) + struct.pack(">I", 0xFFFFFF00))
    moov = mp4box.new_container(b"moov", [stco])
    with pytest.raises(CorruptFileError):
        mp4box.shift_chunk_offsets(moov, threshold=0, delta=1024)


def test_co64_tables_are_supported():
    co64 = mp4box.Box(b"co64", payload=struct.pack(">II", 0, 1) + struct.pack(">Q", 1 << 33))
    moov = mp4box.new_container(b"moov", [co64])
    mp4box.shift_chunk_offsets(moov, threshold=0, delta=-8)
    assert struct.unpack_from(">Q", co64.payload, 8)[0] == (1 << 33) - 8


def test_large_box_uses_64_bit_size():
    box = mp4box.Box(b"free", payload=b"\x00" * 16)
    assert box.serialize()[:4] == struct.pack(">I", 24)


def test_scan_rejects_truncated_box(tmp_path):
    path = tmp_path / "bad.mp4"
    path.write_bytes(struct.pack(">I", 999) + b"ftyp" + b"isom")
    with pytest.raises(CorruptFileError):
        with open(path, "rb") as handle:
            mp4box.scan_top_level(handle)


def _raw_moov(path):
    with open(path, "rb") as handle:
        for entry in mp4box.scan_top_level(handle):
            if entry.type == b"moov":
                handle.seek(entry.offset)
                return handle.read(entry.size)
    raise AssertionError("no moov")
