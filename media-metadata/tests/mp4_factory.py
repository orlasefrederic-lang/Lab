"""Build small but structurally valid MP4 files for the test-suite.

Real videos are too big to keep in the repository, and we need both
layouts that exist in the wild: ``mdat`` first (how cameras write) and
``moov`` first (how "faststart" web videos are muxed).
"""

from __future__ import annotations

import struct
from pathlib import Path

TIMESCALE = 1000
DURATION = 2000  # two seconds


def _box(box_type: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + box_type + payload


def _container(box_type: bytes, *children: bytes) -> bytes:
    return _box(box_type, b"".join(children))


def _ftyp() -> bytes:
    return _box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isomiso2avc1mp41")


def _mvhd() -> bytes:
    payload = struct.pack(">IIII", 0, 0, 0, TIMESCALE) + struct.pack(">I", DURATION)
    payload += struct.pack(">I", 0x00010000)  # rate
    payload += struct.pack(">H", 0x0100)  # volume
    payload += b"\x00" * 10  # reserved
    matrix = [0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000]
    payload += b"".join(struct.pack(">I", value) for value in matrix)
    payload += b"\x00" * 24  # pre_defined
    payload += struct.pack(">I", 2)  # next track id
    return _box(b"mvhd", payload)


def _tkhd(width: int, height: int) -> bytes:
    payload = struct.pack(">I", 0x00000007)  # version 0, enabled
    payload += struct.pack(">IIII", 0, 0, 1, 0)  # created, modified, track id, reserved
    payload += struct.pack(">I", DURATION) + b"\x00" * 8
    payload += struct.pack(">HHHH", 0, 0, 0, 0)  # layer, group, volume, reserved
    matrix = [0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000]
    payload += b"".join(struct.pack(">I", value) for value in matrix)
    payload += struct.pack(">II", width << 16, height << 16)
    return _box(b"tkhd", payload)


def _mdhd() -> bytes:
    payload = struct.pack(">IIIII", 0, 0, 0, TIMESCALE, DURATION)
    payload += struct.pack(">HH", 0x55C4, 0)  # language "und"
    return _box(b"mdhd", payload)


def _hdlr(handler: bytes, name: bytes) -> bytes:
    payload = struct.pack(">II", 0, 0) + handler + b"\x00" * 12 + name + b"\x00"
    return _box(b"hdlr", payload)


def _stbl(offsets, sizes) -> bytes:
    stsd = _box(b"stsd", struct.pack(">II", 0, 0))
    stts = _box(b"stts", struct.pack(">II", 0, 0))
    stsc = _box(b"stsc", struct.pack(">II", 0, 0))
    stsz = _box(b"stsz", struct.pack(">III", 0, 0, len(sizes)) + b"".join(
        struct.pack(">I", size) for size in sizes
    ))
    stco = _box(b"stco", struct.pack(">II", 0, len(offsets)) + b"".join(
        struct.pack(">I", offset) for offset in offsets
    ))
    return _container(b"stbl", stsd, stts, stsc, stsz, stco)


def _minf(handler: bytes, offsets, sizes) -> bytes:
    header = _box(b"vmhd", struct.pack(">IHHHH", 1, 0, 0, 0, 0)) if handler == b"vide" \
        else _box(b"smhd", struct.pack(">IHH", 0, 0, 0))
    dref = _box(b"dref", struct.pack(">II", 0, 1) + _box(b"url ", struct.pack(">I", 1)))
    dinf = _container(b"dinf", dref)
    return _container(b"minf", header, dinf, _stbl(offsets, sizes))


def _trak(handler: bytes, name: bytes, offsets, sizes, width=640, height=480) -> bytes:
    mdia = _container(b"mdia", _mdhd(), _hdlr(handler, name), _minf(handler, offsets, sizes))
    return _container(b"trak", _tkhd(width, height), mdia)


def _moov(offsets, sizes, with_audio: bool, udta: bytes = b"") -> bytes:
    parts = [_mvhd(), _trak(b"vide", b"VideoHandler", offsets, sizes)]
    if with_audio:
        parts.append(_trak(b"soun", b"SoundHandler", offsets, sizes, 0, 0))
    if udta:
        parts.append(udta)
    return _container(b"moov", *parts)


def make_mp4(
    path,
    faststart: bool = False,
    with_audio: bool = True,
    samples=(b"sample-one", b"sample-two-longer"),
    free_padding: int = 0,
) -> Path:
    """Write a tiny MP4 and return its path.

    ``faststart`` puts ``moov`` before ``mdat`` (so editing tags has to fix
    the chunk offsets), ``free_padding`` adds a ``free`` box right after
    ``moov`` (so editing can absorb the size change instead).
    """
    path = Path(path)
    sizes = [len(sample) for sample in samples]
    mdat_payload = b"".join(samples)

    ftyp = _ftyp()
    free = _box(b"free", b"\x00" * free_padding) if free_padding else b""

    if faststart:
        # Two passes: the offsets depend on the size of moov itself.
        placeholder = _moov([0] * len(samples), sizes, with_audio)
        data_start = len(ftyp) + len(placeholder) + len(free) + 8
        offsets, cursor = [], data_start
        for size in sizes:
            offsets.append(cursor)
            cursor += size
        moov = _moov(offsets, sizes, with_audio)
        assert len(moov) == len(placeholder)
        blob = ftyp + moov + free + _box(b"mdat", mdat_payload)
    else:
        data_start = len(ftyp) + 8
        offsets, cursor = [], data_start
        for size in sizes:
            offsets.append(cursor)
            cursor += size
        blob = ftyp + _box(b"mdat", mdat_payload) + free + _moov(offsets, sizes, with_audio)

    path.write_bytes(blob)
    return path


def read_samples(path):
    """Follow the stco/stsz tables and return the sample bytes they point at.

    Used by the tests to prove that editing metadata never corrupts the
    media payload.
    """
    from mediameta import mp4box

    data = Path(path).read_bytes()
    moov, _ = mp4box.read_moov(path)
    trak = moov.findall(b"trak")[0]
    stbl = trak.find(b"mdia", b"minf", b"stbl")
    stco = stbl.find(b"stco")
    stsz = stbl.find(b"stsz")

    count = struct.unpack_from(">I", stco.payload, 4)[0]
    offsets = [struct.unpack_from(">I", stco.payload, 8 + 4 * i)[0] for i in range(count)]
    sample_count = struct.unpack_from(">I", stsz.payload, 8)[0]
    sizes = [struct.unpack_from(">I", stsz.payload, 12 + 4 * i)[0] for i in range(sample_count)]

    return [data[offset : offset + size] for offset, size in zip(offsets, sizes)]
