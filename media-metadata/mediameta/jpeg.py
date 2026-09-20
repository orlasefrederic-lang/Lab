"""Just enough JPEG segment walking to find and remove metadata blocks."""

from __future__ import annotations

import struct

SOI = b"\xff\xd8"
EOI = 0xD9
SOS = 0xDA
#: Markers without a payload.
STANDALONE = {0x01} | set(range(0xD0, 0xD8))

EXIF_SIGNATURE = b"Exif\x00\x00"
XMP_SIGNATURE = b"http://ns.adobe.com/xap/1.0/\x00"
IPTC_SIGNATURE = b"Photoshop 3.0\x00"


def is_jpeg(data: bytes) -> bool:
    return data[:2] == SOI


def iter_segments(data: bytes):
    """Yield ``(marker, start, payload_start, payload_end)`` for each segment.

    Iteration stops at the start of scan data, which is where metadata
    segments can no longer appear.
    """
    if not is_jpeg(data):
        return
    offset = 2
    total = len(data)
    while offset + 1 < total:
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        if marker == 0xFF:
            offset += 1
            continue
        if marker in STANDALONE:
            offset += 2
            continue
        if marker in (EOI, SOS):
            yield marker, offset, offset + 2, offset + 2
            return
        if offset + 4 > total:
            return
        length = struct.unpack_from(">H", data, offset + 2)[0]
        payload_start = offset + 4
        payload_end = offset + 2 + length
        if payload_end > total:
            return
        yield marker, offset, payload_start, payload_end
        offset = payload_end


def find_segment(data: bytes, marker: int, signature: bytes | None = None):
    """Return the payload of the first matching APP segment, if any."""
    for found, _start, payload_start, payload_end in iter_segments(data):
        if found != marker:
            continue
        payload = data[payload_start:payload_end]
        if signature is None:
            return payload
        if payload.startswith(signature):
            return payload[len(signature):]
    return None


def strip_metadata(data: bytes) -> bytes:
    """Drop every APPn and COM segment, keeping the image itself intact."""
    if not is_jpeg(data):
        return data

    output = bytearray(SOI)
    cursor = 2
    for marker, start, _payload_start, payload_end in iter_segments(data):
        if marker in (SOS, EOI):
            output += data[cursor:]
            return bytes(output)
        droppable = 0xE0 <= marker <= 0xEF or marker == 0xFE
        # Keep the JFIF header: some decoders rely on it for pixel density.
        if droppable and not (marker == 0xE0 and data[start + 4 : start + 9] == b"JFIF\x00"):
            output += data[cursor:start]
            cursor = payload_end
    output += data[cursor:]
    return bytes(output)
