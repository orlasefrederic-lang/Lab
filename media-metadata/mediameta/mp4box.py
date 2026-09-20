"""A small ISO base media file format (MP4/MOV) box engine.

Enough of the container to find, rewrite and re-serialise the metadata that
lives in ``moov``, without pulling in an external dependency and without the
"audio track required" restriction of music-oriented libraries.

The tricky part of editing MP4 in place is that ``stco``/``co64`` store
absolute file offsets of the media chunks. If ``moov`` grows or shrinks
ahead of ``mdat`` those offsets must move with it, which is what
:func:`rewrite_file` takes care of.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from .errors import CorruptFileError
from .utils import copy_chunks, staged_write

#: Boxes whose payload is simply a list of child boxes.
CONTAINER_TYPES = frozenset(
    b"moov trak edts mdia minf dinf stbl mvex moof traf mfra udta ilst ---- "
    b"tref iprp ipco grpl strk".split()
)

#: Boxes that start with a 4-byte version/flags word before their children.
PREFIXED_CONTAINERS = {b"meta": 4}

FREE_TYPES = frozenset((b"free", b"skip"))

_MAX_U32 = 0xFFFFFFFF


@dataclass
class Box:
    """One box. Either a leaf with ``payload`` or a container with ``children``."""

    type: bytes
    payload: bytes = b""
    children: list | None = None
    prefix: bytes = b""
    extended_type: bytes | None = None

    @property
    def is_container(self) -> bool:
        return self.children is not None

    def body(self) -> bytes:
        if self.is_container:
            return self.prefix + b"".join(child.serialize() for child in self.children)
        return self.payload

    def serialize(self) -> bytes:
        body = self.body()
        header = self.type
        if self.extended_type is not None:
            header += self.extended_type
        size = 8 + len(header) - 4 + len(body)
        if size > _MAX_U32:
            return struct.pack(">I", 1) + header + struct.pack(">Q", size + 8) + body
        return struct.pack(">I", size) + header + body

    def size(self) -> int:
        return len(self.serialize())

    # -- navigation ----------------------------------------------------

    def find(self, *path):
        """Return the first descendant matching ``path`` (``b"udta", b"meta"``)."""
        current = self
        for wanted in path:
            if not current.is_container:
                return None
            for child in current.children:
                if child.type == wanted:
                    current = child
                    break
            else:
                return None
        return current

    def findall(self, wanted: bytes) -> list:
        """All direct children of the given type."""
        if not self.is_container:
            return []
        return [child for child in self.children if child.type == wanted]

    def walk(self):
        """Depth-first iteration over this box and everything inside it."""
        yield self
        if self.is_container:
            for child in self.children:
                yield from child.walk()

    def ensure_path(self, *path):
        """Get or create a chain of container boxes, returning the innermost."""
        current = self
        for wanted in path:
            if not current.is_container:
                raise CorruptFileError(
                    f"{current.type.decode('latin-1')} is not a container"
                )
            existing = current.find(wanted)
            if existing is None:
                existing = new_container(wanted)
                current.children.append(existing)
            current = existing
        return current

    def remove(self, wanted: bytes) -> int:
        """Drop every direct child of the given type; returns how many went."""
        if not self.is_container:
            return 0
        before = len(self.children)
        self.children = [child for child in self.children if child.type != wanted]
        return before - len(self.children)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        name = self.type.decode("latin-1", "replace")
        if self.is_container:
            return f"<Box {name} [{len(self.children)} children]>"
        return f"<Box {name} {len(self.payload)}B>"


def new_container(box_type: bytes, children=None, prefix: bytes = b"") -> Box:
    if box_type in PREFIXED_CONTAINERS and not prefix:
        prefix = b"\x00" * PREFIXED_CONTAINERS[box_type]
    return Box(box_type, children=list(children or []), prefix=prefix)


def _is_printable_type(value: bytes) -> bool:
    return len(value) == 4 and all(0x20 <= byte <= 0x7E or byte == 0xA9 for byte in value)


def parse_boxes(data: bytes, parent_type: bytes | None = None) -> list:
    """Parse a byte string into a list of boxes, recursing into containers."""
    boxes = []
    offset = 0
    total = len(data)

    while offset + 8 <= total:
        size = struct.unpack_from(">I", data, offset)[0]
        box_type = data[offset + 4 : offset + 8]
        header = 8

        if size == 1:
            if offset + 16 > total:
                break
            size = struct.unpack_from(">Q", data, offset + 8)[0]
            header = 16
        elif size == 0:
            size = total - offset

        if size < header or offset + size > total:
            # Trailing garbage: keep what parsed cleanly rather than failing.
            break

        extended_type = None
        if box_type == b"uuid" and offset + header + 16 <= total:
            extended_type = data[offset + header : offset + header + 16]
            header += 16

        body = data[offset + header : offset + size]
        boxes.append(_build_box(box_type, body, parent_type, extended_type))
        offset += size

    return boxes


def _build_box(box_type: bytes, body: bytes, parent_type: bytes | None, extended_type) -> Box:
    if box_type in PREFIXED_CONTAINERS:
        prefix_length = PREFIXED_CONTAINERS[box_type]
        # QuickTime sometimes omits the version/flags word; detect which it is.
        if len(body) >= 8 and _is_printable_type(body[4:8]):
            prefix, rest = b"", body
        elif len(body) >= prefix_length + 8 and _is_printable_type(
            body[prefix_length + 4 : prefix_length + 8]
        ):
            prefix, rest = body[:prefix_length], body[prefix_length:]
        else:
            return Box(box_type, payload=body, extended_type=extended_type)
        return Box(
            box_type,
            children=parse_boxes(rest, box_type),
            prefix=prefix,
            extended_type=extended_type,
        )

    is_container = box_type in CONTAINER_TYPES or parent_type == b"ilst"
    if is_container and body:
        children = parse_boxes(body, box_type)
        # Only accept the container reading if it consumed everything.
        if children and sum(child.size() for child in children) == len(body):
            return Box(box_type, children=children, extended_type=extended_type)

    return Box(box_type, payload=body, extended_type=extended_type)


@dataclass
class TopBox:
    """A top-level box located inside the file, kept as an offset range."""

    type: bytes
    offset: int
    size: int
    header: int

    @property
    def end(self) -> int:
        return self.offset + self.size


def scan_top_level(handle) -> list:
    """List the top-level boxes of an open binary file."""
    handle.seek(0, 2)
    file_size = handle.tell()
    handle.seek(0)

    boxes = []
    offset = 0
    while offset + 8 <= file_size:
        handle.seek(offset)
        header_bytes = handle.read(16)
        if len(header_bytes) < 8:
            break
        size = struct.unpack_from(">I", header_bytes, 0)[0]
        box_type = header_bytes[4:8]
        header = 8
        if size == 1:
            if len(header_bytes) < 16:
                break
            size = struct.unpack_from(">Q", header_bytes, 8)[0]
            header = 16
        elif size == 0:
            size = file_size - offset

        if size < header or offset + size > file_size:
            raise CorruptFileError(
                f"box {box_type.decode('latin-1', 'replace')} at {offset} claims {size} bytes"
            )
        boxes.append(TopBox(box_type, offset, size, header))
        offset += size

    if not boxes:
        raise CorruptFileError("no ISO base media boxes found")
    return boxes


def read_moov(path):
    """Return ``(moov_box, top_level_boxes)`` for the given file."""
    path = Path(path)
    with path.open("rb") as handle:
        top = scan_top_level(handle)
        for entry in top:
            if entry.type == b"moov":
                handle.seek(entry.offset)
                raw = handle.read(entry.size)
                parsed = parse_boxes(raw)
                if not parsed or parsed[0].type != b"moov":
                    raise CorruptFileError("moov box could not be parsed")
                return parsed[0], top
    raise CorruptFileError("this file has no moov box (not an MP4/MOV container?)")


# -- chunk offset bookkeeping ------------------------------------------


def _iter_offset_tables(moov: Box):
    """Yield every ``stco``/``co64`` box found under ``moov``."""
    for box in moov.walk():
        if box.type in (b"stco", b"co64") and not box.is_container:
            yield box


def shift_chunk_offsets(moov: Box, threshold: int, delta: int) -> int:
    """Move chunk offsets at or after ``threshold`` by ``delta`` bytes."""
    if delta == 0:
        return 0

    moved = 0
    for box in _iter_offset_tables(moov):
        payload = box.payload
        if len(payload) < 8:
            continue
        count = struct.unpack_from(">I", payload, 4)[0]
        wide = box.type == b"co64"
        item = 8 if wide else 4
        if len(payload) < 8 + count * item:
            raise CorruptFileError(
                f"{box.type.decode('latin-1')} table is shorter than its entry count"
            )

        values = bytearray(payload)
        for index in range(count):
            position = 8 + index * item
            if wide:
                value = struct.unpack_from(">Q", values, position)[0]
            else:
                value = struct.unpack_from(">I", values, position)[0]
            if value < threshold:
                continue
            shifted = value + delta
            if shifted < 0:
                raise CorruptFileError("chunk offset would become negative")
            if not wide and shifted > _MAX_U32:
                raise CorruptFileError(
                    "chunk offsets no longer fit in a 32-bit stco table; "
                    "this file needs a co64 rewrite (try the exiftool backend)"
                )
            if wide:
                struct.pack_into(">Q", values, position, shifted)
            else:
                struct.pack_into(">I", values, position, shifted)
            moved += 1
        box.payload = bytes(values)
    return moved


def _free_box(size: int) -> Box:
    if size < 8:
        raise ValueError("a free box needs at least 8 bytes")
    return Box(b"free", payload=b"\x00" * (size - 8))


def rewrite_file(source, destination, new_moov: Box, top_level=None) -> dict:
    """Write ``source`` to ``destination`` with ``moov`` replaced.

    Returns a small report describing how the size difference was handled:
    absorbed into padding, or compensated by shifting chunk offsets.
    """
    source = Path(source)
    report = {"delta": 0, "strategy": "none", "offsets_moved": 0}

    with source.open("rb") as handle:
        top = top_level or scan_top_level(handle)
        moov_entry = next((entry for entry in top if entry.type == b"moov"), None)
        if moov_entry is None:
            raise CorruptFileError("this file has no moov box")

        plan = list(top)
        new_size = len(new_moov.serialize())
        delta = new_size - moov_entry.size

        # 1. Prefer keeping the file layout intact by using padding.
        if delta != 0:
            delta = _absorb_delta(plan, moov_entry, new_moov, delta, report)

        # 2. Otherwise every byte after moov moves, so chunk offsets follow.
        if delta != 0:
            if any(entry.type == b"moof" for entry in top):
                raise CorruptFileError(
                    "fragmented MP4 (moof) cannot be resized safely; "
                    "write to a new file with --output or use exiftool"
                )
            report["offsets_moved"] = shift_chunk_offsets(new_moov, moov_entry.offset, delta)
            report["strategy"] = "shift-offsets"
            report["delta"] = delta
            if len(new_moov.serialize()) != new_size:
                raise CorruptFileError("moov size changed while adjusting chunk offsets")

        serialized_moov = new_moov.serialize()

        with staged_write(destination) as temporary:
            with open(temporary, "wb") as output:
                for entry in plan:
                    if entry is moov_entry:
                        output.write(serialized_moov)
                    elif isinstance(entry, Box):  # padding we invented
                        output.write(entry.serialize())
                    else:
                        copy_chunks(handle, output, entry.offset, entry.size)

    return report


def _absorb_delta(plan: list, moov_entry: TopBox, new_moov: Box, delta: int, report: dict) -> int:
    """Try to keep the file layout stable by trading bytes with padding.

    Growing ``moov`` can eat a neighbouring ``free`` box; shrinking it can be
    balanced by padding inside ``moov`` itself. Either way the offsets of the
    media data stay valid.
    """
    index = plan.index(moov_entry)
    neighbour = plan[index + 1] if index + 1 < len(plan) else None

    if neighbour is not None and getattr(neighbour, "type", None) in FREE_TYPES:
        remaining = neighbour.size - delta
        if remaining == 0:
            plan.pop(index + 1)
            report["strategy"] = "absorbed-free"
            return 0
        if remaining >= 8:
            plan[index + 1] = _free_box(remaining)
            report["strategy"] = "absorbed-free"
            return 0

    if delta < -8 or delta == -8:
        # moov shrank: pad it back to its old size from the inside.
        new_moov.children.append(_free_box(-delta))
        report["strategy"] = "internal-padding"
        return 0

    return delta
