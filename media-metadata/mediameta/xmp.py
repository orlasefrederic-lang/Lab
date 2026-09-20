"""Read the XMP packet that editors like Lightroom leave in media files.

Writing XMP is out of scope: reading it is what keeps titles and keywords
from silently disappearing when a file was tagged by another program.
"""

from __future__ import annotations

import re
from xml.etree import ElementTree

NAMESPACES = {
    "dc": "http://purl.org/dc/elements/1.1/",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "photoshop": "http://ns.adobe.com/photoshop/1.0/",
    "tiff": "http://ns.adobe.com/tiff/1.0/",
    "exif": "http://ns.adobe.com/exif/1.0/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
}

_PACKET_RE = re.compile(rb"<x:xmpmeta.*?</x:xmpmeta>", re.DOTALL)

#: XMP property -> canonical field name.
INTERESTING = {
    ("dc", "title"): "title",
    ("dc", "description"): "description",
    ("dc", "creator"): "artist",
    ("dc", "rights"): "copyright",
    ("dc", "subject"): "keywords",
    ("xmp", "Rating"): "rating",
    ("xmp", "CreateDate"): "datetime_original",
    ("xmp", "CreatorTool"): "software",
    ("photoshop", "DateCreated"): "datetime_original",
    ("tiff", "Make"): "camera_make",
    ("tiff", "Model"): "camera_model",
}


def extract_packet(data: bytes):
    """Find a raw XMP packet inside arbitrary file bytes."""
    match = _PACKET_RE.search(data)
    return match.group(0) if match else None


def parse(packet) -> dict:
    """Parse an XMP packet into ``{"dc:title": value, ...}``."""
    if packet is None:
        return {}
    if isinstance(packet, str):
        packet = packet.encode("utf-8")

    try:
        root = ElementTree.fromstring(packet)
    except ElementTree.ParseError:
        return {}

    reverse = {uri: prefix for prefix, uri in NAMESPACES.items()}
    found: dict = {}

    for element in root.iter():
        if not element.tag.startswith("{"):
            continue
        uri, _, local = element.tag[1:].partition("}")
        prefix = reverse.get(uri)
        if prefix is None or prefix == "rdf":
            continue
        value = _element_value(element)
        if value not in (None, "", []):
            found[f"{prefix}:{local}"] = value

    # Attributes carry properties too when the file uses compact RDF.
    for element in root.iter():
        for name, value in element.attrib.items():
            if not name.startswith("{"):
                continue
            uri, _, local = name[1:].partition("}")
            prefix = reverse.get(uri)
            if prefix and prefix != "rdf" and value:
                found.setdefault(f"{prefix}:{local}", value)

    return found


def _element_value(element):
    """Flatten ``rdf:Alt`` / ``rdf:Bag`` / ``rdf:Seq`` wrappers into values."""
    rdf = NAMESPACES["rdf"]
    container = None
    for name in ("Alt", "Bag", "Seq"):
        container = element.find(f"{{{rdf}}}{name}")
        if container is not None:
            break

    if container is not None:
        items = [
            (item.text or "").strip()
            for item in container.findall(f"{{{rdf}}}li")
        ]
        items = [item for item in items if item]
        if not items:
            return None
        return items[0] if len(items) == 1 else items

    text = (element.text or "").strip()
    return text or None


def to_common(properties: dict) -> dict:
    """Translate parsed XMP properties into canonical fields."""
    common: dict = {}
    for (prefix, local), field_name in INTERESTING.items():
        value = properties.get(f"{prefix}:{local}")
        if value in (None, "", []):
            continue
        if field_name == "keywords" and isinstance(value, str):
            value = [part.strip() for part in value.split(",") if part.strip()]
        common.setdefault(field_name, value)
    return common
