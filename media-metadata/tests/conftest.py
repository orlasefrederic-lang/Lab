"""Shared fixtures: small real files of every supported format."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

from mp4_factory import make_mp4  # noqa: E402


@pytest.fixture
def jpeg(tmp_path) -> Path:
    from PIL import Image

    path = tmp_path / "photo.jpg"
    Image.new("RGB", (120, 80), (200, 120, 40)).save(path, quality=88)
    return path


@pytest.fixture
def webp(tmp_path) -> Path:
    from PIL import Image

    path = tmp_path / "photo.webp"
    Image.new("RGB", (60, 40), (20, 160, 90)).save(path)
    return path


@pytest.fixture
def png(tmp_path) -> Path:
    from PIL import Image

    path = tmp_path / "shot.png"
    Image.new("RGBA", (64, 32), (10, 10, 90, 255)).save(path)
    return path


@pytest.fixture
def tiff(tmp_path) -> Path:
    from PIL import Image

    path = tmp_path / "scan.tif"
    Image.new("RGB", (32, 32), (90, 90, 90)).save(path)
    return path


@pytest.fixture
def mp4(tmp_path) -> Path:
    return make_mp4(tmp_path / "clip.mp4")


@pytest.fixture
def mp4_faststart(tmp_path) -> Path:
    """moov before mdat: editing tags has to rewrite the chunk offsets."""
    return make_mp4(tmp_path / "web.mp4", faststart=True)


@pytest.fixture
def mp4_silent(tmp_path) -> Path:
    """A video track and nothing else, like a screen recording."""
    return make_mp4(tmp_path / "silent.mp4", with_audio=False)
