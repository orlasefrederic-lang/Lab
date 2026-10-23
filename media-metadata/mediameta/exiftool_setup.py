"""Download and look after a private copy of ExifTool.

ExifTool is what opens HEIC, RAW, MKV, AVI and friends, but asking people
to download an executable, rename it and fix their PATH by hand is where
most of them give up. ``mediameta exiftool install`` does it instead: it
fetches the official release from exiftool.org, checks it against the
SHA-256 sum the site publishes, and unpacks it into mediameta's own data
folder, where :class:`~mediameta.backends.exiftool.ExifToolBackend` finds it.

Nothing here runs implicitly: downloading a program only happens when the
user asks for it.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform as _platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .errors import MediaMetaError

SITE = "https://exiftool.org"

#: Refuse archives that unpack to more than this; the real ones are ~40 MB.
MAX_UNPACKED_BYTES = 500 * 1024 * 1024

_VERSION_RE = re.compile(r"^\d+\.\d+$")


@dataclass
class Release:
    version: str
    archive: str
    url: str
    sha256: str


# -- locations ---------------------------------------------------------


def _is_windows(platform: str | None = None) -> bool:
    return (platform or sys.platform) == "win32"


def data_dir() -> Path:
    """Per-user folder for mediameta's own files.

    ``MEDIAMETA_HOME`` overrides it, which the tests rely on and which is
    handy for portable setups.
    """
    override = os.environ.get("MEDIAMETA_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "mediameta"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "mediameta"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "mediameta"


def install_dir() -> Path:
    return data_dir() / "exiftool"


def managed_command(platform: str | None = None):
    """The command that runs our private copy, or ``None`` if there is none.

    On Windows the official build is a self-contained ``exiftool.exe``;
    elsewhere it is a Perl script, so we need ``perl`` to start it.
    """
    folder = install_dir()
    if _is_windows(platform):
        executable = folder / "exiftool.exe"
        return [str(executable)] if executable.is_file() else None

    script = folder / "exiftool"
    if not script.is_file():
        return None
    perl = shutil.which("perl")
    return [perl, str(script)] if perl else None


def installed_version():
    marker = install_dir() / "VERSION"
    try:
        return marker.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def uninstall() -> bool:
    """Delete the private copy; returns whether there was one."""
    folder = install_dir()
    if not folder.exists():
        return False
    shutil.rmtree(folder)
    return True


# -- finding the release -----------------------------------------------


def _fetch(url: str, timeout: float = 60.0) -> bytes:
    from . import __version__

    request = urllib.request.Request(url, headers={"User-Agent": f"mediameta/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except (urllib.error.URLError, OSError) as exc:
        raise MediaMetaError(f"could not download {url}: {exc}") from exc


def _is_64bit(machine: str | None = None) -> bool:
    machine = (machine or _platform.machine() or "").lower()
    return machine.endswith("64") or machine in ("amd64", "x86_64", "arm64", "aarch64")


def archive_candidates(version: str, platform: str | None = None, machine: str | None = None) -> list:
    """File names the release may be published under, preferred first."""
    if _is_windows(platform):
        bits = "64" if _is_64bit(machine) else "32"
        # Since 12.88 the Windows build ships as a zip with a Perl folder;
        # older releases used a single self-extracting executable.
        return [f"exiftool-{version}_{bits}.zip", f"exiftool-{version}.zip"]
    return [f"Image-ExifTool-{version}.tar.gz"]


def find_sha256(checksums: str, name: str):
    """Pull the SHA-256 for ``name`` out of exiftool.org's ``checksums.txt``.

    Accepts the ``SHA256(name)= hex`` lines OpenSSL prints as well as the
    ``hex  name`` layout of ``sha256sum``.
    """
    escaped = re.escape(name)
    patterns = (
        rf"SHA-?256\s*\(\s*{escaped}\s*\)\s*=\s*([0-9a-fA-F]{{64}})",
        rf"^\s*([0-9a-fA-F]{{64}})\s+\*?{escaped}\s*$",
    )
    for pattern in patterns:
        match = re.search(pattern, checksums, re.MULTILINE)
        if match:
            return match.group(1).lower()
    return None


def latest_release(fetch=None, platform: str | None = None, machine: str | None = None) -> Release:
    fetch = fetch or _fetch
    version = fetch(f"{SITE}/ver.txt").decode("ascii", "replace").strip()
    if not _VERSION_RE.match(version):
        raise MediaMetaError(f"exiftool.org reported an unexpected version: {version!r}")

    checksums = fetch(f"{SITE}/checksums.txt").decode("utf-8", "replace")
    for archive in archive_candidates(version, platform, machine):
        digest = find_sha256(checksums, archive)
        if digest:
            return Release(version, archive, f"{SITE}/{archive}", digest)

    raise MediaMetaError(
        f"exiftool.org publishes no SHA-256 for exiftool {version} on this system, "
        "so the download cannot be verified; install it by hand from https://exiftool.org/"
    )


# -- unpacking ---------------------------------------------------------


def _safe_target(destination: Path, name: str) -> Path:
    """Map an archive member to a path that cannot escape ``destination``."""
    cleaned = name.replace("\\", "/")
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise MediaMetaError(f"archive member has an absolute path: {name!r}")
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise MediaMetaError(f"archive member tries to leave its folder: {name!r}")
    return destination.joinpath(*parts)


def _extract_zip(data: bytes, destination: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if sum(member.file_size for member in members) > MAX_UNPACKED_BYTES:
            raise MediaMetaError("the exiftool archive is suspiciously large")
        for member in members:
            target = _safe_target(destination, member.filename)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                continue  # never follow links out of the archive
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, open(target, "wb") as output:
                shutil.copyfileobj(source, output)


def _extract_tar(data: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        members = archive.getmembers()
        if sum(member.size for member in members if member.isfile()) > MAX_UNPACKED_BYTES:
            raise MediaMetaError("the exiftool archive is suspiciously large")
        for member in members:
            target = _safe_target(destination, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                with source, open(target, "wb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            # Links, devices and the like are skipped on purpose.


def _stage_windows(unpacked: Path, stage: Path) -> None:
    """Lay the Windows build out as ``exiftool.exe`` + ``exiftool_files``."""
    candidates = sorted(
        (
            path for path in unpacked.rglob("*")
            if path.is_file() and path.name.lower() in ("exiftool(-k).exe", "exiftool.exe")
        ),
        key=lambda path: len(path.parts),
    )
    if not candidates:
        raise MediaMetaError("the downloaded archive contains no exiftool executable")

    executable = candidates[0]
    stage.mkdir(parents=True)
    # "(-k)" in the name makes exiftool wait for a key press; drop it.
    shutil.copy2(executable, stage / "exiftool.exe")
    support = executable.parent / "exiftool_files"
    if support.is_dir():
        shutil.copytree(support, stage / "exiftool_files")


def _stage_posix(unpacked: Path, stage: Path) -> None:
    """Keep the Perl script next to the ``lib`` folder it loads modules from."""
    for script in sorted(unpacked.rglob("exiftool"), key=lambda path: len(path.parts)):
        library = script.parent / "lib"
        if script.is_file() and (library / "Image" / "ExifTool.pm").is_file():
            break
    else:
        raise MediaMetaError("the downloaded archive does not look like an ExifTool release")

    stage.mkdir(parents=True)
    shutil.copy2(script, stage / "exiftool")
    (stage / "exiftool").chmod(0o755)
    shutil.copytree(library, stage / "lib")


def _verify(command, expected_version: str) -> None:
    try:
        result = subprocess.run(
            [*command, "-ver"], capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MediaMetaError(f"the downloaded exiftool does not start: {exc}") from exc

    reported = (result.stdout or "").strip()
    if result.returncode != 0 or not _VERSION_RE.match(reported):
        details = (result.stderr or result.stdout or "").strip()
        raise MediaMetaError(f"the downloaded exiftool does not start: {details}")
    if reported != expected_version:
        raise MediaMetaError(
            f"exiftool reports version {reported}, but {expected_version} was downloaded"
        )


def _stage_command(stage: Path, platform: str | None):
    if _is_windows(platform):
        return [str(stage / "exiftool.exe")]
    perl = shutil.which("perl")
    if not perl:
        raise MediaMetaError(
            "exiftool needs Perl on this system; install it "
            "(sudo apt install perl) or use: sudo apt install libimage-exiftool-perl"
        )
    return [perl, str(stage / "exiftool")]


# -- installing --------------------------------------------------------


def install(
    force: bool = False,
    fetch=None,
    platform: str | None = None,
    machine: str | None = None,
    verify: bool = True,
    progress=None,
) -> dict:
    """Download, verify and unpack the latest ExifTool.

    Returns ``{"version", "path", "changed"}``. The previous copy stays in
    place until the new one has been unpacked and has started successfully.
    """
    say = progress or (lambda message: None)
    fetch = fetch or _fetch

    say("checking exiftool.org for the latest version...")
    release = latest_release(fetch, platform, machine)

    current = installed_version()
    if not force and current == release.version and managed_command(platform):
        return {"version": current, "path": install_dir(), "changed": False}

    say(f"downloading {release.archive}...")
    data = fetch(release.url)
    digest = hashlib.sha256(data).hexdigest()
    if digest != release.sha256:
        raise MediaMetaError(
            f"{release.archive} does not match the SHA-256 published on exiftool.org "
            f"(expected {release.sha256}, got {digest}); nothing was installed"
        )
    say(f"SHA-256 verified ({len(data) / 1024 / 1024:.1f} MB)")

    target = install_dir()
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".exiftool-", dir=str(target.parent)) as work:
        work = Path(work)
        unpacked = work / "unpacked"
        unpacked.mkdir()
        if release.archive.endswith(".zip"):
            _extract_zip(data, unpacked)
        else:
            _extract_tar(data, unpacked)

        stage = work / "exiftool"
        if _is_windows(platform):
            _stage_windows(unpacked, stage)
        else:
            _stage_posix(unpacked, stage)
        (stage / "VERSION").write_text(release.version + "\n", encoding="utf-8")

        if verify:
            say("checking that it starts...")
            _verify(_stage_command(stage, platform), release.version)

        previous = work / "previous"
        try:
            if target.exists():
                os.replace(target, previous)
            try:
                os.replace(stage, target)
            except OSError:
                if previous.exists():
                    os.replace(previous, target)
                raise
        except OSError as exc:
            # Typically Windows refusing to move a folder whose exiftool.exe
            # another process is still running.
            raise MediaMetaError(
                f"could not replace {target}: {exc}; close other programs using "
                "exiftool and try again"
            ) from exc

    return {"version": release.version, "path": target, "changed": True}
