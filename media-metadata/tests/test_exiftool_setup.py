"""``mediameta exiftool install``: finding, verifying and unpacking releases.

No test talks to exiftool.org. A fake site serves ``ver.txt``,
``checksums.txt`` and an archive; when ExifTool is installed on this machine
its real Perl files are repackaged to exercise a genuine install end to end.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from mediameta import exiftool_setup, read_metadata, write_metadata
from mediameta.backends.exiftool import ExifToolBackend
from mediameta.cli import main
from mediameta.errors import MediaMetaError

SITE = exiftool_setup.SITE


def fake_site(version: str, archive_name: str, archive: bytes, checksum: str | None = None):
    """A ``fetch`` replacement serving one release, recording what was asked."""
    digest = checksum or hashlib.sha256(archive).hexdigest()
    pages = {
        f"{SITE}/ver.txt": f"{version}\n".encode(),
        f"{SITE}/checksums.txt": (
            f"SHA1({archive_name})= {'0' * 40}\n"
            f"SHA256({archive_name})= {digest}\n"
        ).encode(),
        f"{SITE}/{archive_name}": archive,
    }
    requested = []

    def fetch(url):
        requested.append(url)
        if url not in pages:
            raise MediaMetaError(f"404 for {url}")
        return pages[url]

    fetch.requested = requested
    return fetch


def make_zip(files: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def make_tar(files: dict, symlinks: dict | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            data = content if isinstance(content, bytes) else content.encode()
            info.size = len(data)
            info.mode = 0o755 if name.endswith("/exiftool") else 0o644
            archive.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            archive.addfile(info)
    return buffer.getvalue()


WINDOWS_RELEASE = {
    "exiftool-13.10_64/exiftool(-k).exe": b"MZ fake windows executable",
    "exiftool-13.10_64/exiftool_files/perl.exe": b"MZ fake perl",
    "exiftool-13.10_64/exiftool_files/lib/Image/ExifTool.pm": b"1;",
}


# -- release discovery ---------------------------------------------------


def test_sha256_in_openssl_format():
    text = "SHA1(a.zip)= " + "1" * 40 + "\nSHA256(a.zip)= " + "ab" * 32 + "\n"
    assert exiftool_setup.find_sha256(text, "a.zip") == "ab" * 32


def test_sha256_in_sha256sum_format():
    text = "cd" * 32 + "  Image-ExifTool-13.10.tar.gz\n"
    assert exiftool_setup.find_sha256(text, "Image-ExifTool-13.10.tar.gz") == "cd" * 32


def test_sha256_does_not_confuse_similar_names():
    text = "SHA256(exiftool-13.10_32.zip)= " + "aa" * 32 + "\n"
    assert exiftool_setup.find_sha256(text, "exiftool-13.10_64.zip") is None


def test_archive_names():
    assert exiftool_setup.archive_candidates("13.10", "win32", "AMD64")[0] == "exiftool-13.10_64.zip"
    assert exiftool_setup.archive_candidates("13.10", "win32", "x86")[0] == "exiftool-13.10_32.zip"
    assert exiftool_setup.archive_candidates("13.10", "linux") == ["Image-ExifTool-13.10.tar.gz"]


def test_falls_back_to_the_older_windows_name():
    archive = make_zip({"exiftool(-k).exe": b"MZ"})
    fetch = fake_site("12.50", "exiftool-12.50.zip", archive)
    release = exiftool_setup.latest_release(fetch, "win32", "AMD64")
    assert release.archive == "exiftool-12.50.zip"


def test_refuses_a_release_without_a_checksum():
    def fetch(url):
        return b"13.10" if url.endswith("ver.txt") else b"SHA256(other.zip)= " + b"0" * 64

    with pytest.raises(MediaMetaError, match="cannot be verified"):
        exiftool_setup.latest_release(fetch, "linux")


def test_refuses_a_strange_version_string():
    with pytest.raises(MediaMetaError, match="unexpected version"):
        exiftool_setup.latest_release(lambda url: b"<html>maintenance</html>", "linux")


# -- unpacking safety ----------------------------------------------------


@pytest.mark.parametrize("name", ["../evil.txt", "a/../../evil.txt", "/etc/evil", "C:/evil.txt"])
def test_member_names_cannot_escape(tmp_path, name):
    with pytest.raises(MediaMetaError):
        exiftool_setup._safe_target(tmp_path, name)


def test_zip_with_traversal_is_rejected(tmp_path):
    archive = make_zip({"../outside.txt": b"x"})
    with pytest.raises(MediaMetaError):
        exiftool_setup._extract_zip(archive, tmp_path / "out")
    assert not (tmp_path / "outside.txt").exists()


def test_tar_symlinks_are_skipped(tmp_path):
    archive = make_tar({"pkg/readme.txt": "hi"}, symlinks={"pkg/link": "/etc/passwd"})
    exiftool_setup._extract_tar(archive, tmp_path)
    assert (tmp_path / "pkg" / "readme.txt").read_text() == "hi"
    assert not (tmp_path / "pkg" / "link").exists()


# -- installing ------------------------------------------------------------


def test_windows_layout(isolated_home):
    archive = make_zip(WINDOWS_RELEASE)
    fetch = fake_site("13.10", "exiftool-13.10_64.zip", archive)

    result = exiftool_setup.install(fetch=fetch, platform="win32", machine="AMD64", verify=False)

    folder = exiftool_setup.install_dir()
    assert result == {"version": "13.10", "path": folder, "changed": True}
    assert isolated_home in folder.parents
    # The "(-k)" that makes exiftool wait for a key press is gone.
    assert (folder / "exiftool.exe").read_bytes() == b"MZ fake windows executable"
    assert (folder / "exiftool_files" / "perl.exe").is_file()
    assert exiftool_setup.installed_version() == "13.10"
    assert exiftool_setup.managed_command("win32") == [str(folder / "exiftool.exe")]


def test_checksum_mismatch_installs_nothing(isolated_home):
    archive = make_zip(WINDOWS_RELEASE)
    fetch = fake_site("13.10", "exiftool-13.10_64.zip", archive, checksum="0" * 64)

    with pytest.raises(MediaMetaError, match="does not match the SHA-256"):
        exiftool_setup.install(fetch=fetch, platform="win32", machine="AMD64", verify=False)
    assert not exiftool_setup.install_dir().exists()


def test_failed_update_keeps_the_previous_copy(isolated_home):
    good = fake_site("13.10", "exiftool-13.10_64.zip", make_zip(WINDOWS_RELEASE))
    exiftool_setup.install(fetch=good, platform="win32", machine="AMD64", verify=False)

    broken = make_zip({"exiftool-13.11_64/readme.txt": b"no executable here"})
    fetch = fake_site("13.11", "exiftool-13.11_64.zip", broken)
    with pytest.raises(MediaMetaError, match="no exiftool executable"):
        exiftool_setup.install(fetch=fetch, platform="win32", machine="AMD64", verify=False)

    assert exiftool_setup.installed_version() == "13.10"
    assert (exiftool_setup.install_dir() / "exiftool.exe").is_file()
    leftovers = [item.name for item in isolated_home.iterdir() if item.name != "exiftool"]
    assert leftovers == []


def test_same_version_is_not_downloaded_twice(isolated_home):
    fetch = fake_site("13.10", "exiftool-13.10_64.zip", make_zip(WINDOWS_RELEASE))
    exiftool_setup.install(fetch=fetch, platform="win32", machine="AMD64", verify=False)
    fetch.requested.clear()

    again = exiftool_setup.install(fetch=fetch, platform="win32", machine="AMD64", verify=False)
    assert again["changed"] is False
    assert f"{SITE}/exiftool-13.10_64.zip" not in fetch.requested

    forced = exiftool_setup.install(
        fetch=fetch, platform="win32", machine="AMD64", verify=False, force=True
    )
    assert forced["changed"] is True


def test_posix_release_without_lib_is_rejected(isolated_home):
    archive = make_tar({"Image-ExifTool-13.10/exiftool": "#!/usr/bin/perl\n"})
    fetch = fake_site("13.10", "Image-ExifTool-13.10.tar.gz", archive)
    with pytest.raises(MediaMetaError, match="does not look like an ExifTool release"):
        exiftool_setup.install(fetch=fetch, platform="linux", verify=False)


def test_uninstall(isolated_home):
    fetch = fake_site("13.10", "exiftool-13.10_64.zip", make_zip(WINDOWS_RELEASE))
    exiftool_setup.install(fetch=fetch, platform="win32", machine="AMD64", verify=False)
    assert exiftool_setup.uninstall() is True
    assert not exiftool_setup.install_dir().exists()
    assert exiftool_setup.uninstall() is False


def test_data_dir_follows_the_override(isolated_home):
    assert exiftool_setup.data_dir() == isolated_home


# -- a genuine install, using this machine's ExifTool as the "download" --------


def _real_exiftool_release():
    """Repackage the installed ExifTool the way exiftool.org ships it."""
    script = shutil.which("exiftool")
    perl = shutil.which("perl")
    if not script or not perl:
        pytest.skip("needs exiftool and perl installed")
    located = subprocess.run(
        [perl, "-MImage::ExifTool", "-e", 'print $INC{"Image/ExifTool.pm"}'],
        capture_output=True, text=True,
    )
    if located.returncode != 0:
        pytest.skip("Image::ExifTool is not importable")
    library = Path(located.stdout).parent.parent  # .../perl5
    version = subprocess.run([script, "-ver"], capture_output=True, text=True).stdout.strip()

    root = f"Image-ExifTool-{version}"
    files = {f"{root}/exiftool": Path(script).read_bytes()}
    for module in [library / "Image" / "ExifTool.pm", library / "File" / "RandomAccess.pm"]:
        files[f"{root}/lib/{module.relative_to(library).as_posix()}"] = module.read_bytes()
    for module in (library / "Image" / "ExifTool").rglob("*"):
        if module.is_file():
            files[f"{root}/lib/{module.relative_to(library).as_posix()}"] = module.read_bytes()
    return version, f"{root}.tar.gz", make_tar(files)


def test_real_install_is_used_by_the_backend(isolated_home, jpeg):
    version, name, archive = _real_exiftool_release()
    result = exiftool_setup.install(fetch=fake_site(version, name, archive), platform="linux")
    assert result["changed"] is True

    command, source = ExifToolBackend().resolve()
    assert source == "mediameta's own copy"
    assert command[-1] == str(exiftool_setup.install_dir() / "exiftool")

    record = write_metadata(jpeg, {"title": "Через свою копию"}, backend="exiftool")
    assert record.common["title"] == "Через свою копию"
    assert read_metadata(jpeg, backend="exiftool").common["title"] == "Через свою копию"


def test_install_verifies_that_the_program_starts(isolated_home):
    archive = make_tar({
        "Image-ExifTool-13.10/exiftool": "#!/usr/bin/perl\ndie 'broken build';\n",
        "Image-ExifTool-13.10/lib/Image/ExifTool.pm": "1;\n",
    })
    if not shutil.which("perl"):
        pytest.skip("needs perl")
    fetch = fake_site("13.10", "Image-ExifTool-13.10.tar.gz", archive)
    with pytest.raises(MediaMetaError, match="does not start"):
        exiftool_setup.install(fetch=fetch, platform="linux")
    assert not exiftool_setup.install_dir().exists()


# -- how the backend picks a program ------------------------------------------


def test_resolution_prefers_the_environment_variable(isolated_home, tmp_path, monkeypatch):
    fake = tmp_path / "my-exiftool"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("MEDIAMETA_EXIFTOOL", str(fake))
    command, source = ExifToolBackend().resolve()
    assert command == [str(fake)]
    assert source == "MEDIAMETA_EXIFTOOL"


def test_a_missing_configured_path_is_reported(monkeypatch, tmp_path):
    monkeypatch.setenv("MEDIAMETA_EXIFTOOL", str(tmp_path / "nope"))
    available, reason = ExifToolBackend().is_available()
    assert available is False
    assert "MEDIAMETA_EXIFTOOL" in reason


def test_without_any_exiftool_the_hint_names_the_command(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    available, reason = ExifToolBackend().is_available()
    assert available is False
    assert "mediameta exiftool install" in reason


def test_managed_copy_needs_perl_outside_windows(isolated_home, monkeypatch):
    folder = exiftool_setup.install_dir()
    folder.mkdir(parents=True)
    (folder / "exiftool").write_text("#!/usr/bin/perl\n")
    monkeypatch.setattr(exiftool_setup.shutil, "which", lambda name: None)
    assert exiftool_setup.managed_command("linux") is None


# -- command line --------------------------------------------------------------


def test_cli_install_status_remove(isolated_home, monkeypatch, capsys):
    fetch = fake_site("13.10", "exiftool-13.10_64.zip", make_zip(WINDOWS_RELEASE))
    monkeypatch.setattr(exiftool_setup, "_fetch", fetch)
    # Pretend to be 64-bit Windows; the fake executable cannot actually run
    # here, so the start-up check is skipped.
    real_install = exiftool_setup.install
    monkeypatch.setattr(
        exiftool_setup,
        "install",
        lambda **kwargs: real_install(verify=False, platform="win32", machine="AMD64", **kwargs),
    )

    assert main(["exiftool", "install"]) == 0
    out = capsys.readouterr().out
    assert "SHA-256 verified" in out
    assert "installed exiftool 13.10" in out

    assert main(["exiftool", "install"]) == 0
    assert "already installed" in capsys.readouterr().out

    assert main(["exiftool", "remove"]) == 0
    assert "removed" in capsys.readouterr().out
    assert not exiftool_setup.install_dir().exists()


def test_cli_install_reports_network_errors(monkeypatch, capsys):
    def offline(url):
        raise MediaMetaError(f"could not download {url}: no network")

    monkeypatch.setattr(exiftool_setup, "_fetch", offline)
    assert main(["exiftool", "install"]) == 1
    assert "could not download" in capsys.readouterr().err


def test_cli_status_without_exiftool(monkeypatch, capsys):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert main(["exiftool", "status"]) == 0
    assert "not available" in capsys.readouterr().out


def test_unsupported_format_points_to_the_install_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    path = tmp_path / "IMG_0001.heic"
    path.write_bytes(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 16)
    assert main(["show", str(path)]) == 1
    assert "mediameta exiftool install" in capsys.readouterr().err


def test_a_locked_install_folder_is_reported_cleanly(isolated_home, monkeypatch):
    fetch = fake_site("13.10", "exiftool-13.10_64.zip", make_zip(WINDOWS_RELEASE))
    exiftool_setup.install(fetch=fetch, platform="win32", machine="AMD64", verify=False)

    def locked(source, destination):
        raise PermissionError("[WinError 32] the file is in use")

    with monkeypatch.context() as patch:
        patch.setattr(exiftool_setup.os, "replace", locked)
        with pytest.raises(MediaMetaError, match="close other programs"):
            exiftool_setup.install(
                fetch=fetch, platform="win32", machine="AMD64", verify=False, force=True
            )
    assert exiftool_setup.installed_version() == "13.10"
    assert (exiftool_setup.install_dir() / "exiftool.exe").is_file()
