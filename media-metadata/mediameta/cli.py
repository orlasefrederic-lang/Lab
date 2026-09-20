"""Command line interface: ``mediameta show|set|remove|copy|fields|backends``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .api import copy_metadata, read_metadata, remove_metadata, write_metadata
from .backends import backend_status
from .errors import MediaMetaError
from .fields import parse_assignments, resolve_field
from .record import describe_fields
from .utils import iter_media_files

EPILOG = """\
examples:
  mediameta show photo.jpg
  mediameta show album/ -r --json
  mediameta set photo.jpg -s title="Sunset" -s "date=2024-07-01 18:30" -s gps=55.7558,37.6176
  mediameta set clip.mp4 -s artist="Kostya" -s keywords="sea,summer" --backup
  mediameta remove photo.jpg -f gps_latitude -f gps_longitude
  mediameta remove photo.jpg --all --backup
  mediameta copy original.jpg edited.jpg
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mediameta",
        description="Read and edit metadata of photos and videos.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"mediameta {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--backend",
        default="auto",
        help="auto (default), native, exif, png, mp4 or exiftool",
    )
    common.add_argument(
        "-r", "--recursive", action="store_true", help="descend into directories"
    )

    show = subparsers.add_parser("show", parents=[common], aliases=["read", "info"],
                                 help="print the metadata of one or more files")
    show.add_argument("paths", nargs="+", type=Path)
    show.add_argument("--json", action="store_true", help="machine-readable output")
    show.add_argument("--raw", action="store_true", help="also list backend-specific tags")
    show.add_argument("-f", "--field", action="append", default=[],
                      help="show only these canonical fields (repeatable)")
    show.set_defaults(handler=command_show)

    write = subparsers.add_parser("set", parents=[common], aliases=["edit"],
                                  help="set or delete metadata fields")
    write.add_argument("paths", nargs="+", type=Path)
    write.add_argument("-s", "--set", action="append", default=[], metavar="NAME=VALUE",
                       dest="assignments",
                       help="canonical field; an empty value deletes it")
    write.add_argument("-t", "--tag", action="append", default=[], metavar="TAG=VALUE",
                       help="backend-specific tag, e.g. EXIF:ISOSpeedRatings=400")
    write.add_argument("-o", "--output", type=Path,
                       help="write the result here instead of editing in place")
    write.add_argument("--backup", action="store_true",
                       help="keep the original as FILE.bak")
    write.add_argument("-n", "--dry-run", action="store_true",
                       help="show what would change without touching any file")
    write.set_defaults(handler=command_set)

    remove = subparsers.add_parser("remove", parents=[common], aliases=["clear", "strip"],
                                   help="delete single fields or every metadata block")
    remove.add_argument("paths", nargs="+", type=Path)
    remove.add_argument("-f", "--field", action="append", default=[],
                        help="canonical field to delete (repeatable)")
    remove.add_argument("--all", action="store_true", dest="remove_all",
                        help="strip all metadata, including tags we do not map")
    remove.add_argument("-o", "--output", type=Path, help="write the result here instead")
    remove.add_argument("--backup", action="store_true", help="keep the original as FILE.bak")
    remove.add_argument("-n", "--dry-run", action="store_true", help="only report what would go")
    remove.set_defaults(handler=command_remove)

    copy = subparsers.add_parser("copy", parents=[common],
                                 help="copy metadata from one file to another")
    copy.add_argument("source", type=Path)
    copy.add_argument("destination", type=Path)
    copy.add_argument("-f", "--field", action="append", default=[],
                      help="copy only these fields (default: everything writable)")
    copy.add_argument("-o", "--output", type=Path, help="write the result here instead")
    copy.add_argument("--backup", action="store_true", help="keep the destination as FILE.bak")
    copy.set_defaults(handler=command_copy)

    fields = subparsers.add_parser("fields", help="list the canonical field names")
    fields.set_defaults(handler=command_fields)

    backends = subparsers.add_parser("backends", help="show which backends are usable")
    backends.set_defaults(handler=command_backends)

    return parser


# -- commands ----------------------------------------------------------


def command_show(args) -> int:
    paths = list(iter_media_files(args.paths, args.recursive))
    if not paths:
        print("no files matched", file=sys.stderr)
        return 1

    wanted = [resolve_field(name).name for name in args.field]
    records, failures = [], 0

    for path in paths:
        try:
            record = read_metadata(path, backend=args.backend)
        except MediaMetaError as exc:
            _report_error(path, exc)
            failures += 1
            continue

        if wanted:
            record.common = {
                name: value for name, value in record.common.items() if name in wanted
            }
        records.append(record)

    if args.json:
        print(json.dumps([record.to_dict(args.raw) for record in records],
                         indent=2, ensure_ascii=False))
    else:
        for index, record in enumerate(records):
            if index:
                print()
            print(record.render(include_raw=args.raw))

    return 1 if failures else 0


def command_set(args) -> int:
    changes = parse_assignments(args.assignments)
    raw_changes = _parse_raw_tags(args.tag)
    if not changes and not raw_changes:
        print("nothing to do: pass at least one --set or --tag", file=sys.stderr)
        return 2

    paths = list(iter_media_files(args.paths, args.recursive))
    if not paths:
        print("no files matched", file=sys.stderr)
        return 1
    if args.output and len(paths) > 1:
        print("--output works with a single file only", file=sys.stderr)
        return 2

    if args.dry_run:
        _print_planned_changes(paths, changes, raw_changes)
        return 0

    failures = 0
    for path in paths:
        try:
            record = write_metadata(
                path,
                changes,
                raw_changes,
                backend=args.backend,
                output=args.output,
                backup=args.backup,
            )
        except MediaMetaError as exc:
            _report_error(path, exc)
            failures += 1
            continue
        _report_success(record, changes, raw_changes)
    return 1 if failures else 0


def command_remove(args) -> int:
    if not args.field and not args.remove_all:
        print("pass --field NAME or --all", file=sys.stderr)
        return 2

    paths = list(iter_media_files(args.paths, args.recursive))
    if not paths:
        print("no files matched", file=sys.stderr)
        return 1
    if args.output and len(paths) > 1:
        print("--output works with a single file only", file=sys.stderr)
        return 2

    fields = [] if args.remove_all else [resolve_field(name).name for name in args.field]

    if args.dry_run:
        target = "every metadata block" if args.remove_all else ", ".join(fields)
        for path in paths:
            print(f"would remove {target} from {path}")
        return 0

    failures = 0
    for path in paths:
        try:
            record = remove_metadata(
                path,
                fields,
                backend=args.backend,
                output=args.output,
                backup=args.backup,
            )
        except MediaMetaError as exc:
            _report_error(path, exc)
            failures += 1
            continue
        removed = "all metadata" if args.remove_all else ", ".join(fields)
        print(f"{record.path}: removed {removed}")
        _print_warnings(record)
    return 1 if failures else 0


def command_copy(args) -> int:
    try:
        record = copy_metadata(
            args.source,
            args.destination,
            args.field,
            backend=args.backend,
            output=args.output,
            backup=args.backup,
        )
    except MediaMetaError as exc:
        _report_error(args.destination, exc)
        return 1

    copied = ", ".join(args.field) if args.field else "all writable fields"
    print(f"{record.path}: copied {copied} from {args.source}")
    _print_warnings(record)
    return 0


def command_fields(args) -> int:
    print(describe_fields())
    return 0


def command_backends(args) -> int:
    for name, available, reason, formats in backend_status():
        mark = "yes" if available else "no "
        print(f"  [{mark}] {name:<10} {formats}")
        if not available:
            print(f"         {reason}")
    return 0


# -- helpers -----------------------------------------------------------


def _parse_raw_tags(pairs) -> dict:
    tags = {}
    for pair in pairs:
        if "=" not in pair:
            raise MediaMetaError(f"expected TAG=VALUE, got {pair!r}")
        name, _, value = pair.partition("=")
        tags[name.strip()] = None if value == "" else value
    return tags


def _print_planned_changes(paths, changes: dict, raw_changes: dict) -> None:
    for path in paths:
        print(f"{path}:")
        for name, value in changes.items():
            print(f"    {name} = {'(delete)' if value is None else value}")
        for name, value in raw_changes.items():
            print(f"    {name} = {'(delete)' if value is None else value}")


def _report_success(record, changes: dict, raw_changes: dict) -> None:
    touched = list(changes) + list(raw_changes)
    print(f"{record.path}: updated {', '.join(touched)}")
    _print_warnings(record)


def _print_warnings(record) -> None:
    for warning in record.warnings:
        print(f"    ! {warning}", file=sys.stderr)


def _report_error(path, exc: Exception) -> None:
    print(f"{path}: {exc}", file=sys.stderr)


def configure_console() -> None:
    """Make sure non-ASCII output survives the terminal.

    The Windows console still defaults to a legacy code page, where a
    Cyrillic title or the separator dot would raise UnicodeEncodeError
    instead of being printed. Switching the console and our own streams to
    UTF-8 fixes both; everywhere else this is a no-op.
    """
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass  # a redirected or unusual console: the reconfigure below still helps

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def main(argv=None) -> int:
    configure_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except MediaMetaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
