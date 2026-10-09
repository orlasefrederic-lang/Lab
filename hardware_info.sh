#!/bin/sh
# Hardware report for Linux: run "sh hardware_info.sh" (asks for sudo, opens the HTML report)
cd "$(dirname "$0")" || exit 1
exec python3 hardware_info.py --elevate --open "$@"
