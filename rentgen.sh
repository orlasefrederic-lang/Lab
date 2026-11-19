#!/bin/sh
# Rentgen for Linux: run "sh rentgen.sh" (asks for sudo, opens the HTML report).
# Parameters are passed on to the program, e.g.: sh rentgen.sh --stress
cd "$(dirname "$0")" || exit 1
exec python3 rentgen.py --elevate --open "$@"
