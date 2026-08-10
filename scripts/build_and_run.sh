#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

swift build --arch arm64 --product powervpn
bin_path=$(swift build --arch arm64 --show-bin-path)
binary="$bin_path/powervpn"

if [ ! -x "$binary" ]; then
	printf 'error: built powervpn executable not found at %s\n' "$binary" >&2
	exit 1
fi

if [ "$#" -eq 0 ]; then
	set -- --help
fi

exec "$binary" "$@"
