#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
. "$repo_root/scripts/lib/route_snapshot.sh"
. "$repo_root/scripts/lib/network_snapshot.sh"
pvn_init_runtime_paths

output=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--output)
		shift
		[ "$#" -gt 0 ] || pvn_fail "--output requires a path" || exit 2
		output=$1
		;;
	*) pvn_fail "usage: $0 [--output <scratch-json>]" || exit 2 ;;
	esac
	shift
done

if [ -z "$output" ]; then
	pvn_snapshot_json
	exit 0
fi

case "$output" in
"$PVN_SCRATCH_ROOT"/*) ;;
*) pvn_fail "snapshot output must stay below the PowerVPN scratch root" || exit 1 ;;
esac
parent=$(dirname -- "$output")
[ -d "$parent" ] || pvn_fail "snapshot output parent does not exist" || exit 1
[ ! -L "$parent" ] || pvn_fail "snapshot output parent must not be a symlink" || exit 1
[ ! -e "$output" ] || pvn_fail "snapshot output already exists" || exit 1
umask 077
pvn_snapshot_json >"$output"
chmod 600 "$output"
printf '%s\n' "$output"
