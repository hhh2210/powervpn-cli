#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
. "$repo_root/scripts/lib/cp7b_runtime.sh"
pvn_cp7b_init_paths "$repo_root"

operation_mode=
approved_sha=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--dry-run) operation_mode=dry-run ;;
	--execute-reviewed) operation_mode=execute ;;
	--manifest-sha256)
		shift
		[ "$#" -gt 0 ] || pvn_fail "--manifest-sha256 requires a value" || exit 2
		approved_sha=$1
		;;
	*) pvn_fail "usage: $0 --dry-run|--execute-reviewed --manifest-sha256 <sha256>" || exit 2 ;;
	esac
	shift
done
[ -n "$operation_mode" ] && [ -n "$approved_sha" ] ||
	pvn_fail "mode and manifest hash are required" || exit 2
readonly operation_mode approved_sha
[ "$(id -u)" -ne 0 ] || pvn_fail "authorization wrapper must run as the desktop user" || exit 1
actual_sha=$(pvn_sha256_file "$PVN_CP7B_MANIFEST")
[ "$approved_sha" = "$actual_sha" ] || pvn_fail "approved CP7B manifest hash changed" || exit 1
exact_command="$repo_root/scripts/stop_cp7b_backend.sh --execute-reviewed --manifest-sha256 $actual_sha"
if [ "$operation_mode" = dry-run ]; then
	printf '%s\n' 'mode=dry-run' 'signals=INT,TERM,KILL-bounded' \
		'cleanup=generation-owned-only' "exact_command=$exact_command"
	exit 0
fi

pvn_cp7b_require_safe_file "$PVN_CP7B_MANIFEST"
expected_authorizer=$(jq -er '.artifacts.authorizerSHA256 |
  select(test("^[0-9a-f]{64}$"))' "$PVN_CP7B_MANIFEST") ||
	pvn_fail "CP7B manifest has no reviewed authorizer hash" || exit 1
pvn_cp7b_require_safe_file "$PVN_CP7B_AUTHORIZER"
[ "$(pvn_sha256_file "$PVN_CP7B_AUTHORIZER")" = "$expected_authorizer" ] ||
	pvn_fail "CP7B authorizer hash changed" || exit 1

/usr/bin/osascript "$PVN_CP7B_AUTHORIZER" --stop-reviewed "$actual_sha"
