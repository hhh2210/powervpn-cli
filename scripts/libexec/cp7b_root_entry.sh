#!/bin/sh

set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

repo_root=/Users/larry_1/Opensource/powervpn-cli
runtime_root=/Users/larry_1/scratch-data/powervpn-strongswan/runtime-6.0.7-cp7b
closure_root="$runtime_root/closure"
source_python=/Users/larry_1/scratch-data/powervpn-strongswan/strongswan-6.0.7-cp7b/src/libcharon/plugins/vici/python/vici
manifest="$repo_root/fixtures/redacted/cp7b-approval-manifest-v1.json"
bundle_root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
closure_bootstrap="$bundle_root/cp7b-closure-bootstrap.sh"
closure_helpers_loaded=false

fail() {
	echo "error: $*" >&2
	exit 1
}

sha256_file() {
	/usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

pvn_fail() {
	echo "error: $*" >&2
	return 1
}

require_root_bundle() {
	[ -d "$runtime_root" ] && [ ! -L "$runtime_root" ] || fail "CP7B runtime root is invalid"
	[ "$(/usr/bin/stat -f '%u:%g:%Lp' "$runtime_root")" = 0:0:700 ] ||
		fail "CP7B runtime root is not protected by root"
	case "$bundle_root" in
	"$runtime_root"/.bootstrap-*) ;;
	*) fail "CP7B root entry is outside the fixed bootstrap root" ;;
	esac
	[ -d "$bundle_root" ] && [ ! -L "$bundle_root" ] || fail "bootstrap root is invalid"
	[ "$(/usr/bin/stat -f '%u' "$bundle_root")" -eq 0 ] || fail "bootstrap root is not root-owned"
	[ "$(/usr/bin/stat -f '%Lp' "$bundle_root")" = 700 ] || fail "bootstrap root mode is not 700"
	[ -z "$(/usr/bin/find "$runtime_root" -mindepth 1 -maxdepth 1 \
		! -path "$closure_root" ! -path "$bundle_root" \
		! -path "$runtime_root/pfkey-attempt-ledger" -print -quit)" ] ||
		fail "CP7B root bootstrap has ambiguous runtime residue"
	if [ -e "$runtime_root/pfkey-attempt-ledger" ]; then
		[ -f "$runtime_root/pfkey-attempt-ledger" ] &&
			[ ! -L "$runtime_root/pfkey-attempt-ledger" ] &&
			[ "$(/usr/bin/stat -f '%u:%g:%Lp' "$runtime_root/pfkey-attempt-ledger")" = 0:0:600 ] ||
			fail "CP7B retry ledger identity changed"
	fi
}

copy_reviewed() {
	source_file=$1
	destination=$2
	expected=$3
	mode=$4
	[ -f "$source_file" ] && [ ! -L "$source_file" ] || fail "reviewed input is missing or a symlink"
	[ "$(/usr/bin/stat -f '%u' "$source_file")" -eq 502 ] || fail "reviewed input owner changed"
	case "$(/usr/bin/stat -f '%Lp' "$source_file")" in
	*2 | *3 | *6 | *7 | ?[2367]?) fail "reviewed input is group/world writable" ;;
	esac
	[ "$(sha256_file "$source_file")" = "$expected" ] || fail "reviewed input hash changed"
	/bin/cp "$source_file" "$destination"
	/usr/sbin/chown 0:0 "$destination"
	/bin/chmod "$mode" "$destination"
	[ "$(sha256_file "$destination")" = "$expected" ] || fail "root-owned copy hash changed"
}

cleanup_incomplete_bundle() {
	rc=$?
	trap - EXIT HUP INT TERM
	for file in \
		"$closure_bootstrap" \
		"$bundle_root/lib/cp7b_runtime.sh" \
		"$bundle_root/lib/cp7b_closure.sh" \
		"$bundle_root/lib/cp7b_state.sh" \
		"$bundle_root/lib/cp7b_attempts.sh" \
		"$bundle_root/lib/cp7b_snapshot.sh" \
		"$bundle_root/lib/cp7b_bundle.sh" \
		"$bundle_root/lib/native_charon_runtime.sh" \
		"$bundle_root/lib/network_snapshot.sh" \
		"$bundle_root/python/vici/__init__.py" \
		"$bundle_root/python/vici/command_wrappers.py" \
		"$bundle_root/python/vici/event_listener.py" \
		"$bundle_root/python/vici/exception.py" \
		"$bundle_root/python/vici/protocol.py" \
		"$bundle_root/python/vici/session.py" \
		"$bundle_root/cp7b_backend_window.sh" \
		"$bundle_root/cp7b_emergency_stop.sh" \
		"$bundle_root/official_vici_runtime.py" \
		"$bundle_root/cp7b_vici_readonly.py" \
		"$bundle_root/approval-manifest.json" \
		"$bundle_root/root-entry.sh"
	do
		[ ! -e "$file" ] || /bin/rm -f -- "$file"
	done
	/bin/rmdir "$bundle_root/python/vici" 2>/dev/null || true
	/bin/rmdir "$bundle_root/python" 2>/dev/null || true
	/bin/rmdir "$bundle_root/lib" 2>/dev/null || true
	/bin/rmdir "$bundle_root" 2>/dev/null || true
	if [ "$closure_helpers_loaded" = true ]; then
		pvn_cp7b_restore_runtime_owner_if_clean >/dev/null 2>&1 || true
	elif [ -d "$closure_root" ] && [ ! -L "$closure_root" ] &&
		[ "$(/usr/bin/stat -f '%u:%g' "$closure_root")" = 502:20 ] &&
		[ "$(/usr/bin/find "$runtime_root" -mindepth 1 -maxdepth 1 -print |
			/usr/bin/awk 'END { print NR + 0 }')" -eq 1 ]
	then
		/usr/sbin/chown 502:20 "$runtime_root"
		/bin/chmod 700 "$runtime_root"
	fi
	exit "$rc"
}

[ "$(/usr/bin/id -u)" -eq 0 ] || fail "CP7B root entry requires native authorization"
[ "$#" -eq 2 ] || fail "usage: $0 --run-reviewed|--stop-reviewed <manifest-sha256>"
action=$1
manifest_sha=$2
case "$action" in
--run-reviewed | --stop-reviewed) ;;
*) fail "unsupported CP7B root action" ;;
esac
case "$manifest_sha" in
*[!0-9a-f]* | '') fail "manifest hash must be lowercase hexadecimal" ;;
esac
[ "${#manifest_sha}" -eq 64 ] || fail "manifest hash must contain 64 characters"
require_root_bundle
trap cleanup_incomplete_bundle EXIT HUP INT TERM
copy_reviewed "$repo_root/scripts/lib/cp7b_closure.sh" "$closure_bootstrap" 03d8cafde71e1b72513e889c6910696fc690c58f0aec03ea6a04128cfa9fcdda 600
PVN_CP7B_RUNTIME_ROOT=$runtime_root
PVN_CP7B_PREFIX=$closure_root
export PVN_CP7B_RUNTIME_ROOT PVN_CP7B_PREFIX
# The sourced file was copied and hash-checked immediately above.
# shellcheck disable=SC1090
. "$closure_bootstrap"
closure_helpers_loaded=true
pvn_cp7b_take_closure_ownership

/bin/mkdir "$bundle_root/lib" "$bundle_root/python" "$bundle_root/python/vici"
/bin/chmod 700 "$bundle_root/lib" "$bundle_root/python" "$bundle_root/python/vici"
/bin/mv "$closure_bootstrap" "$bundle_root/lib/cp7b_closure.sh"
copy_reviewed "$manifest" "$bundle_root/approval-manifest.json" "$manifest_sha" 600
copy_reviewed "$repo_root/scripts/lib/cp7b_runtime.sh" "$bundle_root/lib/cp7b_runtime.sh" 715db9d4c6ada0da81c571f69900a1aa501d65adbdead52318a47afe6340ee55 600
copy_reviewed "$repo_root/scripts/lib/cp7b_state.sh" "$bundle_root/lib/cp7b_state.sh" 878dc8e7c6488449e3e09acb61e4f8cf4d55cf924864bd4758bed62b8ab03fa1 600
copy_reviewed "$repo_root/scripts/lib/cp7b_attempts.sh" "$bundle_root/lib/cp7b_attempts.sh" 0516e9dca6af11e0b08ffdab553163c684104d21fc0f0d15dfc5ee4a39075bc5 600
copy_reviewed "$repo_root/scripts/lib/cp7b_snapshot.sh" "$bundle_root/lib/cp7b_snapshot.sh" d57dccb9b97adb31388c1780004ac9a7e6ec7c37a6dc610440545d5581e4b192 600
copy_reviewed "$repo_root/scripts/lib/cp7b_bundle.sh" "$bundle_root/lib/cp7b_bundle.sh" 9ecc5daacf47ce315b049871ca6dd528c3fb8d13fea8da2820c0018c18f6c371 600
copy_reviewed "$repo_root/scripts/lib/native_charon_runtime.sh" "$bundle_root/lib/native_charon_runtime.sh" cf7b3a367970db7ad355501f7ee3192208876f04b15e8b1a9588ce12ccf30aee 600
copy_reviewed "$repo_root/scripts/lib/network_snapshot.sh" "$bundle_root/lib/network_snapshot.sh" f6012d94bd1eae418105daad9dae566a70cdfda0911fbe3ade9082b51a154bdd 600
copy_reviewed "$repo_root/scripts/libexec/cp7b_backend_window.sh" "$bundle_root/cp7b_backend_window.sh" 43ef9d031b8a3ad7b3e0e4a41c7076c2024061a1a8cbcde840b9e617a57f6229 700
copy_reviewed "$repo_root/scripts/libexec/cp7b_emergency_stop.sh" "$bundle_root/cp7b_emergency_stop.sh" fb82025b81727851539d4ed6691ba627bb0ac239ed0dacc8445271fa2aa27df1 700
copy_reviewed "$repo_root/scripts/verify/official_vici_runtime.py" "$bundle_root/official_vici_runtime.py" 73c0b98f6bd2abe687b4dd24762f467ad1ae15787cd27564f005b7a65175a62d 600
copy_reviewed "$repo_root/scripts/libexec/cp7b_vici_readonly.py" "$bundle_root/cp7b_vici_readonly.py" 6bf42eec4c75c505ef2af6e6901d426591780a892a71b08a0caacb3c58d10154 600
copy_reviewed "$source_python/__init__.py" "$bundle_root/python/vici/__init__.py" f77019594ecc7a2198c796d7ca62bf22e90d8e0258b0831e4467b572a2393c52 600
copy_reviewed "$source_python/command_wrappers.py" "$bundle_root/python/vici/command_wrappers.py" 0ee5f892bacfbcdcf7ceff3f45d76a471de30d3ec8cfda15d69fb6b350205f4f 600
copy_reviewed "$source_python/event_listener.py" "$bundle_root/python/vici/event_listener.py" 85c57c1fb4cbdadc03a5341963cf3aa28f62709d3443d46e71ead3f75c6bf448 600
copy_reviewed "$source_python/exception.py" "$bundle_root/python/vici/exception.py" 97ef178d3a97b71eb1be45e9ef369de6b0fd96a376526b21044f204b8712feb3 600
copy_reviewed "$source_python/protocol.py" "$bundle_root/python/vici/protocol.py" f86247d58ce36a84a651bc7fcce9b5acd789b185c056e8fc6dc7015bfc07d3a5 600
copy_reviewed "$source_python/session.py" "$bundle_root/python/vici/session.py" 78c4ba125b0dc8d83703f03055de39c9fb80180965b52512de836b4f68dbdb59 600

exec /usr/bin/env -i \
	PATH=/usr/bin:/bin:/usr/sbin:/sbin \
	PYTHONDONTWRITEBYTECODE=1 \
	PVN_CP7B_BUNDLE_ROOT="$bundle_root" \
	"$bundle_root/cp7b_backend_window.sh" "$action" --manifest-sha256 "$manifest_sha"
