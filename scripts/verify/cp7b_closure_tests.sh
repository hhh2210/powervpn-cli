#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
. "$repo_root/scripts/lib/cp7b_runtime.sh"
. "$repo_root/scripts/lib/cp7b_closure.sh"

expect_failure() {
	if "$@" >/dev/null 2>&1; then
		pvn_fail "command unexpectedly succeeded: $*" || exit 1
	fi
}

pvn_cp7b_init_paths "$repo_root"
source_closure=$PVN_CP7B_PREFIX
test_root="$PVN_CP7B_SCRATCH_ROOT/cp7b-closure-tests.$$"

cleanup() {
	rc=$?
	trap - EXIT HUP INT TERM
	case "$test_root" in
	"$PVN_CP7B_SCRATCH_ROOT"/cp7b-closure-tests.*)
		rm -rf -- "$test_root"
		;;
	*) rc=1 ;;
	esac
	exit "$rc"
}
trap cleanup EXIT HUP INT TERM

mkdir "$test_root"
chmod 700 "$test_root"
rebuilt_launcher="$test_root/gated-launcher.rebuilt"
installed_text="$test_root/gated-launcher.installed.text"
rebuilt_text="$test_root/gated-launcher.rebuilt.text"
/usr/bin/xcrun clang -std=c11 -arch arm64 -Wall -Wextra -Werror \
	"$repo_root/scripts/libexec/cp7b_gated_launcher.c" -o "$rebuilt_launcher"
otool -tvV "$source_closure/libexec/ipsec/cp7b-gated-launcher" | tail -n +2 \
	>"$installed_text"
otool -tvV "$rebuilt_launcher" | tail -n +2 >"$rebuilt_text"
cmp "$installed_text" "$rebuilt_text"
cp -R "$source_closure" "$test_root/closure"
export POWERVPN_CP7B_TEST_MODE=1
export POWERVPN_CP7B_RUNTIME_ROOT="$test_root"
pvn_cp7b_init_paths "$repo_root"
PVN_CP7B_PREFIX="$test_root/closure"
PVN_CP7B_BINARY="$PVN_CP7B_PREFIX/libexec/ipsec/charon"
PVN_CP7B_SWANCTL="$PVN_CP7B_PREFIX/sbin/swanctl"
PVN_CP7B_LIBSTRONGSWAN="$PVN_CP7B_PREFIX/lib/ipsec/libstrongswan.0.dylib"
PVN_CP7B_LIBCHARON="$PVN_CP7B_PREFIX/lib/ipsec/libcharon.0.dylib"
PVN_CP7B_OPENSSL_PLUGIN="$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-openssl.so"
PVN_CP7B_NONCE_PLUGIN="$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-nonce.so"
PVN_CP7B_LIBCRYPTO="$PVN_CP7B_PREFIX/lib/private/libcrypto.3.dylib"
PVN_CP7B_LAUNCHER="$PVN_CP7B_PREFIX/libexec/ipsec/cp7b-gated-launcher"

pvn_cp7b_require_closure_tree 502
pvn_cp7b_verify_manifest_closure

test_replacement_rejected() {
	target_relative=$1
	replacement_relative=$2
	target="$PVN_CP7B_PREFIX/$target_relative"
	replacement="$source_closure/$replacement_relative"
	original="$source_closure/$target_relative"
	case "$target" in
	"$test_root"/closure/*) ;;
	*) pvn_fail "closure test target escaped scratch" || return 1 ;;
	esac
	rm -f -- "$target"
	cp "$replacement" "$target"
	pvn_cp7b_require_closure_tree 502
	expect_failure pvn_cp7b_verify_manifest_closure
	rm -f -- "$target"
	cp "$original" "$target"
	pvn_cp7b_require_closure_tree 502
	pvn_cp7b_verify_manifest_closure
}

test_replacement_rejected \
	libexec/ipsec/charon \
	sbin/swanctl
test_replacement_rejected \
	lib/ipsec/plugins/libstrongswan-openssl.so \
	lib/ipsec/plugins/libstrongswan-nonce.so
test_replacement_rejected \
	lib/private/libcrypto.3.dylib \
	libexec/ipsec/cp7b-gated-launcher

chmod g+w "$PVN_CP7B_OPENSSL_PLUGIN"
expect_failure pvn_cp7b_require_closure_tree 502
chmod g-w "$PVN_CP7B_OPENSSL_PLUGIN"
pvn_cp7b_require_closure_tree 502
pvn_cp7b_verify_manifest_closure

trap - EXIT HUP INT TERM
rm -rf -- "$test_root"
printf '%s\n' 'PASS: CP7B sealed-closure replacement tests (scratch copy only)'
