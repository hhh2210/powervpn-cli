#!/bin/sh

set -eu

scratch_root=${POWERVPN_STRONGSWAN_ROOT:-"$HOME/scratch-data/powervpn-strongswan"}
source_dir=${STRONGSWAN_SOURCE_DIR:-"$scratch_root/strongswan-6.0.7"}
build_dir=${STRONGSWAN_BUILD_DIR:-"$scratch_root/build-6.0.7-arm64"}
prefix_dir=${STRONGSWAN_PREFIX_DIR:-"$scratch_root/install-6.0.7-arm64"}
jobs=${JOBS:-8}
expected_commit=5973ff8e41deef4e015e1138a2de688acedf6f75
mode=${1:-build}

usage() {
	cat <<'EOF'
Usage: scripts/build_strongswan.sh [build|--verify-only]

Environment overrides:
  POWERVPN_STRONGSWAN_ROOT  Scratch root; all source/build/prefix paths must stay below it
  STRONGSWAN_SOURCE_DIR     Official strongSwan 6.0.7 checkout
  STRONGSWAN_BUILD_DIR      Out-of-tree build directory
  STRONGSWAN_PREFIX_DIR     Scratch-only install prefix
  JOBS                      Parallel make jobs (default: 8)
EOF
}

fail() {
	echo "error: $*" >&2
	exit 1
}

case "$mode" in
build | --verify-only) ;;
-h | --help)
	usage
	exit 0
	;;
*)
	usage >&2
	exit 2
	;;
esac

case "$jobs" in
'' | *[!0-9]*) fail "JOBS must be a positive integer" ;;
0) fail "JOBS must be a positive integer" ;;
esac

[ -d "$scratch_root" ] || fail "scratch root does not exist: $scratch_root"
[ -d "$source_dir/.git" ] || fail "source is not a Git checkout: $source_dir"
[ -x "$source_dir/configure" ] || fail "source configure script is missing"

if [ "$mode" = "build" ]; then
	mkdir -p "$build_dir" "$prefix_dir"
else
	[ -d "$build_dir" ] || fail "build directory does not exist: $build_dir"
	[ -d "$prefix_dir" ] || fail "prefix directory does not exist: $prefix_dir"
fi

scratch_root=$(CDPATH='' cd -- "$scratch_root" && pwd -P)
source_dir=$(CDPATH='' cd -- "$source_dir" && pwd -P)
build_dir=$(CDPATH='' cd -- "$build_dir" && pwd -P)
prefix_dir=$(CDPATH='' cd -- "$prefix_dir" && pwd -P)

for path in "$source_dir" "$build_dir" "$prefix_dir"; do
	case "$path" in
	"$scratch_root"/*) ;;
	*) fail "path escapes scratch root: $path" ;;
	esac
done

actual_commit=$(git -C "$source_dir" rev-parse HEAD)
[ "$actual_commit" = "$expected_commit" ] ||
	fail "source commit is $actual_commit, expected $expected_commit"

if [ -n "$(git -C "$source_dir" status --porcelain --untracked-files=no)" ]; then
	fail "tracked files in the strongSwan source checkout are modified"
fi

verify_artifacts() {
	for relative in \
		libexec/ipsec/charon \
		sbin/swanctl \
		lib/ipsec/plugins/libstrongswan-vici.so \
		lib/ipsec/plugins/libstrongswan-kernel-pfkey.so \
		lib/ipsec/plugins/libstrongswan-kernel-pfroute.so \
		lib/ipsec/plugins/libstrongswan-kernel-libipsec.so; do
		artifact="$prefix_dir/$relative"
		[ -f "$artifact" ] || fail "missing artifact: $artifact"
		file "$artifact" | grep -q 'Mach-O 64-bit.*arm64' ||
			fail "artifact is not Mach-O arm64: $artifact"
		echo "verified arm64: $relative"
	done
}

if [ "$mode" = "--verify-only" ]; then
	verify_artifacts
	exit 0
fi

brew_prefix=${BREW_PREFIX:-/opt/homebrew}
for tool in \
	"$brew_prefix/opt/bison/bin/bison" \
	"$brew_prefix/bin/gperf" \
	"$brew_prefix/bin/pkg-config"; do
	[ -x "$tool" ] || fail "required build tool is missing: $tool"
done
command -v make >/dev/null 2>&1 || fail "make is required"

openssl_prefix=${OPENSSL_PREFIX:-"$brew_prefix/opt/openssl@3"}
[ -d "$openssl_prefix" ] || fail "OpenSSL prefix is missing: $openssl_prefix"

PATH="$brew_prefix/opt/bison/bin:$brew_prefix/opt/gettext/bin:$brew_prefix/bin:$PATH"
export PATH

cd "$build_dir"
PKG_CONFIG_PATH="$openssl_prefix/lib/pkgconfig" \
	CFLAGS='-arch arm64 -Wno-address-of-packed-member' \
	LDFLAGS="-L$openssl_prefix/lib" \
	CPPFLAGS="-I$openssl_prefix/include" \
	"$source_dir/configure" \
	--prefix="$prefix_dir" \
	--disable-defaults \
	--enable-charon \
	--enable-swanctl \
	--enable-ikev1 \
	--enable-ikev2 \
	--enable-kernel-pfkey \
	--enable-kernel-pfroute \
	--enable-kernel-libipsec \
	--enable-nonce \
	--enable-openssl \
	--enable-osx-attr \
	--enable-pem \
	--enable-pkcs1 \
	--enable-pkcs8 \
	--enable-pubkey \
	--enable-socket-default \
	--enable-x509 \
	--enable-xauth-generic \
	--enable-vici \
	--enable-hmac \
	--enable-kdf \
	--enable-constraints \
	--enable-revocation \
	--enable-eap-identity \
	--enable-eap-mschapv2 \
	--enable-eap-md5 \
	--enable-eap-gtc \
	--enable-drbg \
	--disable-scripts

make -j"$jobs"
make install
make check -j"$jobs"
verify_artifacts
