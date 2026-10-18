#!/bin/sh
# Build the patched strongSwan 6.0.7 runtime used by the native backend.
#
# Output: <out>/stage, a tree to copy verbatim to $PREFIX by install.sh.
# Nothing here needs root. Requires Xcode command line tools and Homebrew
# autoconf automake libtool gettext bison gperf pkg-config openssl@3.
#
# usage: scripts/native/build_runtime.sh [--source DIR] [out-dir]
#   out-dir defaults to ~/.cache/powervpn-native. Without --source the pinned
#   upstream tag is cloned with git; --source takes an unpacked, unmodified
#   strongSwan 6.0.7 source tree instead (the Homebrew formula uses this).

set -eu

source_tree=
if [ "${1:-}" = --source ]; then
	[ $# -ge 2 ] || { echo "build_runtime: --source needs a directory" >&2; exit 1; }
	source_tree=$2
	shift 2
fi

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
patch_dir="$repo_root/patches/strongswan-6.0.7"
out=${1:-"$HOME/.cache/powervpn-native"}
jobs=${JOBS:-$(sysctl -n hw.ncpu)}
brew_prefix=${BREW_PREFIX:-/opt/homebrew}
openssl_prefix="$brew_prefix/opt/openssl@3"

# Must match install.sh: the runtime is linked against its final location.
PREFIX=/Library/PrivilegedHelperTools/com.hhh2210.powervpn-native/runtime
PIDDIR=/var/run/powervpn-native
UPSTREAM=https://github.com/strongswan/strongswan.git
UPSTREAM_TAG=6.0.7
UPSTREAM_COMMIT=5973ff8e41deef4e015e1138a2de688acedf6f75

fail() {
	echo "build_runtime: $*" >&2
	exit 1
}

[ "$(uname -m)" = arm64 ] || fail "arm64 Mac required"
for tool in autoconf automake libtool gettext bison gperf pkgconf; do
	[ -d "$brew_prefix/opt/$tool" ] || fail "missing Homebrew package: $tool (brew install $tool)"
done
[ -f "$openssl_prefix/lib/libcrypto.3.dylib" ] || fail "missing Homebrew openssl@3"

src="$out/strongswan"
build="$out/build"
stage="$out/stage"
mkdir -p "$out"

if [ -n "$source_tree" ]; then
	grep -q '^AC_INIT(\[strongSwan\],\[6\.0\.7\])' "$source_tree/configure.ac" 2>/dev/null ||
		fail "not a strongSwan $UPSTREAM_TAG source tree: $source_tree"
	rm -rf "$src"
	ditto "$source_tree" "$src"
	for patch in "$patch_dir"/000[1-4]-*.patch; do
		patch -d "$src" -p1 --forward --batch --quiet -i "$patch" >/dev/null ||
			fail "patch does not apply: $(basename "$patch")"
	done
	! find "$src" -name '*.rej' | grep -q . || fail "patch left rejects in $src"
	echo "build_runtime: patched source tree for $UPSTREAM_TAG"
else
	if [ ! -d "$src/.git" ]; then
		git clone --quiet --depth 1 --branch "$UPSTREAM_TAG" "$UPSTREAM" "$src"
	fi
	[ "$(git -C "$src" rev-parse 'HEAD^{commit}' 2>/dev/null || true)" != "" ] || fail "bad checkout: $src"

	# Reset to the pinned upstream commit, then apply the series in order.
	base=$(git -C "$src" rev-list -n 1 "$UPSTREAM_TAG")
	[ "$base" = "$UPSTREAM_COMMIT" ] || fail "tag $UPSTREAM_TAG is $base, expected $UPSTREAM_COMMIT"
	git -C "$src" checkout --quiet --detach "$base"
	git -C "$src" reset --quiet --hard "$base"
	git -C "$src" clean -qfdx
	for patch in "$patch_dir"/000[1-4]-*.patch; do
		git -C "$src" -c user.name=powervpn -c user.email=powervpn@localhost \
			am --quiet --keep-cr "$patch" || fail "patch does not apply: $(basename "$patch")"
	done
	echo "build_runtime: patched $(git -C "$src" rev-parse --short HEAD) on $UPSTREAM_TAG"
fi

PATH="$brew_prefix/opt/bison/bin:$brew_prefix/opt/gettext/bin:$brew_prefix/bin:$PATH"
export PATH
(cd "$src" && ./autogen.sh >/dev/null)

rm -rf "$build" "$stage"
mkdir -p "$build"
cd "$build"
PKG_CONFIG_PATH="$openssl_prefix/lib/pkgconfig" \
	PYTHON=/usr/bin/python3 \
	CFLAGS='-arch arm64 -O2 -Wno-address-of-packed-member' \
	LDFLAGS="-L$openssl_prefix/lib -Wl,-headerpad_max_install_names" \
	CPPFLAGS="-I$openssl_prefix/include" \
	"$src/configure" --quiet --prefix="$PREFIX" --with-piddir="$PIDDIR" \
	--disable-defaults --enable-charon --enable-ikev1 --enable-ikev2 \
	--enable-kernel-libipsec --enable-kernel-pfroute --enable-socket-default \
	--enable-nonce --enable-openssl --enable-hmac --enable-kdf --enable-drbg \
	--enable-vici --enable-swanctl --disable-scripts
make -s -j"$jobs" >/dev/null
make -s install DESTDIR="$stage" >/dev/null

root="$stage$PREFIX"
# Keep the root daemon off user-writable Homebrew paths: ship a private libcrypto.
cp "$openssl_prefix/lib/libcrypto.3.dylib" "$root/lib/ipsec/libcrypto.3.dylib"
chmod 644 "$root/lib/ipsec/libcrypto.3.dylib"
install_name_tool -id "$PREFIX/lib/ipsec/libcrypto.3.dylib" "$root/lib/ipsec/libcrypto.3.dylib"
openssl_plugin="$root/lib/ipsec/plugins/libstrongswan-openssl.so"
old=$(otool -L "$openssl_plugin" | awk '/libcrypto\.3\.dylib/ {print $1; exit}')
install_name_tool -change "$old" "$PREFIX/lib/ipsec/libcrypto.3.dylib" "$openssl_plugin"
mkdir -p "$root/lib/ossl-modules"
: > "$root/etc/powervpn-openssl.cnf"

# install_name_tool invalidates signatures; re-sign ad hoc.
find "$root" -type f \( -name '*.dylib' -o -name '*.so' -o -perm -u+x \) | while read -r file; do
	if file "$file" | grep -q 'Mach-O'; then codesign -f -s - "$file" 2>/dev/null; fi
done

if otool -L "$openssl_plugin" | grep -q "$brew_prefix"; then
	fail "openssl plugin still links Homebrew"
fi
for artifact in libexec/ipsec/charon lib/ipsec/libcharon.0.dylib \
	lib/ipsec/plugins/libstrongswan-kernel-libipsec.so lib/ipsec/plugins/libstrongswan-vici.so; do
	file "$root/$artifact" | grep -q 'Mach-O 64-bit.*arm64' || fail "not arm64: $artifact"
done

# The runtime is redistributed: ship the strongSwan (GPL-2.0-or-later) and
# OpenSSL (Apache-2.0) license texts and where the corresponding source lives.
licenses="$root/share/licenses"
mkdir -p "$licenses/strongswan" "$licenses/openssl"
cp "$src/COPYING" "$src/LICENSE" "$licenses/strongswan/"
cp "$openssl_prefix/LICENSE.txt" "$licenses/openssl/"
openssl_version=$(sed -n 's/^Version: //p' "$openssl_prefix/lib/pkgconfig/libcrypto.pc")
cat > "$licenses/SOURCE" <<EOF
charon and its libraries: strongSwan $UPSTREAM_TAG
  https://github.com/strongswan/strongswan/tree/$UPSTREAM_TAG
with the patch series in
  https://github.com/hhh2210/powervpn-cli/tree/main/patches/strongswan-$UPSTREAM_TAG
lib/ipsec/libcrypto.3.dylib: OpenSSL $openssl_version
  https://github.com/openssl/openssl
EOF
find "$licenses" -type f -exec chmod 644 {} +

(cd "$root" && find . -type f | sort | xargs shasum -a 256) > "$out/runtime.sha256"
# The Homebrew keg ships this tar, so Homebrew never relocates the Mach-O files.
tar -c -f "$out/runtime.tar" -C "$root" --no-acls --no-xattrs --no-mac-metadata .
(cd "$patch_dir" && shasum -a 256 000[1-4]-*.patch) > "$out/patches.txt"
echo "build_runtime: staged $root"
