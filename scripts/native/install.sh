#!/bin/sh
# Install (or upgrade) the native strongSwan backend. Run once with sudo:
#
#   scripts/native/build_runtime.sh
#   swift build -c release --product powervpn-native-helper --arch arm64
#   sudo scripts/native/install.sh
#
# Homebrew installs run `sudo powervpn native install`, which calls this script
# with POWERVPN_NATIVE_RUNTIME_ARCHIVE (a tar of the runtime tree, so Homebrew
# never rewrites its Mach-O files) and POWERVPN_NATIVE_HELPER.
#
# It installs our own files only: the patched charon runtime and the helper
# under /Library/PrivilegedHelperTools/com.hhh2210.powervpn-native, and one
# LaunchDaemon. Nothing of the official PowerVPN client is touched.

set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

LABEL=com.hhh2210.powervpn-native
HOME_DIR=/Library/PrivilegedHelperTools/$LABEL
PLIST=/Library/LaunchDaemons/$LABEL.plist
RUN_DIR=/var/run/powervpn-native

fail() {
	echo "install: $*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || fail "run with sudo"
owner_uid=${SUDO_UID:-}
[ -n "$owner_uid" ] && [ "$owner_uid" != 0 ] || fail "run with sudo from your own account"
owner_home=$(dscl . -read "/Users/$(id -un "$owner_uid")" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)

archive=${POWERVPN_NATIVE_RUNTIME_ARCHIVE:-}
runtime=${POWERVPN_NATIVE_RUNTIME:-"$owner_home/.cache/powervpn-native/stage$HOME_DIR/runtime"}
helper=${POWERVPN_NATIVE_HELPER:-"$repo_root/.build/release/powervpn-native-helper"}
if [ -n "$archive" ]; then
	[ -f "$archive" ] && [ ! -L "$archive" ] || fail "no runtime archive at $archive"
else
	[ -x "$runtime/libexec/ipsec/charon" ] || fail "no runtime at $runtime (run scripts/native/build_runtime.sh first)"
	file "$runtime/libexec/ipsec/charon" | grep -q 'Mach-O 64-bit.*arm64' || fail "runtime is not arm64"
fi
[ -x "$helper" ] || fail "no helper at $helper (swift build -c release --product powervpn-native-helper)"
file "$helper" | grep -q 'Mach-O 64-bit.*arm64' || fail "helper is not arm64"

# Prepare and validate a fresh tree before stopping the running backend. Never
# reuse an existing destination ACL, hard link, or symlink as a write target.
parent=/Library/PrivilegedHelperTools
[ -d "$parent" ] && [ ! -L "$parent" ] || fail "unsafe helper parent"
[ ! -L "$HOME_DIR" ] || fail "install destination is a symlink"
new_home=$(mktemp -d "$parent/.powervpn-native.XXXXXXXX")
trap 'rm -rf "$new_home"' EXIT HUP INT TERM
chmod -N "$new_home"
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
# Copy the helper (and the archive) into the root-owned tree first and use only
# those copies, so the files hashed, run and installed are the same bytes.
install -m 755 "$helper" "$new_home/powervpn-native-helper"
if [ -n "$archive" ]; then
	install -m 600 "$archive" "$new_home/runtime.tar"
	# bsdtar strips a leading "/" and refuses ".." members by default; drop
	# owners, ACLs, extended attributes and macOS metadata so only file
	# contents, modes and symlinks land. verify-install then rejects hard links
	# and symlinks that leave the tree.
	mkdir "$new_home/runtime"
	tar -x -f "$new_home/runtime.tar" -C "$new_home/runtime" --no-same-owner --no-acls --no-xattrs --no-mac-metadata ||
		fail "could not unpack $archive"
	[ -x "$new_home/runtime/libexec/ipsec/charon" ] || fail "archive has no libexec/ipsec/charon"
	file "$new_home/runtime/libexec/ipsec/charon" | grep -q 'Mach-O 64-bit.*arm64' || fail "runtime is not arm64"
	runtime_source="runtime-archive $(sha256 "$new_home/runtime.tar")"
	rm -f "$new_home/runtime.tar"
else
	ditto --noacl --noextattr --noqtn "$runtime" "$new_home/runtime"
	runtime_source="runtime-directory $runtime"
fi
# What this install was made from; `powervpn native status` and doctor compare
# it with the Homebrew keg to tell whether an upgrade needs a reinstall.
printf 'installer %s\nhelper %s\n%s\n' "$(sha256 "$0")" \
	"$(sha256 "$new_home/powervpn-native-helper")" "$runtime_source" > "$new_home/installed-from"
# Enhanced Security for the two root executables (see docs/security-settings.md),
# signed ad hoc on the root-owned copies only after installed-from has recorded
# the bytes that were copied. Nothing rewrites these files afterwards.
cat > "$new_home/hardened.entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.hardened-process</key><true/>
  <key>com.apple.security.hardened-process.enhanced-security-version-string</key><string>2</string>
  <key>com.apple.security.hardened-process.hardened-heap</key><true/>
  <key>com.apple.security.hardened-process.dyld-ro</key><true/>
  <key>com.apple.security.hardened-process.platform-restrictions-string</key><string>2</string>
</dict>
</plist>
EOF
for binary in "$new_home/powervpn-native-helper" "$new_home/runtime/libexec/ipsec/charon"; do
	codesign --force --sign - --entitlements "$new_home/hardened.entitlements" "$binary" 2>/dev/null ||
		fail "could not sign $binary"
done
rm -f "$new_home/hardened.entitlements"
printf '%s\n' "$owner_uid" > "$new_home/owner-uid"
targets=${POWERVPN_NATIVE_TARGETS:-"$owner_home/.config/powervpn/targets.json"}
"$new_home/powervpn-native-helper" host-policy < "$targets" > "$new_home/allowed-hosts"
mkdir "$new_home/openssl-empty"

cat > "$new_home/strongswan.conf" <<EOF
# Written by powervpn-cli scripts/native/install.sh. No endpoint or secret here:
# connections and keys are loaded over VICI per session and unloaded after.
charon {
    load_modular = no
    load = openssl! nonce! hmac! kdf! drbg! kernel-libipsec! kernel-pfroute! socket-default! vici!
    threads = 16
    port = 50020
    port_nat_t = 50021
    install_routes = no
    install_virtual_ip = yes
    initiator_only = yes
    retransmit_timeout = 3
    retransmit_tries = 3
    # Required by the LeadSec gateway: without the NEW CLIENT vendor ID it
    # completes IKE but never returns ESP for the virtual IP.
    leadsec_new_client_vid = yes
    syslog {
        daemon { default = -1 }
        auth { default = -1 }
    }
    filelog {
        stderr { default = -1 }
        native {
            path = /var/log/powervpn-native-charon.log
            time_format = %F %T
            append = no
            default = 0
            ike = 1
            cfg = 1
        }
    }
    plugins {
        socket-default {
            use_ipv4 = yes
            use_ipv6 = no
        }
        kernel-libipsec {
            raw_esp = no
            allow_peer_ts = no
        }
        vici {
            socket = unix://$RUN_DIR/private/charon.vici
        }
    }
}
EOF

chown -R -P root:wheel "$new_home"
chmod -R -P -N "$new_home"
chmod -R -P go-w,u-s,g-s "$new_home"
chmod 755 "$new_home" "$new_home/openssl-empty"
chmod 644 "$new_home/strongswan.conf" "$new_home/owner-uid" "$new_home/allowed-hosts" "$new_home/installed-from"
"$new_home/powervpn-native-helper" verify-install "$new_home" || fail "unsafe runtime tree"

if launchctl print "system/$LABEL" >/dev/null 2>&1; then
	launchctl bootout "system/$LABEL" || fail "could not stop existing helper"
	sleep 1
fi
rm -rf "$HOME_DIR"
mv "$new_home" "$HOME_DIR"

# A previous installation may have handed this socket to the user. The new
# daemon creates it root-only; do not leave an old endpoint at activation.
if [ -e "$RUN_DIR" ]; then
	[ -d "$RUN_DIR" ] && [ ! -L "$RUN_DIR" ] || fail "unsafe runtime directory"
	[ "$(stat -f %u "$RUN_DIR")" = 0 ] || fail "runtime directory not root-owned"
	chmod -N "$RUN_DIR"
	chmod 755 "$RUN_DIR"
	rm -f "$RUN_DIR/charon.vici" "$RUN_DIR/vici.sock" "$RUN_DIR/control.sock"
fi

plist_stage=$(mktemp /Library/LaunchDaemons/.powervpn-native.XXXXXXXX)
cat > "$plist_stage" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$HOME_DIR/powervpn-native-helper</string><string>serve</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>Umask</key><integer>63</integer>
  <key>StandardErrorPath</key><string>/var/log/powervpn-native-helper.log</string>
</dict>
</plist>
EOF
chown root:wheel "$plist_stage"
chmod -N "$plist_stage"
chmod 644 "$plist_stage"
mv -f "$plist_stage" "$PLIST"
launchctl bootstrap system "$PLIST"

for _ in $(seq 1 50); do
	[ -S "$RUN_DIR/control.sock" ] && [ -S "$RUN_DIR/vici.sock" ] && \
		[ "$(stat -f '%u:%Lp' "$RUN_DIR/private/charon.vici" 2>/dev/null || true)" = '0:600' ] && break
	sleep 0.2
done
[ -S "$RUN_DIR/control.sock" ] || fail "helper did not start; see /var/log/powervpn-native-helper.log"
[ -S "$RUN_DIR/private/charon.vici" ] || fail "charon did not start; see /var/log/powervpn-native-helper.log"
[ -S "$RUN_DIR/vici.sock" ] || fail "VICI broker did not start"
[ "$(stat -f '%u:%Lp' "$RUN_DIR/private/charon.vici")" = '0:600' ] || fail "unsafe charon socket"
# The sockets are up within a second, but a helper that dies later (its first
# reconcile runs after 5 s) would otherwise be reported as running.
helper_pid() { launchctl print "system/$LABEL" 2>/dev/null | awk '$1 == "pid" { print $3; exit }'; }
started=$(helper_pid)
sleep 6
[ -n "$started" ] && [ "$(helper_pid)" = "$started" ] || fail "helper exited after start; see /var/log/powervpn-native-helper.log"
echo "install: native backend running ($LABEL)"
