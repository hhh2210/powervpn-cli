#!/bin/sh
# Install (or upgrade) the native strongSwan backend. Run once with sudo:
#
#   scripts/native/build_runtime.sh
#   swift build -c release --product powervpn-native-helper --arch arm64
#   sudo scripts/native/install.sh
#
# It installs our own files only: the patched charon runtime and the helper
# under /Library/PrivilegedHelperTools/com.hhh2210.powervpn-native, and one
# LaunchDaemon. Nothing of the official PowerVPN client is touched.

set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

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
owner_home=$(dscl . -read "/Users/$(id -un "$owner_uid")" NFSHomeDirectory | awk '{print $2}')
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)

runtime=${POWERVPN_NATIVE_RUNTIME:-"$owner_home/.cache/powervpn-native/stage$HOME_DIR/runtime"}
helper=${POWERVPN_NATIVE_HELPER:-"$repo_root/.build/release/powervpn-native-helper"}
[ -x "$runtime/libexec/ipsec/charon" ] || fail "no runtime at $runtime (run scripts/native/build_runtime.sh first)"
[ -x "$helper" ] || fail "no helper at $helper (swift build -c release --product powervpn-native-helper)"
file "$runtime/libexec/ipsec/charon" | grep -q 'Mach-O 64-bit.*arm64' || fail "runtime is not arm64"
file "$helper" | grep -q 'Mach-O 64-bit.*arm64' || fail "helper is not arm64"

if launchctl print "system/$LABEL" >/dev/null 2>&1; then
	launchctl bootout "system/$LABEL" 2>/dev/null || true
	sleep 1
fi

mkdir -p "$HOME_DIR"
rm -rf "$HOME_DIR/runtime.new"
ditto "$runtime" "$HOME_DIR/runtime.new"
rm -rf "$HOME_DIR/runtime"
mv "$HOME_DIR/runtime.new" "$HOME_DIR/runtime"
install -m 755 "$helper" "$HOME_DIR/powervpn-native-helper"
printf '%s\n' "$owner_uid" > "$HOME_DIR/owner-uid"

cat > "$HOME_DIR/strongswan.conf" <<EOF
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
            socket = unix://$RUN_DIR/charon.vici
        }
    }
}
EOF

chown -R root:wheel "$HOME_DIR"
chmod -R go-w "$HOME_DIR"
chmod 755 "$HOME_DIR"
chmod 644 "$HOME_DIR/strongswan.conf" "$HOME_DIR/owner-uid"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$HOME_DIR/powervpn-native-helper</string><string>serve</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/powervpn-native-helper.log</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl bootstrap system "$PLIST"

for _ in $(seq 1 50); do
	[ -S "$RUN_DIR/control.sock" ] && [ -S "$RUN_DIR/charon.vici" ] && break
	sleep 0.2
done
[ -S "$RUN_DIR/control.sock" ] || fail "helper did not start; see /var/log/powervpn-native-helper.log"
[ -S "$RUN_DIR/charon.vici" ] || fail "charon did not start; see /var/log/powervpn-native-helper.log"
echo "install: native backend running ($LABEL)"
