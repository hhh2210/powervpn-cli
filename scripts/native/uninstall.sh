#!/bin/sh
# Remove the native backend installed by install.sh. Run with sudo.
set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
LABEL=com.hhh2210.powervpn-native
[ "$(id -u)" = 0 ] || { echo "uninstall: run with sudo" >&2; exit 1; }
# Stopping the helper deletes the host routes it owns and stops charon.
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -rf "/Library/PrivilegedHelperTools/$LABEL" /var/run/powervpn-native
echo "uninstall: removed $LABEL"
