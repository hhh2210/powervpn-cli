#!/bin/sh
# Remove the native backend installed by install.sh. Run with sudo.
set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
LABEL=com.hhh2210.powervpn-native
[ "$(id -u)" = 0 ] || { echo "uninstall: run with sudo" >&2; exit 1; }
# Stopping the helper deletes the host routes it owns and stops charon.
launchctl bootout "system/$LABEL" 2>/dev/null || true
# A charon left behind by a helper that crashed is not stopped by bootout.
# The helper identifies it by the path it was executed as (not argv[0]); if it
# cannot be stopped, nothing is removed, so a later run can retry.
helper="/Library/PrivilegedHelperTools/$LABEL/powervpn-native-helper"
if [ -x "$helper" ]; then
	"$helper" stop-stray-charon || {
		echo "uninstall: a charon is still running; nothing removed" >&2
		exit 1
	}
elif [ -e /var/run/powervpn-native/charon.pid ]; then
	echo "uninstall: helper missing; a charon named in /var/run/powervpn-native/charon.pid may still run" >&2
fi
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -rf "/Library/PrivilegedHelperTools/$LABEL" /var/run/powervpn-native
echo "uninstall: removed $LABEL"
