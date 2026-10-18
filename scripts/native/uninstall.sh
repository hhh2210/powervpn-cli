#!/bin/sh
# Remove the native backend installed by install.sh. Run with sudo.
set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
LABEL=com.hhh2210.powervpn-native
[ "$(id -u)" = 0 ] || { echo "uninstall: run with sudo" >&2; exit 1; }
# Stopping the helper deletes the host routes it owns and stops charon.
launchctl bootout "system/$LABEL" 2>/dev/null || true
# A charon left behind by a helper that crashed is not stopped by bootout.
pid=$(cat /var/run/powervpn-native/charon.pid 2>/dev/null || true)
case $pid in
'' | *[!0-9]*) ;;
*)
	if [ "$(ps -o uid= -p "$pid" | tr -d ' ')" = 0 ] && ps -o comm= -p "$pid" | grep -q '/charon$'; then
		kill "$pid" 2>/dev/null || true
		for _ in $(seq 1 50); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.1
		done
		kill -9 "$pid" 2>/dev/null || true
	fi
	;;
esac
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -rf "/Library/PrivilegedHelperTools/$LABEL" /var/run/powervpn-native
echo "uninstall: removed $LABEL"
