#!/bin/sh
# Remove the native backend installed by install.sh. Run with sudo.
set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
LABEL=com.hhh2210.powervpn-native
[ "$(id -u)" = 0 ] || { echo "uninstall: run with sudo" >&2; exit 1; }
# Stopping the helper deletes the host routes it owns and stops charon.
launchctl bootout "system/$LABEL" 2>/dev/null || true
# A charon left behind by a helper that crashed is not stopped by bootout.
# The installed helper identifies it by the path it was executed as (not
# argv[0]) and stops it. If that helper is missing, predates
# stop-stray-charon (exit 64) or fails, a live pid cannot be told apart from a
# reused one: then remove nothing while the pidfile names a live process, so
# the cleanup information survives for a later run.
helper="/Library/PrivilegedHelperTools/$LABEL/powervpn-native-helper"
pidfile=/var/run/powervpn-native/charon.pid
status=127
if [ -x "$helper" ]; then
	status=0
	"$helper" stop-stray-charon || status=$?
fi
if [ "$status" != 0 ] && [ -e "$pidfile" ]; then
	pid=$(cat "$pidfile" 2>/dev/null || true)
	case $pid in
	'' | *[!0-9]*) live=yes ;;
	*) if kill -0 "$pid" 2>/dev/null; then live=yes; else live=no; fi ;;
	esac
	if [ "$live" = yes ]; then
		echo "uninstall: $pidfile names a process that may be charon; stop it (or remove the pidfile once it is gone) and rerun; nothing removed" >&2
		exit 1
	fi
fi
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -rf "/Library/PrivilegedHelperTools/$LABEL" /var/run/powervpn-native
echo "uninstall: removed $LABEL"
