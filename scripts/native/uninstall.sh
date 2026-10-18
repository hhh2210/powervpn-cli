#!/bin/sh
# Remove the native backend installed by install.sh. Run with sudo.
set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
LABEL=com.hhh2210.powervpn-native
[ "$(id -u)" = 0 ] || { echo "uninstall: run with sudo" >&2; exit 1; }
# Stopping the helper deletes the host routes it owns and stops charon.
launchctl bootout "system/$LABEL" 2>/dev/null || true
# A charon left behind by a helper that crashed is not stopped by bootout.
# It is pinned by uid, start time and the path it was executed as, and each
# signal goes out only while the pid still names that process.
charon_identity() { ps -o uid=,lstart=,comm= -p "$1" 2>/dev/null | sed 's/^ *//'; }
pid=$(cat /var/run/powervpn-native/charon.pid 2>/dev/null || true)
case $pid in
'' | *[!0-9]*) ;;
*)
	identity=$(charon_identity "$pid")
	case $identity in
	"0 "*" /Library/PrivilegedHelperTools/$LABEL/runtime/libexec/ipsec/charon")
		for signal in TERM KILL; do
			[ "$(charon_identity "$pid")" = "$identity" ] || break
			kill -s "$signal" "$pid" 2>/dev/null || true
			for _ in $(seq 1 50); do
				[ "$(charon_identity "$pid")" = "$identity" ] || break
				sleep 0.1
			done
		done
		[ "$(charon_identity "$pid")" != "$identity" ] || echo "uninstall: charon pid $pid did not exit" >&2
		;;
	esac
	;;
esac
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -rf "/Library/PrivilegedHelperTools/$LABEL" /var/run/powervpn-native
echo "uninstall: removed $LABEL"
