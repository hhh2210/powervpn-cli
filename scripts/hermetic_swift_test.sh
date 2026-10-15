#!/bin/sh

# Runs `swift test` with this machine's real PowerVPN state, config, and
# vendor data made inaccessible. A test that falls through to a production
# default (for example ProductMutationLease.acquireCurrentMachine) then fails
# deterministically instead of locking, reading, or racing a live session.
# Arguments are passed through to `swift test`.

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

# Foundation resolves the home directory from the user database, not $HOME.
home=$(id -P | cut -d: -f9)
if [ -z "$home" ] || [ ! -d "$home" ]; then
	echo "error: cannot resolve the user database home directory" >&2
	exit 1
fi
home=$(CDPATH='' cd -- "$home" && pwd -P)

profile="(version 1)
(allow default)
(deny file* (subpath \"$home/.local/state/powervpn\"))
(deny file* (subpath \"$home/.config/powervpn\"))
(deny file* (subpath \"$home/Library/Application Support/com.leadsec.PowerVPN-Mac\"))"

# SwiftPM's own manifest sandbox cannot nest inside sandbox-exec.
exec sandbox-exec -p "$profile" swift test --disable-sandbox "$@"
