#!/bin/sh

pvn_fail() {
	echo "error: $*" >&2
	return 1
}

pvn_init_runtime_paths() {
	PVN_SCRATCH_ROOT=${POWERVPN_STRONGSWAN_ROOT:-"$HOME/scratch-data/powervpn-strongswan"}
	PVN_PREFIX="$PVN_SCRATCH_ROOT/install-6.0.7-cp7a-arm64"
	PVN_SOURCE="$PVN_SCRATCH_ROOT/strongswan-6.0.7-expandrule"
	PVN_BINARY="$PVN_PREFIX/libexec/ipsec/charon"
	PVN_PYTHON_ROOT="$PVN_SOURCE/src/libcharon/plugins/vici/python"
	PVN_EXPECTED_COMMIT=67c9810900e2d8486cb3b11495a8362433494ca0
	PVN_RUNTIME_ROOT="$PVN_SCRATCH_ROOT/runtime-6.0.7-cp7a"
	if [ "${POWERVPN_CP7A_TEST_MODE:-0}" = 1 ]; then
		PVN_RUNTIME_ROOT=${POWERVPN_CP7A_RUNTIME_ROOT:-"$PVN_RUNTIME_ROOT"}
	fi
	PVN_STATE_FILE="$PVN_RUNTIME_ROOT/current.state"
	PVN_PID_FILE="$PVN_RUNTIME_ROOT/charon.pid"
}

pvn_canonical_existing_dir() {
	[ -d "$1" ] || pvn_fail "directory does not exist: $1" || return 1
	[ ! -L "$1" ] || pvn_fail "directory must not be a symlink: $1" || return 1
	CDPATH='' cd -- "$1" && pwd -P
}

pvn_require_runtime_path() {
	case "$1" in
	"$PVN_RUNTIME_ROOT" | "$PVN_RUNTIME_ROOT"/*) ;;
	*) pvn_fail "path escapes the CP7A runtime root: $1" || return 1 ;;
	esac
}

pvn_validate_unix_socket_path() {
	path_bytes=$(LC_ALL=C printf '%s' "$1" | wc -c | tr -d ' ')
	[ "$path_bytes" -le 103 ] ||
		pvn_fail "Unix socket path exceeds the macOS 103-byte limit: $path_bytes" || return 1
}

pvn_sha256_file() {
	shasum -a 256 "$1" | awk '{print $1}'
}

pvn_process_start_sha256() {
	ps -p "$1" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//' | shasum -a 256 |
		awk '{print $1}'
}

pvn_process_command() {
	ps -p "$1" -o command= 2>/dev/null | sed 's/^[[:space:]]*//'
}

pvn_state_value() {
	key=$1
	file=${2:-"$PVN_STATE_FILE"}
	awk -F= -v key="$key" '$1 == key { count++; value = substr($0, length(key) + 2) }
		END { if (count == 1) print value; else exit 1 }' "$file"
}

pvn_validate_state_file() {
	file=${1:-"$PVN_STATE_FILE"}
	[ -f "$file" ] || pvn_fail "runtime state file is missing: $file" || return 1
	[ ! -L "$file" ] || pvn_fail "runtime state file must not be a symlink" || return 1
	[ "$(stat -f '%u' "$file")" = "$(id -u)" ] ||
		pvn_fail "runtime state file has the wrong owner" || return 1
	[ "$(stat -f '%Lp' "$file")" = 600 ] ||
		pvn_fail "runtime state file mode must be 600" || return 1
	awk -F= '
		NF != 2 { bad = 1 }
		$1 !~ /^(schema|generation|pid|executable|executable_sha256|process_start_sha256|socket_path|socket_inode|config_path|log_path|threads)$/ { bad = 1 }
		seen[$1]++ { bad = 1 }
		END { exit (bad || length(seen) != 11) }
	' "$file" || pvn_fail "runtime state schema is invalid" || return 1
	[ "$(pvn_state_value schema "$file")" = 1 ] ||
		pvn_fail "runtime state schema version is unsupported" || return 1
}

pvn_verify_owned_process() {
	pvn_validate_state_file || return 1
	pid=$(pvn_state_value pid)
	case "$pid" in
	'' | *[!0-9]*) pvn_fail "runtime PID is invalid" || return 1 ;;
	esac
	kill -0 "$pid" 2>/dev/null || pvn_fail "runtime PID is stale: $pid" || return 1
	executable=$(pvn_state_value executable)
	[ "$executable" = "$PVN_BINARY" ] ||
		pvn_fail "runtime executable path does not match the pinned CP7A binary" || return 1
	[ "$(pvn_sha256_file "$PVN_BINARY")" = "$(pvn_state_value executable_sha256)" ] ||
		pvn_fail "runtime executable hash does not match" || return 1
	case "$(pvn_process_command "$pid")" in
	"$PVN_BINARY" | "$PVN_BINARY "*) ;;
	*) pvn_fail "PID $pid is not the recorded charon executable" || return 1 ;;
	esac
	[ "$(pvn_process_start_sha256 "$pid")" = "$(pvn_state_value process_start_sha256)" ] ||
		pvn_fail "PID $pid start identity does not match" || return 1
	socket_path=$(pvn_state_value socket_path)
	pvn_require_runtime_path "$socket_path" || return 1
	[ -S "$socket_path" ] || pvn_fail "recorded VICI socket is missing" || return 1
	[ "$(stat -f '%i' "$socket_path")" = "$(pvn_state_value socket_inode)" ] ||
		pvn_fail "VICI socket inode does not match" || return 1
	lsof -a -p "$pid" -U 2>/dev/null | grep -Fq -- "$socket_path" ||
		pvn_fail "VICI socket is not owned by the recorded PID" || return 1
	PVN_OWNED_PID=$pid
	PVN_OWNED_SOCKET=$socket_path
	export PVN_OWNED_PID PVN_OWNED_SOCKET
}

pvn_safe_remove_file() {
	path=$1
	pvn_require_runtime_path "$path" || return 1
	[ ! -L "$path" ] || pvn_fail "refusing to remove symlink: $path" || return 1
	if [ -e "$path" ] || [ -S "$path" ]; then
		rm -f -- "$path"
	fi
}

pvn_wait_for_spawned_child() {
	pid=$1
	attempts=$2
	attempt=0
	while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt "$attempts" ]; do
		case "$(ps -p "$pid" -o stat= 2>/dev/null | tr -d ' ')" in
		*Z*)
			wait "$pid" 2>/dev/null || true
			return 0
			;;
		esac
		attempt=$((attempt + 1))
		sleep 0.1
	done
	if ! kill -0 "$pid" 2>/dev/null; then
		wait "$pid" 2>/dev/null || true
		return 0
	fi
	return 1
}

pvn_stop_spawned_child() {
	pid=$1
	int_attempts=${2:-30}
	term_attempts=${3:-20}
	kill_attempts=${4:-10}
	if ! kill -0 "$pid" 2>/dev/null; then
		wait "$pid" 2>/dev/null || true
		return 0
	fi
	kill -INT "$pid" 2>/dev/null || true
	pvn_wait_for_spawned_child "$pid" "$int_attempts" && return 0
	kill -TERM "$pid" 2>/dev/null || true
	pvn_wait_for_spawned_child "$pid" "$term_attempts" && return 0
	kill -KILL "$pid" 2>/dev/null || true
	pvn_wait_for_spawned_child "$pid" "$kill_attempts"
}
