#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
pvn_init_runtime_paths

mode=dry-run
authorized=false
while [ "$#" -gt 0 ]; do
	case "$1" in
	--dry-run) mode=dry-run ;;
	--stop) mode=stop ;;
	--cp7a-unprivileged) authorized=true ;;
	*) pvn_fail "usage: $0 [--dry-run|--stop --cp7a-unprivileged]" || exit 2 ;;
	esac
	shift
done

if [ "$mode" = dry-run ]; then
	printf '%s\n' \
		"mode=dry-run" \
		"state_file=$PVN_STATE_FILE" \
		"identity_checks=pid,executable_hash,start_time,socket_inode" \
		"signals=INT,TERM,KILL-bounded" \
		"cleanup=generation-owned-only"
	exit 0
fi

[ "$authorized" = true ] || pvn_fail "--stop requires --cp7a-unprivileged" || exit 2
if [ ! -e "$PVN_STATE_FILE" ]; then
	[ ! -e "$PVN_PID_FILE" ] ||
		pvn_fail "unowned charon PID file exists without runtime state" || exit 1
	printf '%s\n' 'already_stopped=true'
	exit 0
fi

pvn_validate_state_file
pid=$(pvn_state_value pid)
case "$pid" in
'' | *[!0-9]*) pvn_fail "runtime PID is invalid" || exit 1 ;;
esac
socket_path=$(pvn_state_value socket_path)
pvn_require_runtime_path "$socket_path"
stale_pid=false
if kill -0 "$pid" 2>/dev/null; then
	pvn_verify_owned_process
	pid=$PVN_OWNED_PID
	socket_path=$PVN_OWNED_SOCKET
else
	stale_pid=true
	[ "$(pvn_state_value executable)" = "$PVN_BINARY" ] ||
		pvn_fail "stale state executable path does not match the pinned binary" || exit 1
	[ "$(pvn_sha256_file "$PVN_BINARY")" = "$(pvn_state_value executable_sha256)" ] ||
		pvn_fail "stale state executable hash does not match" || exit 1
	if [ -S "$socket_path" ]; then
		[ "$(stat -f '%i' "$socket_path")" = "$(pvn_state_value socket_inode)" ] ||
			pvn_fail "stale VICI socket inode does not match" || exit 1
		if lsof -U 2>/dev/null | grep -Fq -- "$socket_path"; then
			pvn_fail "stale-state VICI socket is owned by another process" || exit 1
		fi
	fi
fi
config_path=$(pvn_state_value config_path)
log_path=$(pvn_state_value log_path)
generation=$(pvn_state_value generation)
run_dir="$PVN_RUNTIME_ROOT/generation-$generation"

for path in "$config_path" "$log_path" "$run_dir"; do
	pvn_require_runtime_path "$path"
done
[ "$config_path" = "$run_dir/strongswan.conf" ] || pvn_fail "config path is not canonical" || exit 1
[ "$log_path" = "$run_dir/charon.log" ] || pvn_fail "log path is not canonical" || exit 1
[ -d "$run_dir" ] && [ ! -L "$run_dir" ] || pvn_fail "generation directory is invalid" || exit 1

if [ "$stale_pid" = false ]; then
	kill -INT "$pid"
	attempt=0
	while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 30 ]; do
		attempt=$((attempt + 1))
		sleep 0.1
	done
	if kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid"
		attempt=0
		while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 20 ]; do
			attempt=$((attempt + 1))
			sleep 0.1
		done
	fi
	if kill -0 "$pid" 2>/dev/null; then
		kill -KILL "$pid"
		attempt=0
		while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 10 ]; do
			attempt=$((attempt + 1))
			sleep 0.1
		done
	fi
	kill -0 "$pid" 2>/dev/null && pvn_fail "owned charon process did not stop" && exit 1
fi

if [ -S "$socket_path" ]; then
	[ "$(stat -f '%i' "$socket_path")" = "$(pvn_state_value socket_inode)" ] ||
		pvn_fail "refusing to remove a replaced VICI socket" || exit 1
fi
pvn_safe_remove_file "$socket_path"
if [ -e "$PVN_PID_FILE" ]; then
	[ "$(sed -n '1p' "$PVN_PID_FILE")" = "$pid" ] ||
		pvn_fail "refusing to remove a mismatched charon PID file" || exit 1
fi
pvn_safe_remove_file "$PVN_PID_FILE"
pvn_safe_remove_file "$config_path"
pvn_safe_remove_file "$log_path"
rmdir "$run_dir"
pvn_safe_remove_file "$PVN_STATE_FILE"

printf '%s\n' \
	"stopped_pid=$pid" \
	"stale_pid_cleanup=$stale_pid" \
	"generation=$generation" \
	"residue=none"
