#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
pvn_init_runtime_paths

mode=dry-run
authorized=false
threads=5

while [ "$#" -gt 0 ]; do
	case "$1" in
	--dry-run) mode=dry-run ;;
	--start) mode=start ;;
	--cp7a-unprivileged) authorized=true ;;
	--threads)
		shift
		[ "$#" -gt 0 ] || pvn_fail "--threads requires a value" || exit 2
		threads=$1
		;;
	*) pvn_fail "usage: $0 [--dry-run|--start --cp7a-unprivileged] [--threads 4|5|8]" || exit 2 ;;
	esac
	shift
done

case "$threads" in
4 | 5 | 8) ;;
*) pvn_fail "CP7A threads must be 4, 5, or 8" || exit 2 ;;
esac

[ -x "$PVN_BINARY" ] || pvn_fail "pinned CP7A charon binary is missing" || exit 1
[ "$(git -C "$PVN_SOURCE" rev-parse HEAD)" = "$PVN_EXPECTED_COMMIT" ] ||
	pvn_fail "CP7A source commit does not match the locked CP6 anchor" || exit 1
"$repo_root/scripts/build_strongswan.sh" --verify-cp7a-runtime >/dev/null

if [ "$mode" = dry-run ]; then
	printf '%s\n' \
		"mode=dry-run" \
		"binary=$PVN_BINARY" \
		"binary_sha256=$(pvn_sha256_file "$PVN_BINARY")" \
		"source_commit=$PVN_EXPECTED_COMMIT" \
		"runtime_root=$PVN_RUNTIME_ROOT" \
		"threads=$threads" \
		"ports=ephemeral" \
		"backend=fake-kernel" \
		"server_traffic=forbidden"
	exit 0
fi

[ "$authorized" = true ] || pvn_fail "--start requires --cp7a-unprivileged" || exit 2
[ "$(id -u)" -ne 0 ] || pvn_fail "CP7A daemon must not run as root" || exit 1
[ ! -e "$PVN_STATE_FILE" ] || pvn_fail "a CP7A runtime state already exists" || exit 1
[ ! -e "$PVN_PID_FILE" ] || pvn_fail "a CP7A charon PID file already exists" || exit 1

umask 077
mkdir -p "$PVN_RUNTIME_ROOT"
chmod 700 "$PVN_RUNTIME_ROOT"
PVN_RUNTIME_ROOT=$(pvn_canonical_existing_dir "$PVN_RUNTIME_ROOT")
PVN_STATE_FILE="$PVN_RUNTIME_ROOT/current.state"
PVN_PID_FILE="$PVN_RUNTIME_ROOT/charon.pid"
generation="$(date -u '+%Y%m%dT%H%M%SZ').$$"
run_dir="$PVN_RUNTIME_ROOT/generation-$generation"
mkdir "$run_dir"
chmod 700 "$run_dir"
config_path="$run_dir/strongswan.conf"
log_path="$run_dir/charon.log"
socket_path="$PVN_RUNTIME_ROOT/charon.vici"
pvn_validate_unix_socket_path "$socket_path"
[ ! -e "$socket_path" ] || pvn_fail "owned VICI socket path already exists" || exit 1

{
	printf '%s\n' \
		'charon {' \
		'    load_modular = no' \
		'    load = openssl nonce hmac kdf drbg kernel-pfroute load-tester socket-default vici' \
		"    threads = $threads" \
		'    port = 0' \
		'    port_nat_t = 0' \
		'    interfaces_use = lo0' \
		'    plugins {' \
		'        load-tester {' \
		'            enable = yes' \
		'            fake_kernel = yes' \
		'            initiators = 0' \
		'            iterations = 0' \
		'            shutdown_when_complete = no' \
		'            socket = unix:///dev/null/cp7a-disabled.ldt' \
		'        }' \
		'        socket-default {' \
		'            use_ipv4 = yes' \
		'            use_ipv6 = no' \
		'            set_source = no' \
		'            set_sourceif = no' \
		'        }' \
		'        vici {' \
		"            socket = unix://$socket_path" \
		'        }' \
		'    }' \
		'}'
} >"$config_path"
chmod 600 "$config_path"
: >"$log_path"
chmod 600 "$log_path"

daemon_pid=
cleanup_failed_start() {
	if [ -n "$daemon_pid" ] && ! pvn_stop_spawned_child "$daemon_pid"; then
		owner_file="$run_dir/failed-start.owner"
		{
			printf '%s\n' \
				"pid=$daemon_pid" \
				"executable=$PVN_BINARY" \
				"executable_sha256=$(pvn_sha256_file "$PVN_BINARY")" \
				"process_start_sha256=$(pvn_process_start_sha256 "$daemon_pid")" \
				"socket_path=$socket_path" \
				"config_path=$config_path" \
				"log_path=$log_path"
		} >"$owner_file"
		chmod 600 "$owner_file"
		echo "error: failed-start daemon did not terminate; ownership evidence preserved at $owner_file" >&2
		return 1
	fi
	pvn_safe_remove_file "$socket_path" || true
	pvn_safe_remove_file "$PVN_PID_FILE" || true
	pvn_safe_remove_file "$PVN_STATE_FILE" || true
	pvn_safe_remove_file "$config_path" || true
	pvn_safe_remove_file "$log_path" || true
	rmdir "$run_dir" 2>/dev/null || true
}
trap cleanup_failed_start HUP INT TERM EXIT

nohup env STRONGSWAN_CONF="$config_path" "$PVN_BINARY" \
	--debug-dmn 2 --debug-cfg 2 --debug-knl 2 --debug-net 2 \
	</dev/null >"$log_path" 2>&1 &
daemon_pid=$!

ready=false
attempt=0
while [ "$attempt" -lt 30 ]; do
	if ! kill -0 "$daemon_pid" 2>/dev/null; then
		pvn_fail "charon exited before creating the owned VICI socket" || exit 1
	fi
	if [ -S "$socket_path" ] && lsof -a -p "$daemon_pid" -U 2>/dev/null |
		grep -Fq -- "$socket_path"
	then
		ready=true
		break
	fi
	attempt=$((attempt + 1))
	sleep 0.1
done
[ "$ready" = true ] || pvn_fail "charon VICI socket readiness timed out" || exit 1
chmod 600 "$socket_path"
[ -f "$PVN_PID_FILE" ] || pvn_fail "charon did not create its compiled PID file" || exit 1
chmod 600 "$PVN_PID_FILE"

binary_sha=$(pvn_sha256_file "$PVN_BINARY")
start_sha=$(pvn_process_start_sha256 "$daemon_pid")
socket_inode=$(stat -f '%i' "$socket_path")
{
	printf '%s\n' \
		'schema=1' \
		"generation=$generation" \
		"pid=$daemon_pid" \
		"executable=$PVN_BINARY" \
		"executable_sha256=$binary_sha" \
		"process_start_sha256=$start_sha" \
		"socket_path=$socket_path" \
		"socket_inode=$socket_inode" \
		"config_path=$config_path" \
		"log_path=$log_path" \
		"threads=$threads"
} >"$PVN_STATE_FILE"
chmod 600 "$PVN_STATE_FILE"

trap - HUP INT TERM EXIT
printf '%s\n' \
	"generation=$generation" \
	"pid=$daemon_pid" \
	"socket_path=$socket_path" \
	"socket_inode=$socket_inode" \
	"threads=$threads" \
	"binary_sha256=$binary_sha"
