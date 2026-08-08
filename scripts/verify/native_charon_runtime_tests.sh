#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
pvn_init_runtime_paths

expect_failure() {
	if "$@" >/dev/null 2>&1; then
		pvn_fail "command unexpectedly succeeded: $*" || exit 1
	fi
}

expect_failure "$repo_root/scripts/run_native_charon.sh" --start --threads 5
expect_failure "$repo_root/scripts/run_native_charon.sh" --dry-run --threads 3

bin_path=$(swift build --show-bin-path --arch arm64)
expect_failure "$bin_path/powervpn" vici version \
	--socket /tmp/powervpn-cp7a-definitely-missing.vici --timeout-ms 20 --json

overlong="/$(
	awk 'BEGIN { for (i = 0; i < 140; i++) printf "a" }'
)"
expect_failure pvn_validate_unix_socket_path "$overlong"
expect_failure pvn_require_runtime_path /tmp/outside-cp7a-runtime

test_root="$PVN_SCRATCH_ROOT/cp7a-script-tests.$$"
mkdir "$test_root"
chmod 700 "$test_root"
export POWERVPN_CP7A_TEST_MODE=1
export POWERVPN_CP7A_RUNTIME_ROOT="$test_root"
pvn_init_runtime_paths

cleanup_test_root() {
	rm -f -- "$test_root/current.state" "$test_root/charon.pid" \
		"$test_root/state-link" "$test_root/charon.vici" \
		"$test_root/before.json" "$test_root/after.json" "$test_root/stubborn.ready"
	for directory in "$test_root/generation-wrong" "$test_root/generation-stale" \
		"$test_root/generation-orphan"; do
		rm -f -- "$directory/strongswan.conf" "$directory/charon.log" \
			"$directory/unexpected.residue"
		rmdir "$directory" 2>/dev/null || true
	done
	rmdir "$test_root" 2>/dev/null || true
}
trap cleanup_test_root EXIT HUP INT TERM

wrong_dir="$test_root/generation-wrong"
mkdir "$wrong_dir"
chmod 700 "$wrong_dir"
: >"$wrong_dir/strongswan.conf"
: >"$wrong_dir/charon.log"
chmod 600 "$wrong_dir/strongswan.conf" "$wrong_dir/charon.log"
{
	printf '%s\n' \
		'schema=1' \
		'generation=wrong' \
		"pid=$$" \
		'executable=/bin/false' \
		"executable_sha256=$(pvn_sha256_file "$PVN_BINARY")" \
		"process_start_sha256=$(pvn_process_start_sha256 $$)" \
		"socket_path=$test_root/missing.vici" \
		'socket_inode=0' \
		"config_path=$wrong_dir/strongswan.conf" \
		"log_path=$wrong_dir/charon.log" \
		'threads=5'
} >"$test_root/current.state"
chmod 600 "$test_root/current.state"
expect_failure pvn_verify_owned_process
rm -f "$test_root/current.state" "$wrong_dir/strongswan.conf" "$wrong_dir/charon.log"
rmdir "$wrong_dir"

ln -s /dev/null "$test_root/current.state"
expect_failure pvn_validate_state_file "$test_root/current.state"
rm -f "$test_root/current.state"

stale_dir="$test_root/generation-stale"
mkdir "$stale_dir"
chmod 700 "$stale_dir"
: >"$stale_dir/strongswan.conf"
: >"$stale_dir/charon.log"
chmod 600 "$stale_dir/strongswan.conf" "$stale_dir/charon.log"
stale_pid=999999
{
	printf '%s\n' \
		'schema=1' \
		'generation=stale' \
		"pid=$stale_pid" \
		"executable=$PVN_BINARY" \
		"executable_sha256=$(pvn_sha256_file "$PVN_BINARY")" \
		'process_start_sha256=0000000000000000000000000000000000000000000000000000000000000000' \
		"socket_path=$test_root/charon.vici" \
		'socket_inode=0' \
		"config_path=$stale_dir/strongswan.conf" \
		"log_path=$stale_dir/charon.log" \
		'threads=5'
} >"$test_root/current.state"
printf '%s\n' "$stale_pid" >"$test_root/charon.pid"
chmod 600 "$test_root/current.state" "$test_root/charon.pid"

printf '%s\n' 'preserve-me' >"$stale_dir/unexpected.residue"
expect_failure env POWERVPN_CP7A_TEST_MODE=1 POWERVPN_CP7A_RUNTIME_ROOT="$test_root" \
	"$repo_root/scripts/stop_native_charon.sh" --stop --cp7a-unprivileged
test -f "$test_root/current.state"
test -f "$stale_dir/unexpected.residue"
rm -f -- "$stale_dir/unexpected.residue"
POWERVPN_CP7A_TEST_MODE=1 POWERVPN_CP7A_RUNTIME_ROOT="$test_root" \
	"$repo_root/scripts/stop_native_charon.sh" --stop --cp7a-unprivileged >/dev/null
POWERVPN_CP7A_TEST_MODE=1 POWERVPN_CP7A_RUNTIME_ROOT="$test_root" \
	"$repo_root/scripts/stop_native_charon.sh" --stop --cp7a-unprivileged |
	grep -q '^already_stopped=true$'

POWERVPN_CP7A_TEST_MODE=1 POWERVPN_CP7A_RUNTIME_ROOT="$test_root" \
	"$repo_root/scripts/snapshot_network_state.sh" --output "$test_root/before.json" >/dev/null
/usr/bin/python3 -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.close()' \
	"$test_root/charon.vici"
POWERVPN_CP7A_TEST_MODE=1 POWERVPN_CP7A_RUNTIME_ROOT="$test_root" \
	"$repo_root/scripts/snapshot_network_state.sh" --output "$test_root/after.json" >/dev/null
jq -e '.ownedVICISocketPresent == true' "$test_root/after.json" >/dev/null
expect_failure env POWERVPN_CP7A_TEST_MODE=1 POWERVPN_CP7A_RUNTIME_ROOT="$test_root" \
	"$repo_root/scripts/assert_clean_teardown.sh" \
	--before "$test_root/before.json" --after "$test_root/after.json"
rm -f -- "$test_root/charon.vici" "$test_root/after.json"

mkdir "$test_root/generation-orphan"
chmod 700 "$test_root/generation-orphan"
POWERVPN_CP7A_TEST_MODE=1 POWERVPN_CP7A_RUNTIME_ROOT="$test_root" \
	"$repo_root/scripts/snapshot_network_state.sh" --output "$test_root/after.json" >/dev/null
jq -e '.generationDirectoryCount == 1' "$test_root/after.json" >/dev/null
expect_failure env POWERVPN_CP7A_TEST_MODE=1 POWERVPN_CP7A_RUNTIME_ROOT="$test_root" \
	"$repo_root/scripts/assert_clean_teardown.sh" \
	--before "$test_root/before.json" --after "$test_root/after.json"
rmdir "$test_root/generation-orphan"
rm -f -- "$test_root/before.json" "$test_root/after.json"

/usr/bin/python3 -c \
	'import signal, time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); print("ready", flush=True); time.sleep(60)' \
	>"$test_root/stubborn.ready" &
stubborn_pid=$!
attempt=0
while ! grep -q '^ready$' "$test_root/stubborn.ready" && [ "$attempt" -lt 20 ]; do
	attempt=$((attempt + 1))
	sleep 0.05
done
grep -q '^ready$' "$test_root/stubborn.ready"
pvn_stop_spawned_child "$stubborn_pid" 1 1 10
expect_failure kill -0 "$stubborn_pid"
rm -f -- "$test_root/stubborn.ready"

test -z "$(find "$test_root" -mindepth 1 -maxdepth 1 -print)"
trap - EXIT HUP INT TERM
rmdir "$test_root"
printf '%s\n' 'PASS: native charon lifecycle negative tests'
