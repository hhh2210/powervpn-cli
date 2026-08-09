#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
. "$repo_root/scripts/lib/route_snapshot.sh"
. "$repo_root/scripts/lib/network_snapshot.sh"
. "$repo_root/scripts/lib/cp7b_runtime.sh"
. "$repo_root/scripts/lib/cp7b_closure.sh"
. "$repo_root/scripts/lib/cp7b_state.sh"
. "$repo_root/scripts/lib/cp7b_attempts.sh"
. "$repo_root/scripts/lib/cp7b_snapshot.sh"

expect_failure() {
	if "$@" >/dev/null 2>&1; then
		pvn_fail "command unexpectedly succeeded: $*" || exit 1
	fi
}

test_root="$HOME/scratch-data/powervpn-strongswan/cp7b-preflight-tests.$$"
mkdir "$test_root"
chmod 700 "$test_root"
export POWERVPN_CP7B_TEST_MODE=1
export POWERVPN_CP7B_RUNTIME_ROOT="$test_root"
pvn_cp7b_init_paths "$repo_root"

cleanup() {
	[ -z "${harness_pid:-}" ] || kill -TERM "$harness_pid" 2>/dev/null || true
	[ -z "${harness_pid:-}" ] || wait "$harness_pid" 2>/dev/null || true
	[ -z "${direct_pid:-}" ] || kill -TERM "$direct_pid" 2>/dev/null || true
	[ -z "${direct_pid:-}" ] || wait "$direct_pid" 2>/dev/null || true
	[ -z "${test_pid:-}" ] || kill "$test_pid" 2>/dev/null || true
	[ -z "${test_pid:-}" ] || wait "$test_pid" 2>/dev/null || true
	[ -z "${deadline_guard_pid:-}" ] || kill -TERM "$deadline_guard_pid" 2>/dev/null || true
	[ -z "${deadline_test_child_pid:-}" ] || kill -TERM "$deadline_test_child_pid" 2>/dev/null || true
	for file in "$test_root/current.state" "$test_root/charon.pid" \
		"$test_root/pfkey-attempt-ledger" "$test_root/emergency-stop" \
		"$test_root/authorizer.scpt" "$test_root/vici-failure.json" \
		"$test_root/gated-launcher-test" "$test_root/direct.gate" \
		"$test_root/direct.handshake"; do
		[ ! -e "$file" ] && [ ! -L "$file" ] || rm -f -- "$file"
	done
	directory="$test_root/generation-test"
	if [ -d "$directory" ]; then
		for file in "$directory/strongswan.conf" "$directory/charon.log" \
			"$directory/launch.gate" "$directory/launch.handshake"; do
			[ ! -e "$file" ] || rm -f -- "$file"
		done
		rmdir "$directory" 2>/dev/null || true
	fi
	rmdir "$test_root" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

pvn_cp7b_verify_runtime_build
config="$test_root/config.rendered"
reviewed_socket="$PVN_CP7B_SCRATCH_ROOT/runtime-6.0.7-cp7b/charon.vici"
pvn_cp7b_render_config "$reviewed_socket" >"$config"
test "$(pvn_hash_stdin <"$config")" = 64fbae7626306419a08018234bbb6bf5040f954e8ff6d2622b2f9969ca96fa20
grep -Fq 'load = openssl! nonce! kernel-pfkey! kernel-pfroute! socket-dynamic! vici!' "$config"
grep -Fq 'install_routes = no' "$config"
grep -Fq 'install_virtual_ip = no' "$config"
grep -Fq 'initiator_only = yes' "$config"
if grep -Eq 'socket-default|kernel-libipsec|load-tester|keychain|files|sql' "$config"; then
	pvn_fail "CP7B config contains a forbidden plugin" || exit 1
fi
rm -f -- "$config"

case "$(jq -r '.review.state' "$PVN_CP7B_MANIFEST")" in
pending_integrated_preflight_review)
	expect_failure pvn_cp7b_verify_manifest
	;;
passed_integrated_preflight_review)
	cp7b_test_socket="$PVN_CP7B_SOCKET"
	PVN_CP7B_SOCKET="$reviewed_socket"
	pvn_cp7b_verify_manifest
	PVN_CP7B_SOCKET="$cp7b_test_socket"
	;;
*) pvn_fail "CP7B manifest review state is invalid" || exit 1 ;;
esac
PVN_CP7B_WINDOW_STARTED=$(date +%s)
export PVN_CP7B_WINDOW_STARTED
deadline_started=$PVN_CP7B_WINDOW_STARTED
pvn_cp7b_start_deadline_guard
deadline_guard_pid=$PVN_CP7B_DEADLINE_GUARD_PID
deadline_test_child_pid=
deadline_attempt=0
while [ -z "$deadline_test_child_pid" ] && [ "$deadline_attempt" -lt 20 ]; do
	deadline_test_child_pid=$(pgrep -P "$deadline_guard_pid" 2>/dev/null || true)
	deadline_attempt=$((deadline_attempt + 1))
	[ -n "$deadline_test_child_pid" ] || sleep 0.05
done
[ -n "$deadline_test_child_pid" ]
pvn_cp7b_stop_deadline_guard
[ $(($(date +%s) - deadline_started)) -le 2 ]
if kill -0 "$deadline_guard_pid" 2>/dev/null ||
	kill -0 "$deadline_test_child_pid" 2>/dev/null; then
	pvn_fail "CP7B deadline guard cleanup left a process" || exit 1
fi
deadline_guard_pid=
deadline_test_child_pid=
expect_failure "$repo_root/scripts/libexec/cp7b_root_entry.sh" \
	--run-reviewed 0000000000000000000000000000000000000000000000000000000000000000
expect_failure "$repo_root/scripts/libexec/cp7b_backend_window.sh" \
	--run-reviewed --manifest-sha256 0000000000000000000000000000000000000000000000000000000000000000
expect_failure "$repo_root/scripts/libexec/cp7b_emergency_stop.sh" --stop

/usr/bin/osacompile -o "$test_root/authorizer.scpt" \
	"$repo_root/scripts/libexec/authorize_cp7b.applescript"
test -f "$test_root/authorizer.scpt"

run_dir="$test_root/generation-test"
mkdir "$run_dir"
chmod 700 "$run_dir"
config_path="$run_dir/strongswan.conf"
log_path="$run_dir/charon.log"
emergency_path="$test_root/emergency-stop"
gate_path="$run_dir/launch.gate"
handshake_path="$run_dir/launch.handshake"
pvn_cp7b_render_config "$PVN_CP7B_SOCKET" >"$config_path"
: >"$log_path"
: >"$emergency_path"
chmod 600 "$config_path" "$log_path"
chmod 700 "$emergency_path"
mkfifo -m 600 "$gate_path"
config_sha=$(pvn_sha256_file "$config_path")
pvn_cp7b_write_state prepared test 1 0 \
	0000000000000000000000000000000000000000000000000000000000000000 \
	"$config_path" "$config_sha" "$log_path" 0 \
	0000000000000000000000000000000000000000000000000000000000000000 \
	"$emergency_path" "$gate_path" "$handshake_path"
pvn_cp7b_validate_state

rm -f -- "$PVN_CP7B_STATE_FILE"
ln -s /dev/null "$PVN_CP7B_STATE_FILE"
expect_failure pvn_cp7b_validate_state
rm -f -- "$PVN_CP7B_STATE_FILE"

/bin/sleep 30 &
test_pid=$!
start_sha=$(pvn_process_start_sha256 "$test_pid")
pvn_cp7b_write_state starting test 1 "$test_pid" "$start_sha" \
	"$config_path" "$config_sha" "$log_path" 0 \
	0000000000000000000000000000000000000000000000000000000000000000 \
	"$emergency_path" "$gate_path" "$handshake_path"
expect_failure pvn_cp7b_verify_state_process
kill "$test_pid"
wait "$test_pid" 2>/dev/null || true
test_pid=
rm -f -- "$PVN_CP7B_STATE_FILE"

now=$(date +%s)
pvn_cp7b_begin_attempt "$now"
test "$PVN_CP7B_ATTEMPT" -eq 1
pvn_cp7b_begin_attempt "$now"
test "$PVN_CP7B_ATTEMPT" -eq 2
expect_failure pvn_cp7b_begin_attempt "$now"

# Exercise the exact spawn-before-starting-state interruption: the state remains
# prepared while the real C launcher is alive behind its FIFO. TERM of the
# supervising harness must drive emergency recovery through the handshake.
rm -f -- "$PVN_CP7B_LEDGER" "$PVN_CP7B_STATE_FILE" "$emergency_path"
test_launcher="$test_root/gated-launcher-test"
clang -arch arm64 -std=c11 -Wall -Wextra -Werror \
	"$repo_root/scripts/libexec/cp7b_gated_launcher.c" -o "$test_launcher"
chmod 700 "$test_launcher"
direct_gate="$test_root/direct.gate"
direct_handshake="$test_root/direct.handshake"
mkfifo -m 600 "$direct_gate"
"$test_launcher" -- "$direct_gate" "$direct_handshake" /bin/sleep 30 \
	</dev/null >/dev/null 2>&1 &
direct_pid=$!
direct_start_sha=$(pvn_process_start_sha256 "$direct_pid")
attempt=0
while [ ! -e "$direct_handshake" ] && [ "$attempt" -lt 40 ]; do
	attempt=$((attempt + 1))
	sleep 0.05
done
test "$(awk -F= '$1 == "pid" { print $2 }' "$direct_handshake")" -eq "$direct_pid"
printf G >"$direct_gate"
attempt=0
while [ "$(pvn_process_command "$direct_pid")" != '/bin/sleep 30' ] && [ "$attempt" -lt 40 ]; do
	attempt=$((attempt + 1))
	sleep 0.05
done
test "$(pvn_process_command "$direct_pid")" = '/bin/sleep 30'
test "$(pvn_process_start_sha256 "$direct_pid")" = "$direct_start_sha"
kill -TERM "$direct_pid"
wait "$direct_pid" 2>/dev/null || true
direct_pid=
rm -f -- "$direct_gate" "$direct_handshake"
cp "$repo_root/scripts/libexec/cp7b_emergency_stop.sh" "$emergency_path"
chmod 700 "$emergency_path"
original_binary=$PVN_CP7B_BINARY
original_launcher=$PVN_CP7B_LAUNCHER
PVN_CP7B_BINARY=/bin/sleep
PVN_CP7B_LAUNCHER=$test_launcher
export PVN_CP7B_BINARY PVN_CP7B_LAUNCHER
pvn_cp7b_write_state prepared test 1 0 \
	0000000000000000000000000000000000000000000000000000000000000000 \
	"$config_path" "$config_sha" "$log_path" 0 \
	0000000000000000000000000000000000000000000000000000000000000000 \
	"$emergency_path" "$gate_path" "$handshake_path"
(
	injected_launcher_pid=
	# shellcheck disable=SC2329
	on_injected_term() {
		trap - TERM
		POWERVPN_CP7B_TEST_RUNTIME_ROOT="$test_root" \
			POWERVPN_CP7B_TEST_BINARY="$PVN_CP7B_BINARY" \
			POWERVPN_CP7B_TEST_LAUNCHER="$PVN_CP7B_LAUNCHER" \
			"$emergency_path" --stop-preserve-ledger >/dev/null
		[ -z "$injected_launcher_pid" ] || wait "$injected_launcher_pid" 2>/dev/null || true
		exit 143
	}
	trap on_injected_term TERM
	env -i PATH=/usr/bin:/bin HOME="$HOME" "$PVN_CP7B_LAUNCHER" -- \
		"$gate_path" "$handshake_path" "$PVN_CP7B_BINARY" \
		--debug-dmn 2 --debug-cfg 1 --debug-knl 1 --debug-net 2 \
		</dev/null >"$log_path" 2>&1 &
	injected_launcher_pid=$!
	while [ ! -e "$handshake_path" ]; do sleep 0.05; done
	while :; do sleep 0.1; done
) 2>/dev/null &
harness_pid=$!
attempt=0
while [ ! -e "$handshake_path" ] && [ "$attempt" -lt 40 ]; do
	attempt=$((attempt + 1))
	sleep 0.05
done
test -e "$handshake_path"
injected_pid=$(pvn_cp7b_handshake_pid "$handshake_path")
test "$(pvn_cp7b_state_value phase)" = prepared
test "$(pvn_cp7b_state_value pid)" -eq 0
kill -TERM "$harness_pid"
if wait "$harness_pid" 2>/dev/null; then
	pvn_fail "injected TERM harness unexpectedly exited successfully" || exit 1
fi
if kill -0 "$injected_pid" 2>/dev/null; then
	pvn_fail "spawn-before-state injection left its launcher alive" || exit 1
fi
for residue in "$PVN_CP7B_STATE_FILE" "$emergency_path" "$config_path" \
	"$log_path" "$gate_path" "$handshake_path"; do
	[ ! -e "$residue" ] && [ ! -L "$residue" ] ||
		pvn_fail "spawn-before-state injection left residue: $residue" || exit 1
done
[ ! -d "$run_dir" ] || pvn_fail "spawn-before-state injection left its generation" || exit 1
PVN_CP7B_BINARY=$original_binary
PVN_CP7B_LAUNCHER=$original_launcher
export PVN_CP7B_BINARY PVN_CP7B_LAUNCHER
rm -f -- "$PVN_CP7B_LEDGER"
{
	printf '%s\n' 'schema=1' 'backend=pfkey-pfroute' \
		"window_started_epoch=$((now - 301))" 'attempts=1'
} >"$PVN_CP7B_LEDGER"
chmod 600 "$PVN_CP7B_LEDGER"
expect_failure pvn_cp7b_begin_attempt "$now"

if rg -n -- '--initiate|--load-|setkey[[:space:]]+-(F|PF)|socket-default|kernel-libipsec|load-tester' \
	"$repo_root/scripts/libexec/cp7b_backend_window.sh"; then
	pvn_fail "CP7B reviewed worker contains a forbidden action" || exit 1
fi
if rg -n 'session\.(load_|unload_|initiate|terminate|install|rekey|redirect)' \
	"$repo_root/scripts/libexec/cp7b_vici_readonly.py"; then
	pvn_fail "CP7B VICI inventory helper contains a mutating command" || exit 1
fi
grep -Fq 'socket.socket(socket.AF_UNIX' \
	"$repo_root/scripts/libexec/cp7b_vici_readonly.py"
if grep -Fq 'PVN_CP7B_SWANCTL' "$repo_root/scripts/libexec/cp7b_backend_window.sh"; then
	pvn_fail "CP7B root worker must not execute user-prefix swanctl" || exit 1
fi
if PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 \
	"$repo_root/scripts/libexec/cp7b_vici_readonly.py" \
	--socket "$test_root/missing.vici" --python-root "$PVN_CP7B_PYTHON_ROOT" \
	--oracle-root "$repo_root/scripts/verify" --timeout-ms 100 \
	>"$test_root/vici-failure.json"; then
	pvn_fail "CP7B VICI helper unexpectedly connected to a missing socket" || exit 1
fi
jq -e 'keys == ["containsRawState","containsSecrets","errorClass","errorCode",
  "schemaVersion","success"] and .success == false and .containsSecrets == false and
  .containsRawState == false and .errorCode == "cp7b_read_only_probe_failed"' \
	"$test_root/vici-failure.json" >/dev/null
grep -Fq '/usr/sbin/setkey -D' "$repo_root/scripts/lib/network_snapshot.sh"
grep -Fq '/usr/sbin/setkey -DP' "$repo_root/scripts/lib/network_snapshot.sh"
if grep -Fq 'setkey_output=' "$repo_root/scripts/lib/network_snapshot.sh"; then
	pvn_fail "CP7B snapshot retains raw SAD output in a shell variable" || exit 1
fi

rm -f -- "$PVN_CP7B_STATE_FILE" "$PVN_CP7B_LEDGER" "$emergency_path" \
	"$config_path" "$log_path" "$test_root/authorizer.scpt" \
	"$test_root/vici-failure.json" "$test_launcher"
[ ! -d "$run_dir" ] || rmdir "$run_dir"
trap - EXIT HUP INT TERM
rmdir "$test_root"
printf '%s\n' 'PASS: CP7B preflight negative tests (no root or daemon launch)'
