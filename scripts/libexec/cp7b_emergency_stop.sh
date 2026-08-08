#!/bin/sh

set -eu

fail() {
	echo "error: $*" >&2
	exit 1
}

test_mode=${POWERVPN_CP7B_TEST_MODE:-0}
if [ "$test_mode" = 1 ]; then
	[ "$(/usr/bin/id -u)" -ne 0 ] || fail "CP7B emergency test mode is forbidden as root"
	runtime_root=${POWERVPN_CP7B_TEST_RUNTIME_ROOT:-}
	case "$runtime_root" in
	"$HOME/scratch-data/powervpn-strongswan/cp7b-preflight-tests."*) ;;
	*) fail "CP7B emergency test root is outside the scratch harness" ;;
	esac
	binary=${POWERVPN_CP7B_TEST_BINARY:-}
	launcher=${POWERVPN_CP7B_TEST_LAUNCHER:-}
	case "$binary:$launcher" in
	/*:/*) ;;
	*) fail "CP7B emergency test executables must be absolute" ;;
	esac
	expected_owner=$(/usr/bin/id -u)
else
	[ "$test_mode" = 0 ] || fail "CP7B emergency test mode is invalid"
	[ "$(/usr/bin/id -u)" -eq 0 ] || fail "CP7B emergency stop requires root"
	runtime_root=/Users/larry_1/scratch-data/powervpn-strongswan/runtime-6.0.7-cp7b
	binary="$runtime_root/closure/libexec/ipsec/charon"
	launcher="$runtime_root/closure/libexec/ipsec/cp7b-gated-launcher"
	expected_owner=0
fi

state_file="$runtime_root/current.state"
pid_file="$runtime_root/charon.pid"
socket_path="$runtime_root/charon.vici"
emergency_path="$runtime_root/emergency-stop"
attempt_ledger="$runtime_root/pfkey-attempt-ledger"
closure="$runtime_root/closure"

state_value() {
	key=$1
	/usr/bin/awk -F= -v key="$key" '$1 == key { count++; value = substr($0, length(key) + 2) }
		END { if (count == 1) print value; else exit 1 }' "$state_file"
}

sha256_file() {
	/usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

process_command() {
	/bin/ps -p "$1" -o command= 2>/dev/null | /usr/bin/sed 's/^[[:space:]]*//'
}

process_start_sha256() {
	/bin/ps -p "$1" -o lstart= 2>/dev/null | /usr/bin/sed 's/^[[:space:]]*//' |
		/usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'
}

launcher_command() {
	printf '%s -- %s %s %s --debug-dmn 2 --debug-cfg 1 --debug-knl 1 --debug-net 2\n' \
		"$launcher" "$gate_path" "$handshake_path" "$binary"
}

target_command() {
	printf '%s --debug-dmn 2 --debug-cfg 1 --debug-knl 1 --debug-net 2\n' "$binary"
}

handshake_pid() {
	[ -f "$handshake_path" ] && [ ! -L "$handshake_path" ] || return 1
	[ "$(/usr/bin/stat -f '%u' "$handshake_path")" -eq "$expected_owner" ] || return 1
	[ "$(/usr/bin/stat -f '%Lp' "$handshake_path")" = 600 ] || return 1
	/usr/bin/awk -F= '
		NF != 2 || $1 != "pid" || $2 !~ /^[1-9][0-9]*$/ { bad = 1 }
		seen++ { bad = 1 }
		{ pid = $2 }
		END { if (!bad && seen == 1) print pid; else exit 1 }
	' "$handshake_path"
}

process_owner_matches() {
	uid=$(/bin/ps -p "$1" -o uid= 2>/dev/null | /usr/bin/tr -d ' ')
	[ "$uid" = "$expected_owner" ]
}

process_command_allowed() {
	command=$(process_command "$1")
	case "$phase" in
	prepared) [ "$command" = "$(launcher_command)" ] ;;
	starting) [ "$command" = "$(launcher_command)" ] || [ "$command" = "$(target_command)" ] ;;
	ready) [ "$command" = "$(target_command)" ] ;;
	esac
}

find_prepared_process() {
	attempt=0
	while [ "$attempt" -lt 20 ]; do
		if [ -e "$handshake_path" ]; then
			candidate=$(handshake_pid) || fail "prepared CP7B handshake is invalid"
			if /bin/kill -0 "$candidate" 2>/dev/null; then
				if ! process_owner_matches "$candidate" || ! process_command_allowed "$candidate"; then
					fail "prepared CP7B handshake PID identity changed"
				fi
				printf '%s\n' "$candidate"
				return 0
			fi
		fi
		matches=$(/bin/ps -axo pid=,uid=,command= | /usr/bin/awk \
			-v owner="$expected_owner" -v expected="$(launcher_command)" '
			{ pid = $1; uid = $2; $1 = ""; $2 = ""; sub(/^[[:space:]]+/, "") }
			uid == owner && $0 == expected { print pid }
		')
		count=$(printf '%s\n' "$matches" | /usr/bin/awk 'NF { count++ } END { print count + 0 }')
		[ "$count" -le 1 ] || fail "multiple unrecorded CP7B launchers found"
		if [ "$count" -eq 1 ]; then
			printf '%s\n' "$matches"
			return 0
		fi
		attempt=$((attempt + 1))
		/bin/sleep 0.05
	done
	printf '%s\n' 0
}

original_process_alive() {
	/bin/kill -0 "$owned_pid" 2>/dev/null || return 1
	case "$(/bin/ps -p "$owned_pid" -o stat= 2>/dev/null | /usr/bin/tr -d ' ')" in
	*Z*) return 1 ;;
	esac
	process_owner_matches "$owned_pid" || return 1
	[ "$(process_start_sha256 "$owned_pid")" = "$owned_start_sha" ] || return 1
	process_command_allowed "$owned_pid"
}

wait_for_exit() {
	attempts=$1
	attempt=0
	while original_process_alive && [ "$attempt" -lt "$attempts" ]; do
		attempt=$((attempt + 1))
		/bin/sleep 0.1
	done
	! original_process_alive
}

stop_owned_process() {
	original_process_alive || return 0
	/bin/kill -INT "$owned_pid" 2>/dev/null || true
	wait_for_exit 30 && return 0
	original_process_alive || return 0
	/bin/kill -TERM "$owned_pid" 2>/dev/null || true
	wait_for_exit 20 && return 0
	original_process_alive || return 0
	/bin/kill -KILL "$owned_pid" 2>/dev/null || true
	wait_for_exit 10 || fail "CP7B process did not stop"
}

[ "$#" -eq 1 ] || fail "usage: $0 --stop|--stop-preserve-ledger"
case "$1" in
--stop) preserve_ledger=false ;;
--stop-preserve-ledger) preserve_ledger=true ;;
*) fail "usage: $0 --stop|--stop-preserve-ledger" ;;
esac
[ -d "$runtime_root" ] && [ ! -L "$runtime_root" ] || fail "CP7B runtime root is invalid"
[ "$(/usr/bin/stat -f '%u' "$runtime_root")" -eq "$expected_owner" ] ||
	fail "CP7B runtime root owner changed"
[ -f "$state_file" ] && [ ! -L "$state_file" ] || fail "CP7B state is missing or a symlink"
[ "$(/usr/bin/stat -f '%u' "$state_file")" -eq "$expected_owner" ] || fail "CP7B state owner changed"
[ "$(/usr/bin/stat -f '%Lp' "$state_file")" = 600 ] || fail "CP7B state mode changed"
/usr/bin/awk -F= '
	NF != 2 { bad = 1 }
	$1 !~ /^(schema|checkpoint|phase|backend|attempt|generation|pid|executable|executable_sha256|launcher_path|launcher_sha256|process_start_sha256|config_path|config_sha256|log_path|socket_path|socket_inode|manifest_sha256|emergency_stop_path|gate_path|handshake_path)$/ { bad = 1 }
	seen[$1]++ { bad = 1 }
	END { exit (bad || length(seen) != 21) }
' "$state_file" || fail "CP7B state schema is invalid"
[ "$(state_value schema)" = 3 ] || fail "CP7B state version is unsupported"
[ "$(state_value checkpoint)" = 7b ] || fail "CP7B checkpoint identity changed"
[ "$(state_value backend)" = pfkey-pfroute ] || fail "CP7B backend identity changed"
phase=$(state_value phase)
case "$phase" in prepared | starting | ready) ;; *) fail "CP7B state phase is invalid" ;; esac
[ "$(state_value executable)" = "$binary" ] || fail "CP7B binary path changed"
[ "$(sha256_file "$binary")" = "$(state_value executable_sha256)" ] || fail "CP7B binary hash changed"
[ "$(state_value launcher_path)" = "$launcher" ] || fail "CP7B launcher path changed"
[ "$(sha256_file "$launcher")" = "$(state_value launcher_sha256)" ] || fail "CP7B launcher hash changed"
[ "$(state_value socket_path)" = "$socket_path" ] || fail "CP7B socket path changed"
[ "$(state_value emergency_stop_path)" = "$emergency_path" ] || fail "CP7B emergency path changed"

generation=$(state_value generation)
case "$generation" in '' | *[!A-Za-z0-9._-]*) fail "CP7B generation is invalid" ;; esac
run_dir="$runtime_root/generation-$generation"
config_path=$(state_value config_path)
log_path=$(state_value log_path)
gate_path=$(state_value gate_path)
handshake_path=$(state_value handshake_path)
[ "$config_path" = "$run_dir/strongswan.conf" ] || fail "CP7B config path changed"
[ "$log_path" = "$run_dir/charon.log" ] || fail "CP7B log path changed"
[ "$gate_path" = "$run_dir/launch.gate" ] || fail "CP7B gate path changed"
[ "$handshake_path" = "$run_dir/launch.handshake" ] || fail "CP7B handshake path changed"
[ -d "$run_dir" ] && [ ! -L "$run_dir" ] || fail "CP7B generation directory is invalid"

pid=$(state_value pid)
case "$pid" in '' | *[!0-9]*) fail "CP7B PID is invalid" ;; esac
[ "$phase" = prepared ] || [ "$pid" -ne 0 ] || fail "active CP7B state has no PID"
[ "$phase" != prepared ] || [ "$pid" -eq 0 ] || fail "prepared CP7B state has a PID"
if [ "$pid" -eq 0 ]; then
	[ ! -e "$pid_file" ] || fail "prepared CP7B state has a PID file"
	owned_pid=$(find_prepared_process)
else
	owned_pid=$pid
fi
owned_start_sha=
if [ "$owned_pid" -ne 0 ] && /bin/kill -0 "$owned_pid" 2>/dev/null; then
	if ! process_owner_matches "$owned_pid" || ! process_command_allowed "$owned_pid"; then
		fail "CP7B process identity changed"
	fi
	owned_start_sha=$(process_start_sha256 "$owned_pid")
	if [ "$pid" -ne 0 ]; then
		[ "$owned_start_sha" = "$(state_value process_start_sha256)" ] ||
			fail "CP7B PID start identity changed"
	fi
	if [ "$phase" = ready ] && [ -S "$socket_path" ]; then
		[ "$(/usr/bin/stat -f '%i' "$socket_path")" = "$(state_value socket_inode)" ] ||
			fail "CP7B socket inode changed"
		/usr/sbin/lsof -a -p "$owned_pid" -U 2>/dev/null | /usr/bin/grep -Fq -- "$socket_path" ||
			fail "CP7B socket owner changed"
	fi
	stop_owned_process
fi

if [ "$preserve_ledger" = false ] && [ -e "$attempt_ledger" ]; then
	[ -f "$attempt_ledger" ] && [ ! -L "$attempt_ledger" ] || fail "CP7B attempt ledger is invalid"
	[ "$(/usr/bin/stat -f '%u' "$attempt_ledger")" -eq "$expected_owner" ] || fail "CP7B ledger owner changed"
	[ "$(/usr/bin/stat -f '%Lp' "$attempt_ledger")" = 600 ] || fail "CP7B ledger mode changed"
	/usr/bin/awk -F= '
		NF != 2 { bad = 1 }
		$1 !~ /^(schema|backend|window_started_epoch|attempts)$/ { bad = 1 }
		seen[$1]++ { bad = 1 }
		END { exit (bad || length(seen) != 4) }
	' "$attempt_ledger" || fail "CP7B attempt ledger schema changed"
	[ "$(/usr/bin/awk -F= '$1 == "schema" { print $2 }' "$attempt_ledger")" = 1 ] ||
		fail "CP7B attempt ledger version changed"
	[ "$(/usr/bin/awk -F= '$1 == "backend" { print $2 }' "$attempt_ledger")" = pfkey-pfroute ] ||
		fail "CP7B attempt ledger backend changed"
	/bin/rm -f -- "$attempt_ledger"
fi
if [ -S "$socket_path" ]; then
	[ "$(state_value socket_inode)" = 0 ] ||
		[ "$(/usr/bin/stat -f '%i' "$socket_path")" = "$(state_value socket_inode)" ] ||
		fail "refusing to remove a replaced CP7B socket"
	/bin/rm -f -- "$socket_path"
fi
if [ -e "$pid_file" ]; then
	[ "$pid" -ne 0 ] && [ "$(/usr/bin/sed -n '1p' "$pid_file")" = "$pid" ] ||
		fail "refusing to remove a mismatched CP7B PID file"
	/bin/rm -f -- "$pid_file"
fi
if [ -e "$handshake_path" ]; then
	seen_pid=$(handshake_pid) || fail "refusing to remove an invalid CP7B handshake"
	[ "$owned_pid" -eq 0 ] || [ "$seen_pid" -eq "$owned_pid" ] || fail "CP7B handshake PID changed"
	/bin/rm -f -- "$handshake_path"
fi
if [ -e "$gate_path" ]; then
	[ -p "$gate_path" ] && [ ! -L "$gate_path" ] || fail "refusing to remove a replaced CP7B gate"
	[ "$(/usr/bin/stat -f '%u' "$gate_path")" -eq "$expected_owner" ] || fail "CP7B gate owner changed"
	[ "$(/usr/bin/stat -f '%Lp' "$gate_path")" = 600 ] || fail "CP7B gate mode changed"
	/bin/rm -f -- "$gate_path"
fi
for file in "$config_path" "$log_path"; do
	[ -f "$file" ] && [ ! -L "$file" ] || fail "CP7B runtime file is invalid"
	[ "$(/usr/bin/stat -f '%u' "$file")" -eq "$expected_owner" ] || fail "CP7B runtime file owner changed"
	/bin/rm -f -- "$file"
done
/bin/rmdir "$run_dir" || fail "unexpected CP7B generation residue"
/bin/rm -f -- "$state_file" "$emergency_path"

if [ "$preserve_ledger" = false ] && [ "$test_mode" = 0 ]; then
	entries=$(/usr/bin/find "$runtime_root" -mindepth 1 -maxdepth 1 -print)
	[ "$entries" = "$closure" ] || fail "CP7B terminal runtime contains unexpected residue"
	[ -d "$closure" ] && [ ! -L "$closure" ] || fail "CP7B closure baseline is invalid"
	[ "$(/usr/bin/stat -f '%u' "$closure")" -eq 0 ] || fail "CP7B closure is not root-owned"
	/usr/sbin/chown -Rh 502:20 "$closure"
	/usr/sbin/chown 502:20 "$runtime_root"
	/bin/chmod 700 "$runtime_root"
fi
printf '%s\n' 'cp7b_stopped=true' 'generation_owned_residue=false'
