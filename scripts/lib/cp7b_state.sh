#!/bin/sh

pvn_cp7b_state_value() {
	key=$1
	file=${2:-"$PVN_CP7B_STATE_FILE"}
	awk -F= -v key="$key" '$1 == key { count++; value = substr($0, length(key) + 2) }
		END { if (count == 1) print value; else exit 1 }' "$file"
}

pvn_cp7b_validate_state() {
	file=${1:-"$PVN_CP7B_STATE_FILE"}
	[ -f "$file" ] && [ ! -L "$file" ] ||
		pvn_fail "CP7B state is missing or a symlink" || return 1
	[ "$(stat -f '%u' "$file")" = "$(id -u)" ] ||
		pvn_fail "CP7B state owner does not match the caller" || return 1
	[ "$(stat -f '%Lp' "$file")" = 600 ] ||
		pvn_fail "CP7B state mode must be 600" || return 1
	awk -F= '
		NF != 2 { bad = 1 }
		$1 !~ /^(schema|checkpoint|phase|backend|attempt|generation|pid|executable|executable_sha256|launcher_path|launcher_sha256|process_start_sha256|config_path|config_sha256|log_path|socket_path|socket_inode|manifest_sha256|emergency_stop_path|gate_path|handshake_path)$/ { bad = 1 }
		seen[$1]++ { bad = 1 }
		END { exit (bad || length(seen) != 21) }
	' "$file" || pvn_fail "CP7B state schema is invalid" || return 1
	[ "$(pvn_cp7b_state_value schema "$file")" = 3 ] ||
		pvn_fail "CP7B state version is unsupported" || return 1
	[ "$(pvn_cp7b_state_value checkpoint "$file")" = 7b ] ||
		pvn_fail "CP7B state checkpoint is invalid" || return 1
	[ "$(pvn_cp7b_state_value backend "$file")" = pfkey-pfroute ] ||
		pvn_fail "CP7B state backend is invalid" || return 1
	phase=$(pvn_cp7b_state_value phase "$file")
	case "$phase" in
	prepared | starting | ready) ;;
	*) pvn_fail "CP7B state phase is invalid" || return 1 ;;
	esac
	generation=$(pvn_cp7b_state_value generation "$file")
	case "$generation" in
	'' | *[!A-Za-z0-9._-]*) pvn_fail "CP7B state generation is invalid" || return 1 ;;
	esac
	for key in config_path log_path socket_path emergency_stop_path gate_path handshake_path; do
		pvn_require_runtime_path "$(pvn_cp7b_state_value "$key" "$file")" || return 1
	done
	run_dir="$PVN_CP7B_RUNTIME_ROOT/generation-$generation"
	[ "$(pvn_cp7b_state_value config_path "$file")" = "$run_dir/strongswan.conf" ] ||
		pvn_fail "CP7B state config path changed" || return 1
	[ "$(pvn_cp7b_state_value log_path "$file")" = "$run_dir/charon.log" ] ||
		pvn_fail "CP7B state log path changed" || return 1
	[ "$(pvn_cp7b_state_value gate_path "$file")" = "$run_dir/launch.gate" ] ||
		pvn_fail "CP7B state gate path changed" || return 1
	[ "$(pvn_cp7b_state_value handshake_path "$file")" = "$run_dir/launch.handshake" ] ||
		pvn_fail "CP7B state handshake path changed" || return 1
	[ "$(pvn_cp7b_state_value executable "$file")" = "$PVN_CP7B_BINARY" ] ||
		pvn_fail "CP7B state executable path changed" || return 1
	[ "$(pvn_cp7b_state_value launcher_path "$file")" = "$PVN_CP7B_LAUNCHER" ] ||
		pvn_fail "CP7B state launcher path changed" || return 1
	pid=$(pvn_cp7b_state_value pid "$file")
	case "$pid" in
	'' | *[!0-9]*) pvn_fail "CP7B state PID is invalid" || return 1 ;;
	esac
	start_sha=$(pvn_cp7b_state_value process_start_sha256 "$file")
	case "$start_sha" in
	'' | *[!0-9a-f]*) pvn_fail "CP7B process start identity is invalid" || return 1 ;;
	esac
	[ "${#start_sha}" -eq 64 ] || pvn_fail "CP7B process start identity is invalid" || return 1
	case "$phase:$pid:$start_sha" in
	prepared:0:0000000000000000000000000000000000000000000000000000000000000000) ;;
	prepared:*) pvn_fail "prepared CP7B state has a live process identity" || return 1 ;;
	starting:0:* | ready:0:*) pvn_fail "active CP7B state has no PID identity" || return 1 ;;
	esac
}

pvn_cp7b_write_state() {
	phase=$1
	generation=$2
	attempt=$3
	pid=$4
	process_start_sha=$5
	config_path=$6
	config_sha=$7
	log_path=$8
	socket_inode=$9
	manifest_sha=${10}
	emergency_stop_path=${11}
	gate_path=${12}
	handshake_path=${13}
	temp_state="$PVN_CP7B_RUNTIME_ROOT/.current.state.$$"
	{
		printf '%s\n' \
			'schema=3' \
			'checkpoint=7b' \
			"phase=$phase" \
			'backend=pfkey-pfroute' \
			"attempt=$attempt" \
			"generation=$generation" \
			"pid=$pid" \
			"executable=$PVN_CP7B_BINARY" \
			"executable_sha256=$(pvn_sha256_file "$PVN_CP7B_BINARY")" \
			"launcher_path=$PVN_CP7B_LAUNCHER" \
			"launcher_sha256=$(pvn_sha256_file "$PVN_CP7B_LAUNCHER")" \
			"process_start_sha256=$process_start_sha" \
			"config_path=$config_path" \
			"config_sha256=$config_sha" \
			"log_path=$log_path" \
			"socket_path=$PVN_CP7B_SOCKET" \
			"socket_inode=$socket_inode" \
			"manifest_sha256=$manifest_sha" \
			"emergency_stop_path=$emergency_stop_path" \
			"gate_path=$gate_path" \
			"handshake_path=$handshake_path"
	} >"$temp_state"
	chmod 600 "$temp_state"
	mv -f -- "$temp_state" "$PVN_CP7B_STATE_FILE"
}

pvn_cp7b_expected_launcher_command() {
	gate_path=$1
	handshake_path=$2
	printf '%s -- %s %s %s --debug-dmn 2 --debug-cfg 1 --debug-knl 1 --debug-net 2\n' \
		"$PVN_CP7B_LAUNCHER" "$gate_path" "$handshake_path" "$PVN_CP7B_BINARY"
}

pvn_cp7b_expected_target_command() {
	printf '%s --debug-dmn 2 --debug-cfg 1 --debug-knl 1 --debug-net 2\n' \
		"$PVN_CP7B_BINARY"
}

pvn_cp7b_process_matches_launcher() {
	pid=$1
	gate_path=$2
	handshake_path=$3
	[ "$(pvn_process_command "$pid")" = \
		"$(pvn_cp7b_expected_launcher_command "$gate_path" "$handshake_path")" ]
}

pvn_cp7b_process_matches_target() {
	[ "$(pvn_process_command "$1")" = "$(pvn_cp7b_expected_target_command)" ]
}

pvn_cp7b_validate_gate() {
	gate_path=$1
	[ -p "$gate_path" ] && [ ! -L "$gate_path" ] ||
		pvn_fail "CP7B launch gate is missing, replaced, or not a FIFO" || return 1
	[ "$(stat -f '%u' "$gate_path")" = "$(id -u)" ] ||
		pvn_fail "CP7B launch gate owner changed" || return 1
	[ "$(stat -f '%Lp' "$gate_path")" = 600 ] ||
		pvn_fail "CP7B launch gate mode changed" || return 1
}

pvn_cp7b_handshake_pid() {
	handshake_path=$1
	[ -f "$handshake_path" ] && [ ! -L "$handshake_path" ] || return 1
	[ "$(stat -f '%u' "$handshake_path")" = "$(id -u)" ] || return 1
	[ "$(stat -f '%Lp' "$handshake_path")" = 600 ] || return 1
	awk -F= '
		NF != 2 || $1 != "pid" || $2 !~ /^[1-9][0-9]*$/ { bad = 1 }
		seen++ { bad = 1 }
		END { if (!bad && seen == 1) print pid; else exit 1 }
		{ pid = $2 }
	' "$handshake_path"
}

pvn_cp7b_wait_for_launcher_handshake() {
	expected_pid=$1
	gate_path=$2
	handshake_path=$3
	attempt=0
	while [ "$attempt" -lt 40 ]; do
		kill -0 "$expected_pid" 2>/dev/null || return 1
		pvn_cp7b_process_matches_launcher "$expected_pid" "$gate_path" "$handshake_path" || return 1
		if [ -e "$handshake_path" ]; then
			[ "$(pvn_cp7b_handshake_pid "$handshake_path")" = "$expected_pid" ] || return 1
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 0.05
	done
	return 1
}

pvn_cp7b_wait_for_target_exec() {
	pid=$1
	gate_path=$2
	handshake_path=$3
	attempt=0
	while [ "$attempt" -lt 40 ]; do
		kill -0 "$pid" 2>/dev/null || return 1
		pvn_cp7b_process_matches_target "$pid" && return 0
		pvn_cp7b_process_matches_launcher "$pid" "$gate_path" "$handshake_path" || return 1
		attempt=$((attempt + 1))
		sleep 0.05
	done
	return 1
}

pvn_cp7b_start_gated_target() {
	generation=$1
	attempt_number=$2
	config_path=$3
	config_sha=$4
	log_path=$5
	manifest_sha=$6
	emergency_path=$7
	gate_path=$8
	handshake_path=$9
	stage_file=${10}
	env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/var/root \
		STRONGSWAN_CONF="$config_path" "$PVN_CP7B_LAUNCHER" -- \
		"$gate_path" "$handshake_path" "$PVN_CP7B_BINARY" \
		--debug-dmn 2 --debug-cfg 1 --debug-knl 1 --debug-net 2 \
		</dev/null >"$log_path" 2>&1 &
	daemon_pid=$!
	printf '%s\n' gated_launcher_spawned >"$stage_file"
	pvn_cp7b_wait_for_launcher_handshake "$daemon_pid" "$gate_path" "$handshake_path" || return 1
	start_sha=$(pvn_process_start_sha256 "$daemon_pid")
	pvn_cp7b_write_state starting "$generation" "$attempt_number" "$daemon_pid" \
		"$start_sha" "$config_path" "$config_sha" "$log_path" 0 \
		"$manifest_sha" "$emergency_path" "$gate_path" "$handshake_path"
	printf '%s\n' starting_state_committed >"$stage_file"
	printf G >"$gate_path"
	pvn_cp7b_wait_for_target_exec "$daemon_pid" "$gate_path" "$handshake_path" || return 1
	[ "$(pvn_process_start_sha256 "$daemon_pid")" = "$start_sha" ] || return 1
	printf '%s\n' target_exec_verified >"$stage_file"
	PVN_CP7B_OWNED_PID=$daemon_pid
	PVN_CP7B_PROCESS_START_SHA=$start_sha
	export PVN_CP7B_OWNED_PID PVN_CP7B_PROCESS_START_SHA
}

pvn_cp7b_start_deadline_guard() {
	remaining_seconds=$((PVN_CP7B_WINDOW_STARTED + 300 - $(date +%s)))
	[ "$remaining_seconds" -gt 0 ] || pvn_fail "CP7B approval window expired" || return 1
	worker_pid=$$
	(sleep "$remaining_seconds"; kill -TERM "$worker_pid" 2>/dev/null || true) &
	PVN_CP7B_DEADLINE_GUARD_PID=$!
	export PVN_CP7B_DEADLINE_GUARD_PID
}

pvn_cp7b_stop_deadline_guard() {
	[ -z "${PVN_CP7B_DEADLINE_GUARD_PID:-}" ] ||
		kill "$PVN_CP7B_DEADLINE_GUARD_PID" 2>/dev/null || true
	[ -z "${PVN_CP7B_DEADLINE_GUARD_PID:-}" ] ||
		wait "$PVN_CP7B_DEADLINE_GUARD_PID" 2>/dev/null || true
	PVN_CP7B_DEADLINE_GUARD_PID=
}

pvn_cp7b_verify_state_process() {
	pvn_cp7b_validate_state || return 1
	pid=$(pvn_cp7b_state_value pid)
	case "$pid" in
	'' | *[!0-9]* | 0) pvn_fail "CP7B state has no live PID identity" || return 1 ;;
	esac
	kill -0 "$pid" 2>/dev/null || pvn_fail "CP7B PID is stale: $pid" || return 1
	[ "$(pvn_cp7b_state_value executable)" = "$PVN_CP7B_BINARY" ] ||
		pvn_fail "CP7B executable path changed" || return 1
	[ "$(pvn_sha256_file "$PVN_CP7B_BINARY")" = \
		"$(pvn_cp7b_state_value executable_sha256)" ] ||
		pvn_fail "CP7B executable hash changed" || return 1
	[ "$(pvn_cp7b_state_value launcher_path)" = "$PVN_CP7B_LAUNCHER" ] ||
		pvn_fail "CP7B launcher path changed" || return 1
	[ "$(pvn_sha256_file "$PVN_CP7B_LAUNCHER")" = \
		"$(pvn_cp7b_state_value launcher_sha256)" ] ||
		pvn_fail "CP7B launcher hash changed" || return 1
	phase=$(pvn_cp7b_state_value phase)
	gate_path=$(pvn_cp7b_state_value gate_path)
	handshake_path=$(pvn_cp7b_state_value handshake_path)
	if [ "$phase" = starting ]; then
		pvn_cp7b_process_matches_launcher "$pid" "$gate_path" "$handshake_path" ||
			pvn_cp7b_process_matches_target "$pid" ||
			pvn_fail "CP7B PID matches neither gated launcher nor target" || return 1
	else
		pvn_cp7b_process_matches_target "$pid" ||
			pvn_fail "CP7B PID does not run the recorded target" || return 1
	fi
	[ "$(pvn_process_start_sha256 "$pid")" = \
		"$(pvn_cp7b_state_value process_start_sha256)" ] ||
		pvn_fail "CP7B PID start identity changed" || return 1
	if [ "$phase" = ready ]; then
		[ -S "$PVN_CP7B_SOCKET" ] || pvn_fail "CP7B VICI socket is missing" || return 1
		[ "$(stat -f '%i' "$PVN_CP7B_SOCKET")" = \
			"$(pvn_cp7b_state_value socket_inode)" ] ||
			pvn_fail "CP7B VICI socket inode changed" || return 1
		lsof -a -p "$pid" -U 2>/dev/null | grep -Fq -- "$PVN_CP7B_SOCKET" ||
			pvn_fail "CP7B VICI socket owner changed" || return 1
	fi
	PVN_CP7B_OWNED_PID=$pid
	export PVN_CP7B_OWNED_PID
}

pvn_cp7b_generation_dir() {
	printf '%s/generation-%s\n' "$PVN_CP7B_RUNTIME_ROOT" \
		"$(pvn_cp7b_state_value generation)"
}
