#!/bin/sh

# Deadline-aware owned-process cleanup for run_r2_tls_evidence.sh.
# The caller initializes the PID/path/status globals before invoking functions.
# shellcheck disable=SC2034,SC2154

owned_child_alive() {
	[ -n "$child_pid" ] && r2tls_runner_owned_process_alive "$child_pid" "$$"
}
owned_aux_alive() { r2tls_runner_owned_process_alive "$1" "$$"; }
stop_child() {
	[ -n "$child_pid" ] || return 0
	child_stopped=false; r2tls_runner_force_stop_owned "$child_pid" 200 || true
	if ! owned_child_alive; then
		set +e; wait "$child_pid" 2>/dev/null; child_rc=$?; set -e
		child_stopped=true; child_pid=
	fi
}
stop_monitor() {
	[ -n "$monitor_pid" ] || return 0
	monitor_stopped=false; [ -e "$stop" ] || r2tls_create_sentinel "$stop" || true
	r2tls_runner_wait_owned_process "$monitor_pid" 50 ||
		r2tls_runner_force_stop_owned "$monitor_pid" 50 || true
	if ! owned_aux_alive "$monitor_pid"; then
		set +e; wait "$monitor_pid" 2>/dev/null; set -e
		monitor_pid=; monitor_stopped=true
	fi
	rm -f "$ready" "$stop"
}
stop_validator() {
	[ -n "$jq_pid" ] || return 0
	validator_stopped=false; r2tls_runner_force_stop_owned "$jq_pid" 50 || true
	if ! owned_aux_alive "$jq_pid"; then
		set +e; wait "$jq_pid" 2>/dev/null; set -e
		jq_pid=; validator_stopped=true
	fi
}
stop_gate_writer() {
	[ -n "$gate_pid" ] || return 0
	gate_stopped=false; r2tls_runner_force_stop_owned "$gate_pid" 50 || true
	if ! owned_aux_alive "$gate_pid"; then
		set +e; wait "$gate_pid" 2>/dev/null; set -e
		gate_pid=; gate_stopped=true
	fi
}
stop_phase() {
	[ -n "$phase_pid" ] || return 0
	phase_stopped=false; r2tls_runner_force_stop_owned "$phase_pid" 50 || true
	if ! owned_aux_alive "$phase_pid"; then
		set +e; wait "$phase_pid" 2>/dev/null; set -e
		phase_pid=; phase_stopped=true
	fi
}
wait_phase_naturally() {
	while owned_aux_alive "$phase_pid" && r2tls_deadline_open; do sleep 0.01; done
	owned_aux_alive "$phase_pid" && return 124
	set +e; wait "$phase_pid"; phase_rc=$?; set -e
	phase_pid=; phase_stopped=true; [ "$phase_rc" -eq 0 ]
}
r2tls_deadline_ack_exact() {
	[ -f "$1" ] && [ ! -L "$1" ] &&
		[ "$(stat -f '%u:%Lp' "$1")" = "$(id -u):600" ] &&
		printf '%s\n' "$2" | /usr/bin/cmp -s - "$1"
}
stop_deadline_guard() {
	[ -n "$deadline_pid" ] || return 0
	deadline_guard_pid=$deadline_pid; deadline_stopped=false
	deadline_waited=false; deadline_acknowledged=false
	if [ ! -e "$deadline_stop" ]; then r2tls_create_sentinel "$deadline_stop" || return 1; fi
	[ -f "$deadline_stop" ] && [ ! -L "$deadline_stop" ] &&
		[ "$(stat -f '%u:%Lp' "$deadline_stop")" = "$(id -u):600" ] || return 1
	r2tls_runner_force_stop_owned "$deadline_pid" 20 || true
	if ! owned_aux_alive "$deadline_pid"; then
		set +e; wait "$deadline_pid" 2>/dev/null; deadline_wait_rc=$?; set -e
		if [ "$deadline_wait_rc" -ne 127 ]; then
			deadline_pid=; deadline_stopped=true; deadline_waited=true
		fi
	fi
	if [ "$deadline_stopped" = true ] && [ "$deadline_waited" = true ] &&
		[ "$deadline_wait_rc" -eq 0 ] &&
		r2tls_deadline_ack_exact "$deadline_ack" "$deadline_guard_pid"; then
		deadline_acknowledged=true
	fi
	return 0
}
cleanup_resources() {
	if [ "${finalization_published:-false}" = true ]; then
		rm -f "$gate" "$report_fifo" "$deadline_ready" "$deadline_expired" \
			"$deadline_stop" "$deadline_ack"
		[ -z "${result_tmp:-}" ] || rm -f "$result_tmp"
		return 0
	fi
	stop_monitor; stop_gate_writer; stop_child; stop_validator; stop_phase; stop_deadline_guard
	rm -f "$gate" "$report_fifo" "$deadline_ready" "$deadline_expired" \
		"$deadline_stop" "$deadline_ack"
	[ -z "${result_tmp:-}" ] || rm -f "$result_tmp"
}
