#!/bin/sh

# One-way finalization barrier for the R2 TLS evidence runner.
# The caller sources runtime, result, and deadline helpers first.
# shellcheck disable=SC2034,SC2154

r2tls_finalization_test_hook() { :; }

r2tls_finalization_owned_resources_stopped() {
	[ -z "$child_pid" ] && [ -z "$monitor_pid" ] && [ -z "$jq_pid" ] &&
		[ -z "$gate_pid" ] && [ -z "$phase_pid" ] && [ -z "$deadline_pid" ] &&
		[ "$child_stopped" = true ] && [ "$monitor_stopped" = true ] &&
		[ "$validator_stopped" = true ] && [ "$gate_stopped" = true ] &&
		[ "$phase_stopped" = true ] && [ "$deadline_stopped" = true ] &&
		[ "$deadline_waited" = true ] && [ "$deadline_acknowledged" = true ] &&
		[ ! -e "$gate" ] && [ ! -L "$gate" ] &&
		[ ! -e "$report_fifo" ] && [ ! -L "$report_fifo" ] &&
		[ ! -e "$ready" ] && [ ! -L "$ready" ] &&
		[ ! -e "$stop" ] && [ ! -L "$stop" ]
}

r2tls_publish_result_atomic() {
	result_parent=$(CDPATH='' cd -- "$(dirname -- "$result")" && pwd -P) || return 1
	[ -d "$result_parent" ] && [ ! -L "$result_parent" ] &&
		[ "$(stat -f '%u:%Lp' "$result_parent")" = "$(id -u):700" ] || return 1
	[ ! -e "$result" ] && [ ! -L "$result" ] || return 1
	result_tmp="$result_parent/.r2-tls-result-finalizing.$$"
	r2tls_create_sentinel "$result_tmp" || return 1
	if ! r2tls_render_live_result >"$result_tmp" || ! jq -e . "$result_tmp" >/dev/null; then
		rm -f "$result_tmp"; result_tmp=; return 1
	fi
	[ -f "$result_tmp" ] && [ ! -L "$result_tmp" ] &&
		[ "$(stat -f '%u:%Lp' "$result_tmp")" = "$(id -u):600" ] &&
		[ "$(stat -f '%d' "$result_tmp")" = "$(stat -f '%d' "$result_parent")" ] || {
		rm -f "$result_tmp"; result_tmp=; return 1;
	}
	/bin/mv -n "$result_tmp" "$result" || { rm -f "$result_tmp"; result_tmp=; return 1; }
	[ ! -e "$result_tmp" ] && [ -f "$result" ] && [ ! -L "$result" ] &&
		[ "$(stat -f '%u:%Lp' "$result")" = "$(id -u):600" ] || {
		rm -f "$result_tmp"; result_tmp=; return 1;
	}
	result_tmp=
}

r2tls_finalization_barrier() {
	[ "${finalization_state:-open}" = open ] || return 73
	finalization_state=closing; finalization_published=false
	stop_deadline_guard || { finalization_state=guard_failed; return 70; }
	guard_exact=false
	[ "$deadline_stopped" = true ] && [ "$deadline_waited" = true ] &&
		[ "$deadline_acknowledged" = true ] && guard_exact=true
	r2tls_finalization_test_hook || { finalization_state=hook_failed; return 70; }
	if ! r2tls_deadline_open; then finalization_state=expired; return 124; fi
	[ "$guard_exact" = true ] && [ "$harness_kill" = false ] || {
		finalization_state=guard_failed; return 70;
	}
	r2tls_finalization_owned_resources_stopped || {
		finalization_state=resources_live; return 71;
	}
	deadline_clear=true
	r2tls_compute_final_dimensions_once || {
		finalization_state=dimension_failed; return 72;
	}
	r2tls_publish_result_atomic || { finalization_state=publish_failed; return 72; }
	finalization_published=true; finalization_state=published
}
