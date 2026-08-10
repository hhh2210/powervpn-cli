#!/bin/sh

set -eu
umask 077

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
R2TLS_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$repo_root/scripts/lib/r2_tls_evidence_runtime.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_result.sh
. "$repo_root/scripts/lib/r2_tls_evidence_result.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_deadline.sh
. "$repo_root/scripts/lib/r2_tls_evidence_deadline.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_finalize.sh
. "$repo_root/scripts/lib/r2_tls_evidence_finalize.sh"

test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
test_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r2-tls-finalize.XXXXXX")
chmod 700 "$test_root"
deadline_pid=; target_pid=; child_pid=; publish_pid=
cleanup() {
	exit_status=$?; trap - EXIT HUP INT TERM
	for cleanup_pid in "$publish_pid" "$deadline_pid" "$target_pid" "$child_pid"; do
		[ -z "$cleanup_pid" ] || ! r2tls_runner_owned_process_alive "$cleanup_pid" "$$" ||
			/bin/kill -KILL "$cleanup_pid" 2>/dev/null || true
		[ -z "$cleanup_pid" ] || wait "$cleanup_pid" 2>/dev/null || true
	done
	find "$test_root" -type l -delete 2>/dev/null || true
	find "$test_root" -type f -delete 2>/dev/null || true
	find "$test_root" -type p -delete 2>/dev/null || true
	find "$test_root" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	exit "$exit_status"
}
trap cleanup EXIT HUP INT TERM

case_index=0
reset_case() {
	case_index=$((case_index + 1)); case_dir="$test_root/$case_index-$1"
	mkdir "$case_dir"; chmod 700 "$case_dir"
	result="$case_dir/result.json"; result_tmp=
	gate="$case_dir/start.fifo"; report_fifo="$case_dir/report.fifo"
	ready="$case_dir/.monitor-ready"; stop="$case_dir/.monitor-stop"
	deadline_ready="$case_dir/.deadline-ready"; deadline_expired="$case_dir/.deadline-expired"
	deadline_stop="$case_dir/.deadline-stop"; deadline_ack="$case_dir/.deadline-ack"
	R2TLS_DEADLINE_FILE=$deadline_expired
	child_pid=; monitor_pid=; jq_pid=; gate_pid=; phase_pid=; deadline_pid=
	child_stopped=true; monitor_stopped=true; validator_stopped=true
	gate_stopped=true; phase_stopped=true; deadline_stopped=true
	deadline_waited=false; deadline_acknowledged=false; deadline_guard_pid=
	harness_kill=false; deadline=false; observed=true; cli_rc=0
	report_valid=true; monitor_execution=true; manifest_stable=true; artifact=true
	cleanup_safe=true; predecessor_validated=true; authorization_consumed=true
	transport=true; trust=true; monitor_quality=complete; environment=true
	finalization_state=open; finalization_dimensions_computed=false
	finalization_published=false; execution='unset'; checkpoint='unset'
	authorized_manifest_sha=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
	report_json=null; monitor_valid=true; monitor_json=null
	compatibility=compatible_under_system_trust; disposition=system_trusted
	projection=true; ipv4_changed=false; launchd=true; runs_before=19; runs_after=19
	R2TLS_ATTEMPT2_ARCHIVE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	R2TLS_ATTEMPT2_FIXTURE_SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
	R2TLS_ATTEMPT3_EXPERIMENT=attempt3-after-inconclusive-v2
}
start_guard() {
	/bin/sleep 5 & target_pid=$!
	r2tls_deadline_guard "$deadline_ready" "$deadline_expired" "$deadline_stop" \
		"$deadline_ack" 1500 "$target_pid" 2>"$case_dir/guard.stderr" &
	deadline_pid=$!; expected_guard_pid=$deadline_pid; deadline_stopped=false
	wait_attempt=0
	while [ ! -f "$deadline_ready" ] && [ "$wait_attempt" -lt 100 ]; do
		wait_attempt=$((wait_attempt + 1)); sleep 0.01
	done
	[ "$wait_attempt" -lt 100 ]
}
stop_target() {
	[ -z "$target_pid" ] || /bin/kill -TERM "$target_pid" 2>/dev/null || true
	[ -z "$target_pid" ] || { set +e; wait "$target_pid"; set -e; }
	target_pid=
}
assert_no_result() {
	[ ! -e "$result" ] &&
		[ -z "$(find "$case_dir" -name '.r2-tls-result-finalizing.*' -print)" ]
}

reset_case positive; start_guard
r2tls_finalization_barrier
[ "$finalization_state" = published ] && [ "$finalization_published" = true ] &&
	[ "$finalization_dimensions_computed" = true ] && [ "$execution" = true ] &&
	[ "$checkpoint" = true ] && [ "$deadline_guard_pid" = "$expected_guard_pid" ] &&
	r2tls_deadline_ack_exact "$deadline_ack" "$expected_guard_pid"
if r2tls_deadline_ack_exact "$deadline_ack" 999999; then exit 1; fi
[ -f "$result" ] && [ ! -L "$result" ] &&
	[ "$(stat -f '%u:%Lp' "$result")" = "$(id -u):600" ] &&
	[ "$(stat -f '%d' "$result")" = "$(stat -f '%d' "$case_dir")" ]
jq -e '.executionSafetyPass and .checkpointPass and .complete' "$result" >/dev/null
positive_hash=$(r2tls_hash_file "$result")
if r2tls_finalization_barrier; then repeat_rc=0; else repeat_rc=$?; fi
if r2tls_compute_final_dimensions_once; then recompute_rc=0; else recompute_rc=$?; fi
[ "$repeat_rc" -eq 73 ] && [ "$recompute_rc" -ne 0 ]
cleanup_resources
[ "$positive_hash" = "$(r2tls_hash_file "$result")" ] &&
	[ "$execution" = true ] && [ "$checkpoint" = true ] &&
	[ "$finalization_state" = published ]
stop_target

reset_case boundary-expiry; start_guard
r2tls_finalization_test_hook() { r2tls_create_sentinel "$deadline_expired"; }
if r2tls_finalization_barrier; then boundary_rc=0; else boundary_rc=$?; fi
[ "$boundary_rc" -eq 124 ] && [ "$finalization_state" = expired ] &&
	[ "$finalization_dimensions_computed" = false ] &&
	r2tls_deadline_ack_exact "$deadline_ack" "$expected_guard_pid"
assert_no_result; r2tls_finalization_test_hook() { :; }
cleanup_resources; stop_target

reset_case forged-exact-ack; start_guard
printf '%s\n' "$expected_guard_pid" >"$deadline_ack"; chmod 600 "$deadline_ack"
if r2tls_finalization_barrier; then wrong_ack_rc=0; else wrong_ack_rc=$?; fi
[ "$wrong_ack_rc" -eq 70 ] && [ "$finalization_state" = guard_failed ] &&
	[ "$deadline_acknowledged" = false ] && [ "$finalization_dimensions_computed" = false ]
assert_no_result; cleanup_resources; stop_target

reset_case kill-guard
/usr/bin/perl -e '$SIG{TERM}="IGNORE"; select undef,undef,undef,5' & deadline_pid=$!
killed_guard_pid=$deadline_pid; deadline_stopped=false; sleep 0.05
if r2tls_finalization_barrier 2>"$case_dir/kill.stderr"; then kill_rc=0; else kill_rc=$?; fi
[ "$kill_rc" -eq 70 ] && [ "$harness_kill" = true ] &&
	[ "$deadline_acknowledged" = false ] && [ "$finalization_dimensions_computed" = false ] &&
	! /bin/kill -0 "$killed_guard_pid" 2>/dev/null
assert_no_result; cleanup_resources

reset_case resource-live; start_guard
/bin/sleep 5 & child_pid=$!; child_stopped=false
if r2tls_finalization_barrier; then live_rc=0; else live_rc=$?; fi
[ "$live_rc" -eq 71 ] && [ "$finalization_state" = resources_live ] &&
	[ "$finalization_dimensions_computed" = false ]
assert_no_result; stop_child; cleanup_resources; stop_target

reset_case atomic-publication
render_ready="$case_dir/render.ready"; render_release="$case_dir/render.release"
r2tls_render_live_result() {
	printf '%s' '{"phase":"complete"'
	r2tls_create_sentinel "$render_ready"
	while [ ! -f "$render_release" ]; do sleep 0.01; done
	printf '%s\n' ',"valid":true}'
}
r2tls_publish_result_atomic & publish_pid=$!
wait_attempt=0
while [ ! -f "$render_ready" ] && [ "$wait_attempt" -lt 100 ]; do
	wait_attempt=$((wait_attempt + 1)); sleep 0.01
done
[ "$wait_attempt" -lt 100 ] && [ ! -e "$result" ]
partial_tmp=$(find "$case_dir" -name '.r2-tls-result-finalizing.*' -type f -print)
[ "$(printf '%s\n' "$partial_tmp" | awk 'NF{n++} END{print n+0}')" -eq 1 ] &&
	[ "$(stat -f '%u:%Lp' "$partial_tmp")" = "$(id -u):600" ]
r2tls_create_sentinel "$render_release"; wait "$publish_pid"; publish_pid=
[ ! -e "$partial_tmp" ] && [ -f "$result" ] &&
	[ "$(stat -f '%u:%Lp' "$result")" = "$(id -u):600" ] &&
	[ "$(stat -f '%d' "$result")" = "$(stat -f '%d' "$case_dir")" ]
jq -e '.phase=="complete" and .valid==true' "$result" >/dev/null

printf '%s\n' 'R2 TLS evidence finalization tests: PASS (offline synthetic only)'
