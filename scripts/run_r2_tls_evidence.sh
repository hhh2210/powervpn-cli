#!/bin/sh
set -eu
umask 077
R2TLS_REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_runtime.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_result.sh
. "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_result.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_manifest.sh
. "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_manifest.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_monitor.sh
. "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_monitor.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_attempts.sh
. "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_attempts.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_deadline.sh
. "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_deadline.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_finalize.sh
. "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_finalize.sh"
usage() { printf 'usage: %s [--preflight-only]\n' "$0" >&2; exit 2; }
[ "$#" -le 1 ] || usage
mode=live
if [ "$#" -eq 1 ]; then [ "$1" = --preflight-only ] || usage; mode=preflight; fi
test_active=false; test_cli=; test_report=; test_scenario=live
deadline_duration_ms=20000
monitor_expected_comm=$R2TLS_CLI; monitor_expected_command=$R2TLS_CLI
case "${POWERVPN_R2_TLS_TEST_ACTIVE_MONITOR:-}" in
'') ;;
reviewed-no-network-v1 | reviewed-no-network-deadline-gate-v1 | \
reviewed-no-network-deadline-validator-v1)
	[ "$mode" = preflight ] || usage
	test_active=true
	case "$POWERVPN_R2_TLS_TEST_ACTIVE_MONITOR" in
	reviewed-no-network-v1) test_scenario=signal ;;
	reviewed-no-network-deadline-gate-v1) test_scenario=blocked_gate; deadline_duration_ms=300 ;;
	reviewed-no-network-deadline-validator-v1)
		test_scenario=blocked_validator; deadline_duration_ms=300 ;;
	esac
	test_root=${POWERVPN_R2_TLS_TEST_SCRATCH_ROOT:-}
	test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
	case "$test_root" in "$test_parent"/powervpn-r2-tls-test.*) ;; *) usage ;; esac
	[ -d "$test_root" ] && [ ! -L "$test_root" ] &&
		[ "$(stat -f '%u:%Lp' "$test_root")" = "$(id -u):700" ] || usage
	test_cli=$test_root/fake-cli; test_report=$test_root/fake-report.json
	[ -f "$test_cli" ] && [ ! -L "$test_cli" ] && [ -x "$test_cli" ] &&
		[ "$(stat -f '%u:%Lp' "$test_cli")" = "$(id -u):700" ] || usage
	[ -f "$test_report" ] && [ ! -L "$test_report" ] &&
		[ "$(stat -f '%u:%Lp' "$test_report")" = "$(id -u):600" ] || usage
	R2TLS_SCRATCH_ROOT=$test_root
	monitor_expected_comm=$test_cli
	if [ "$test_scenario" = blocked_validator ]; then
		monitor_expected_command="$test_cli $test_report"
	else monitor_expected_command="$test_cli 1000"; fi
	;;
*) usage ;;
esac

r2tls_cold_preflight
test_manifest_allowed=$R2TLS_MANIFEST_EXACT
if [ "$test_scenario" = blocked_gate ] || [ "$test_scenario" = blocked_validator ]; then
	test_manifest_allowed=true
fi
if [ "$test_active" = true ] && [ "$R2TLS_PREFLIGHT_SAFE" = false ] &&
	[ "$R2TLS_GUI_ABSENT" = true ] && [ "$R2TLS_HELPERS_ABSENT" = true ] &&
	[ "$R2TLS_NATIVE_ABSENT" = true ] && [ "$R2TLS_CLI_ABSENT" = true ] &&
	[ "$R2TLS_LAUNCHD_EXACT" = true ] && [ "$R2TLS_CLI_READY" = true ] &&
	[ "$R2TLS_DEPENDENCIES_READY" = true ] && [ "$test_manifest_allowed" = true ]; then
	R2TLS_PREFLIGHT_SAFE=true
fi
if [ "$mode" = preflight ] && [ "$test_active" = false ]; then
	r2tls_preflight_json
	[ "$R2TLS_PREFLIGHT_SAFE" = true ]
	exit
fi
if [ "$R2TLS_PREFLIGHT_SAFE" != true ]; then r2tls_preflight_json >&2; exit 3; fi
authorized_manifest_sha=$R2TLS_CANDIDATE_MANIFEST_SHA256
launchd_runs_before=$R2TLS_LAUNCHD_RUNS
predecessor_validated=false
authorization_consumed=false

if [ "$mode" = live ]; then
	[ -z "${POWERVPN_R2_APPROVED_MANIFEST_SHA256:-}" ] &&
		[ -z "${POWERVPN_R2_EXPOSED_CREDENTIAL_RISK_ACCEPTED:-}" ] || {
		echo 'error: portal-login approval variables are invalid for TLS evidence' >&2; exit 4;
	}
	r2tls_attempt3_environment_exact || {
		echo 'error: exact attempt3 experiment selector is absent or stale' >&2; exit 5;
	}
	[ "${POWERVPN_R2_TLS_EVIDENCE_APPROVED_MANIFEST_SHA256:-}" = \
		"$R2TLS_CANDIDATE_MANIFEST_SHA256" ] || {
		echo 'error: exact TLS-evidence manifest approval is absent or stale' >&2; exit 6;
	}
	r2tls_prepare_scratch_root || exit 7
	r2tls_attempt3_predecessor_exact "$R2TLS_SCRATCH_ROOT" || {
		echo 'error: exact attempt1/attempt2 lineage is absent or altered' >&2; exit 8;
	}
	r2tls_attempt3_consume_authorization "$R2TLS_SCRATCH_ROOT" \
		"$POWERVPN_R2_TLS_EVIDENCE_APPROVED_MANIFEST_SHA256" \
		"$R2TLS_CANDIDATE_MANIFEST_SHA256" || {
		echo 'error: attempt3 authorization is stale, raced, or consumed' >&2; exit 9;
	}
	predecessor_validated=true
	authorization_consumed=true
fi
kind=run; [ "$test_active" = false ] || kind=synthetic
run_dir="$R2TLS_SCRATCH_ROOT/$kind-$(date -u '+%Y%m%dT%H%M%SZ')-$$"
mkdir "$run_dir"; chmod 700 "$run_dir"
before="$run_dir/network-before.json"; after="$run_dir/network-after.json"
gate="$run_dir/start.fifo"; report_fifo="$run_dir/report.fifo"
report="$run_dir/report.json"; monitor="$run_dir/monitor.json"
ready="$run_dir/.monitor-ready"; stop="$run_dir/.monitor-stop"
result="$run_dir/result.json"; signal_result="$run_dir/incomplete-signal.json"
deadline_ready="$run_dir/.deadline-ready"; deadline_expired="$run_dir/.deadline-expired"
deadline_stop="$run_dir/.deadline-stop"; deadline_ack="$run_dir/.deadline-ack"
deadline_result="$run_dir/incomplete-deadline.json"
child_pid=; monitor_pid=; jq_pid=; gate_pid=; phase_pid=; deadline_pid=
network_started=false; harness_kill=false; deadline=false
child_stopped=true; monitor_stopped=true; validator_stopped=true; gate_stopped=true
phase_stopped=true
deadline_stopped=true; deadline_acknowledged=false
deadline_waited=false; deadline_guard_pid=; result_tmp=
finalization_state=open; finalization_dimensions_computed=false; finalization_published=false
R2TLS_DEADLINE_FILE=$deadline_expired

cleanup_on_exit() {
	exit_status=$?; trap - EXIT
	cleanup_resources
	exit "$exit_status"
}
signal_exit() {
	code=$1; trap - EXIT HUP INT TERM
	[ ! -f "$deadline_expired" ] || deadline_exit
	cleanup_resources
	jq -n --argjson code "$code" --argjson network "$network_started" \
		--argjson killed "$harness_kill" --argjson child "$child_stopped" \
		--argjson monitor "$monitor_stopped" \
		'{schemaVersion:1,evidenceClass:"r2_tls_peer_incomplete_signal",
      complete:false,signalExitStatus:$code,networkStarted:$network,
      ownedEvidenceCLIStopped:$child,monitorStopped:$monitor,
      harnessKillSent:$killed,helperKillSent:false,
      containsSecrets:false,containsRawCertificate:false}' >"$signal_result"
	chmod 600 "$signal_result"; exit "$code"
}
deadline_exit() {
	trap - EXIT HUP INT TERM; deadline=true; cleanup_resources; rm -f "$result"
	jq -n --argjson network "$network_started" --argjson killed "$harness_kill" \
		--argjson child "$child_stopped" --argjson monitor "$monitor_stopped" \
		--argjson validator "$validator_stopped" --argjson gateStopped "$gate_stopped" \
		--argjson phase "$phase_stopped" --argjson guard "$deadline_stopped" \
		'{schemaVersion:2,evidenceClass:"r2_tls_peer_incomplete_deadline",complete:false,
      deadlineReached:true,networkStarted:$network,ownedEvidenceCLIStopped:$child,
      monitorStopped:$monitor,validatorStopped:$validator,gateWriterStopped:$gateStopped,
      phaseStopped:$phase,deadlineGuardStopped:$guard,
      harnessKillSent:$killed,helperKillSent:false,containsSecrets:false,
      containsRawCertificate:false}' >"$deadline_result"
	chmod 600 "$deadline_result"; printf '%s\n' "$deadline_result"; exit 124
}
trap cleanup_on_exit EXIT
trap 'signal_exit 129' HUP
trap 'signal_exit 130' INT
trap 'signal_exit 143' TERM

r2tls_deadline_guard "$deadline_ready" "$deadline_expired" "$deadline_stop" "$deadline_ack" \
	"$deadline_duration_ms" "$$" &
deadline_pid=$!; deadline_stopped=false
while [ ! -f "$deadline_ready" ] && r2tls_deadline_open &&
	owned_aux_alive "$deadline_pid"; do sleep 0.01; done
[ -f "$deadline_ready" ] && [ ! -L "$deadline_ready" ] || deadline_exit

if [ "$test_active" = false ]; then
	r2tls_capture_network "$before" & phase_pid=$!; phase_stopped=false
	if ! wait_phase_naturally; then r2tls_deadline_open || deadline_exit; exit 8; fi
fi
r2tls_deadline_open || deadline_exit
mkfifo "$gate" "$report_fifo"; chmod 600 "$gate" "$report_fifo"
if [ "$test_scenario" = blocked_validator ]; then
	(exec 3<"$report_fifo"; while :; do sleep 1; done) & jq_pid=$!
else r2tls_reconstruct_report "$report_fifo" "$report" & jq_pid=$!; fi
(
	if [ "$test_scenario" = blocked_gate ]; then while :; do sleep 1; done; fi
	IFS= read -r token <"$gate"; [ "$token" = GO ] || exit 71
	if [ "$test_active" = true ]; then
		if [ "$test_scenario" = blocked_validator ]; then
			exec /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
				"$test_cli" "$test_report" </dev/null >"$report_fifo" 2>/dev/null
		else exec /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
			"$test_cli" 1000 </dev/null >"$report_fifo" 2>/dev/null; fi
	else
		exec /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
			"$R2TLS_CLI" </dev/null >"$report_fifo" 2>/dev/null
	fi
) & child_pid=$!
r2tls_monitor_exact_child "$child_pid" "$$" "$monitor_expected_comm" \
	"$monitor_expected_command" "$ready" "$stop" "$monitor" & monitor_pid=$!
while [ ! -f "$ready" ] && r2tls_deadline_open && owned_aux_alive "$monitor_pid"; do
	sleep 0.01
done
[ -f "$ready" ] && [ ! -L "$ready" ] || deadline_exit

network_started=$([ "$test_active" = true ] && printf false || printf true)
printf '%s\n' GO >"$gate" & gate_pid=$!; gate_stopped=false
while owned_aux_alive "$gate_pid" && r2tls_deadline_open; do sleep 0.01; done
owned_aux_alive "$gate_pid" && deadline_exit
set +e; wait "$gate_pid"; gate_rc=$?; set -e; gate_pid=; gate_stopped=true
[ "$gate_rc" -eq 0 ] || exit 9
if [ "$test_scenario" = signal ]; then
	while r2tls_deadline_open; do sleep 0.05; done
	deadline_exit
fi

while owned_child_alive && r2tls_deadline_open; do sleep 0.01; done
owned_child_alive && deadline_exit
stop_child; cli_rc=$child_rc
while owned_aux_alive "$jq_pid" && r2tls_deadline_open; do sleep 0.01; done
owned_aux_alive "$jq_pid" && deadline_exit
set +e; wait "$jq_pid"; report_rc=$?; set -e; jq_pid=; validator_stopped=true
stop_monitor; rm -f "$gate" "$report_fifo"
r2tls_deadline_open && [ "$monitor_stopped" = true ] || deadline_exit
[ "$test_active" = false ] || exit 12

r2tls_capture_network "$after" & phase_pid=$!; phase_stopped=false
if ! wait_phase_naturally; then r2tls_deadline_open || deadline_exit; exit 10; fi
projection=false; r2tls_network_projection_stable "$before" "$after" && projection=true
ipv4_changed=false
[ "$(jq -r .ipv4RouteSHA256 "$before")" = "$(jq -r .ipv4RouteSHA256 "$after")" ] || ipv4_changed=true
runs_before=$launchd_runs_before
runs_after=$(r2tls_launchd_runs) || runs_after=-1
launchd=false; [ "$runs_before" -eq "$runs_after" ] && r2tls_launchd_inactive && launchd=true
manifest_stable=false
if r2tls_candidate_manifest_matches_approval "$authorized_manifest_sha"; then
	manifest_stable=true
fi
artifact=false
expected_cli_sha=$(jq -r '.artifacts.arm64CLISHA256 // empty' "$R2TLS_MANIFEST") || expected_cli_sha=
if [ -n "$expected_cli_sha" ] &&
	[ "$(r2tls_hash_file "$R2TLS_CLI")" = "$expected_cli_sha" ]; then artifact=true; fi
r2tls_deadline_open || deadline_exit
cleanup_safe=false
r2tls_process_absent PowerVPN && r2tls_helpers_absent && r2tls_native_absent &&
	r2tls_cli_absent && cleanup_safe=true
report_valid=false; report_json=null; observed=false; transport=false; trust=false
disposition=unavailable; compatibility=inconclusive
if [ "$report_rc" -eq 0 ] && [ -f "$report" ] && [ ! -L "$report" ]; then
	report_valid=true; report_json=$(jq -c . "$report")
	[ "$(jq -r .status "$report")" = observed ] && observed=true
	r2tls_transport_evidence_complete "$report" && transport=true
	r2tls_trust_evidence_complete "$report" && trust=true
	disposition=$(r2tls_trust_disposition "$report")
	compatibility=$(r2tls_compatibility_outcome "$report")
fi
monitor_valid=false; monitor_json=null; monitor_execution=false
monitor_quality=$(r2tls_monitor_quality "$monitor")
if r2tls_monitor_schema_exact "$monitor"; then
	monitor_valid=true; monitor_json=$(jq -c . "$monitor")
	r2tls_monitor_execution_safe "$monitor" && monitor_execution=true
fi
environment=false; [ "$projection" = true ] && [ "$launchd" = true ] && environment=true
if r2tls_finalization_barrier; then finalization_rc=0; else finalization_rc=$?; fi
[ "$finalization_rc" -ne 124 ] || deadline_exit
[ "$finalization_rc" -eq 0 ] || exit 11
trap - EXIT HUP INT TERM; cleanup_resources
printf '%s\n' "$result"
[ "$checkpoint" = true ]
