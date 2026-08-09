#!/bin/sh

set -eu
umask 077

R1_REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=scripts/lib/r1_xpc_runtime.sh
. "$R1_REPO_ROOT/scripts/lib/r1_xpc_runtime.sh"
# shellcheck source=scripts/lib/r1_xpc_experiments.sh
. "$R1_REPO_ROOT/scripts/lib/r1_xpc_experiments.sh"

usage() { printf 'usage: %s [--preflight-only|--experiment-2-generation-binding|--experiment-3-first-terminal]\n' "$0" >&2; exit 2; }
[ "$#" -le 1 ] || usage
mode=live
experiment_2=false
experiment_3=false
R1_EXPERIMENT_ATTEMPT=1
if [ "$#" -eq 1 ]; then
	case "$1" in
	--preflight-only) mode=preflight ;;
	--experiment-2-generation-binding) experiment_2=true; R1_EXPERIMENT_ATTEMPT=2 ;;
	--experiment-3-first-terminal) experiment_3=true; R1_EXPERIMENT_ATTEMPT=3 ;;
	*) usage ;;
	esac
fi
test_active_monitor=false
case "${POWERVPN_R1_TEST_ACTIVE_MONITOR_SIGNAL:-}" in
'') ;;
reviewed-no-xpc)
	[ "$mode" = preflight ] || usage
	test_active_monitor=true
	test_root=${POWERVPN_R1_TEST_SCRATCH_ROOT:-}
	test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
	case "$test_root" in "$test_parent"/powervpn-r1-harness-test.*) ;; *) usage ;; esac
	R1_SCRATCH_ROOT=$test_root
	;;
*) usage ;;
esac
test_experiment_2_gate=false
case "${POWERVPN_R1_TEST_EXPERIMENT2_GATE_ONLY:-}" in
'') ;;
reviewed-no-xpc) [ "$experiment_2" = true ] || usage; test_experiment_2_gate=true ;;
*) usage ;;
esac
test_experiment_3_gate=false
case "${POWERVPN_R1_TEST_EXPERIMENT3_GATE_ONLY:-}" in
'') ;;
reviewed-no-xpc) [ "$experiment_3" = true ] || usage; test_experiment_3_gate=true ;;
*) usage ;;
esac
if [ "$test_experiment_2_gate" = true ] || [ "$test_experiment_3_gate" = true ]; then
	test_root=${POWERVPN_R1_TEST_SCRATCH_ROOT:-}
	test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
	case "$test_root" in "$test_parent"/powervpn-r1-harness-test.*) ;; *) usage ;; esac
	R1_SCRATCH_ROOT=$test_root
fi

r1_cold_preflight
if [ "$mode" = preflight ] && [ "$test_active_monitor" = false ]; then
	r1_preflight_json
	[ "$R1_PREFLIGHT_SAFE" = true ]
	exit
fi
if [ "$R1_PREFLIGHT_SAFE" != true ]; then
	r1_preflight_json >&2
	exit 3
fi

if [ "$test_active_monitor" = true ] || [ "$test_experiment_2_gate" = true ] ||
	[ "$test_experiment_3_gate" = true ]; then
	[ -d "$R1_SCRATCH_ROOT" ] && [ ! -L "$R1_SCRATCH_ROOT" ] &&
		[ "$(stat -f '%u:%Lp' "$R1_SCRATCH_ROOT")" = "$(id -u):700" ] || usage
elif ! r1_prepare_scratch_root; then
	echo 'error: R1 scratch root must be an owned, non-symlink mode-700 directory' >&2
	exit 4
fi
if [ "$experiment_3" = true ]; then
	r1_validate_experiment_3_predecessors "$R1_SCRATCH_ROOT" || {
		echo 'error: experiment 3 predecessor signature is absent or mismatched' >&2
		exit 8
	}
	if [ "$test_experiment_3_gate" = true ]; then
		jq -n '{experimentAttempt:3,predecessorsValidated:true,xpcSent:false}'
		exit 0
	fi
elif [ "$experiment_2" = true ]; then
	r1_validate_experiment_2_predecessor "$R1_SCRATCH_ROOT" || {
		echo 'error: experiment 2 predecessor signature is absent or mismatched' >&2
		exit 7
	}
	if [ "$test_experiment_2_gate" = true ]; then
		jq -n '{experimentAttempt:2,predecessorValidated:true,xpcSent:false}'
		exit 0
	fi
else
	existing_runs=$(find "$R1_SCRATCH_ROOT" -mindepth 1 -maxdepth 1 -name 'run-*' -print |
		awk 'END {print NR+0}')
	[ "$existing_runs" -eq 0 ] || {
		echo 'error: experiment attempt 1 already has retained run evidence; refusing retry' >&2
		exit 6
	}
fi
run_dir="$R1_SCRATCH_ROOT/run-$(date -u '+%Y%m%dT%H%M%SZ')-$$"
mkdir "$run_dir"
chmod 700 "$run_dir"
before="$run_dir/network-before.json"
after="$run_dir/network-after.json"
probe="$run_dir/probe.json"
monitor="$run_dir/helper-monitor.json"
ready_file="$run_dir/.monitor-ready"
stop_file="$run_dir/.monitor-stop"
signal_evidence="$run_dir/incomplete-signal.json"
result="$run_dir/result.json"
monitor_pid=

cleanup_monitor() {
	if [ -n "$monitor_pid" ]; then
		[ -e "$stop_file" ] || r1_create_sentinel "$stop_file" || true
		wait "$monitor_pid" 2>/dev/null || true
		monitor_pid=
	fi
	rm -f "$ready_file" "$stop_file"
}
observe_helper_absence() {
	absence_count=0
	while ! r1_process_absent com.leadsec.charon-xpc && [ "$absence_count" -lt 500 ]; do
		absence_count=$((absence_count + 1))
		sleep 0.01
	done
	r1_process_absent com.leadsec.charon-xpc
}
signal_exit() {
	signal_status=$1
	trap - EXIT HUP INT TERM
	cleanup_monitor
	signal_helper_absent=false
	observe_helper_absence && signal_helper_absent=true
	r1_write_signal_evidence "$signal_evidence" "$signal_status" "$signal_helper_absent"
	exit "$signal_status"
}
trap cleanup_monitor EXIT
trap 'signal_exit 129' HUP
trap 'signal_exit 130' INT
trap 'signal_exit 143' TERM

cli_sha_before=$(r1_hash_file "$R1_CLI")
artifact_before=$R1_ARTIFACT_EXACT
log_before=$(r1_vendor_log_metadata)
R1_LOG_BEFORE_ABSENT=false
[ "$log_before" = absent ] && R1_LOG_BEFORE_ABSENT=true
launchd_runs_before=$(r1_launchd_runs)
POWERVPN_STRONGSWAN_ROOT="$R1_SCRATCH_ROOT" \
	"$R1_SNAPSHOT" --output "$before" >/dev/null

monitor_helper() (
	seen=false
	inspected=false
	failed=false
	max_count=0
	r1_create_sentinel "$ready_file" || exit 1
	while [ ! -e "$stop_file" ]; do
		if helper_pids=$(/usr/bin/pgrep -x com.leadsec.charon-xpc 2>/dev/null); then
			seen=true
			for helper_pid in $helper_pids; do
				set +e
				fd_output=$(/usr/sbin/lsof -nP -a -p "$helper_pid" -iTCP -iUDP 2>&1)
				fd_rc=$?
				set -e
				fd_count=$(r1_lsof_tcp_udp_count "$helper_pid" "$fd_rc" "$fd_output") || fd_count=
				if printf '%s\n' "$fd_count" | grep -Eq '^[0-9]+$'; then
					inspected=true
					[ "$fd_count" -le "$max_count" ] || max_count=$fd_count
				elif /bin/ps -p "$helper_pid" -o pid= 2>/dev/null | grep -q '[0-9]'; then
					failed=true
				fi
			done
		else
			[ "$?" -eq 1 ] || failed=true
		fi
		sleep 0.01
	done
	inspection=false
	[ "$seen" = true ] && [ "$inspected" = true ] && [ "$failed" = false ] && inspection=true
	jq -n --argjson seen "$seen" --argjson inspected "$inspection" \
		--argjson max "$max_count" \
		'{processSeen:$seen,inspectionSucceeded:$inspected,maxTCPUDPCount:$max}' >"$monitor"
	chmod 600 "$monitor"
)

monitor_helper &
monitor_pid=$!
ready_attempt=0
while [ ! -f "$ready_file" ] && [ "$ready_attempt" -lt 100 ]; do
	/bin/ps -p "$monitor_pid" -o pid= 2>/dev/null | grep -q '[0-9]' || break
	ready_attempt=$((ready_attempt + 1))
	sleep 0.01
done
[ -f "$ready_file" ] && [ ! -L "$ready_file" ] &&
	[ "$(/usr/bin/stat -f '%u:%Lp' "$ready_file")" = "$(id -u):600" ] || {
	echo 'error: helper monitor did not become ready' >&2
	exit 5
}
if [ "$test_active_monitor" = true ]; then
	while :; do sleep 1; done
fi

set +e
"$R1_CLI" xpc get-version --timeout-ms 3000 --json >"$probe" 2>/dev/null
probe_exit=$?
set -e
chmod 600 "$probe"

R1_NATURAL_EXIT=false
observe_helper_absence && R1_NATURAL_EXIT=true
r1_create_sentinel "$stop_file"
wait "$monitor_pid"
monitor_pid=
rm -f "$ready_file" "$stop_file"

POWERVPN_STRONGSWAN_ROOT="$R1_SCRATCH_ROOT" \
	"$R1_SNAPSHOT" --output "$after" >/dev/null
artifact_after=false
r1_artifacts_exact && artifact_after=true
cli_stable=false
[ "$(r1_hash_file "$R1_CLI")" = "$cli_sha_before" ] && cli_stable=true
log_after_safe=false
log_changed=true
if log_after=$(r1_vendor_log_metadata); then
	log_after_safe=true
	[ "$log_after" = "$log_before" ] && log_changed=false
fi
R1_LOG_AFTER_SAFE=$log_after_safe
R1_LOG_CHANGED=$log_changed
launchd_runs_after=$(r1_launchd_runs)
R1_LAUNCHD_RUNS_DELTA=$((launchd_runs_after - launchd_runs_before))

R1_NETWORK_STABLE=false
r1_network_stable "$before" "$after" && R1_NETWORK_STABLE=true
r1_sad_spd_evidence "$before" "$after"
[ "$R1_SAD_SPD_STATE" != indeterminate ] || R1_NETWORK_STABLE=false
r1_extract_probe "$probe"
R1_PROCESS_SEEN=$(jq -r '.processSeen' "$monitor")
R1_INSPECTION_SUCCEEDED=$(jq -r '.inspectionSucceeded' "$monitor")
R1_MAX_FDS=$(jq -r '.maxTCPUDPCount' "$monitor")

gui_after=false
r1_process_absent PowerVPN && gui_after=true
other_helpers_after=false
if r1_process_absent com.leadsec.ipsec-xpc &&
	r1_process_absent com.leadsec.sh-xpc; then
	other_helpers_after=true
fi
launchd_after=false
r1_launchd_inactive && launchd_after=true
dns_after=false
r1_lstat_enoent "$R1_DNS_RECOVERY" && dns_after=true
cleanup=false
[ "$R1_NATURAL_EXIT" = true ] && [ "$gui_after" = true ] &&
	[ "$other_helpers_after" = true ] &&
	[ "$launchd_after" = true ] && [ "$dns_after" = true ] && cleanup=true
R1_ARTIFACT_STABLE=false
[ "$artifact_before" = true ] && [ "$artifact_after" = true ] &&
	[ "$cli_stable" = true ] && [ "$log_after_safe" = true ] && R1_ARTIFACT_STABLE=true
R1_SERVER_TRAFFIC=null
R1_SERVER_TRAFFIC_STATE=unavailable_process_not_seen
if [ "$R1_PROCESS_SEEN" = true ]; then
	R1_SERVER_TRAFFIC_STATE=unavailable_inspection_failed
	if [ "$R1_INSPECTION_SUCCEEDED" = true ]; then
		R1_SERVER_TRAFFIC=true; R1_SERVER_TRAFFIC_STATE=tcp_udp_fds_observed
		[ "$R1_MAX_FDS" -eq 0 ] && R1_SERVER_TRAFFIC=false && R1_SERVER_TRAFFIC_STATE=observed_no_tcp_udp_fds
	fi
fi
generation_accepted=false
case "$R1_GENERATION_RELATION" in launched | launched_and_exited) generation_accepted=true ;; esac
R1_CHECKPOINT_PASS=false
[ "$probe_exit" -eq 0 ] && [ "$R1_PROBE_VALID" = true ] &&
	[ "$R1_TRANSACTION" = true ] && [ "$R1_TRANSPORT" = accepted ] &&
	[ "$R1_EXACT" = true ] && [ "$R1_VERSION_LENGTH" = 5 ] &&
	[ "$R1_VERSION_MATCH" = true ] && [ "$R1_VERSION_SUCCESS" = true ] &&
	[ "$R1_CONNECTION_CANCEL_REQUESTED" = true ] && [ "$R1_PEER_MATCH" = true ] &&
	[ "$R1_PROCESS_SEEN" = true ] && [ "$R1_INSPECTION_SUCCEEDED" = true ] &&
	[ "$R1_MAX_FDS" -eq 0 ] && [ "$R1_NATURAL_EXIT" = true ] &&
	[ "$R1_NETWORK_STABLE" = true ] && [ "$R1_SERVER_TRAFFIC" = false ] && [ "$R1_SERVER_TRAFFIC_STATE" = observed_no_tcp_udp_fds ] &&
	[ "$R1_ARTIFACT_STABLE" = true ] && [ "$cleanup" = true ] &&
	[ "$R1_ACCEPTED_EXACT" = true ] && [ "$generation_accepted" = true ] &&
	[ "$R1_LAUNCHD_RUNS_DELTA" -eq 1 ] && R1_CHECKPOINT_PASS=true

r1_write_result "$result"
printf '%s\n' "$result"
[ "$R1_CHECKPOINT_PASS" = true ]
