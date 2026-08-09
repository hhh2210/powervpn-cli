#!/bin/sh

set -eu
umask 077

R2_REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=scripts/lib/r2_portal_runtime.sh
. "$R2_REPO_ROOT/scripts/lib/r2_portal_runtime.sh"

usage() { printf 'usage: %s [--preflight-only]\n' "$0" >&2; exit 2; }
[ "$#" -le 1 ] || usage
mode=live
if [ "$#" -eq 1 ]; then
	[ "$1" = --preflight-only ] || usage
	mode=preflight
fi

test_active=false
case "${POWERVPN_R2_TEST_ACTIVE_MONITOR_SIGNAL:-}" in
'') ;;
reviewed-no-network-active-cli-v1)
	[ "$mode" = preflight ] || usage
	test_active=true
	test_root=${POWERVPN_R2_TEST_SCRATCH_ROOT:-}
	test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
	case "$test_root" in "$test_parent"/powervpn-r2-harness-test.*) ;; *) usage ;; esac
	[ -d "$test_root" ] && [ ! -L "$test_root" ] &&
		[ "$(/usr/bin/stat -f '%u:%Lp' "$test_root")" = "$(id -u):700" ] || usage
	test_cli=$test_root/fake-cli
	test_report=$test_root/cancelled-report.json
	[ -f "$test_cli" ] && [ ! -L "$test_cli" ] && [ -x "$test_cli" ] &&
		[ "$(/usr/bin/stat -f '%u:%Lp' "$test_cli")" = "$(id -u):700" ] || usage
	[ -f "$test_report" ] && [ ! -L "$test_report" ] &&
		[ "$(/usr/bin/stat -f '%u:%Lp' "$test_report")" = "$(id -u):600" ] || usage
	R2_SCRATCH_ROOT=$test_root
	;;
*) usage ;;
esac

r2_cold_preflight
if [ "$test_active" = true ] && [ "$R2_PREFLIGHT_SAFE" = false ] &&
	[ "$R2_GUI_ABSENT" = true ] && [ "$R2_HELPERS_ABSENT" = true ] &&
	[ "$R2_NATIVE_ABSENT" = true ] && [ "$R2_CLI_ABSENT" = true ] &&
	[ "$R2_LAUNCHD_EXACT" = true ] && [ "$R2_CLI_READY" = true ] &&
	[ "$R2_DEPENDENCIES_READY" = true ]; then
	# The hidden preflight-only branch runs only the owned fake child validated
	# above, so it remains independent of a changing candidate manifest.
	R2_PREFLIGHT_SAFE=true
fi
if [ "$mode" = preflight ] && [ "$test_active" = false ]; then
	r2_preflight_json
	[ "$R2_PREFLIGHT_SAFE" = true ]
	exit
fi
if [ "$R2_PREFLIGHT_SAFE" != true ]; then
	r2_preflight_json >&2
	exit 3
fi

if [ "$mode" = live ]; then
	[ "$R2_MANIFEST_EXACT" = true ] &&
		[ "${POWERVPN_R2_APPROVED_MANIFEST_SHA256:-}" = "$R2_CANDIDATE_MANIFEST_SHA256" ] || {
		echo 'error: reviewed R2 candidate manifest approval is absent or stale' >&2
		exit 4
	}
	[ "${POWERVPN_R2_ROTATED_CREDENTIAL_CONFIRMATION:-}" = "$R2_CONFIRMATION_TOKEN" ] || {
		echo 'error: reviewed rotated-credential confirmation is absent' >&2
		exit 5
	}
	(: </dev/tty >/dev/tty) 2>/dev/null || {
		echo 'error: R2 login requires a direct controlling TTY' >&2
		exit 6
	}
	r2_prepare_scratch_root || {
		echo 'error: R2 scratch root must be an owned non-symlink mode-700 directory' >&2
		exit 7
	}
	existing_runs=$(find "$R2_SCRATCH_ROOT" -mindepth 1 -maxdepth 1 -name 'run-*' -print |
		awk 'END {print NR+0}')
	[ "$existing_runs" -eq 0 ] || {
		echo 'error: retained R2 live evidence exists; refusing an unreviewed retry' >&2
		exit 8
	}
fi

run_kind=run
[ "$test_active" = false ] || run_kind=synthetic
run_dir="$R2_SCRATCH_ROOT/$run_kind-$(date -u '+%Y%m%dT%H%M%SZ')-$$"
mkdir "$run_dir"; chmod 700 "$run_dir"
before="$run_dir/network-before.json"; after="$run_dir/network-after.json"
fifo="$run_dir/cli-stdout.fifo"; report="$run_dir/cli-report.json"
monitor="$run_dir/portal-monitor.json"; result="$run_dir/result.json"
ready_file="$run_dir/.monitor-ready"; stop_file="$run_dir/.monitor-stop"
signal_evidence="$run_dir/incomplete-signal.json"
monitor_pid=; cli_pid=; jq_pid=
network_command_started=false
cli_signal_forwarded=false; cli_exited_within_deadline=false
cli_deadline_reached=false; cli_signal_rc=null; harness_kill_sent=false

cli_is_owned_child() {
	owned_pid=$1
	[ -n "$owned_pid" ] && /bin/ps -p "$owned_pid" -o ppid= -o state= 2>/dev/null |
		awk -v parent="$$" '$1 == parent && $2 !~ /^Z/ { active=1 } END { exit !active }'
}
wait_cli_naturally() {
	natural_cli_pid=$cli_pid
	while cli_is_owned_child "$natural_cli_pid"; do sleep 0.05; done
	set +e; wait "$natural_cli_pid"; natural_cli_rc=$?; set -e
}
signal_cli_bounded() {
	forward_signal=$1; owned_cli_pid=$cli_pid
	[ -n "$owned_cli_pid" ] || return 0
	if cli_is_owned_child "$owned_cli_pid" &&
		/bin/kill -"$forward_signal" "$owned_cli_pid" 2>/dev/null; then
		cli_signal_forwarded=true
	fi
	wait_attempt=0
	while cli_is_owned_child "$owned_cli_pid" && [ "$wait_attempt" -lt 500 ]; do
		wait_attempt=$((wait_attempt + 1)); sleep 0.05
	done
	if cli_is_owned_child "$owned_cli_pid"; then
		cli_deadline_reached=true
		if /bin/kill -KILL "$owned_cli_pid" 2>/dev/null; then
			harness_kill_sent=true
		fi
	else
		cli_exited_within_deadline=true
	fi
	set +e; wait "$owned_cli_pid"; cli_signal_rc=$?; set -e
	cli_pid=
}

cleanup_monitor() {
	if [ -n "$monitor_pid" ]; then
		[ -e "$stop_file" ] || r2_create_sentinel "$stop_file" || true
		wait "$monitor_pid" 2>/dev/null || true
		monitor_pid=
	fi
	rm -f "$ready_file" "$stop_file"
}
cleanup_runtime() {
	if [ -n "$cli_pid" ]; then signal_cli_bounded TERM; fi
	if [ -n "$jq_pid" ]; then wait "$jq_pid" 2>/dev/null || true; jq_pid=; fi
	cleanup_monitor
	rm -f "$fifo"
}
signal_exit() {
	forward_signal=$1; signal_status=$2
	trap - EXIT; trap '' HUP INT TERM
	signal_cli_bounded "$forward_signal"
	report_rc=-1
	if [ -n "$jq_pid" ]; then set +e; wait "$jq_pid"; report_rc=$?; set -e; jq_pid=; fi
	cleanup_monitor; rm -f "$fifo"
	monitor_stopped=false
	[ -f "$monitor" ] && [ ! -L "$monitor" ] && monitor_stopped=true
	report_exact=false; reported_cancelled=false
	if [ "$report_rc" -eq 0 ] && jq -e '.status=="cancelled" and .transactionAccepted==false' "$report" >/dev/null 2>&1; then
		report_exact=true; reported_cancelled=true
	fi
	jq -n --argjson status "$signal_status" --argjson stopped "$monitor_stopped" \
		--argjson started "$network_command_started" \
		--argjson forwarded "$cli_signal_forwarded" --argjson exited "$cli_exited_within_deadline" \
		--argjson deadline "$cli_deadline_reached" --argjson cliRC "$cli_signal_rc" \
		--argjson exact "$report_exact" --argjson cancelled "$reported_cancelled" \
		--argjson killed "$harness_kill_sent" \
		'{schemaVersion:1,evidenceClass:"r2_incomplete_signal_cleanup",complete:false,signalExitStatus:$status,monitorStopped:$stopped,networkCommandStarted:$started,cliSignalForwarded:$forwarded,cliExitedWithinDeadline:$exited,cliDeadlineReached:$deadline,cliExitStatus:$cliRC,cliReportExact:$exact,cliReportedCancelled:$cancelled,harnessKillSent:$killed,helperKillSent:false,containsSecrets:false,containsRawPortal:false}' >"$signal_evidence"
	chmod 600 "$signal_evidence"
	exit "$signal_status"
}
trap cleanup_runtime EXIT
trap 'signal_exit TERM 129' HUP
trap 'signal_exit INT 130' INT
trap 'signal_exit TERM 143' TERM

start_monitor() {
	monitor_target=$1
	r2_monitor_portal "$monitor_target" "$ready_file" "$stop_file" "$monitor" &
	monitor_pid=$!
	ready_attempt=0
	while [ ! -f "$ready_file" ] && [ "$ready_attempt" -lt 200 ]; do
		/bin/ps -p "$monitor_pid" -o pid= 2>/dev/null | grep -q '[0-9]' || break
		ready_attempt=$((ready_attempt + 1)); sleep 0.01
	done
	[ -f "$ready_file" ] && [ ! -L "$ready_file" ] &&
		[ "$(/usr/bin/stat -f '%u:%Lp' "$ready_file")" = "$(id -u):600" ] || {
		echo 'error: R2 portal monitor did not become ready' >&2
		exit 8
	}
}

if [ "$test_active" = true ]; then
	mkfifo "$fifo"; chmod 600 "$fifo"
	r2_reconstruct_report "$fifo" "$report" & jq_pid=$!
	(
		while [ ! -f "$ready_file" ]; do sleep 0.01; done
		exec "$test_cli" "$test_report" >"$fifo" 2>/dev/null
	) & cli_pid=$!
	start_monitor "$cli_pid"
	wait_cli_naturally
	exit 12
fi

launchd_runs_before=$(r2_launchd_runs)
[ "$launchd_runs_before" -eq "$R2_EXPECTED_LAUNCHD_RUNS" ] && r2_launchd_inactive || exit 9
cli_sha_before=$(r2_hash_file "$R2_CLI")
r2_capture_network "$before" || exit 10
mkfifo "$fifo"; chmod 600 "$fifo"
r2_reconstruct_report "$fifo" "$report" &
jq_pid=$!
network_command_started=true
(
	while [ ! -f "$ready_file" ]; do sleep 0.01; done
	exec /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
		"$R2_CLI" login </dev/null >"$fifo" 2>/dev/tty
) &
cli_pid=$!
start_monitor "$cli_pid"

wait_cli_naturally; cli_rc=$natural_cli_rc; cli_pid=
wait "$jq_pid"; report_rc=$?; jq_pid=
cleanup_monitor
rm -f "$fifo"

r2_capture_network "$after" || exit 11
network_stable=false; r2_network_stable "$before" "$after" && network_stable=true
launchd_runs_after=$(r2_launchd_runs) || launchd_runs_after=-1
launchd_stable=false
[ "$launchd_runs_after" -eq "$launchd_runs_before" ] && r2_launchd_inactive && launchd_stable=true
artifact_stable=false
[ "$(r2_hash_file "$R2_CLI")" = "$cli_sha_before" ] && artifact_stable=true
cleanup_safe=false
r2_process_absent PowerVPN && r2_helpers_absent && r2_native_charon_absent &&
	r2_cli_absent && cleanup_safe=true

report_valid=false; report_json=null; transaction=false
if [ "$report_rc" -eq 0 ] && [ -f "$report" ] && [ ! -L "$report" ] &&
	[ "$(/usr/bin/stat -f '%u:%Lp' "$report")" = "$(id -u):600" ]; then
	report_valid=true; report_json=$(jq -c . "$report")
	transaction=$(jq -r '.transactionAccepted' "$report")
fi
monitor_valid=false; monitor_json=null; inspection=false; only=false; portal=false
max_tcp=0; max_udp=0; helper_seen=true; native_seen=true
if jq -e 'keys==["inspectionSucceeded","maximumTCPCount","maximumUDPCount","nativeCharonObserved","onlySealedPortalTCP","portalTCPObserved","targetObserved","vendorHelperObserved"]' "$monitor" >/dev/null 2>&1; then
	monitor_valid=true; monitor_json=$(jq -c . "$monitor")
	inspection=$(jq -r '.inspectionSucceeded' "$monitor")
	only=$(jq -r '.onlySealedPortalTCP' "$monitor"); portal=$(jq -r '.portalTCPObserved' "$monitor")
	max_tcp=$(jq -r '.maximumTCPCount' "$monitor"); max_udp=$(jq -r '.maximumUDPCount' "$monitor")
	helper_seen=$(jq -r '.vendorHelperObserved' "$monitor"); native_seen=$(jq -r '.nativeCharonObserved' "$monitor")
fi

checkpoint=false
[ "$cli_rc" -eq 0 ] && [ "$report_valid" = true ] && [ "$transaction" = true ] &&
	[ "$monitor_valid" = true ] && [ "$inspection" = true ] && [ "$only" = true ] &&
	[ "$portal" = true ] && [ "$max_tcp" -ge 1 ] && [ "$max_udp" -eq 0 ] &&
	[ "$helper_seen" = false ] && [ "$native_seen" = false ] &&
	[ "$network_stable" = true ] && [ "$launchd_stable" = true ] &&
	[ "$artifact_stable" = true ] && [ "$cleanup_safe" = true ] && checkpoint=true
jq -n --argjson pass "$checkpoint" --argjson cliRC "$cli_rc" \
	--arg manifest "$R2_CANDIDATE_MANIFEST_SHA256" \
	--argjson reportValid "$report_valid" --argjson report "$report_json" \
	--argjson monitorValid "$monitor_valid" --argjson monitor "$monitor_json" \
	--argjson network "$network_stable" --argjson launchd "$launchd_stable" \
	--argjson runsBefore "$launchd_runs_before" --argjson runsAfter "$launchd_runs_after" \
	--argjson artifact "$artifact_stable" --argjson cleanup "$cleanup_safe" \
	'{schemaVersion:1,evidenceClass:"r2_portal_login_live_window",candidateManifestSHA256:$manifest,manifestExact:true,checkpointPass:$pass,complete:true,cliExitStatus:$cliRC,cliReportExact:$reportValid,cliReport:$report,monitorExact:$monitorValid,monitor:$monitor,networkStable:$network,launchd:{inactiveAndRunsStable:$launchd,runsBefore:$runsBefore,runsAfter:$runsAfter},artifactIdentityStable:$artifact,cleanupSafe:$cleanup,credentialPath:{directControllingTTY:true,stdinUsed:false,argumentUsed:false,environmentUsed:false,fileUsed:false,rotatedCredentialConfirmed:true},harnessKillSent:false,containsSecrets:false,containsRawPortal:false}' >"$result"
chmod 600 "$result"
trap - EXIT HUP INT TERM
cleanup_runtime
printf '%s\n' "$result"
[ "$checkpoint" = true ]
