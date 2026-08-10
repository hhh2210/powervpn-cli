#!/bin/sh
set -eu
umask 077
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
runner="$repo_root/scripts/run_r2_tls_evidence.sh"
attempt_tests="$repo_root/scripts/verify/r2_tls_evidence_attempt_tests.sh"
runtime_tests="$repo_root/scripts/verify/r2_tls_evidence_runtime_tests.sh"
finalization_tests="$repo_root/scripts/verify/r2_tls_evidence_finalization_tests.sh"
R2TLS_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$repo_root/scripts/lib/r2_tls_evidence_runtime.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_manifest.sh
. "$repo_root/scripts/lib/r2_tls_evidence_manifest.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_monitor.sh
. "$repo_root/scripts/lib/r2_tls_evidence_monitor.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_attempts.sh
. "$repo_root/scripts/lib/r2_tls_evidence_attempts.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_deadline.sh
. "$repo_root/scripts/lib/r2_tls_evidence_deadline.sh"
runs_before=$(r2tls_launchd_runs)
[ "$runs_before" -eq "$R2TLS_EXPECTED_LAUNCHD_RUNS" ]
r2tls_launchd_inactive
r2tls_helpers_absent
r2tls_native_absent
r2tls_candidate_manifest_exact
manifest_sha=$R2TLS_CANDIDATE_MANIFEST_SHA256
review=$(jq -r .reviewState "$R2TLS_MANIFEST")
if [ -e "$R2TLS_SCRATCH_ROOT" ]; then
	real_scratch_before=$(stat -f '%d:%i:%m:%z' "$R2TLS_SCRATCH_ROOT")
else real_scratch_before=absent; fi

test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
test_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r2-tls-test.XXXXXX")
chmod 700 "$test_root"
test_child_pid=; test_monitor_pid=; runner_pid=
cleanup() {
	exit_status=$?; trap - EXIT HUP INT TERM
	for cleanup_pid in "$runner_pid" "$test_monitor_pid" "$test_child_pid"; do
		[ -z "$cleanup_pid" ] || /bin/kill -TERM "$cleanup_pid" 2>/dev/null || true
	done
	find "$test_root" -type f -delete 2>/dev/null || true
	find "$test_root" -type p -delete 2>/dev/null || true
	find "$test_root" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

manifest_copy="$test_root/candidate-manifest.json"
/bin/cp "$R2TLS_MANIFEST" "$manifest_copy"; chmod 644 "$manifest_copy"
original_manifest=$R2TLS_MANIFEST; R2TLS_MANIFEST=$manifest_copy
r2tls_candidate_manifest_matches_approval "$manifest_sha"
printf '\n' >>"$manifest_copy"
if r2tls_candidate_manifest_matches_approval "$manifest_sha"; then exit 1; fi
R2TLS_MANIFEST=$original_manifest
report_source="$test_root/report-source.json"
jq -n '{schemaVersion:3,evidenceClass:"r2_tls_peer_value_free",status:"observed",
	  chainLength:1,orderedCertificateSHA256:[("a"*64)],leafCertificateSHA256:("a"*64),
	  leafSPKISHA256:("b"*64),sslTrustAccepted:false,sslTrustCategory:"untrusted_chain",
	  basicTrustAccepted:false,basicTrustCategory:"untrusted_chain",transportProgress:{
	    connectionStarted:true,preparingObserved:true,waitingObserved:false,
	    verifyCallbackObserved:true,failedObserved:true,readyObserved:false},evidenceProgress:{
	    metadataChainAccessAttempted:true,metadataChainAccessible:true,peerDERCopyCompleted:true,
	    verifyCompletionInvokedWithFalse:true,verifyCompletionReturned:true,sslEvaluationStarted:true,
	    sslEvaluationCompleted:true,basicEvaluationStarted:true,basicEvaluationCompleted:true,
	    evaluationDeadlineExpired:false,duplicateVerifyCallbackObserved:false,
	    transportEvidenceComplete:true,trustEvidenceComplete:true},applicationDataSent:false,
	  verifyAccepted:false,containsRawCertificate:false,containsSubject:false,containsIssuer:false,
	  containsSAN:false,containsSerial:false,containsSecrets:false}' >"$report_source"
chmod 600 "$report_source"
validate_report() {
	input=$1; expected=$2; fifo="$test_root/report-$expected.fifo"; output="$test_root/report-$expected.json"
	mkfifo "$fifo"; chmod 600 "$fifo"
	r2tls_reconstruct_report "$fifo" "$output" & validator_pid=$!
	/bin/cat "$input" >"$fifo"
	set +e; wait "$validator_pid"; validator_rc=$?; set -e
	rm -f "$fifo"
	[ "$validator_rc" -eq "$expected" ]
	if [ "$expected" -eq 0 ]; then
		[ -f "$output" ] && [ "$(stat -f '%Lp' "$output")" = 600 ]
		jq -e '.status=="observed" and .containsSecrets==false' "$output" >/dev/null
	else [ ! -e "$output" ]; fi
}
validate_report "$report_source" 0
jq '.extra=true' "$report_source" >"$test_root/extra.json"
validate_report "$test_root/extra.json" 1
jq '.sslTrustAccepted=true' "$report_source" >"$test_root/contradictory.json"
validate_report "$test_root/contradictory.json" 1
jq '.orderedCertificateSHA256[0]="A"+(("a"*63))' "$report_source" >"$test_root/nonhex.json"
validate_report "$test_root/nonhex.json" 1
jq '.chainLength=17 | .orderedCertificateSHA256=[range(0;17)|("a"*64)]' \
	"$report_source" >"$test_root/too-long-chain.json"
validate_report "$test_root/too-long-chain.json" 1
jq '.chainLength=1.5' "$report_source" >"$test_root/fractional-chain.json"
validate_report "$test_root/fractional-chain.json" 1
jq '.transportProgress.extra=true' "$report_source" >"$test_root/progress-extra.json"
validate_report "$test_root/progress-extra.json" 1

snapshot_before="$test_root/network-before.json"
snapshot_after="$test_root/network-after.json"
jq -n '{schemaVersion:1,timestamp:"before",ipv4RouteCount:10,
  ipv4RouteSHA256:"v4-before",ipv4PersistentRouteCount:4,
  ipv4PersistentRouteSHA256:"persistent",powerVPNProcessCount:0,
  nativeCharonPids:[],productionIKEPortsBoundByNative:false,
  containsSecrets:false,containsRawRoutes:false,containsRawSAState:false,
  defaultRouteSHA256:"default",dnsSHA256:"dns",utunNames:["utun0"],
  interfaceInventorySHA256:"interfaces",espPortSHA256:"esp",
  surgeProcessIdentitySHA256:"surge"}' >"$snapshot_before"
jq '.timestamp="after" | .ipv4RouteSHA256="v4-after"' "$snapshot_before" >"$snapshot_after"
r2tls_network_projection_stable "$snapshot_before" "$snapshot_after"
jq '.ipv4RouteCount=11' "$snapshot_after" >"$test_root/network-bad-count.json"
if r2tls_network_projection_stable "$snapshot_before" "$test_root/network-bad-count.json"; then exit 1; fi
jq '.ipv4PersistentRouteSHA256="changed"' "$snapshot_after" >"$test_root/network-bad-persistent.json"
if r2tls_network_projection_stable "$snapshot_before" "$test_root/network-bad-persistent.json"; then exit 1; fi

preflight="$test_root/preflight.json"
set +e; "$runner" --preflight-only >"$preflight" 2>/dev/null; preflight_rc=$?; set -e
if [ "$review" = post_attempt2_narrow_review_completed_no_findings ] ||
	[ "$review" = post_attempt2_narrow_review_completed_findings_applied ]; then
	[ "$preflight_rc" -eq 0 ]
	jq -e --arg manifest "$manifest_sha" '
    keys==["candidateManifestSHA256","cliReady","cold","containsSecrets",
      "dependenciesReady","evidenceClass","manifestExact","manifestReviewComplete",
      "networkStarted","predecessorReady","safeToObserve","schemaVersion"] and
    .safeToObserve==true and .manifestExact==true and
    .manifestReviewComplete==true and .candidateManifestSHA256==$manifest and
    .predecessorReady==true and
    .networkStarted==false and .containsSecrets==false
  ' "$preflight" >/dev/null
	set +e; "$runner" >/dev/null 2>&1; missing_rc=$?; set -e
		[ "$missing_rc" -eq 5 ]
		set +e
		POWERVPN_R2_TLS_EVIDENCE_EXPERIMENT=attempt2-after-inconclusive-v1 \
			"$runner" >/dev/null 2>&1
		old_attempt_rc=$?
		set -e
		[ "$old_attempt_rc" -eq 5 ]
	set +e
	POWERVPN_R2_APPROVED_MANIFEST_SHA256=old-portal-approval \
		"$runner" >/dev/null 2>&1
	old_rc=$?
	set -e
	[ "$old_rc" -eq 4 ]
else
	[ "$review" = post_attempt2_narrow_review_pending ] && [ "$preflight_rc" -eq 1 ]
	jq -e '.safeToObserve==false and .manifestExact==true and
		.manifestReviewComplete==false and .predecessorReady==true and
		.networkStarted==false' "$preflight" >/dev/null
fi
set +e; "$runner" --unknown >/dev/null 2>&1; usage_rc=$?; set -e
[ "$usage_rc" -eq 2 ]
"$attempt_tests" >/dev/null
"$finalization_tests" >/dev/null
"$runtime_tests" >/dev/null
fake_cli="$test_root/fake-cli"
fake_report="$test_root/fake-report.json"
/bin/cp "$report_source" "$fake_report"; chmod 600 "$fake_report"
/bin/cp /bin/sleep "$fake_cli"; chmod 700 "$fake_cli"
wait_for_file() {
	wait_path=$1; wait_attempt=0
	while [ ! -f "$wait_path" ] && [ "$wait_attempt" -lt 500 ]; do
		wait_attempt=$((wait_attempt + 1)); sleep 0.01
	done
	[ "$wait_attempt" -lt 500 ] && [ ! -L "$wait_path" ]
}

# A gate-blocked shell is owned by the harness but is not the expected executable.
wrapper_gate="$test_root/wrapper.fifo"; wrapper_ready="$test_root/wrapper.ready"
wrapper_stop="$test_root/wrapper.stop"; wrapper_monitor="$test_root/wrapper-monitor.json"
mkfifo "$wrapper_gate"
(
	IFS= read -r wrapper_token <"$wrapper_gate"
	[ "$wrapper_token" = STOP ]
) & test_child_pid=$!
r2tls_monitor_exact_child "$test_child_pid" "$$" "$fake_cli" "$fake_cli 1000" \
	"$wrapper_ready" "$wrapper_stop" "$wrapper_monitor" & test_monitor_pid=$!
wait_for_file "$wrapper_ready"; r2tls_create_sentinel "$wrapper_stop"
wait "$test_monitor_pid"; test_monitor_pid=
printf '%s\n' STOP >"$wrapper_gate"; wait "$test_child_pid"; test_child_pid=
jq -e '.schemaVersion==2 and .evidenceClass=="r2_tls_process_monitor" and
  .targetObserved==false and .targetIdentityExact==false and
  .targetIdentityStable==false and .inspectionAttemptCount==0 and
  .inspectionSuccessCount==0 and .inspectionFailureCount==0 and
  .inspectionSucceeded==false' "$wrapper_monitor" >/dev/null

# The same captured PID becomes the exact executable only after exec.
exec_gate="$test_root/exec.fifo"; exec_ready="$test_root/exec.ready"
exec_stop="$test_root/exec.stop"; exec_monitor="$test_root/exec-monitor.json"
mkfifo "$exec_gate"
(
	IFS= read -r exec_token <"$exec_gate"; [ "$exec_token" = GO ]
	exec "$fake_cli" 1000
) & test_child_pid=$!
captured_pid=$test_child_pid
r2tls_monitor_exact_child "$test_child_pid" "$$" "$fake_cli" "$fake_cli 1000" \
	"$exec_ready" "$exec_stop" "$exec_monitor" & test_monitor_pid=$!
wait_for_file "$exec_ready"; printf '%s\n' GO >"$exec_gate"
identity_attempt=0
while ! r2tls_monitor_exact_identity "$test_child_pid" "$$" "$fake_cli" \
	"$fake_cli 1000" && [ "$identity_attempt" -lt 500 ]; do
	identity_attempt=$((identity_attempt + 1)); sleep 0.01
done
[ "$identity_attempt" -lt 500 ] && [ "$test_child_pid" -eq "$captured_pid" ]
sleep 0.25; r2tls_create_sentinel "$exec_stop"; wait "$test_monitor_pid"; test_monitor_pid=
/bin/kill -TERM "$test_child_pid"; set +e; wait "$test_child_pid"; set -e; test_child_pid=
jq -e '.targetObserved and .targetIdentityExact and .targetIdentityStable and
  .inspectionAttemptCount>=1 and .inspectionSuccessCount>=1 and
  .inspectionFailureCount==0 and .inspectionSucceeded and
  .maximumTCPCount==0 and .maximumUDPCount==0' "$exec_monitor" >/dev/null

# A post-exec inspection failure is sticky and fail closed.
failure_ready="$test_root/failure.ready"; failure_stop="$test_root/failure.stop"
failure_monitor="$test_root/failure-monitor.json"
"$fake_cli" 1000 >/dev/null 2>&1 & test_child_pid=$!
(
	r2tls_monitor_socket_summary() { return 1; }
	r2tls_monitor_exact_child "$test_child_pid" "$$" "$fake_cli" "$fake_cli 1000" \
		"$failure_ready" "$failure_stop" "$failure_monitor"
) & test_monitor_pid=$!
wait_for_file "$failure_ready"; sleep 0.25
r2tls_create_sentinel "$failure_stop"; wait "$test_monitor_pid"; test_monitor_pid=
/bin/kill -TERM "$test_child_pid"; set +e; wait "$test_child_pid"; set -e; test_child_pid=
jq -e '.targetObserved and .targetIdentityExact and .targetIdentityStable and
  .inspectionAttemptCount>=1 and .inspectionSuccessCount==0 and
  .inspectionFailureCount>=1 and (.inspectionSucceeded|not)' \
	"$failure_monitor" >/dev/null

synthetic_stdout="$test_root/synthetic-stdout"
(
	export POWERVPN_R2_TLS_TEST_ACTIVE_MONITOR=reviewed-no-network-v1
	export POWERVPN_R2_TLS_TEST_SCRATCH_ROOT="$test_root"
	exec "$runner" --preflight-only >"$synthetic_stdout" 2>/dev/null
) &
runner_pid=$!
i=0
while [ -z "$(find "$test_root" -name .monitor-ready -type f -print -quit)" ] &&
	[ "$i" -lt 500 ]; do
	i=$((i+1)); sleep 0.01
done
[ "$i" -lt 500 ]
i=0
while r2tls_command_absent "$fake_cli" && [ "$i" -lt 500 ]; do
	i=$((i + 1)); sleep 0.01
done
[ "$i" -lt 500 ]
sleep 0.25
/bin/kill -TERM "$runner_pid"
completed_runner_pid=$runner_pid
set +e; wait "$runner_pid"; signal_rc=$?; set -e
runner_pid=
[ "$signal_rc" -eq 143 ]
signal_file=$(find "$test_root" -name incomplete-signal.json -type f -print)
[ "$(printf '%s\n' "$signal_file" | awk 'NF{n++} END{print n+0}')" -eq 1 ]
[ "$(stat -f '%Lp' "$signal_file")" = 600 ]
if ! jq -e 'keys==["complete","containsRawCertificate","containsSecrets","evidenceClass",
    "harnessKillSent","helperKillSent","monitorStopped","networkStarted",
    "ownedEvidenceCLIStopped","schemaVersion","signalExitStatus"] and
  .schemaVersion==1 and .evidenceClass=="r2_tls_peer_incomplete_signal" and
  .complete==false and .signalExitStatus==143 and .networkStarted==false and
  .ownedEvidenceCLIStopped==true and .monitorStopped==true and .harnessKillSent==false and
  .helperKillSent==false and .containsSecrets==false and
  .containsRawCertificate==false' "$signal_file" >/dev/null; then
	jq -c . "$signal_file" >&2
	exit 1
fi
monitor_file=$(find "$test_root" -name monitor.json -type f -print)
[ "$(printf '%s\n' "$monitor_file" | awk 'NF{n++} END{print n+0}')" -eq 1 ]
if ! jq -e '.schemaVersion==2 and .evidenceClass=="r2_tls_process_monitor" and
  .targetObserved==true and .targetIdentityExact==true and
  .targetIdentityStable==true and .inspectionSucceeded==true and
  .inspectionAttemptCount>=1 and .inspectionSuccessCount>=1 and
  .inspectionFailureCount==0 and
  .maximumTCPCount==0 and .maximumUDPCount==0 and
  .vendorHelperObserved==false and .nativeCharonObserved==false' \
	"$monitor_file" >/dev/null; then jq -c . "$monitor_file" >&2; exit 1; fi
[ -z "$(find "$test_root" \( -name start.fifo -o -name report.fifo -o \
	-name .monitor-ready -o -name .monitor-stop -o -name result.json \) -print)" ]
r2tls_command_absent "$fake_cli"
if /bin/ps -p "$completed_runner_pid" >/dev/null 2>&1; then exit 1; fi

if [ -e "$R2TLS_SCRATCH_ROOT" ]; then
	real_scratch_after=$(stat -f '%d:%i:%m:%z' "$R2TLS_SCRATCH_ROOT")
else real_scratch_after=absent; fi
[ "$real_scratch_after" = "$real_scratch_before" ]
[ "$(r2tls_launchd_runs)" -eq "$runs_before" ]
r2tls_launchd_inactive
r2tls_helpers_absent
r2tls_native_absent

	shellcheck -x -e SC1091 "$0" "$runner" \
		"$repo_root/scripts/lib/r2_tls_evidence_runtime.sh" \
		"$repo_root/scripts/lib/r2_tls_evidence_result.sh" \
	"$repo_root/scripts/lib/r2_tls_evidence_manifest.sh" \
	"$repo_root/scripts/lib/r2_tls_evidence_monitor.sh" \
	"$repo_root/scripts/lib/r2_tls_evidence_attempts.sh" \
	"$repo_root/scripts/lib/r2_tls_evidence_deadline.sh" \
	"$repo_root/scripts/lib/r2_tls_evidence_finalize.sh" \
	"$attempt_tests" "$runtime_tests" "$finalization_tests"
printf '%s\n' 'R2 TLS evidence harness tests: PASS (no network sent)'
