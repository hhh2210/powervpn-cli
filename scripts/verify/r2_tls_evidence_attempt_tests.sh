#!/bin/sh

set -eu
umask 077

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
R2TLS_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$repo_root/scripts/lib/r2_tls_evidence_runtime.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_result.sh
. "$repo_root/scripts/lib/r2_tls_evidence_result.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_attempts.sh
. "$repo_root/scripts/lib/r2_tls_evidence_attempts.sh"

test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
test_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r2-tls-attempts.XXXXXX")
scratch=$test_root/scratch; mkdir "$scratch"; chmod 700 "$test_root" "$scratch"
cleanup() {
	exit_status=$?; trap - EXIT HUP INT TERM
	find "$test_root" -type l -delete 2>/dev/null || true
	find "$test_root" -type f -delete 2>/dev/null || true
	find "$test_root" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	exit "$exit_status"
}
trap cleanup EXIT HUP INT TERM

r2tls_attempt3_experiment_exact "$R2TLS_ATTEMPT3_EXPERIMENT"
if r2tls_attempt3_experiment_exact ''; then exit 1; fi
if r2tls_attempt3_experiment_exact attempt2-after-inconclusive-v1; then exit 1; fi
if (unset POWERVPN_R2_TLS_EVIDENCE_EXPERIMENT; r2tls_attempt3_environment_exact); then exit 1; fi
if (POWERVPN_R2_TLS_EVIDENCE_EXPERIMENT=attempt2-after-inconclusive-v1
	export POWERVPN_R2_TLS_EVIDENCE_EXPERIMENT; r2tls_attempt3_environment_exact); then exit 1; fi
(POWERVPN_R2_TLS_EVIDENCE_EXPERIMENT=$R2TLS_ATTEMPT3_EXPERIMENT
 export POWERVPN_R2_TLS_EVIDENCE_EXPERIMENT; r2tls_attempt3_environment_exact)
r2tls_attempt3_repo_lineage_exact

make_run() {
	make_dir=$1; make_result=$2; make_tag=$3
	mkdir "$make_dir"; chmod 700 "$make_dir"
	for make_name in monitor.json network-after.json network-before.json report.json; do
		printf '{"fixture":"%s-%s"}\n' "$make_tag" "$make_name" >"$make_dir/$make_name"
	done
	/bin/cp "$make_result" "$make_dir/result.json"; chmod 600 "$make_dir"/*.json
}
run1=$scratch/run-attempt1; run2=$scratch/run-attempt2
make_run "$run1" "$R2TLS_ATTEMPT1_FIXTURE" attempt1
make_run "$run2" "$R2TLS_ATTEMPT2_FIXTURE" attempt2
R2TLS_ATTEMPT1_RUN_AGGREGATE_SHA256=$(r2tls_attempt_run_aggregate "$run1")
R2TLS_ATTEMPT2_RUN_AGGREGATE_SHA256=$(r2tls_attempt_run_aggregate "$run2")
r2tls_attempt3_predecessor_exact "$scratch"

jq '.checkpointPass=true' "$R2TLS_ATTEMPT2_FIXTURE" >"$run2/result.json"; chmod 600 "$run2/result.json"
if r2tls_attempt3_predecessor_exact "$scratch"; then exit 1; fi
/bin/cp "$R2TLS_ATTEMPT2_FIXTURE" "$run2/result.json"; chmod 600 "$run2/result.json"
printf '\n' >>"$run2/monitor.json"
if r2tls_attempt3_predecessor_exact "$scratch"; then exit 1; fi
printf '{"fixture":"attempt2-monitor.json"}\n' >"$run2/monitor.json"; chmod 600 "$run2/monitor.json"
: >"$scratch/extra"; chmod 600 "$scratch/extra"
if r2tls_attempt3_predecessor_exact "$scratch"; then exit 1; fi
find "$scratch" -maxdepth 1 -name extra -type f -delete
mv "$run2" "$test_root/held-run"
if r2tls_attempt3_predecessor_exact "$scratch"; then exit 1; fi
mv "$test_root/held-run" "$run2"
r2tls_attempt3_predecessor_exact "$scratch"

saved_attempt2_fixture=$R2TLS_ATTEMPT2_FIXTURE
/bin/cp "$saved_attempt2_fixture" "$test_root/tampered-attempt2.json"; chmod 644 "$test_root/tampered-attempt2.json"
printf '\n' >>"$test_root/tampered-attempt2.json"
R2TLS_ATTEMPT2_FIXTURE=$test_root/tampered-attempt2.json
if r2tls_attempt3_repo_lineage_exact; then exit 1; fi
R2TLS_ATTEMPT2_FIXTURE=$saved_attempt2_fixture

candidate=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
if r2tls_attempt3_consume_authorization "$scratch" '' "$candidate"; then exit 1; fi
if r2tls_attempt3_consume_authorization "$scratch" "$R2TLS_ATTEMPT2_ARCHIVE_SHA256" "$candidate"; then exit 1; fi
consume1=$test_root/consume1; consume2=$test_root/consume2
(if r2tls_attempt3_consume_authorization "$scratch" "$candidate" "$candidate"; then
	printf 'pass\n'; else printf 'fail\n'; fi) >"$consume1" & consume1_pid=$!
(if r2tls_attempt3_consume_authorization "$scratch" "$candidate" "$candidate"; then
	printf 'pass\n'; else printf 'fail\n'; fi) >"$consume2" & consume2_pid=$!
wait "$consume1_pid"; wait "$consume2_pid"
[ "$(grep -hxc pass "$consume1" "$consume2" | awk '{n+=$1} END {print n+0}')" -eq 1 ]
marker=$scratch/.attempt3-consumed-$candidate
[ -d "$marker" ] && [ ! -L "$marker" ] &&
	[ "$(stat -f '%u:%Lp' "$marker")" = "$(id -u):700" ]
if r2tls_attempt3_predecessor_exact "$scratch"; then exit 1; fi
if r2tls_attempt3_consume_authorization "$scratch" "$candidate" "$candidate"; then exit 1; fi

report_raw=$test_root/report-raw.json; report=$test_root/report.json
jq -n '{schemaVersion:3,evidenceClass:"r2_tls_peer_value_free",status:"observed",
  chainLength:1,orderedCertificateSHA256:[("a"*64)],leafCertificateSHA256:("a"*64),
  leafSPKISHA256:("b"*64),sslTrustAccepted:false,sslTrustCategory:"untrusted_chain",
  basicTrustAccepted:false,basicTrustCategory:"untrusted_chain",
  transportProgress:{connectionStarted:true,preparingObserved:true,waitingObserved:false,
    verifyCallbackObserved:true,failedObserved:true,readyObserved:false},
  evidenceProgress:{metadataChainAccessAttempted:true,metadataChainAccessible:true,
    peerDERCopyCompleted:true,verifyCompletionInvokedWithFalse:true,
    verifyCompletionReturned:true,sslEvaluationStarted:true,sslEvaluationCompleted:true,
    basicEvaluationStarted:true,basicEvaluationCompleted:true,evaluationDeadlineExpired:false,
    duplicateVerifyCallbackObserved:false,transportEvidenceComplete:true,
    trustEvidenceComplete:true},
  applicationDataSent:false,verifyAccepted:false,containsRawCertificate:false,
  containsSubject:false,containsIssuer:false,containsSAN:false,containsSerial:false,
  containsSecrets:false}' >"$report_raw"; chmod 600 "$report_raw"
r2tls_filter_report "$report_raw" "$report"
r2tls_transport_evidence_complete "$report"; r2tls_trust_evidence_complete "$report"
[ "$(r2tls_compatibility_outcome "$report")" = blocked_by_system_trust ]
[ "$(r2tls_trust_disposition "$report")" = untrusted_chain ]
jq '.transportProgress.failedObserved=false' "$report_raw" >"$test_root/no-failed-raw.json"
chmod 600 "$test_root/no-failed-raw.json"
r2tls_filter_report "$test_root/no-failed-raw.json" "$test_root/no-failed.json"
r2tls_transport_evidence_complete "$test_root/no-failed.json"
reject_report_mutation() {
	mutation=$1; mutation_name=$2
	jq "$mutation" "$report_raw" >"$test_root/$mutation_name-raw.json"
	chmod 600 "$test_root/$mutation_name-raw.json"
	if r2tls_filter_report "$test_root/$mutation_name-raw.json" \
		"$test_root/$mutation_name.json"; then exit 1; fi
}
reject_report_mutation '.evidenceProgress.transportEvidenceComplete=false' bad-transport-derived
reject_report_mutation '.evidenceProgress.trustEvidenceComplete=false' bad-trust-derived
reject_report_mutation '.evidenceProgress.verifyCompletionReturned=false' bad-return-phase
reject_report_mutation '.evidenceProgress.extra=true' bad-progress-shape
jq '.sslTrustAccepted=true | .sslTrustCategory="accepted" |
  .basicTrustAccepted=true | .basicTrustCategory="accepted"' "$report_raw" >"$test_root/accepted-raw.json"
chmod 600 "$test_root/accepted-raw.json"
r2tls_filter_report "$test_root/accepted-raw.json" "$test_root/accepted.json"
[ "$(r2tls_compatibility_outcome "$test_root/accepted.json")" = compatible_under_system_trust ]
[ "$(r2tls_trust_disposition "$test_root/accepted.json")" = system_trusted ]
assert_disposition() {
	disposition_filter=$1; disposition_expected=$2
	jq "$disposition_filter" "$report_raw" >"$test_root/disposition-raw.json"
	chmod 600 "$test_root/disposition-raw.json"; find "$test_root" -name disposition.json -delete
	r2tls_filter_report "$test_root/disposition-raw.json" "$test_root/disposition.json"
	[ "$(r2tls_trust_disposition "$test_root/disposition.json")" = "$disposition_expected" ]
}
assert_disposition '.basicTrustAccepted=true | .basicTrustCategory="accepted" |
  .sslTrustCategory="hostname_mismatch"' hostname_mismatch
for disposition_category in expired not_yet_valid revoked other_failure; do
	assert_disposition ".sslTrustCategory=\"$disposition_category\" |\
    .basicTrustCategory=\"other_failure\"" "$disposition_category"
done
assert_disposition '.sslTrustCategory="unavailable"' unavailable
[ "$(r2tls_compatibility_outcome "$test_root/disposition.json")" = inconclusive ]
jq '.status="timed_out" | .chainLength=0 | .orderedCertificateSHA256=[] |
  .leafCertificateSHA256=null | .leafSPKISHA256=null | .sslTrustAccepted=false |
  .sslTrustCategory="unavailable" | .basicTrustAccepted=false |
  .basicTrustCategory="unavailable" | .evidenceProgress={metadataChainAccessAttempted:false,
    metadataChainAccessible:false,peerDERCopyCompleted:false,
    verifyCompletionInvokedWithFalse:false,verifyCompletionReturned:false,
    sslEvaluationStarted:false,sslEvaluationCompleted:false,basicEvaluationStarted:false,
    basicEvaluationCompleted:false,evaluationDeadlineExpired:false,
    duplicateVerifyCallbackObserved:false,transportEvidenceComplete:false,
    trustEvidenceComplete:false}' "$report_raw" >"$test_root/timeout-raw.json"
chmod 600 "$test_root/timeout-raw.json"
r2tls_filter_report "$test_root/timeout-raw.json" "$test_root/timeout.json"
if r2tls_transport_evidence_complete "$test_root/timeout.json"; then exit 1; fi
if r2tls_trust_evidence_complete "$test_root/timeout.json"; then exit 1; fi
[ "$(r2tls_compatibility_outcome "$test_root/timeout.json")" = inconclusive ]
[ "$(r2tls_trust_disposition "$test_root/timeout.json")" = unavailable ]
jq '.status="cancelled" | .evidenceProgress.verifyCompletionInvokedWithFalse=true |
  .evidenceProgress.verifyCompletionReturned=true' "$test_root/timeout-raw.json" \
	>"$test_root/late-rejection-raw.json"
chmod 600 "$test_root/late-rejection-raw.json"
r2tls_filter_report "$test_root/late-rejection-raw.json" "$test_root/late-rejection.json"
if r2tls_transport_evidence_complete "$test_root/late-rejection.json"; then exit 1; fi
jq '.evidenceProgress.metadataChainAccessAttempted=true |
  .evidenceProgress.metadataChainAccessible=true | .evidenceProgress.peerDERCopyCompleted=true |
  .evidenceProgress.verifyCompletionInvokedWithFalse=true |
  .evidenceProgress.verifyCompletionReturned=true |
	.transportProgress.verifyCallbackObserved=true |
  .evidenceProgress.transportEvidenceComplete=true' "$test_root/timeout-raw.json" \
	>"$test_root/transport-only-raw.json"
chmod 600 "$test_root/transport-only-raw.json"
r2tls_filter_report "$test_root/transport-only-raw.json" "$test_root/transport-only.json"
r2tls_transport_evidence_complete "$test_root/transport-only.json"
if r2tls_trust_evidence_complete "$test_root/transport-only.json"; then exit 1; fi
jq '.transportProgress.verifyCallbackObserved=false' "$test_root/transport-only-raw.json" \
	>"$test_root/metadata-without-callback-raw.json"
chmod 600 "$test_root/metadata-without-callback-raw.json"
if r2tls_filter_report "$test_root/metadata-without-callback-raw.json" \
	"$test_root/metadata-without-callback.json"; then exit 1; fi
jq '.evidenceProgress.duplicateVerifyCallbackObserved=true |
  .transportProgress.verifyCallbackObserved=false' "$test_root/timeout-raw.json" \
	>"$test_root/duplicate-without-callback-raw.json"
chmod 600 "$test_root/duplicate-without-callback-raw.json"
if r2tls_filter_report "$test_root/duplicate-without-callback-raw.json" \
	"$test_root/duplicate-without-callback.json"; then exit 1; fi
jq --slurpfile complete "$report_raw" '.evidenceProgress=$complete[0].evidenceProgress' \
	"$test_root/timeout-raw.json" >"$test_root/timeout-trust-contradiction.json"
chmod 600 "$test_root/timeout-trust-contradiction.json"
if r2tls_filter_report "$test_root/timeout-trust-contradiction.json" \
	"$test_root/timeout-trust-filtered.json"; then exit 1; fi

monitor=$test_root/monitor.json
jq -n '{schemaVersion:2,evidenceClass:"r2_tls_process_monitor",targetObserved:true,
  targetIdentityExact:true,targetIdentityStable:true,inspectionAttemptCount:1,
  inspectionSuccessCount:1,inspectionFailureCount:0,inspectionSucceeded:true,
  onlySealedEndpointTCP:true,sealedEndpointTCPObserved:true,maximumTCPCount:1,
  maximumUDPCount:0,vendorHelperObserved:false,nativeCharonObserved:false}' >"$monitor"
chmod 600 "$monitor"; r2tls_monitor_schema_exact "$monitor"
[ "$(r2tls_monitor_quality "$monitor")" = complete ]; r2tls_monitor_execution_safe "$monitor"
jq '.sealedEndpointTCPObserved=false | .maximumTCPCount=0' "$monitor" >"$test_root/degraded.json"
chmod 600 "$test_root/degraded.json"
[ "$(r2tls_monitor_quality "$test_root/degraded.json")" = degraded ]
r2tls_monitor_execution_safe "$test_root/degraded.json"
jq '.inspectionAttemptCount=2 | .inspectionFailureCount=1 | .inspectionSucceeded=false' \
	"$monitor" >"$test_root/failure.json"; chmod 600 "$test_root/failure.json"
[ "$(r2tls_monitor_quality "$test_root/failure.json")" = degraded ]
if r2tls_monitor_execution_safe "$test_root/failure.json"; then exit 1; fi
jq '.maximumUDPCount=1 | .onlySealedEndpointTCP=false' "$monitor" >"$test_root/invalid.json"
chmod 600 "$test_root/invalid.json"
[ "$(r2tls_monitor_quality "$test_root/invalid.json")" = invalid ]
[ "$(r2tls_monitor_quality "$test_root/absent.json")" = unavailable ]

r2tls_checkpoint_dimensions_pass true true true complete true
for dimensions in 'false true true complete true' 'true false true complete true' \
	'true true false complete true' 'true true true degraded true' \
	'true true true complete false'; do
	# shellcheck disable=SC2086
	if r2tls_checkpoint_dimensions_pass $dimensions; then exit 1; fi
done

printf '%s\n' 'R2 TLS evidence attempt3 lineage/dimension tests: PASS (fixtures only; no network)'
