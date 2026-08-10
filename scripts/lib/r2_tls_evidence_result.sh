#!/bin/sh

# Closed classification of filtered TLS reports and process-monitor evidence.
# The caller must source r2_tls_evidence_runtime.sh first.
# shellcheck disable=SC2154

r2tls_monitor_schema_exact() {
	[ -f "$1" ] && [ ! -L "$1" ] && jq -e '
    keys==["evidenceClass","inspectionAttemptCount","inspectionFailureCount",
      "inspectionSucceeded","inspectionSuccessCount","maximumTCPCount","maximumUDPCount",
      "nativeCharonObserved","onlySealedEndpointTCP","schemaVersion","sealedEndpointTCPObserved",
      "targetIdentityExact","targetIdentityStable","targetObserved","vendorHelperObserved"] and
    .schemaVersion==2 and .evidenceClass=="r2_tls_process_monitor" and
    ([.targetObserved,.targetIdentityExact,.targetIdentityStable,.inspectionSucceeded,
      .onlySealedEndpointTCP,.sealedEndpointTCPObserved,.vendorHelperObserved,
      .nativeCharonObserved]|all(type=="boolean")) and
    ([.inspectionAttemptCount,.inspectionFailureCount,.inspectionSuccessCount,
      .maximumTCPCount,.maximumUDPCount]|all(type=="number" and floor==. and .>=0)) and
    .inspectionAttemptCount==(.inspectionSuccessCount+.inspectionFailureCount) and
    .targetIdentityExact==.targetObserved and
    ((.targetIdentityStable|not) or (.targetObserved and .targetIdentityExact)) and
    .inspectionSucceeded==(.targetIdentityStable and .inspectionAttemptCount>0 and
      .inspectionSuccessCount>0 and .inspectionFailureCount==0) and
    .sealedEndpointTCPObserved==(.maximumTCPCount>0) and
    (.maximumUDPCount==0 or (.onlySealedEndpointTCP|not))
  ' "$1" >/dev/null 2>&1
}

r2tls_monitor_quality() {
	[ -e "$1" ] || { printf 'unavailable\n'; return; }
	r2tls_monitor_schema_exact "$1" || { printf 'invalid\n'; return; }
	if jq -e '.targetObserved and .targetIdentityExact and .targetIdentityStable and
	    .inspectionSucceeded and .inspectionAttemptCount>=1 and .inspectionSuccessCount>=1 and
	    .inspectionFailureCount==0 and .onlySealedEndpointTCP and
	    .sealedEndpointTCPObserved and .maximumTCPCount==1 and .maximumUDPCount==0 and
	    (.vendorHelperObserved|not) and (.nativeCharonObserved|not)' "$1" >/dev/null; then
		printf 'complete\n'
	elif jq -e '.targetObserved and .targetIdentityExact and .targetIdentityStable and
	    .inspectionAttemptCount>=1 and .inspectionSuccessCount>=1 and
	    .onlySealedEndpointTCP and .maximumTCPCount<=1 and .maximumUDPCount==0 and
	    (.vendorHelperObserved|not) and (.nativeCharonObserved|not)' "$1" >/dev/null; then
		printf 'degraded\n'
	else
		printf 'invalid\n'
	fi
}

r2tls_monitor_execution_safe() {
	r2tls_monitor_schema_exact "$1" && jq -e '
    .targetObserved and .targetIdentityExact and .targetIdentityStable and
    .inspectionSucceeded and .inspectionAttemptCount>=1 and .inspectionSuccessCount>=1 and
    .inspectionFailureCount==0 and .onlySealedEndpointTCP and
    .maximumTCPCount<=1 and .maximumUDPCount==0 and
    (.vendorHelperObserved|not) and (.nativeCharonObserved|not)
  ' "$1" >/dev/null
}

r2tls_transport_evidence_complete() {
	jq -e '.evidenceProgress.transportEvidenceComplete and
    .evidenceProgress.metadataChainAccessAttempted and
    .evidenceProgress.metadataChainAccessible and .evidenceProgress.peerDERCopyCompleted and
    .evidenceProgress.verifyCompletionInvokedWithFalse and
    .evidenceProgress.verifyCompletionReturned and
    (.evidenceProgress.duplicateVerifyCallbackObserved|not)' "$1" >/dev/null
}

r2tls_trust_evidence_complete() {
	jq -e '.evidenceProgress.trustEvidenceComplete and .evidenceProgress.peerDERCopyCompleted and
    .evidenceProgress.sslEvaluationStarted and .evidenceProgress.sslEvaluationCompleted and
    .evidenceProgress.basicEvaluationStarted and .evidenceProgress.basicEvaluationCompleted and
    (.evidenceProgress.evaluationDeadlineExpired|not) and
    (.evidenceProgress.duplicateVerifyCallbackObserved|not)' "$1" >/dev/null
}

r2tls_trust_disposition() {
	jq -r 'if (.evidenceProgress.trustEvidenceComplete|not) then "unavailable"
    elif .sslTrustAccepted then "system_trusted"
    elif .sslTrustCategory=="unavailable" or .basicTrustCategory=="unavailable" then "unavailable"
    elif .basicTrustAccepted and .sslTrustCategory=="hostname_mismatch" then "hostname_mismatch"
    elif (.sslTrustCategory|IN("expired","not_yet_valid","revoked")) then .sslTrustCategory
    elif .sslTrustCategory=="untrusted_chain" or .basicTrustCategory=="untrusted_chain" then
      "untrusted_chain"
    else "other_failure" end' "$1"
}

r2tls_compatibility_outcome() {
	jq -r 'if (.evidenceProgress.trustEvidenceComplete|not) or
      .sslTrustCategory=="unavailable" or .basicTrustCategory=="unavailable" then "inconclusive"
    elif .sslTrustAccepted then "compatible_under_system_trust"
    else "blocked_by_system_trust" end' "$1"
}

r2tls_checkpoint_dimensions_pass() {
	[ "$1" = true ] && [ "$2" = true ] && [ "$3" = true ] &&
		[ "$4" = complete ] && [ "$5" = true ]
}

r2tls_cli_exit_consistent() {
	{ [ "$1" = true ] && [ "$2" -eq 0 ]; } ||
		{ [ "$1" = false ] && [ "$2" -eq 2 ]; }
}

r2tls_execution_safety_pass() {
	[ "$#" -eq 17 ] || return 1
	for execution_state; do [ "$execution_state" = true ] || return 1; done
}

r2tls_compute_final_dimensions_once() {
	[ "${finalization_dimensions_computed:-false}" = false ] || return 1
	finalization_dimensions_computed=true
	cli_consistent=false; r2tls_cli_exit_consistent "$observed" "$cli_rc" && cli_consistent=true
	harness_clear=false; [ "$harness_kill" = false ] && harness_clear=true
	execution_states="$deadline_clear $cli_consistent $report_valid $monitor_execution $manifest_stable $artifact $cleanup_safe $harness_clear $predecessor_validated $authorization_consumed $child_stopped $monitor_stopped $validator_stopped $gate_stopped $phase_stopped $deadline_stopped $deadline_acknowledged"
	execution=false
	# shellcheck disable=SC2086
	r2tls_execution_safety_pass $execution_states && execution=true
	checkpoint=false
	r2tls_checkpoint_dimensions_pass "$execution" "$transport" "$trust" \
		"$monitor_quality" "$environment" && checkpoint=true
}

r2tls_render_live_result() {
	jq -n --argjson pass "$checkpoint" --arg manifest "$authorized_manifest_sha" \
		--argjson cliRC "$cli_rc" --argjson reportValid "$report_valid" \
		--argjson report "$report_json" --argjson monitorValid "$monitor_valid" \
		--argjson monitor "$monitor_json" --argjson execution "$execution" \
		--argjson transport "$transport" --argjson trust "$trust" \
		--arg compatibility "$compatibility" --arg disposition "$disposition" \
		--arg quality "$monitor_quality" --argjson environment "$environment" \
		--argjson projection "$projection" --argjson ipv4Changed "$ipv4_changed" \
		--argjson launchd "$launchd" --argjson beforeRuns "$runs_before" \
		--argjson afterRuns "$runs_after" --argjson artifact "$artifact" \
		--argjson cleanupSafe "$cleanup_safe" --argjson manifestExact "$manifest_stable" \
		--argjson deadline "$deadline" --argjson guardStopped "$deadline_stopped" \
		--argjson guardAck "$deadline_acknowledged" --argjson killed "$harness_kill" \
		--argjson predecessor "$predecessor_validated" \
		--argjson consumed "$authorization_consumed" \
		--arg predecessorManifest "$R2TLS_ATTEMPT2_ARCHIVE_SHA256" \
		--arg predecessorResult "$R2TLS_ATTEMPT2_FIXTURE_SHA256" \
		--arg experiment "$R2TLS_ATTEMPT3_EXPERIMENT" \
		'{schemaVersion:3,evidenceClass:"r2_tls_peer_live_window",
      candidateManifestSHA256:$manifest,experimentAttempt:3,
      experimentSelector:$experiment,predecessorAttempt:2,
      predecessorAuthorizedManifestSHA256:$predecessorManifest,
      predecessorResultSHA256:$predecessorResult,predecessorValidated:$predecessor,
      authorizationConsumed:$consumed,manifestExact:$manifestExact,complete:true,
      checkpointPass:$pass,cliExitStatus:$cliRC,executionSafetyPass:$execution,
      transportEvidenceComplete:$transport,trustEvidenceComplete:$trust,
      compatibilityOutcome:$compatibility,trustDisposition:$disposition,
      monitorQuality:$quality,environmentStable:$environment,
      cliReportExact:$reportValid,cliReport:$report,monitorExact:$monitorValid,monitor:$monitor,
      network:{stableUnderTLSProjection:$projection,ipv4TransientRouteHashChanged:$ipv4Changed},
      launchd:{inactiveAndRunsStable:$launchd,runsBefore:$beforeRuns,runsAfter:$afterRuns},
      artifactIdentityStable:$artifact,cleanupSafe:$cleanupSafe,deadlineReached:$deadline,
      deadlineGuardStopped:$guardStopped,deadlineGuardAcknowledged:$guardAck,
      harnessKillSent:$killed,credentialsRequested:false,applicationDataRequested:false,
      httpRequested:false,containsSecrets:false,containsRawCertificate:false}'
}
