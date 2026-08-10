#!/bin/sh

set -eu
umask 077

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
R2TLS_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$repo_root/scripts/lib/r2_tls_evidence_runtime.sh"

attempt1_manifest=fixtures/redacted/r2-tls-evidence-authorized-manifest-v1.json
attempt1_result=fixtures/redacted/r2-tls-peer-runtime-v1.json
attempt2_manifest=fixtures/redacted/r2-tls-evidence-attempt2-authorized-manifest-v1.json
attempt2_result=fixtures/redacted/r2-tls-peer-runtime-attempt2-v1.json
for fixture in "$attempt1_manifest" "$attempt1_result" "$attempt2_manifest" "$attempt2_result"; do
	[ -f "$fixture" ] && [ ! -L "$fixture" ] &&
		[ "$(stat -f '%u:%Lp' "$fixture")" = "$(id -u):644" ]
done
[ "$(r2tls_hash_file "$attempt1_manifest")" = \
	e8b622cb4600ae5e603364accd13dffcd45d1a4aa6a48afe69401fee314cd5d4 ]
[ "$(r2tls_hash_file "$attempt1_result")" = \
	27a0b7a511addff9888041c94c94b1a3ba9f408ff0a15b3941dcb7d4f6e3d61b ]
[ "$(r2tls_hash_file "$attempt2_manifest")" = \
	b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354 ]
[ "$(r2tls_hash_file "$attempt2_result")" = \
	8766a176e542173bf7b53b79ca005cde0c222a5d2c699871e6aeafd329761219 ]

jq -e --arg manifest "$(r2tls_hash_file "$attempt1_manifest")" '
  keys==["applicationDataRequested","artifactIdentityStable",
    "candidateManifestSHA256","checkpointPass","cleanupSafe","cliExitStatus",
    "cliReport","cliReportExact","complete","containsRawCertificate",
    "containsSecrets","credentialsRequested","deadlineReached","evidenceClass",
    "harnessKillSent","httpRequested","launchd","manifestExact","monitor",
    "monitorExact","network","nextTrustDisposition","schemaVersion"] and
  .schemaVersion==1 and .evidenceClass=="r2_tls_peer_live_window" and
  .candidateManifestSHA256==$manifest and .manifestExact and .complete and
  (.checkpointPass|not) and .cliExitStatus==2 and .cliReportExact and
  (.cliReport|type)=="object" and .monitorExact and
  (.monitor|keys)==["inspectionSucceeded","maximumTCPCount","maximumUDPCount",
    "nativeCharonObserved","onlySealedEndpointTCP","sealedEndpointTCPObserved",
    "targetObserved","vendorHelperObserved"] and
  .monitor=={targetObserved:true,inspectionSucceeded:false,onlySealedEndpointTCP:true,
    sealedEndpointTCPObserved:false,maximumTCPCount:0,maximumUDPCount:0,
    vendorHelperObserved:false,nativeCharonObserved:false} and
  .network=={stableUnderTLSProjection:false,ipv4TransientRouteHashChanged:true} and
  .launchd=={inactiveAndRunsStable:true,runsBefore:19,runsAfter:19} and
  .artifactIdentityStable and .cleanupSafe and (.deadlineReached|not) and
  (.harnessKillSent|not) and .nextTrustDisposition=="incompatible_or_inconclusive" and
  (.credentialsRequested|not) and (.applicationDataRequested|not) and
  (.httpRequested|not) and (.containsSecrets|not) and (.containsRawCertificate|not)
' "$attempt1_result" >/dev/null

attempt1_report=$(jq -c '.cliReport' "$attempt1_result")
printf '%s\n' "$attempt1_report" | jq -e '
  keys==["applicationDataSent","basicTrustAccepted","basicTrustCategory",
    "chainLength","containsIssuer","containsRawCertificate","containsSAN",
    "containsSecrets","containsSerial","containsSubject","evidenceClass",
    "leafCertificateSHA256","leafSPKISHA256","orderedCertificateSHA256",
    "schemaVersion","sslTrustAccepted","sslTrustCategory","status","verifyAccepted"] and
  .schemaVersion==1 and .evidenceClass=="r2_tls_peer_value_free" and
  .status=="timed_out" and .chainLength==0 and .orderedCertificateSHA256==[] and
  .leafCertificateSHA256==null and .leafSPKISHA256==null and
  (.sslTrustAccepted|not) and .sslTrustCategory=="unavailable" and
  (.basicTrustAccepted|not) and .basicTrustCategory=="unavailable" and
  (.applicationDataSent|not) and (.verifyAccepted|not) and
  (.containsRawCertificate|not) and (.containsSubject|not) and
  (.containsIssuer|not) and (.containsSAN|not) and (.containsSerial|not) and
  (.containsSecrets|not)
' >/dev/null

jq -e --arg manifest "$(r2tls_hash_file "$attempt2_manifest")" '
  keys==["applicationDataRequested","artifactIdentityStable",
    "candidateManifestSHA256","checkpointPass","cleanupSafe","cliExitStatus",
    "cliReport","cliReportExact","complete","containsRawCertificate",
    "containsSecrets","credentialsRequested","deadlineReached","evidenceClass",
    "experimentAttempt","harnessKillSent","httpRequested","launchd","manifestExact",
    "monitor","monitorExact","network","nextTrustDisposition","predecessorValidated",
    "schemaVersion"] and .schemaVersion==2 and
  .evidenceClass=="r2_tls_peer_live_window" and .candidateManifestSHA256==$manifest and
  .experimentAttempt==2 and .predecessorValidated and .manifestExact and .complete and
  (.checkpointPass|not) and .cliExitStatus==2 and .cliReportExact and
  (.cliReport|type)=="object" and (.monitorExact|not) and .monitor==null and
  .network=={stableUnderTLSProjection:false,ipv4TransientRouteHashChanged:true} and
  .launchd=={inactiveAndRunsStable:true,runsBefore:19,runsAfter:19} and
  .artifactIdentityStable and .cleanupSafe and (.deadlineReached|not) and
  (.harnessKillSent|not) and .nextTrustDisposition=="incompatible_or_inconclusive" and
  (.credentialsRequested|not) and (.applicationDataRequested|not) and
  (.httpRequested|not) and (.containsSecrets|not) and (.containsRawCertificate|not)
' "$attempt2_result" >/dev/null

jq -e '.cliReport | keys==["applicationDataSent","basicTrustAccepted","basicTrustCategory",
  "chainLength","containsIssuer","containsRawCertificate","containsSAN","containsSecrets",
  "containsSerial","containsSubject","evidenceClass","leafCertificateSHA256",
  "leafSPKISHA256","orderedCertificateSHA256","schemaVersion","sslTrustAccepted",
  "sslTrustCategory","status","transportProgress","verifyAccepted"] and
  .schemaVersion==2 and .evidenceClass=="r2_tls_peer_value_free" and .status=="timed_out" and
  .chainLength==0 and .orderedCertificateSHA256==[] and .leafCertificateSHA256==null and
  .leafSPKISHA256==null and (.sslTrustAccepted|not) and .sslTrustCategory=="unavailable" and
  (.basicTrustAccepted|not) and .basicTrustCategory=="unavailable" and
  .transportProgress=={connectionStarted:true,failedObserved:false,
    preparingObserved:true,readyObserved:false,verifyCallbackObserved:true,waitingObserved:true} and
  (.applicationDataSent|not) and (.verifyAccepted|not) and (.containsRawCertificate|not) and
  (.containsSubject|not) and (.containsIssuer|not) and (.containsSAN|not) and
  (.containsSerial|not) and (.containsSecrets|not)' "$attempt2_result" >/dev/null

printf '%s\n' 'R2 TLS historical evidence tests: PASS (fixtures only)'
