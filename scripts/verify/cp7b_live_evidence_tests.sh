#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
. "$repo_root/scripts/lib/route_snapshot.sh"
. "$repo_root/scripts/lib/network_snapshot.sh"
. "$repo_root/scripts/lib/cp7b_runtime.sh"
. "$repo_root/scripts/lib/cp7b_snapshot.sh"
pvn_cp7b_init_paths "$repo_root"

fixture="$repo_root/fixtures/redacted/cp7b-first-live-preflight-summary-v1.json"
historical_manifest_sha=c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877
historical_commit=552652a78e34b5e9a34b25cc1630c760814c755e

jq -e --arg manifest "$historical_manifest_sha" --arg commit "$historical_commit" '
  keys == [
    "classification", "containsRawRoutes", "containsRawSAState",
    "containsSecrets", "containsServerEndpoint", "currentCleanup",
    "evidenceClass", "invocation", "manifest", "missingEvidence",
    "outcome", "postHocBeforeAfter", "reachability",
    "routeVolatilityDiagnosis", "schemaVersion"
  ] and
  .schemaVersion == 1 and
  .evidenceClass == "cp7b_live_preflight_failure_summary" and
  .classification == "inconclusive_preflight_failure" and
  .manifest.sha256 == $manifest and .manifest.labCommit == $commit and
  .invocation.rootResultBytes == 0 and .invocation.attempt == null and
  .invocation.lastBoundRootStage == null and
  .invocation.afterRelationship == "post_hoc_diagnostic_outside_300_second_window" and
  .reachability.backendConstructor == "not_evidenced" and
  .reachability.vici == "not_evidenced" and .reachability.server == "not_evidenced" and
  .postHocBeforeAfter.routeOnlyMismatch == true and
  .postHocBeforeAfter.sadSpdComparable == false and
  .routeVolatilityDiagnosis.fullHashAllEqual == false and
  .routeVolatilityDiagnosis.expireFreeStructuralHashAllEqual == true and
  .routeVolatilityDiagnosis.nonExpiringNonWasClonedPersistentHashAllEqual == true and
  .routeVolatilityDiagnosis.excludedFlag == "W:RTF_WASCLONED" and
  .routeVolatilityDiagnosis.retainedFlags == [
    "D:RTF_DYNAMIC", "C:RTF_CLONING", "c:RTF_PRCLONING"
  ] and
  .currentCleanup.runtimeOwnerRestored == true and
  .currentCleanup.runtimeTopLevel == "closure_only" and
  .currentCleanup.stateResidueCount == 0 and
  .currentCleanup.pidResidueCount == 0 and
  .currentCleanup.socketResidueCount == 0 and
  .currentCleanup.ledgerResidueCount == 0 and
  .currentCleanup.bootstrapResidueCount == 0 and
  .currentCleanup.generationResidueCount == 0 and
  .currentCleanup.nativeProcessResidueCount == 0 and
  .currentCleanup.kernelTeardownProven == false and
  .currentCleanup.boundResultPresent == false and
  .outcome.cp7bBackend == "unproven" and .outcome.l5 == false and
  .outcome.secondLaunchUnderOldManifestAllowedWithoutNewApproval == false and
  .containsSecrets == false and .containsRawRoutes == false and
  .containsRawSAState == false and .containsServerEndpoint == false
' "$fixture" >/dev/null

historical_hash=$(git -C "$repo_root" show \
	"$historical_commit:fixtures/redacted/cp7b-approval-manifest-v1.json" |
	pvn_hash_stdin)
[ "$historical_hash" = "$historical_manifest_sha" ]

report=$(pvn_cp7b_preflight_failure_report_json \
	root_preflight_snapshot_unstable 1 2)
current_manifest_sha=$(pvn_sha256_file "$PVN_CP7B_MANIFEST")
printf '%s\n' "$report" | jq -e --arg manifest "$current_manifest_sha" '
  keys == [
    "approvalManifestSHA256", "attempt", "backend", "configSHA256",
    "containsRawRoutes", "containsRawSAState", "containsSecrets",
    "containsServerEndpoint", "durationSeconds", "evidenceClass",
    "failureCategory", "reachability", "safety", "schemaVersion",
    "socketProvider", "sourceCommit", "success"
  ] and
  .schemaVersion == 1 and
  .evidenceClass == "cp7b_privileged_preflight_failure" and
  .approvalManifestSHA256 == $manifest and .success == false and
  .backend == "pfkey-pfroute" and .socketProvider == "socket-dynamic" and
  .attempt == 1 and .durationSeconds == 2 and
  .failureCategory == "root_preflight_snapshot_unstable" and
  .reachability == {
    rootWorker: true, privilegedSnapshotPair: true, gatedLauncher: false,
    daemon: false, backendConstructor: false, vici: false, server: false
  } and
  .safety == {
    serverTraffic: false, credentialRead: false, initiateCalled: false,
    installCalled: false, retryLedgerRetained: true, cleanupComplete: true
  } and
  .containsSecrets == false and .containsRawRoutes == false and
  .containsRawSAState == false and .containsServerEndpoint == false
' >/dev/null

printf '%s\n' 'PASS: CP7B first-live evidence and bound preflight-failure report tests'
