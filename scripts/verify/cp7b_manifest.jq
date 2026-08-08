keys == [
  "approval", "artifacts", "backend", "containsRawRoutes",
  "containsReplayableCapture", "containsSecrets", "fixtureClass",
  "review", "safety", "schemaVersion", "source", "window"
] and
.schemaVersion == 1 and
.fixtureClass == "cp7b_privileged_backend_approval_manifest" and
.source == "static_preflight_and_scratch_build" and
.backend == {
  ipsec: "kernel-pfkey",
  network: "kernel-pfroute",
  socket: "socket-dynamic"
} and
.approval == {
  preflightAuthorized: true,
  privilegedExecutionAuthorized: false,
  nativeAuthorizationRequired: true,
  executionCommandTemplate: "scripts/run_cp7b_backend.sh --execute-reviewed --manifest-sha256 <approved-manifest-sha256>",
  stopCommandTemplate: "scripts/stop_cp7b_backend.sh --execute-reviewed --manifest-sha256 <approved-manifest-sha256>",
  zeroResidueCommandTemplate: "scripts/assert_cp7b_teardown.sh --result <scratch-result-json>"
} and
.window == {
  maxLaunches: 2,
  maxDurationSeconds: 300,
  oneBackendPerLaunch: true,
  automaticSecondLaunch: false
} and
.safety == {
  udpSocketExpectedCount: 0,
  serverTraffic: false,
  credentials: false,
  initiate: false,
  installRoutes: false,
  installVirtualIP: false,
  socketDefaultLoaded: false,
  kernelLibipsecLoaded: false,
  loadTesterLoaded: false,
  nativeTouchID: true,
  keepPowerVPNRunning: true,
  keepSurgeRunning: true,
  surgeProbe: "read_only_environment_and_dns",
  globalSADSPDAndEspPortMustRemainStable: true,
  rawKernelLogDeletedAfterValueFreeClassification: true,
  rootOwnedExecutionClosure: true,
  samePIDGatedExec: true,
  fullWindowDeadline: true,
  failClosedObservation: true,
  resultBoundToManifest: true
} and
(.artifacts | keys) == [
  "attemptsScriptSHA256", "authorizerSHA256", "bundleScriptSHA256",
  "charonSHA256", "closureScriptSHA256", "configSHA256",
  "emergencySHA256", "gatedLauncherSHA256", "kernelPFArtifactSHA256",
  "libcharonSHA256", "libstrongswanSHA256", "nativeScriptSHA256", "networkScriptSHA256",
  "noncePluginSHA256", "officialProtocolSHA256",
  "officialPyCommandWrappersSHA256", "officialPyEventListenerSHA256",
  "officialPyExceptionSHA256", "officialPyInitSHA256", "officialPySessionSHA256",
  "opensslLibcryptoSHA256", "opensslPluginSHA256", "oracleSHA256",
  "pfrouteSHA256", "readOnlyProbeSHA256",
  "rootEntrySHA256", "runtimeScriptSHA256", "snapshotScriptSHA256",
  "socketDynamicSHA256", "sourceCommit", "sourceParentCP6Commit",
  "stateScriptSHA256", "swanctlSHA256", "viciSHA256", "workerSHA256"
] and
.artifacts.sourceCommit == $cp7b and
.artifacts.sourceParentCP6Commit == $cp6 and
.artifacts.configSHA256 == $config and
(.review | keys) == ["independentSecondReview", "scope", "state"] and
(
  .review.state == "pending_integrated_preflight_review" or
  .review.state == "passed_integrated_preflight_review"
) and
.review.scope == [
  "root execution closure ownership and hashes",
  "gated same-PID launch and emergency recovery",
  "PF_KEY/PF_ROUTE config", "socket-dynamic no-send boundary",
  "full-window deadline", "SAD/SPD/sysctl and process-identity snapshots",
  "manifest-bound retained evidence",
  "bounded rollback and secret/raw-log boundary"
] and
.review.independentSecondReview == false and
.containsSecrets == false and
.containsReplayableCapture == false and
.containsRawRoutes == false
