#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"

base=71fe9eee3d70ef45897002271b4f0a03851e3aff
manifest=fixtures/redacted/r2-reviewed-candidate-manifest-v1.json
live_manifest=fixtures/redacted/r2-portal-login-authorized-manifest-v1.json
runtime_fixture=fixtures/redacted/r2-portal-login-runtime-v1.json

git cat-file -e "$base^{commit}"
git merge-base --is-ancestor "$base" HEAD
[ "$(git branch --show-current)" = rescue-state-machine ]
[ "$(sed -n 's/^current_checkpoint: //p' GOAL.md)" = R2-username-password-portal-login ]

changed_files=$(
	{
		git diff --name-only "$base"
		git ls-files --others --exclude-standard
	} | sort -u
)
[ -n "$changed_files" ]
for file in $changed_files; do
	case "$file" in
	Package.swift | GOAL.md | README.md | \
		docs/protocol-control-plane.md | docs/evidence/checkpoint-5-static-correlation.md | \
		docs/evidence/checkpoint-r2-validation.md | docs/progress/GOAL_STATUS.md | \
		docs/evidence/checkpoint-r2-raw-header-framing.md | \
		fixtures/redacted/protocol-correlation-value-free-v1.json | \
		fixtures/redacted/r2-reviewed-candidate-manifest-v1.json | \
		fixtures/redacted/r2-portal-login-authorized-manifest-v1.json | \
		fixtures/redacted/r2-portal-login-runtime-v1.json | \
		Sources/PowerVPNCore/ProtocolCorrelationFieldNames.swift | \
		Sources/PowerVPNCore/ProtocolCorrelationProfiles.swift | \
		Tests/PowerVPNCoreTests/ProtocolCorrelationProfileTests.swift | \
		Sources/CPortalCurl/*.c | Sources/CPortalCurl/*.h | \
		Tests/CPortalCurlTests/*.c | \
		Sources/PowerVPNCLI/main.swift | Sources/PowerVPNCLI/PortalLoginCommand.swift | \
		Sources/PowerVPNPortal/*.swift | Tests/PowerVPNPortalTests/*.swift | \
		scripts/lib/r2_portal_runtime.sh | scripts/run_r2_portal_login.sh | \
		scripts/verify/r2_live_harness_tests.sh | scripts/verify/checkpoint_r2.sh | \
		scripts/verify/checkpoint_r2_raw_headers.sh | \
		scripts/verify_checkpoint.sh)
		;;
	*)
		echo "error: unexpected R2 artifact: $file" >&2
		exit 1
		;;
	esac
done

for file in $changed_files; do
	[ -f "$file" ] || continue
	git cat-file -e "$base:$file" 2>/dev/null && continue
	[ "$(wc -l <"$file" | tr -d ' ')" -lt 300 ] || {
		echo "error: R2 file exceeds the 300-line split gate: $file" >&2
		exit 1
	}
done

portal_sources=$(rg --files Sources/PowerVPNPortal | sort)
[ -n "$portal_sources" ]
package_json=$(swift package describe --type json)
printf '%s\n' "$package_json" | jq -e '
  .platforms == [{"name":"macos","version":"14.0"}] and
  ([.targets[] | select(.name == "CPortalCurl")] | length) == 1 and
  ([.targets[] | select(.name == "CPortalCurl")][0].target_dependencies // []) == [] and
  ([.targets[] | select(.name == "CPortalCurl")][0].product_dependencies // []) == [] and
  ([.targets[] | select(.name == "PowerVPNPortal")] | length) == 1 and
  ([.targets[] | select(.name == "PowerVPNPortal")][0].target_dependencies // []) ==
    ["CPortalCurl"] and
  ([.targets[] | select(.name == "PowerVPNPortal")][0].product_dependencies // []) == [] and
  ([.targets[] | select(.name == "PowerVPNCLI")][0].target_dependencies | sort) ==
    ["PowerVPNCore", "PowerVPNPortal"]
' >/dev/null

# The list is newline-delimited repo paths produced by rg; splitting is intentional.
# shellcheck disable=SC2086
if rg -n \
	'import PowerVPNCore|import XPC|import NetworkExtension|xpc_|VICI|start_connection|updown_(nc|ipsec)|stop_connection|CommandLine\.arguments|ProcessInfo\.processInfo\.environment|UserDefaults\.standard|readLine\(|FileHandle\.standardInput' \
	$portal_sources; then
	echo 'error: forbidden helper, tunnel, environment, stdin, or cross-target API in R2 portal target' >&2
	exit 1
fi
rg -Fq 'RPP_ECHO_OFF | RPP_REQUIRE_TTY' \
	Sources/PowerVPNPortal/SecureTerminalCredentials.swift
rg -Fq 'readpassphrase' Sources/PowerVPNPortal/SecureTerminalCredentials.swift
rg -Fq 'Task.detached' Sources/PowerVPNPortal/PortalLoginCleanup.swift
rg -Fq 'sessionCheckDelaySeconds: UInt64 = 60' \
	Sources/PowerVPNPortal/PortalLoginWorkflow.swift
rg -Fq 'encode='"'"'1'"'"'&hardware_hash=' \
	Sources/PowerVPNPortal/SecurePortalRequestBody.swift

for script in scripts/lib/r2_portal_runtime.sh scripts/run_r2_portal_login.sh \
	scripts/verify/r2_live_harness_tests.sh scripts/verify/checkpoint_r2.sh \
	scripts/verify/checkpoint_r2_raw_headers.sh scripts/verify_checkpoint.sh; do
	sh -n "$script"
done
shellcheck -x -e SC1091 scripts/lib/r2_portal_runtime.sh \
	scripts/run_r2_portal_login.sh scripts/verify/r2_live_harness_tests.sh \
	scripts/verify/checkpoint_r2.sh scripts/verify/checkpoint_r2_raw_headers.sh

helper_runs_before=$(
	/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
		awk '$1 == "runs" && $2 == "=" { print $3; exit }'
)
[ -n "$helper_runs_before" ]
[ -z "$(pgrep -f '^/Library/PrivilegedHelperTools/com\.leadsec\.charon-xpc$' || true)" ]

scripts/verify/checkpoint_r2_raw_headers.sh
swift test --filter PowerVPNPortalTests
swift test --filter passwordProfileUsesTheRecoveredSortedFieldsAndOptionalChallengeTail
swift test
swift build --arch arm64

changed_swift=$(
	{
		git diff --name-only "$base" -- '*.swift'
		git ls-files --others --exclude-standard -- '*.swift'
	} | sort -u
)
for swift_file in $changed_swift; do
	xcrun swift-format lint --strict "$swift_file"
done

scripts/verify/r2_live_harness_tests.sh
scripts/verify_no_secrets.sh

helper_runs_after=$(
	/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
		awk '$1 == "runs" && $2 == "=" { print $3; exit }'
)
[ "$helper_runs_after" = "$helper_runs_before" ]
[ -z "$(pgrep -f '^/Library/PrivilegedHelperTools/com\.leadsec\.charon-xpc$' || true)" ]

[ -f "$manifest" ]
expected_review=integrated_review_completed_findings_applied
case "${POWERVPN_R2_REVIEW_CANDIDATE:-}" in
'') ;;
offline-pending-v1) expected_review=integrated_review_pending ;;
*) echo 'error: invalid R2 verifier mode' >&2; exit 1 ;;
esac
jq -e --arg review "$expected_review" '
  keys == ["artifacts", "baseCommit", "evidenceClass", "reviewState",
           "runtimeSourceAggregateSHA256", "schemaVersion"] and
  .schemaVersion == 1 and
  .evidenceClass == "r2_reviewed_portal_login_candidate" and
  .baseCommit == "71fe9eee3d70ef45897002271b4f0a03851e3aff" and
  .reviewState == $review and
  (.runtimeSourceAggregateSHA256 | test("^[0-9a-f]{64}$")) and
  (.artifacts | keys) == ["arm64CLISHA256", "harnessTestsSHA256",
    "installedAppSHA256", "installedDatabaseSHA256", "installedInfoPlistSHA256",
    "installedPreferencesSHA256", "networkSnapshotSHA256",
    "rawHeaderTestsAggregateSHA256", "rawHeaderVerifierSHA256",
    "runnerSHA256", "runtimeLibrarySHA256"] and
  all(.artifacts[]; test("^[0-9a-f]{64}$"))
' "$manifest" >/dev/null

if [ -f "$runtime_fixture" ]; then
	[ -f "$live_manifest" ] && [ ! -L "$live_manifest" ]
	manifest_sha=$(shasum -a 256 "$live_manifest" | awk '{print $1}')
	[ "$manifest_sha" = bde4de003e1c5bd2128f5e4b147f05ae3149f2b639126e783585bfb6a1b6302b ]
	jq -e --arg manifest "$manifest_sha" '
    def tls_failure_report:
      {schemaVersion:1,mode:"r2_username_password_portal_login",
       status:"tls_rejected",
       operations:{loginAccepted:false,loginRequested:true,logoutAccepted:false,
         logoutRequested:false,resourceListAccepted:false,
         resourceListRequested:false,sessionCheckAccepted:false,
         sessionCheckRequested:false},
       ownedMaterial:{credentialsErased:true,requestBodiesErased:true,
         responseBodiesErased:true,sessionMaterialErased:true},
       safety:{appOwnedSecureBuffersErasureObserved:true,
         credentialInArguments:false,credentialInEnvironment:false,
         credentialSource:"controlling_tty_no_echo",credentialWrittenToFile:false,
         endpointSource:"sealed_installed_configuration",
         endpointValueRetainedInEvidence:false,helperMutationRequested:false,
         ikeTrafficRequested:false,platformSerialValueRetainedInEvidence:false,
         portalHTTPSAllowed:true,rawRequestRetainedInEvidence:false,
         rawResponseRetainedInEvidence:false,redirectsAllowed:false,
         resourceValueRetainedInEvidence:false,
         sessionValueRetainedInEvidence:false,
         swiftAndFoundationBridgeCopiesErasureClaimed:false,
         systemTrustRequired:true,viciUsed:false,xpcUsed:false},
       transactionAccepted:false};
    def tls_failure_monitor:
      {targetObserved:true,inspectionSucceeded:false,onlySealedPortalTCP:true,
       portalTCPObserved:false,maximumTCPCount:0,maximumUDPCount:0,
       vendorHelperObserved:false,nativeCharonObserved:false};
    keys == ["artifactIdentityStable", "candidateManifestSHA256",
      "checkpointPass", "cleanupSafe", "cliExitStatus", "cliReport",
      "cliReportExact", "complete", "containsRawPortal", "containsSecrets",
      "credentialPath", "evidenceClass", "harnessKillSent", "launchd",
      "manifestExact", "monitor", "monitorExact", "networkStable",
      "schemaVersion"] and
    .schemaVersion == 1 and
    .evidenceClass == "r2_portal_login_live_window" and
    .candidateManifestSHA256 == $manifest and .manifestExact == true and
    .complete == true and .cliReportExact == true and .monitorExact == true and
    .artifactIdentityStable == true and .cleanupSafe == true and
    .credentialPath == {argumentUsed:false,directControllingTTY:true,
      environmentUsed:false,exposedCredentialRiskAccepted:true,fileUsed:false,
      stdinUsed:false} and
    .harnessKillSent == false and
    .containsSecrets == false and .containsRawPortal == false and
    ((.checkpointPass == true and .cliExitStatus == 0 and
      .cliReport.transactionAccepted == true and
      .monitor.inspectionSucceeded == true and
      .monitor.onlySealedPortalTCP == true and
      .monitor.portalTCPObserved == true and .monitor.maximumUDPCount == 0 and
      .monitor.vendorHelperObserved == false and
      .monitor.nativeCharonObserved == false and .networkStable == true and
      .launchd.inactiveAndRunsStable == true) or
     (.checkpointPass == false and .cliExitStatus == 2 and
      .cliReport == tls_failure_report and .monitor == tls_failure_monitor and
      .networkStable == false and
      .launchd == {inactiveAndRunsStable:true,runsAfter:19,runsBefore:19}))
  ' "$runtime_fixture" >/dev/null
fi

git diff --check "$base"
printf 'PASS: Rescue R2 offline portal-login checkpoint (%s)\n' "$expected_review"
