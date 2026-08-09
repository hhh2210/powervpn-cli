#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"

base=a0a465c215a2f949f71b3448ad78e6d0c41e6af0
fixture=fixtures/redacted/r1-xpc-runtime-v1.json
R1_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r1_xpc_runtime.sh
. "$repo_root/scripts/lib/r1_xpc_runtime.sh"

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
	GOAL.md | README.md | docs/protocol-xpc.md | \
		docs/evidence/checkpoint-r1-validation.md | docs/progress/GOAL_STATUS.md | \
		fixtures/redacted/r1-reviewed-candidate-manifest-v1.json | \
		fixtures/redacted/r1-xpc-runtime-v1.json | \
		Sources/PowerVPNCLI/main.swift | Sources/PowerVPNCLI/VendorXPCCommand.swift | \
		Sources/PowerVPNCore/RawVendorXPCTransport.swift | \
		Sources/PowerVPNCore/VendorHelperGeneration.swift | \
		Sources/PowerVPNCore/VendorXPCModels.swift | \
		Sources/PowerVPNCore/VendorXPCProbe.swift | \
		Tests/PowerVPNCoreTests/RawVendorXPCTransportTests.swift | \
		Tests/PowerVPNCoreTests/VendorHelperGenerationTests.swift | \
		Tests/PowerVPNCoreTests/VendorXPCEnvelopeTests.swift | \
		Tests/PowerVPNCoreTests/VendorXPCProbeTests.swift | \
		scripts/lib/r1_xpc_runtime.sh | scripts/run_r1_xpc_probe.sh | \
		scripts/lib/r1_xpc_experiments.sh | \
		scripts/verify/checkpoint_r1.sh | \
		scripts/verify/r1_live_harness_tests.sh | scripts/verify_checkpoint.sh)
		;;
	*)
		echo "error: unexpected R1 artifact: $file" >&2
		exit 1
		;;
	esac
done

for file in $changed_files; do
	[ -f "$file" ] || continue
	git cat-file -e "$base:$file" 2>/dev/null && continue
	[ "$(wc -l <"$file" | tr -d ' ')" -lt 300 ] || {
		echo "error: R1 file exceeds the 300-line split gate: $file" >&2
		exit 1
	}
done

production_files='Sources/PowerVPNCore/RawVendorXPCTransport.swift
Sources/PowerVPNCore/VendorHelperGeneration.swift
Sources/PowerVPNCore/VendorXPCModels.swift
Sources/PowerVPNCore/VendorXPCProbe.swift
Sources/PowerVPNCLI/VendorXPCCommand.swift'
# shellcheck disable=SC2086
if rg -n 'start_connection|updown_nc|stop_connection|xpc_copy_description|xpc_dictionary_get_string|String\(cString:|URLSession|NWConnection|FileHandle' $production_files; then
	echo 'error: forbidden mutable, network, raw-description, or file API in R1 surface' >&2
	exit 1
fi
rg -Fq 'VendorXPCRequestField(key: "type", value: "rpc")' \
	Sources/PowerVPNCore/VendorXPCModels.swift
rg -Fq 'VendorXPCRequestField(key: "rpc", value: "get_version")' \
	Sources/PowerVPNCore/VendorXPCModels.swift
rg -Fq 'xpc_connection_send_message_with_reply' \
	Sources/PowerVPNCore/RawVendorXPCTransport.swift

for script in scripts/lib/r1_xpc_runtime.sh scripts/lib/r1_xpc_experiments.sh \
	scripts/run_r1_xpc_probe.sh \
	scripts/verify/checkpoint_r1.sh \
	scripts/verify/r1_live_harness_tests.sh scripts/verify_checkpoint.sh; do
	sh -n "$script"
done
shellcheck -x -e SC1091 scripts/lib/r1_xpc_runtime.sh \
	scripts/lib/r1_xpc_experiments.sh scripts/run_r1_xpc_probe.sh \
	scripts/verify/r1_live_harness_tests.sh scripts/verify/checkpoint_r1.sh

helper_runs_before=$(
	/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
		awk '$1 == "runs" && $2 == "=" { print $3; exit }'
)
[ -n "$helper_runs_before" ]
[ -z "$(pgrep -f '^/Library/PrivilegedHelperTools/com\.leadsec\.charon-xpc$' || true)" ]

swift test --filter 'VendorXPC|VendorHelperGeneration'
swift test
swift build --arch arm64
r1_candidate_manifest_exact
manifest_sha=$R1_CANDIDATE_MANIFEST_SHA256
changed_swift=$(
	{
		git diff --name-only "$base" -- '*.swift'
		git ls-files --others --exclude-standard -- '*.swift'
	} | sort -u
)
for swift_file in $changed_swift; do
	xcrun swift-format lint --strict "$swift_file"
done
scripts/verify/r1_live_harness_tests.sh
scripts/verify_no_secrets.sh

helper_runs_after=$(
	/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
		awk '$1 == "runs" && $2 == "=" { print $3; exit }'
)
[ "$helper_runs_after" = "$helper_runs_before" ]
[ -z "$(pgrep -f '^/Library/PrivilegedHelperTools/com\.leadsec\.charon-xpc$' || true)" ]

jq -e --arg manifest "$manifest_sha" '
  keys == [
    "artifactIdentityStable", "candidateManifestSHA256", "checkpointPass",
    "coldPreflight", "containsRawXPC", "containsSecrets", "evidenceClass",
    "experimentAttempt", "helper", "network", "r1Transaction", "sadSpd",
    "schemaVersion", "vendorLog"
  ] and
  .schemaVersion == 1 and
  .evidenceClass == "r1_read_only_vendor_xpc_runtime" and
  .experimentAttempt == 3 and
  .checkpointPass == true and
  .artifactIdentityStable == true and
  .candidateManifestSHA256 == $manifest and
  .containsSecrets == false and .containsRawXPC == false and
  .coldPreflight == {
    guiAbsent: true, helperAbsent: true, otherVendorHelpersAbsent: true,
    launchdInactive: true, dnsRecoveryLstatENOENT: true,
    vendorLogRegularAndBounded: true, artifactsExact: true
  } and
  .r1Transaction.transactionAccepted == true and
  .r1Transaction.transportOutcome == "accepted" and
  .r1Transaction.exactReplySchema == true and
  .r1Transaction.versionByteLength == 5 and
  .r1Transaction.versionMatchesLockedBuild == true and
  .r1Transaction.getVersionSuccess == true and
  .r1Transaction.connectionCancelRequested == true and
  .r1Transaction.replyPeerMatchesObservedGeneration == true and
  .r1Transaction.helperGenerationRelation == "launched_and_exited" and
  .helper.processObserved == true and
  .helper.inspectionSucceeded == true and
  .helper.maximumTCPUDPFDCount == 0 and
  .helper.absentWithinDeadlineWithoutHarnessKill == true and
  .helper.launchdRunsDelta == 1 and
  .network.stable == true and
  .network.serverTrafficObservationState == "observed_no_tcp_udp_fds" and
  .network.serverTrafficObserved == false and
  .sadSpd.directComparisonState == "unavailable_unprivileged" and
  .sadSpd.claimedStable == false and
  .vendorLog.afterSafe == true and
  .vendorLog.contentsRead == false and
  (.vendorLog.beforeAbsent | type) == "boolean" and
  (.vendorLog.metadataChanged | type) == "boolean"
' "$fixture" >/dev/null

git diff --check "$base"
printf '%s\n' 'PASS: Rescue R1 exact read-only vendor XPC checkpoint'
