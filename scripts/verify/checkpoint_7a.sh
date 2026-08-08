#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
. "$repo_root/scripts/lib/native_charon_runtime.sh"
pvn_init_runtime_paths

cp6_repo_commit=6122825e37d5061c94d2e1b4e7a88cadcd354e04
cp6_upstream_commit=67c9810900e2d8486cb3b11495a8362433494ca0
cp6_patch_sha=6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213
patch_file=patches/strongswan-6.0.7/0002-integrate-ikev1-expandrule-payload-task-and-hash.patch
fixture=fixtures/redacted/vici-runtime-cp7a-summary-v1.json

git cat-file -e "$cp6_repo_commit^{commit}"
git merge-base --is-ancestor "$cp6_repo_commit" HEAD
test "$(git -C "$PVN_SOURCE" rev-parse HEAD)" = "$cp6_upstream_commit"
test -z "$(git -C "$PVN_SOURCE" status --porcelain=v1)"
test "$(shasum -a 256 "$patch_file" | awk '{print $1}')" = "$cp6_patch_sha"
test "$(sed -n 's/^goal_version: //p' GOAL.md)" = 3
test "$(sed -n 's/^current_checkpoint: //p' GOAL.md)" = \
	live-approval-gate-1

changed_files=$(
	{
		git diff --name-only "$cp6_repo_commit"
		git ls-files --others --exclude-standard
	} | sort -u
)
test -n "$changed_files"
for file in $changed_files; do
	case "$file" in
	.gitignore | GOAL.md | README.md | \
		Sources/PowerVPNCLI/VICICommands.swift | Sources/PowerVPNCLI/main.swift | \
		Sources/PowerVPNCore/VICIMessage.swift | Sources/PowerVPNCore/VICIPacket.swift | \
		Sources/PowerVPNCore/VICIRuntimeProbe.swift | Sources/PowerVPNCore/VICISession.swift | \
		Sources/PowerVPNCore/VICITransport.swift | Sources/PowerVPNCore/VICIUnixTransport.swift | \
		Tests/PowerVPNCoreTests/VICIPacketTests.swift | \
		Tests/PowerVPNCoreTests/VICIRuntimeProbeTests.swift | \
		Tests/PowerVPNCoreTests/VICISessionTests.swift | \
		Tests/PowerVPNCoreTests/VICIUnixTransportTests.swift | \
		docs/evidence/live-test-plan.md | docs/evidence/rollback.md | \
		docs/evidence/vici-runtime-diagnosis.md | docs/progress/GOAL_STATUS.md | \
		fixtures/redacted/vici-runtime-cp7a-summary-v1.json | \
		scripts/assert_clean_teardown.sh | scripts/build_strongswan.sh | \
		scripts/lib/native_charon_runtime.sh | scripts/lib/network_snapshot.sh | \
		scripts/run_native_charon.sh | scripts/snapshot_network_state.sh | \
		scripts/stop_native_charon.sh | scripts/verify/checkpoint_7a.sh | \
		scripts/verify/native_charon_runtime_tests.sh | \
		scripts/verify/official_vici_runtime.py | scripts/verify_checkpoint.sh)
		;;
	*) pvn_fail "unexpected CP7A artifact: $file" || exit 1 ;;
	esac
done

jq -e \
	--arg repo "$cp6_repo_commit" \
	--arg upstream "$cp6_upstream_commit" \
	--arg patch "$cp6_patch_sha" '
  keys == [
    "containsRawRoutes", "containsReplayableCapture", "containsSecrets",
    "containsServerEndpoint", "evidenceLevel", "fixtureClass", "lockedAnchors",
    "notProven", "officialOracle", "runtime", "safetyAndCleanup", "schemaVersion",
    "source", "syntheticLifecycle", "timeoutDiagnosis", "versionExchange"
  ] and
  .schemaVersion == 1 and
  .fixtureClass == "cp7a_vici_runtime_summary" and
  .evidenceLevel == "L5" and
  .source == "bounded_unprivileged_local_runtime" and
  .containsSecrets == false and
  .containsReplayableCapture == false and
  .containsRawRoutes == false and
  .containsServerEndpoint == false and
  .lockedAnchors.repositoryCommit == $repo and
  .lockedAnchors.strongSwanCommit == $upstream and
  .lockedAnchors.strongSwanPatchSHA256 == $patch and
  .runtime.architecture == "arm64" and
  .runtime.fakeKernel == true and
  .runtime.serverTraffic == false and
  .timeoutDiagnosis.thread4.officialClientResult == "timeout_before_response_header" and
  .timeoutDiagnosis.thread4.swiftClientResult == "timeout_before_response_header" and
  .timeoutDiagnosis.thread5.officialClientResult == "command_response" and
  .timeoutDiagnosis.thread5.swiftClientResult == "command_response" and
  .versionExchange.requestPayloadBytes == 9 and
  .versionExchange.requestWireBytes == 13 and
  .versionExchange.responseOperation == 1 and
  .versionExchange.officialAndSwiftExactAgreement == true and
  .syntheticLifecycle.afterLoadSyntheticMatches == 1 and
  .syntheticLifecycle.afterUnloadSyntheticMatches == 0 and
  .syntheticLifecycle.officialClientPass == true and
  .syntheticLifecycle.swiftClientPass == true and
  .syntheticLifecycle.initiateCalled == false and
  .syntheticLifecycle.installCalled == false and
  .syntheticLifecycle.credentialRead == false and
  .safetyAndCleanup.rootUsed == false and
  .safetyAndCleanup.productionIKEPortsBound == false and
  .safetyAndCleanup.syntheticRouteObserved == false and
  .safetyAndCleanup.newUtunObserved == false and
  .safetyAndCleanup.generationOwnedResidue == false and
  .safetyAndCleanup.failedStartSignalsBoundedAndChildReaped == true and
  .safetyAndCleanup.unexpectedGenerationResiduePreservesState == true and
  .safetyAndCleanup.orphanFixedSocketRejected == true and
  .safetyAndCleanup.orphanGenerationDirectoryRejected == true
' "$fixture" >/dev/null

for script in \
	scripts/build_strongswan.sh \
	scripts/run_native_charon.sh \
	scripts/stop_native_charon.sh \
	scripts/snapshot_network_state.sh \
	scripts/assert_clean_teardown.sh \
	scripts/lib/native_charon_runtime.sh \
	scripts/lib/network_snapshot.sh \
	scripts/verify/native_charon_runtime_tests.sh; do
	sh -n "$script"
done
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("scripts/verify/official_vici_runtime.py").read_text())'
scripts/build_strongswan.sh --verify-cp7a-runtime >/dev/null
scripts/run_native_charon.sh --dry-run --threads 5 >/dev/null
scripts/stop_native_charon.sh --dry-run >/dev/null
swift test --filter 'PowerVPNCoreTests.VICI'
swift build --arch arm64
scripts/verify/native_charon_runtime_tests.sh

test ! -e "$PVN_STATE_FILE"
test ! -e "$PVN_PID_FILE"
evidence_dir="$PVN_SCRATCH_ROOT/verify-cp7a.$$"
mkdir "$evidence_dir"
chmod 700 "$evidence_dir"
started=false

cleanup() {
	rc=$?
	if [ "$started" = true ] || [ -e "$PVN_STATE_FILE" ]; then
		scripts/stop_native_charon.sh --stop --cp7a-unprivileged >/dev/null 2>&1 || true
	fi
	if [ "$rc" -eq 0 ]; then
		for file in "$evidence_dir"/*; do
			[ -e "$file" ] || continue
			[ -f "$file" ] && [ ! -L "$file" ] || continue
			rm -f -- "$file"
		done
		rmdir "$evidence_dir"
	else
		echo "CP7A failure evidence preserved at $evidence_dir" >&2
	fi
	exit "$rc"
}
trap cleanup EXIT HUP INT TERM

scripts/snapshot_network_state.sh --output "$evidence_dir/preflight-a.json" >/dev/null
sleep 1
scripts/snapshot_network_state.sh --output "$evidence_dir/before.json" >/dev/null
jq -e --slurpfile first "$evidence_dir/preflight-a.json" '
  .defaultRouteInterface == $first[0].defaultRouteInterface and
  .dnsSHA256 == $first[0].dnsSHA256 and
  .utunNames == $first[0].utunNames and
  .surgeProcessCount == $first[0].surgeProcessCount and
  .surgeExtensionProcessCount == $first[0].surgeExtensionProcessCount and
  .surgeHelperProcessCount == $first[0].surgeHelperProcessCount and
  .surgeCLIProcessCount == $first[0].surgeCLIProcessCount and
  .powerVPNProcessCount == $first[0].powerVPNProcessCount
' "$evidence_dir/before.json" >/dev/null

scripts/run_native_charon.sh --start --cp7a-unprivileged --threads 5 \
	>"$evidence_dir/start.out"
started=true
chmod 600 "$evidence_dir/start.out"
socket_path=$(awk -F= '$1 == "socket_path" { print $2 }' "$evidence_dir/start.out")
initial_pid=$(awk -F= '$1 == "pid" { print $2 }' "$evidence_dir/start.out")
initial_inode=$(awk -F= '$1 == "socket_inode" { print $2 }' "$evidence_dir/start.out")
pvn_verify_owned_process
test "$PVN_OWNED_PID" = "$initial_pid"
test "$(stat -f '%i' "$socket_path")" = "$initial_inode"

python3 scripts/verify/official_vici_runtime.py \
	--socket "$socket_path" --python-root "$PVN_PYTHON_ROOT" \
	--mode version --timeout-ms 2000 >"$evidence_dir/official-version.json"
"$(swift build --show-bin-path --arch arm64)/powervpn" vici version \
	--socket "$socket_path" --timeout-ms 2000 --json >"$evidence_dir/swift-version.json"
chmod 600 "$evidence_dir/official-version.json" "$evidence_dir/swift-version.json"
pvn_verify_owned_process
test "$PVN_OWNED_PID" = "$initial_pid"
test "$(stat -f '%i' "$socket_path")" = "$initial_inode"
test "$(jq -r '.version.trace.requestPayloadSHA256' "$evidence_dir/official-version.json")" = \
	"$(jq -r '.trace.requestPayloadSHA256' "$evidence_dir/swift-version.json")"
test "$(jq -r '.version.trace.responsePayloadSHA256' "$evidence_dir/official-version.json")" = \
	"$(jq -r '.trace.responsePayloadSHA256' "$evidence_dir/swift-version.json")"
test "$(jq -c '.version.responseKeyNames' "$evidence_dir/official-version.json")" = \
	"$(jq -c '.responseKeyNames' "$evidence_dir/swift-version.json")"

python3 scripts/verify/official_vici_runtime.py \
	--socket "$socket_path" --python-root "$PVN_PYTHON_ROOT" \
	--mode cp7a-smoke --timeout-ms 2000 >"$evidence_dir/official-smoke.json"
"$(swift build --show-bin-path --arch arm64)/powervpn" vici cp7a-smoke \
	--socket "$socket_path" --timeout-ms 2000 --json >"$evidence_dir/swift-smoke.json"
chmod 600 "$evidence_dir/official-smoke.json" "$evidence_dir/swift-smoke.json"
jq -e '.success and .listAfterLoad.syntheticConnectionMatches == 1 and
  .listAfterUnload.syntheticConnectionMatches == 0 and
  .credentialRead == false and .initiateCalled == false and .installCalled == false' \
	"$evidence_dir/official-smoke.json" >/dev/null
jq -e '.success and .listAfterLoad.syntheticConnectionMatches == 1 and
  .listAfterUnload.syntheticConnectionMatches == 0 and
  .clientActions.credentialRead == false and
  .clientActions.initiateCalled == false and .clientActions.installCalled == false' \
	"$evidence_dir/swift-smoke.json" >/dev/null

scripts/snapshot_network_state.sh --output "$evidence_dir/during.json" >/dev/null
jq -e --slurpfile before "$evidence_dir/before.json" '
  .runtimeStatePresent == true and .ownedVICISocketPresent == true and
  (.nativeCharonPids | length) == 1 and
  .productionIKEPortsBoundByNative == false and .syntheticRouteObserved == false and
  ((.utunNames - $before[0].utunNames) | length) == 0 and
  .defaultRouteInterface == $before[0].defaultRouteInterface and
  .dnsSHA256 == $before[0].dnsSHA256 and
  .surgeProcessCount == $before[0].surgeProcessCount and
  .surgeExtensionProcessCount == $before[0].surgeExtensionProcessCount and
  .surgeHelperProcessCount == $before[0].surgeHelperProcessCount and
  .surgeCLIProcessCount == $before[0].surgeCLIProcessCount and
  .powerVPNProcessCount == $before[0].powerVPNProcessCount
' "$evidence_dir/during.json" >/dev/null

scripts/stop_native_charon.sh --stop --cp7a-unprivileged >"$evidence_dir/stop.out"
started=false
chmod 600 "$evidence_dir/stop.out"
scripts/snapshot_network_state.sh --output "$evidence_dir/after.json" >/dev/null
scripts/assert_clean_teardown.sh \
	--before "$evidence_dir/before.json" --after "$evidence_dir/after.json" \
	>"$evidence_dir/clean.json"
chmod 600 "$evidence_dir/clean.json"
jq -e '.cleanTeardown == true and .generationOwnedResidue == false' \
	"$evidence_dir/clean.json" >/dev/null

swift test
swift build --arch arm64
changed_swift=$(
	{
		git diff --name-only "$cp6_repo_commit" -- '*.swift'
		git ls-files --others --exclude-standard -- '*.swift'
	} | sort -u
)
for swift_file in $changed_swift; do
	xcrun swift-format lint --strict "$swift_file"
done
scripts/verify_no_secrets.sh
git diff --check "$cp6_repo_commit"

trap - EXIT HUP INT TERM
cleanup
