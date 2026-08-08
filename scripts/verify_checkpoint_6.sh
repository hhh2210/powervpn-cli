#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
checkpoint_base=${POWERVPN_CHECKPOINT_BASE:-876e58da7dca5dc0fa442eefc42c3098fe148d0d}
official_base=5973ff8e41deef4e015e1138a2de688acedf6f75
cp4a_upstream=1fda864cca91da0aa9a87dd96e1823c3962dbd09
cp6_upstream=67c9810900e2d8486cb3b11495a8362433494ca0
source_tree=${POWERVPN_STRONGSWAN_SOURCE:-/Users/larry_1/scratch-data/powervpn-strongswan/strongswan-6.0.7-expandrule}
build_tree=${POWERVPN_STRONGSWAN_BUILD:-/Users/larry_1/scratch-data/powervpn-strongswan/build-6.0.7-expandrule-arm64}
no_ikev1_build=${POWERVPN_STRONGSWAN_NO_IKEV1_BUILD:-/Users/larry_1/scratch-data/powervpn-strongswan/build-6.0.7-expandrule-no-ikev1-arm64}
tool_path=/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/gettext/bin:/opt/homebrew/bin:/usr/bin:/bin
patch_dir=patches/strongswan-6.0.7
patch_1=$patch_dir/0001-Add-strict-IKEv1-expandrule-wire-codec.patch
patch_2=$patch_dir/0002-Integrate-IKEv1-expandrule-payload-task-and-HASH.patch
manifest=$patch_dir/series.json
vici_spec=fixtures/redacted/tunnel-spec.vici-dry-run.json
vici_fixture=fixtures/redacted/vici-load-conn-dry-run-v1.json
smoke_fixture=fixtures/redacted/vici-daemon-smoke-summary-v1.json
hash3_fixture=fixtures/redacted/leadsec-qm-hash3-static-vector-v1.json
tmp_index=$(mktemp "${TMPDIR:-/tmp}/powervpn-cp6-index.XXXXXX")
make_log=$(mktemp "${TMPDIR:-/tmp}/powervpn-cp6-make.XXXXXX")
trap 'rm -f "$tmp_index" "$make_log"' EXIT HUP INT TERM

cd "$repo_root"

git cat-file -e "$checkpoint_base^{commit}"
git merge-base --is-ancestor "$checkpoint_base" HEAD
changed_files=$(
	{
		git diff --name-only "$checkpoint_base"
		git ls-files --others --exclude-standard
	} | sort -u
)
test -n "$changed_files"
for file in $changed_files
do
	case "$file" in
		GOAL.md|README.md|\
		Sources/PowerVPNCLI/main.swift|\
		Sources/PowerVPNCore/ClosedJSONShape.swift|\
		Sources/PowerVPNCore/TunnelSpecDecoding.swift|\
		Sources/PowerVPNCore/TunnelSpecValidation.swift|\
		Sources/PowerVPNCore/TunnelSpecVICIDryRun.swift|\
		Sources/PowerVPNCore/VICIMessage.swift|\
		Sources/PowerVPNCore/VICIMessageDecoding.swift|\
		Tests/PowerVPNCoreTests/TunnelSpecVICIDryRunTests.swift|\
		Tests/PowerVPNCoreTests/VICIMessageTests.swift|\
		docs/evidence/checkpoint-6-validation.md|\
		docs/progress/GOAL_STATUS.md|\
		docs/protocol-ike.md|\
		fixtures/redacted/tunnel-spec.vici-dry-run.json|\
		fixtures/redacted/leadsec-qm-hash3-static-vector-v1.json|\
		fixtures/redacted/vici-daemon-smoke-summary-v1.json|\
		fixtures/redacted/vici-load-conn-dry-run-v1.json|\
		patches/strongswan-6.0.7/0002-Integrate-IKEv1-expandrule-payload-task-and-HASH.patch|\
		patches/strongswan-6.0.7/series.json|\
		scripts/verify_checkpoint.sh|\
		scripts/verify_checkpoint_6.sh|\
		scripts/verify_vici_fixture.py)
			;;
		*)
			echo "error: unexpected CP6 artifact: $file" >&2
			exit 1
			;;
	esac
done

test -d "$source_tree/.git" -o -f "$source_tree/.git"
test -d "$build_tree"
test -d "$no_ikev1_build"
test "$(git -C "$source_tree" rev-parse HEAD)" = "$cp6_upstream"
test -z "$(git -C "$source_tree" status --porcelain=v1)"
test "$(shasum -a 256 "$patch_1" | awk '{print $1}')" = \
	b46031db4589865deef87433fe62ef2437ae0a55fe2f3fe42fa171c240d1aa6e
test "$(shasum -a 256 "$patch_2" | awk '{print $1}')" = \
	6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213

jq -e \
	--arg base "$official_base" \
	--arg cp4a "$cp4a_upstream" \
	--arg cp6 "$cp6_upstream" '
	.schemaVersion == 1 and
	.upstream.version == "6.0.7" and
	.upstream.baseCommit == $base and
	([.patches[].sequence] == [1, 2]) and
	.patch[0] == null and
	.patches[0].commit == $cp4a and
	.patches[1].commit == $cp6 and
	.patches[0].sha256 == "b46031db4589865deef87433fe62ef2437ae0a55fe2f3fe42fa171c240d1aa6e" and
	.patches[1].sha256 == "6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213" and
	.integrationBoundary.taskManagerWired == false and
	.integrationBoundary.viciCustomCommandWired == false and
	.integrationBoundary.securityAssociationMutation == false and
	.integrationBoundary.routeOrPolicyMutation == false and
	.integrationBoundary.utunMutation == false and
	.integrationBoundary.liveServerTested == false and
	.safety.containsSecrets == false and
	.safety.containsReplayableCapture == false and
	.safety.containsVendorBinaryOrObject == false
	' "$manifest" >/dev/null

rm -f "$tmp_index"
GIT_INDEX_FILE="$tmp_index" git -C "$source_tree" read-tree "$official_base"
GIT_INDEX_FILE="$tmp_index" git -C "$source_tree" apply --cached "$repo_root/$patch_1"
GIT_INDEX_FILE="$tmp_index" git -C "$source_tree" apply --cached "$repo_root/$patch_2"
replayed_tree=$(GIT_INDEX_FILE="$tmp_index" git -C "$source_tree" write-tree)
expected_tree=$(git -C "$source_tree" rev-parse "$cp6_upstream^{tree}")
test "$replayed_tree" = "$expected_tree"
git -C "$source_tree" diff --quiet "$cp4a_upstream" "$cp6_upstream" -- src/libcharon/sa/ikev1/task_manager_v1.c
git -C "$source_tree" diff --quiet "$cp4a_upstream" "$cp6_upstream" -- src/libcharon/sa/ikev1/keymat_v1.c
if rg -n -i '(map_?id|tunnel_?name|virtual_?ip|resource_?(id|name)|route_?count)' "$patch_2"; then
	echo "error: CP6 patch contains an unapproved CP4B semantic promotion" >&2
	exit 1
fi
if rg -n 'is_expandrule_only|Hash\(expandrule\)|M-ID \| encoded ADDRULE|generic Phase 2 HASH' "$patch_2"; then
	echo "error: CP6 patch reintroduces the disproven custom Quick Mode HASH path" >&2
	exit 1
fi

env PATH="$tool_path" make -j"${JOBS:-8}" -C "$build_tree/src/libcharon" libcharon.la
env PATH="$tool_path" make -j"${JOBS:-8}" -C "$build_tree/src/libcharon/tests" libcharon_tests
suite_output=$(TESTS_SUITES='expandrule codec' "$build_tree/src/libcharon/tests/libcharon_tests" 2>&1)
printf '%s\n' "$suite_output"
printf '%s\n' "$suite_output" | grep -Fq "Running suite 'expandrule codec'"
printf '%s\n' "$suite_output" | grep -Fq "Passed all 1 'expandrule codec' test cases"
plus_line=$(printf '%s\n' "$suite_output" | awk '/synthetic golden vectors/ { print; exit }')
test "$(printf '%s' "$plus_line" | tr -cd '+' | wc -c | tr -d ' ')" -eq 39

full_output=$("$build_tree/src/libcharon/tests/libcharon_tests" 2>&1)
printf '%s\n' "$full_output"
printf '%s\n' "$full_output" | grep -Fq "Passed all 5 'libcharon' suites"

if ! env PATH="$tool_path" make -j"${JOBS:-8}" -C "$build_tree" check >"$make_log" 2>&1
then
	tail -n 200 "$make_log" >&2
	exit 1
fi
grep -Fq 'All 2 tests passed' "$make_log"
file "$build_tree/src/libcharon/.libs/libcharon.0.dylib" | grep -q 'arm64'

if grep -q '^#define USE_IKEV1 1' "$no_ikev1_build/config.h"
then
	echo "error: no-IKEv1 link gate was configured with IKEv1 enabled" >&2
	exit 1
fi
env PATH="$tool_path" make -j"${JOBS:-8}" -C "$no_ikev1_build/src/libcharon" libcharon.la
env PATH="$tool_path" make -j"${JOBS:-8}" -C "$no_ikev1_build/src/charon" charon
test ! -e "$no_ikev1_build/src/libcharon/encoding/payloads/.libs/expandrule_payload.o"
if nm -u "$no_ikev1_build/src/libcharon/.libs/libcharon.0.dylib" |
	rg -q 'expandrule_payload_create'
then
	echo "error: no-IKEv1 libcharon retains an expandrule factory reference" >&2
	exit 1
fi
file "$no_ikev1_build/src/libcharon/.libs/libcharon.0.dylib" |
	grep -q 'arm64'

swift test --filter 'PowerVPNCoreTests.VICIMessageTests'
swift test --filter 'PowerVPNCoreTests.TunnelSpecVICIDryRunTests'
swift test
swift build --arch arm64
changed_swift=$(
	{
		git diff --name-only "$checkpoint_base" -- '*.swift'
		git ls-files --others --exclude-standard -- '*.swift'
	} | sort -u
)
for swift_file in $changed_swift
do
	xcrun swift-format lint --strict "$swift_file"
done

python3 scripts/verify_vici_fixture.py
swift run powervpn spec vici-dry-run "$vici_spec" --json |
	jq -e '
	.payloadByteCount == 335 and
	.payloadSHA256 == "07e9e6de79024f6c2d879e410942e7a402ce2f2c99d6b2fc8064ddea9819fa15" and
	.metadata.credentialIdentifierSerialized == false and
	.metadata.credentialIdentifierDereferenced == false and
	.metadata.credentialResolved == false and
	.metadata.secretRead == false and
	.metadata.secretSerialized == false and
	.metadata.resourceRuleWireBinding == "unresolved_cp4b" and
	.metadata.resourceRuleMetadataSerialized == false and
	.sideEffects.socketConnection == false and
	.sideEffects.processLaunch == false and
	.sideEffects.securityAssociationMutation == false and
	.sideEffects.routeMutation == false and
	.sideEffects.policyMutation == false and
	.sideEffects.utunMutation == false
	' >/dev/null

jq -e '
	.schemaVersion == 1 and
	.fixtureClass == "vici_daemon_smoke_summary" and
	.attemptCount == 1 and
	.execution.nonRoot == true and
	.execution.randomHighUdpPorts == true and
	.execution.initiators == 0 and
	.credentialBoundary.userOrProjectCredentialLoaded == false and
	.credentialBoundary.viciCredentialCommandSent == false and
	.evidenceSemantics.selfConsistency.evidenceClass == "implementation_self_consistency" and
	.evidenceSemantics.selfConsistency.observed == true and
	.evidenceSemantics.selfConsistency.vendorCompatibilityInferred == false and
	.evidenceSemantics.stockViciByteOracle.evidenceClass == "stock_vici_serialization" and
	.evidenceSemantics.stockViciByteOracle.observed == true and
	.evidenceSemantics.stockViciByteOracle.provesOnly == ["stock_vici_serialization"] and
	.evidenceSemantics.stockViciByteOracle.daemonAcceptanceInferred == false and
	.evidenceSemantics.stockViciByteOracle.vendorHashCompatibilityInferred == false and
	.evidenceSemantics.daemonSmoke.evidenceClass == "daemon_smoke" and
	.evidenceSemantics.daemonSmoke.status == "blocked" and
	.evidenceSemantics.daemonSmoke.acceptancePass == false and
	.evidenceSemantics.vendorHashCompatibility.evidenceClass == "vendor_hash_compatibility" and
	.evidenceSemantics.vendorHashCompatibility.status == "unproven" and
	.evidenceSemantics.vendorHashCompatibility.pendingIndependentEvidence ==
		["independent_hash_oracle", "vendor_server_acceptance"] and
	.evidenceSemantics.vendorHashCompatibility.independentHashOracleObserved == false and
	.evidenceSemantics.vendorHashCompatibility.vendorServerAcceptanceObserved == false and
	.evidenceSemantics.vendorHashCompatibility.promotableFromSelfConsistency == false and
	.evidenceSemantics.vendorHashCompatibility.promotableFromStockViciByteOracle == false and
	.evidenceSemantics.vendorHashCompatibility.promotableFromBlockedDaemonSmoke == false and
	(.evidenceSemantics.selfConsistency.evidenceClass !=
		.evidenceSemantics.vendorHashCompatibility.evidenceClass) and
	.result.classification == "blocked_not_acceptance_pass" and
	.result.firstOperation == "version" and
	.result.firstFailure == "response_timeout" and
	.result.loadConnSent == false and
	.result.daemonSaCountObserved == false and
	.result.daemonPolicyCountObserved == false and
	.cleanup.utunSetChanged == false and
	.cleanup.syntheticDocumentationRouteObserved == false and
	.cleanup.globalRouteSnapshotStable == false and
	.cleanup.residualProcess == false and
	.cleanup.residualUdpDescriptor == false and
	.cleanup.residualPidFile == false and
	.cleanup.residualUnixSocket == false and
	.safety.containsSecrets == false and
	.safety.containsReplayableCapture == false and
	.safety.vendorSessionTouched == false and
	.safety.surgeConfigurationTouched == false and
	.safety.privilegedOperation == false
	' "$smoke_fixture" >/dev/null
test "$(shasum -a 256 "$hash3_fixture" | awk '{print $1}')" = \
	71e02c45359e1153ce11ab7e10a87358c09ea9bb4edfd74a8286993d410aac05
jq -e '
	def closed($expected): keys == ($expected | sort);
	def vector($label; $key; $mid; $input; $output):
		closed(["skeyidALabel", "skeyidAHex", "inputLayout", "inputHex", "inputByteCount", "outputHex"]) and
		(.inputLayout | closed(["zeroHex", "midHex", "niHex", "nrHex"]) and .zeroHex == "00" and .midHex == $mid and
			.niHex == "101112131415161718191a1b1c1d1e1f" and .nrHex == "202122232425262728292a2b2c2d2e2f") and
		.skeyidALabel == $label and .skeyidAHex == $key and
		.inputHex == (.inputLayout.zeroHex + .inputLayout.midHex + .inputLayout.niHex + .inputLayout.nrHex) and
		.inputHex == $input and .inputByteCount == 37 and .outputHex == $output;
	closed(["schemaVersion", "fixtureClass", "vendorBinary", "staticDisassembly", "hash3", "evidence", "safety"]) and
	.schemaVersion == 1 and .fixtureClass == "leadsec_qm_hash3_static_vector" and
	(.vendorBinary | closed(["sha256", "uuid"]) and
		.sha256 == "ce25374f028216374d386c91a7ee8fea8146b4bfd80f5fde6a59954700555404" and
		.uuid == "D6973685-6A34-30CD-A8A9-94A342B1CA47") and
	(.staticDisassembly | closed(["getHashPhase2", "quickModeBuildIState1"])) and
	(.staticDisassembly.getHashPhase2 | closed(["symbol", "address"]) and
		.symbol == "_get_hash_phase2" and .address == "0x10014fa70") and
	(.staticDisassembly.quickModeBuildIState1 |
		closed(["component", "symbol", "functionEntry", "state", "rangeStartInclusive", "rangeEndExclusive", "callInstruction", "callTarget", "callTargetAddress"]) and
		.component == "quick_mode" and .symbol == "_build_i" and .functionEntry == "0x100165db0" and
		.state == 1 and .rangeStartInclusive == "0x10016647b" and .rangeEndExclusive == "0x10016657e" and
		.callInstruction == "0x100166574" and .callTarget == "_add_expandrule" and .callTargetAddress == "0x100166bf0") and
	(.hash3 | closed(["algorithm", "formula", "addruleBytesIncluded", "formulaReference", "candidateKeymatReference"]) and
		.algorithm == "HMAC-SHA1" and .formula == "HASH3=HMAC-SHA1(SKEYID_a,0|MID|Ni|Nr)" and
		.addruleBytesIncluded == false) and
	(.hash3.formulaReference | vector("synthetic_skeyid_a"; "000102030405060708090a0b0c0d0e0f10111213"; "01020304";
		"0001020304101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"; "b8494c87c1816dacf76df03ce97591efcdbe92fc")) and
	(.hash3.candidateKeymatReference | vector("synthetic_derived_skeyid_a"; "1525560a1d9cc81b96c26cfda2f753bfcf4a4f1c"; "10203040";
		"0010203040101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"; "5ac5eb052dd4043437faea7bfb73ab306567e5a6")) and
	(.evidence | closed(["class", "provesOnly", "vendorStaticHashContractStatus", "independentReferenceVectorObserved", "candidateMatchStatus", "liveVendorHashCompatibilityStatus", "independentVendorOracleObserved", "liveDifferentialObserved", "vendorServerAcceptanceObserved"]) and
		.class == "vendor_static_disassembly_plus_independent_synthetic_calculation" and
		.provesOnly == ["vendor_static_hash3_control_flow", "independent_synthetic_hmac_sha1_calculation"] and
		.vendorStaticHashContractStatus == "established" and .independentReferenceVectorObserved == true and
		.candidateMatchStatus == "validated_by_checkpoint_test" and
		.liveVendorHashCompatibilityStatus == "unproven" and .independentVendorOracleObserved == false and
		.liveDifferentialObserved == false and .vendorServerAcceptanceObserved == false) and
	(.safety | closed(["syntheticOnly", "containsSecrets", "containsReplayableCapture", "containsVendorBinaryOrObject"]) and
		.syntheticOnly == true and .containsSecrets == false and .containsReplayableCapture == false and
		.containsVendorBinaryOrObject == false)
	' "$hash3_fixture" >/dev/null
for hash3_reference in formulaReference candidateKeymatReference
do
	hash3_key=$(jq -er --arg ref "$hash3_reference" '.hash3[$ref].skeyidAHex' "$hash3_fixture")
	hash3_input=$(jq -er --arg ref "$hash3_reference" '.hash3[$ref].inputHex' "$hash3_fixture")
	hash3_expected=$(jq -er --arg ref "$hash3_reference" '.hash3[$ref].outputHex' "$hash3_fixture")
	hash3_actual=$(printf '%s' "$hash3_input" | /usr/bin/xxd -r -p |
		/usr/bin/openssl dgst -sha1 -mac HMAC -macopt "hexkey:$hash3_key" -binary |
		/usr/bin/xxd -p -c 256)
	test "$hash3_actual" = "$hash3_expected"
done
jq empty "$vici_spec" "$vici_fixture" "$smoke_fixture" "$hash3_fixture" "$manifest"
scripts/verify_no_secrets.sh
git diff --check "$checkpoint_base"
