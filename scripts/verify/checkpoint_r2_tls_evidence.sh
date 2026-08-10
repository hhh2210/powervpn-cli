#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
base=440657873b6fcb91a88262fb8df0e874f7919ec2
manifest=fixtures/redacted/r2-tls-evidence-reviewed-manifest-v1.json
parent=fixtures/redacted/r2-tls-evidence-parent-r2-manifest-v1.json

git cat-file -e "$base^{commit}"
head=$(git rev-parse HEAD)
[ "$head" = "$base" ] || [ "$(git rev-parse "$head^")" = "$base" ]
[ "$(git branch --show-current)" = rescue-state-machine ]
[ "$(sed -n 's/^current_checkpoint: //p' GOAL.md)" = R2-username-password-portal-login ]

changed=$({ git diff --name-only "$base"; git ls-files --others --exclude-standard; } | sort -u)
[ -n "$changed" ]
for file in $changed; do
	case "$file" in
		.gitleaks.toml | Package.swift | GOAL.md | README.md | docs/evidence/checkpoint-r2-validation.md | \
		docs/evidence/checkpoint-r2-tls-peer-evidence.md | docs/progress/GOAL_STATUS.md | \
		fixtures/redacted/r2-tls-evidence-parent-r2-manifest-v1.json | \
		fixtures/redacted/r2-tls-evidence-reviewed-manifest-v1.json | \
		fixtures/redacted/r2-tls-evidence-authorized-manifest-v1.json | \
		fixtures/redacted/r2-tls-evidence-attempt2-authorized-manifest-v1.json | \
		fixtures/redacted/r2-tls-peer-runtime-attempt2-v1.json | \
		fixtures/redacted/r2-tls-peer-runtime-v1.json | \
		Sources/PowerVPNTLSEvidence/*.swift | Sources/PowerVPNTLSEvidenceCLI/*.swift | \
		Tests/PowerVPNTLSEvidenceTests/*.swift | Tests/PowerVPNTLSEvidenceTests/Fixtures/*.pem | \
		scripts/lib/r2_tls_evidence_attempts.sh | scripts/lib/r2_tls_evidence_monitor.sh | \
		scripts/lib/r2_tls_evidence_deadline.sh | \
		scripts/lib/r2_tls_evidence_finalize.sh | \
		scripts/lib/r2_tls_evidence_manifest.sh | \
		scripts/lib/r2_tls_evidence_result.sh | \
		scripts/lib/r2_tls_evidence_review_bundle.sh | \
		scripts/lib/r2_tls_evidence_runtime.sh | \
		scripts/run_r2_tls_evidence.sh | scripts/export_r2_tls_review_bundle.sh | \
		scripts/verify/r2_tls_evidence_attempt_tests.sh | \
		scripts/verify/r2_tls_evidence_finalization_tests.sh | \
		scripts/verify/r2_tls_evidence_harness_tests.sh | \
		scripts/verify/r2_tls_evidence_historical_tests.sh | \
		scripts/verify/r2_tls_evidence_manifest_tests.sh | \
		scripts/verify/r2_tls_evidence_review_bundle_tests.sh | \
		scripts/verify/r2_tls_evidence_runtime_tests.sh | \
		scripts/verify/checkpoint_r2_tls_evidence.sh | scripts/verify_checkpoint.sh) ;;
	*) echo "error: unexpected R2 TLS evidence artifact: $file" >&2; exit 1 ;;
	esac
done
for file in $changed; do
	[ -f "$file" ] || continue
	git cat-file -e "$base:$file" 2>/dev/null && continue
	[ "$(wc -l <"$file" | tr -d ' ')" -lt 300 ] || {
		echo "error: R2 TLS evidence file exceeds split gate: $file" >&2; exit 1;
	}
done

package=$(swift package describe --type json)
printf '%s\n' "$package" | jq -e '
  .platforms==[{"name":"macos","version":"14.0"}] and
  ([.targets[]|select(.name=="PowerVPNTLSEvidence")]|length)==1 and
  ([.targets[]|select(.name=="PowerVPNTLSEvidence")][0].target_dependencies//[])==[] and
  ([.targets[]|select(.name=="PowerVPNTLSEvidence")][0].product_dependencies//[])==[] and
  ([.targets[]|select(.name=="PowerVPNTLSEvidenceCLI")][0].target_dependencies)==
    ["PowerVPNTLSEvidence"] and
  ([.targets[]|select(.name=="PowerVPNTLSEvidenceTests")][0].target_dependencies)==
    ["PowerVPNTLSEvidence"]
' >/dev/null

production=$(printf '%s\n' Sources/PowerVPNTLSEvidence/*.swift \
	Sources/PowerVPNTLSEvidenceCLI/*.swift)
# The evidence lane may emit only a TLS handshake that its verify callback rejects.
# shellcheck disable=SC2086
if rg -n -i 'http|URLSession|CPortalCurl|curl_|credential|cookie|keychain|readpassphrase|FileHandle|\.send\(' $production; then
	echo 'error: forbidden HTTP, credential, storage, or application-data API in TLS evidence lane' >&2
	exit 1
fi
[ "$(rg -n 'NWConnection\(' Sources/PowerVPNTLSEvidence | wc -l | tr -d ' ')" -eq 1 ]
if rg -Fq 'sec_protocol_options_set_tls_server_name' Sources/PowerVPNTLSEvidence; then
	echo 'error: IP-literal TLS evidence must not add an SNI/server-name override' >&2
	exit 1
fi
rg -Fq 'sec_protocol_metadata_access_peer_certificate_chain' \
	Sources/PowerVPNTLSEvidence/TLSPeerCertificateChain.swift
rg -Fq 'sec_certificate_copy_ref' \
	Sources/PowerVPNTLSEvidence/TLSPeerCertificateChain.swift
rg -Fq 'SecTrustEvaluateAsyncWithError' \
	Sources/PowerVPNTLSEvidence/TLSAsyncTrustEvaluator.swift
if rg -n '\bSecTrustEvaluateWithError\b|SecTrustCopyCertificateChain|sec_trust_copy_ref' \
	Sources/PowerVPNTLSEvidence; then
	echo 'error: TLS evidence must copy the metadata chain and evaluate only asynchronously' >&2
	exit 1
fi
rg -Fq 'retained.0(false)' Sources/PowerVPNTLSEvidence/TLSTrustSource.swift
if rg -Fq 'callback(true)' Sources/PowerVPNTLSEvidence; then exit 1; fi
rg -Fq 'SecTrustSetNetworkFetchAllowed(trust, false)' \
	Sources/PowerVPNTLSEvidence/TLSAsyncTrustSession.swift
rg -Fq 'kSecRevocationNetworkAccessDisabled' \
	Sources/PowerVPNTLSEvidence/TLSAsyncTrustSession.swift
if rg -Fq 'basic.accepted' Sources/PowerVPNTLSEvidence/TLSTrustSnapshot.swift; then
	echo 'error: basic trust must not coerce the SSL failure category' >&2
	exit 1
fi
rg -Fq 'static let sealedHost = "166.111.143.19"' \
	Sources/PowerVPNTLSEvidence/TLSTrustSource.swift
rg -Fq 'static let sealedPort: UInt16 = 4_443' \
	Sources/PowerVPNTLSEvidence/TLSTrustSource.swift
rg -Fq 'static let sealedTimeoutNanoseconds: UInt64 = 15_000_000_000' \
	Sources/PowerVPNTLSEvidence/TLSPeerObserver.swift
rg -Fq 'public let transportProgress: TLSConnectionProgress' \
	Sources/PowerVPNTLSEvidence/TLSPeerEvidenceReport.swift
rg -Fq 'public let evidenceProgress: TLSEvidenceProgress' \
	Sources/PowerVPNTLSEvidence/TLSPeerEvidenceReport.swift
rg -Fq 'schemaVersion = 3' Sources/PowerVPNTLSEvidence/TLSPeerEvidenceReport.swift
if rg -Fq 'manifestExact:true' scripts/run_r2_tls_evidence.sh; then
	echo 'error: live result must not hard-code manifest exactness' >&2
	exit 1
fi
rg -Fq -- '--argjson manifestExact "$manifest_stable"' \
	scripts/lib/r2_tls_evidence_result.sh
rg -Fq 'r2tls_finalization_barrier' scripts/run_r2_tls_evidence.sh
rg -Fq 'r2tls_publish_result_atomic' scripts/lib/r2_tls_evidence_finalize.sh
rg -Fq 'R2TLS_ATTEMPT3_EXPERIMENT=attempt3-after-inconclusive-v2' \
	scripts/lib/r2_tls_evidence_attempts.sh
rg -Fq '.attempt3-consumed-$approved_sha' scripts/lib/r2_tls_evidence_attempts.sh
for dimension in executionSafetyPass transportEvidenceComplete trustEvidenceComplete \
	compatibilityOutcome trustDisposition monitorQuality environmentStable checkpointPass; do
	rg -Fq "$dimension" scripts/lib/r2_tls_evidence_result.sh
done
if rg -n '\.send\(' Tests/PowerVPNTLSEvidenceTests/LocalTLS*.swift \
	Tests/PowerVPNTLSEvidenceTests/TLSIPLiteralIntegrationTests.swift; then
	echo 'error: localhost TLS differential must not send application data' >&2
	exit 1
fi

for script in scripts/lib/r2_tls_evidence_attempts.sh scripts/lib/r2_tls_evidence_deadline.sh \
	scripts/lib/r2_tls_evidence_finalize.sh \
	scripts/lib/r2_tls_evidence_manifest.sh scripts/lib/r2_tls_evidence_monitor.sh \
	scripts/lib/r2_tls_evidence_result.sh scripts/lib/r2_tls_evidence_review_bundle.sh \
	scripts/lib/r2_tls_evidence_runtime.sh \
	scripts/run_r2_tls_evidence.sh scripts/export_r2_tls_review_bundle.sh \
	scripts/verify/r2_tls_evidence_attempt_tests.sh \
	scripts/verify/r2_tls_evidence_finalization_tests.sh \
	scripts/verify/r2_tls_evidence_harness_tests.sh \
	scripts/verify/r2_tls_evidence_historical_tests.sh \
	scripts/verify/r2_tls_evidence_manifest_tests.sh \
	scripts/verify/r2_tls_evidence_review_bundle_tests.sh \
	scripts/verify/r2_tls_evidence_runtime_tests.sh \
	scripts/verify/checkpoint_r2_tls_evidence.sh scripts/verify_checkpoint.sh; do
	sh -n "$script"
done
shellcheck -x -e SC1091 scripts/lib/r2_tls_evidence_attempts.sh \
	scripts/lib/r2_tls_evidence_deadline.sh \
	scripts/lib/r2_tls_evidence_finalize.sh \
	scripts/lib/r2_tls_evidence_manifest.sh \
	scripts/lib/r2_tls_evidence_monitor.sh \
	scripts/lib/r2_tls_evidence_result.sh scripts/lib/r2_tls_evidence_review_bundle.sh \
	scripts/lib/r2_tls_evidence_runtime.sh scripts/export_r2_tls_review_bundle.sh \
	scripts/run_r2_tls_evidence.sh scripts/verify/r2_tls_evidence_harness_tests.sh \
	scripts/verify/r2_tls_evidence_attempt_tests.sh \
	scripts/verify/r2_tls_evidence_finalization_tests.sh \
	scripts/verify/r2_tls_evidence_historical_tests.sh \
	scripts/verify/r2_tls_evidence_manifest_tests.sh \
	scripts/verify/r2_tls_evidence_review_bundle_tests.sh \
	scripts/verify/r2_tls_evidence_runtime_tests.sh \
	scripts/verify/checkpoint_r2_tls_evidence.sh

runs_before=$(/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
	awk '$1=="runs" && $2=="=" {print $3;exit}')
[ "$runs_before" -eq 19 ]
[ -z "$(pgrep -f '^/Library/PrivilegedHelperTools/com\.leadsec\.charon-xpc$' || true)" ]

swift test --filter PowerVPNTLSEvidenceTests
swift test
swift build --product powervpn-tls-evidence --arch arm64
for file in Package.swift Sources/PowerVPNTLSEvidence/*.swift \
	Sources/PowerVPNTLSEvidenceCLI/*.swift Tests/PowerVPNTLSEvidenceTests/*.swift; do
	xcrun swift-format lint --strict "$file"
done

set +e; .build/debug/powervpn-tls-evidence unexpected >/dev/null 2>&1; cli_usage_rc=$?; set -e
[ "$cli_usage_rc" -eq 64 ]
scripts/verify/r2_tls_evidence_harness_tests.sh
scripts/verify/r2_tls_evidence_historical_tests.sh
scripts/verify/r2_tls_evidence_manifest_tests.sh
scripts/verify/r2_tls_evidence_runtime_tests.sh
scripts/verify/r2_tls_evidence_review_bundle_tests.sh
scripts/verify_no_secrets.sh
[ -z "$(/bin/ps -axo command= | awk -v runner="$repo_root/scripts/run_r2_tls_evidence.sh" '
  {sub(/^[[:space:]]*/,"")} $0==runner || index($0,runner " ")==1 {print}')" ]

runs_after=$(/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
	awk '$1=="runs" && $2=="=" {print $3;exit}')
[ "$runs_after" -eq "$runs_before" ]
[ -z "$(pgrep -f '^/Library/PrivilegedHelperTools/com\.leadsec\.charon-xpc$' || true)" ]

R2TLS_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$repo_root/scripts/lib/r2_tls_evidence_runtime.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_manifest.sh
. "$repo_root/scripts/lib/r2_tls_evidence_manifest.sh"
r2tls_candidate_manifest_exact
expected_review=post_attempt2_narrow_review_pending
case "${POWERVPN_R2_TLS_REVIEW_CANDIDATE:-post-attempt2-pending-v2}" in
post-attempt2-pending-v2) ;;
*) echo 'error: R2 TLS review-candidate token is stale' >&2; exit 1 ;;
esac
[ "$(jq -r .reviewState "$manifest")" = "$expected_review" ]
[ "$(r2tls_hash_file "$parent")" = 8e19d1937d7ab432e9a747725d636e565432159561a0962a6d0ec07afe9fdb1e ]
jq -e '
  keys==["artifacts","attempt1AuthorizedManifestSHA256",
    "attempt1RunEvidenceAggregateSHA256","attempt1RuntimeFixtureSHA256",
    "attempt2AuthorizedManifestSHA256","attempt2RunEvidenceAggregateSHA256",
    "attempt2RuntimeFixtureSHA256","baseCommit","evidenceClass",
    "parentR2ManifestSHA256","reviewState","runtimeSourceAggregateSHA256",
    "schemaVersion"] and
  .schemaVersion==2 and .evidenceClass=="r2_tls_peer_evidence_post_attempt2_candidate" and
  .baseCommit=="440657873b6fcb91a88262fb8df0e874f7919ec2" and
  (.parentR2ManifestSHA256|test("^[0-9a-f]{64}$")) and
  .attempt1AuthorizedManifestSHA256==
    "e8b622cb4600ae5e603364accd13dffcd45d1a4aa6a48afe69401fee314cd5d4" and
  .attempt1RuntimeFixtureSHA256==
    "27a0b7a511addff9888041c94c94b1a3ba9f408ff0a15b3941dcb7d4f6e3d61b" and
  .attempt1RunEvidenceAggregateSHA256==
    "aef7d3b7734b132f6b5d1bb3fc498d7609d3424c0808a5a029af0e4076d687c9" and
  .attempt2AuthorizedManifestSHA256==
    "b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354" and
  .attempt2RuntimeFixtureSHA256==
    "8766a176e542173bf7b53b79ca005cde0c222a5d2c699871e6aeafd329761219" and
  .attempt2RunEvidenceAggregateSHA256==
    "21eb127eae03c6c49a56538e285cab0215e00d7122a1c8c0d8184d646bbdcce2" and
  (.runtimeSourceAggregateSHA256|test("^[0-9a-f]{64}$")) and
  (.artifacts|keys)==["arm64CLISHA256","attemptTestsSHA256",
    "attemptsLibrarySHA256","harnessTestsSHA256","manifestLibrarySHA256",
    "manifestTestsSHA256","monitorLibrarySHA256",
    "networkSnapshotInputsAggregateSHA256","networkSnapshotSHA256",
    "resultLibrarySHA256","reviewBundleInputsAggregateSHA256","runnerSHA256",
    "runtimeLibrarySHA256","runtimeScriptsAggregateSHA256",
    "shellTestsAggregateSHA256","testOpenSSLExecutableSHA256",
    "tlsEvidenceTestsAggregateSHA256","verifierInputsAggregateSHA256",
    "verifierSHA256"] and
  all(.artifacts[];test("^[0-9a-f]{64}$"))
' "$manifest" >/dev/null

git diff --check "$base"
printf 'PASS: R2 credential-free TLS peer evidence (%s)\n' "$expected_review"
