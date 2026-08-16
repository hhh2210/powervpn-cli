#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"

base=c849d0bc64e21486134ed8029a3107210b3e7752

git cat-file -e "$base^{commit}"
git merge-base --is-ancestor "$base" HEAD
[ "$(git branch --show-current)" = rescue-mvp ]
[ "$(sed -n 's/^product_branch: //p' GOAL.md)" = rescue-mvp ]

changed_files=$(
	{
		git diff --name-only --diff-filter=ACMRT "$base"
		git ls-files --others --exclude-standard -- \
			Package.swift GOAL.md docs Sources Tests scripts
	} | sort -u
)
[ -n "$changed_files" ]
# Later rescue milestones share this branch; inspect only artifacts owned by this
# checkpoint instead of rejecting unrelated tracked or untracked work.
checkpoint_changed_files=
for file in $changed_files; do
	case "$file" in
	Package.swift | GOAL.md | docs/progress/GOAL_STATUS.md | \
		Sources/CPortalCurl/CPortalCurl.c | \
		Sources/CPortalCurl/CPortalCurlHeaders.c | \
		Sources/CPortalCurl/CPortalCurlInternal.h | \
		Sources/CPortalCurl/CPortalCurlRequest.c | \
		Sources/CPortalCurl/CPortalCurlTrust.c | \
		Sources/CPortalCurl/include/CPortalCurl.h | \
		Sources/PowerVPNCLI/CLIUsage.swift | \
		Sources/PowerVPNCLI/M2ConnectOnceCommand.swift | \
		Sources/PowerVPNCLI/PortalDryRunCommand.swift | \
		Sources/PowerVPNCLI/main.swift | \
		Sources/PowerVPNPortal/CPortalCurlPasswordDriver.swift | \
		Sources/PowerVPNPortal/CurlPasswordPortalTransport.swift | \
		Sources/PowerVPNPortal/CPortalCurlDriver.swift | \
		Sources/PowerVPNPortal/CurlPortalTransport.swift | \
		Sources/PowerVPNPortal/PortalAuthenticationFlow.swift | \
		Sources/PowerVPNPortal/LeadSecPortalCookieJar.swift | \
		Sources/PowerVPNPortal/InstalledPortalProfile.swift | \
		Sources/PowerVPNPortal/LeadSecPortalTransport.swift | \
		Sources/PowerVPNPortal/PortalFixedTOFUVerifier.swift | \
		Sources/PowerVPNPortal/PortalLoginReport.swift | \
		Sources/PowerVPNPortal/PortalLoginWorkflow.swift | \
		Sources/PowerVPNPortal/PortalLoginRuntime.swift | \
		Sources/PowerVPNPortal/PortalURLSessionDelegate.swift | \
		Sources/PowerVPNPortal/DarwinTerminalCredentialDriver.swift | \
		Sources/PowerVPNPortal/URLSessionPortalTransport.swift | \
		Sources/PowerVPNPortal/SecureTerminalCredentials.swift | \
		Sources/PowerVPNProduct/ProductReadinessModels.swift | \
		Sources/PowerVPNProduct/ProductReadinessRuntime.swift | \
		Sources/PowerVPNProduct/ProductPortalDryRunModels.swift | \
		Sources/PowerVPNProduct/ProductPortalDryRunRuntime.swift | \
		Tests/CPortalCurlTests/CPortalCurlHeaderTests.c | \
		Tests/CPortalCurlTests/CPortalCurlStatusTests.c | \
		Tests/CPortalCurlTests/CPortalCurlTrustContractClient.c | \
		Tests/CPortalCurlTests/LocalTLSTrustContractServer.py | \
		Tests/PowerVPNPortalTests/PortalDryRunCommandTests.swift | \
		Tests/PowerVPNPortalTests/DarwinTerminalCredentialDriverPTYTests.swift | \
		Tests/PowerVPNPortalTests/CurlPasswordPortalTransportTests.swift | \
		Tests/PowerVPNPortalTests/CurlPortalTransportTestSupport.swift | \
		Tests/PowerVPNPortalTests/CurlPortalTransportTests.swift | \
		Tests/PowerVPNPortalTests/SetCookieWireOrderTests.swift | \
		Tests/PowerVPNPortalTests/AuthenticatedPortalContextTests.swift | \
		Tests/PowerVPNPortalTests/AuthenticatedPortalGatewayContextTests.swift | \
		Tests/PowerVPNPortalTests/AuthenticatedPortalSnapshotTests.swift | \
		Tests/PowerVPNPortalTests/LeadSecPortalCookieJarTests.swift | \
		Tests/PowerVPNPortalTests/LeadSecPortalSessionBoundaryTests.swift | \
		Tests/PowerVPNPortalTests/PortalLoginWorkflowTestSupport.swift | \
		Tests/PowerVPNPortalTests/PortalRequestFactoryTests.swift | \
		Tests/PowerVPNPortalTests/URLSessionPortalTransportTests.swift | \
		Tests/PowerVPNPortalTests/InstalledConfigDiscoveryTests.swift | \
		Tests/PowerVPNPortalTests/LeadSecPortalTransportTests.swift | \
		Tests/PowerVPNPortalTests/PortalFixedTOFUVerifierTests.swift | \
		Tests/PowerVPNPortalTests/PortalLoginReportTests.swift | \
		Tests/PowerVPNPortalTests/PortalLoginWorkflowTests.swift | \
		Tests/PowerVPNPortalTests/SecureTerminalCredentialsTests.swift | \
		Tests/PowerVPNPortalTests/TerminalCredentialTransactionGatePTYTests.swift | \
		Tests/PowerVPNPortalTests/PortalLoginRuntimeTests.swift | \
		Tests/PowerVPNProductTests/AuthenticatedPortalSnapshotMapperTests.swift | \
		Tests/PowerVPNProductTests/AuthenticatedPortalSnapshotMapperTestSupport.swift | \
		Tests/PowerVPNProductTests/ProductCommandTests.swift | \
		Tests/PowerVPNProductTests/ProductHelperStatusProbeTests.swift | \
		Tests/PowerVPNProductTests/ProductReadinessRuntimeTests.swift | \
		Tests/PowerVPNProductTests/ProductPortalDryRunAcquisitionStatusTests.swift | \
		Tests/PowerVPNProductTests/ProductPortalDryRunRuntimeTests.swift | \
		Tests/PowerVPNProductTests/ProductPortalDryRunTestSupport.swift | \
		Tests/PowerVPNTLSEvidenceTests/Fixtures/portal-leaf.pem | \
		Tests/PowerVPNTLSEvidenceTests/X509SPKIExtractorTests.swift | \
		scripts/lib/r2_portal_runtime.sh | \
		scripts/verify/cportalcurl_trust_contract.sh | \
		scripts/verify/r2_live_harness_tests.sh | \
		scripts/verify/checkpoint_r2_raw_headers.sh)
		checkpoint_changed_files="$checkpoint_changed_files $file"
		;;
	*)
		continue
		;;
	esac
done
changed_files=$checkpoint_changed_files

required_files='Sources/CPortalCurl/CPortalCurl.c
Sources/CPortalCurl/CPortalCurlHeaders.c
Sources/CPortalCurl/CPortalCurlInternal.h
Sources/CPortalCurl/CPortalCurlRequest.c
Sources/CPortalCurl/CPortalCurlTrust.c
Sources/CPortalCurl/include/CPortalCurl.h
Sources/PowerVPNPortal/CPortalCurlDriver.swift
Sources/PowerVPNPortal/DarwinTerminalCredentialDriver.swift
Sources/PowerVPNPortal/CurlPortalTransport.swift
Sources/PowerVPNPortal/LeadSecPortalCookieJar.swift
Sources/PowerVPNPortal/PortalAuthenticationFlow.swift
Sources/PowerVPNPortal/LeadSecPortalTransport.swift
Sources/PowerVPNPortal/PortalFixedTOFUVerifier.swift
Sources/PowerVPNPortal/PortalLoginReport.swift
Sources/PowerVPNPortal/PortalLoginWorkflow.swift
Sources/PowerVPNPortal/SecureTerminalCredentials.swift
Sources/PowerVPNPortal/URLSessionPortalTransport.swift
Sources/PowerVPNProduct/ProductPortalDryRunModels.swift
Sources/PowerVPNProduct/ProductPortalDryRunRuntime.swift
Tests/CPortalCurlTests/CPortalCurlHeaderTests.c
Tests/CPortalCurlTests/CPortalCurlStatusTests.c
Tests/CPortalCurlTests/CPortalCurlTrustContractClient.c
Tests/CPortalCurlTests/LocalTLSTrustContractServer.py
Tests/PowerVPNPortalTests/DarwinTerminalCredentialDriverPTYTests.swift
Tests/PowerVPNPortalTests/CurlPortalTransportTests.swift
Tests/PowerVPNPortalTests/LeadSecPortalTransportTests.swift
Tests/PowerVPNPortalTests/PortalLoginWorkflowTests.swift
Tests/PowerVPNPortalTests/SetCookieWireOrderTests.swift
Tests/PowerVPNPortalTests/PortalLoginReportTests.swift
Tests/PowerVPNPortalTests/SecureTerminalCredentialsTests.swift
Tests/PowerVPNPortalTests/TerminalCredentialTransactionGatePTYTests.swift
Tests/PowerVPNProductTests/ProductPortalDryRunAcquisitionStatusTests.swift
Tests/PowerVPNProductTests/ProductPortalDryRunRuntimeTests.swift
Tests/PowerVPNPortalTests/PortalFixedTOFUVerifierTests.swift
scripts/verify/cportalcurl_trust_contract.sh'
for file in $required_files; do
	[ -f "$file" ] || {
		echo "error: missing R2 raw-header artifact: $file" >&2
		exit 1
	}
done



package_json=$(swift package describe --type json)
printf '%s\n' "$package_json" | jq -e '
  .platforms == [{"name":"macos","version":"14.0"}] and
  ([.targets[] | select(.name == "CPortalCurl")] | length) == 1 and
  ([.targets[] | select(.name == "CPortalCurl")][0].target_dependencies // []) == [] and
  ([.targets[] | select(.name == "CPortalCurl")][0].product_dependencies // []) == [] and
  ([.targets[] | select(.name == "PowerVPNPortal")][0].target_dependencies // []) ==
    ["CPortalCurl"] and
  ([.targets[] | select(.name == "PowerVPNPortal")][0].product_dependencies // []) == [] and
  ([.targets[] | select(.name == "PowerVPNCLI")][0].target_dependencies | sort) ==
    ["PowerVPNCore", "PowerVPNPortal", "PowerVPNProduct"]
' >/dev/null
rg -Fq 'linkerSettings: [.linkedLibrary("curl")]' Package.swift
if rg -n 'pkgConfig:|providers:|unsafeFlags|/opt/homebrew|/usr/local' Package.swift; then
	echo 'error: non-system or unsafe CPortalCurl package linkage' >&2
	exit 1
fi

raw_sources='Sources/CPortalCurl/CPortalCurl.c
Sources/CPortalCurl/CPortalCurlHeaders.c
Sources/CPortalCurl/CPortalCurlInternal.h
Sources/CPortalCurl/CPortalCurlRequest.c
Sources/CPortalCurl/CPortalCurlTrust.c
Sources/CPortalCurl/include/CPortalCurl.h
Sources/PowerVPNPortal/CPortalCurlDriver.swift
Sources/PowerVPNPortal/CurlPortalTransport.swift
Sources/PowerVPNPortal/LeadSecPortalTransport.swift
Sources/PowerVPNPortal/PortalFixedTOFUVerifier.swift'

# Production accepts no process, environment, credential, trust-material, or
# proxy input. The CA blob and pin are compiled constants in the private C file.
# Splitting the newline-delimited repo paths is intentional.
# shellcheck disable=SC2086
if rg -n \
	'(/usr/bin/curl|\bProcess\b|NSTask|ProcessInfo\.processInfo\.environment|\b(getenv|setenv|putenv|system|popen|fork|exec[lv]p?)\s*\(|CURLOPT_(CAPATH|SSLCERT|SSLKEY|PROXYUSERPWD|PROXYAUTH|USERPWD|USERNAME|PASSWORD)|\b(insecure|caFile|caPath|clientCertificate|authorization)[[:space:]]*:)' \
	$raw_sources; then
	echo 'error: forbidden production process, environment, trust, or credential input'
	exit 1
fi
if rg -n -i \
	'(pinned_public_key[[:space:]]*;|pinnedPublicKey[[:space:]]*:|ca_?(info|path|file)[[:space:]]*[:;]|client_?cert[^();]*[[:space:]]*[:;]|userpwd[[:space:]]*[:;])' \
	Sources/CPortalCurl/include/CPortalCurl.h \
	Sources/PowerVPNPortal/CPortalCurlDriver.swift \
	Sources/PowerVPNPortal/CurlPortalTransport.swift; then
	echo 'error: caller-controlled trust input survived fixed-TOFU cutover'
	exit 1
fi

rg -q 'CURLOPT_PROXY[^\n]*""' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_NOPROXY[^\n]*"\*"' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_PROTOCOLS_STR[^\n]*"https"' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_REDIR_PROTOCOLS_STR[^\n]*"https"' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_FOLLOWLOCATION[^\n]*0L' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_MAXREDIRS[^\n]*0L' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURL_HTTP_VERSION_1_1' Sources/CPortalCurl/CPortalCurl.c
rg -q 'SecureTransport' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_SSL_VERIFYPEER[^\n]*1L' Sources/CPortalCurl/CPortalCurlTrust.c
if rg -q 'CURLOPT_SSL_VERIFYPEER[^\n]*0L' Sources/CPortalCurl/CPortalCurlTrust.c; then
	echo 'error: disabled TLS peer verification in production trust adapter'
	exit 1
fi
rg -q 'CURLOPT_SSL_VERIFYHOST[^\n]*0L' Sources/CPortalCurl/CPortalCurlTrust.c
rg -q 'CURLOPT_CAINFO_BLOB' Sources/CPortalCurl/CPortalCurlTrust.c
rg -q 'CURLOPT_PINNEDPUBLICKEY' Sources/CPortalCurl/CPortalCurlTrust.c
rg -Fq '#if defined(PVCURL_ENABLE_TEST_TRUST_PROFILE)' \
	Sources/CPortalCurl/CPortalCurlTrust.c
rg -Fq 'pvcurl_url_matches_host(pvcurl_bytes_t url,' \
	Sources/CPortalCurl/CPortalCurlRequest.c
rg -Fq 'pvcurl_url_matches_host(config->url, config->host_header)' \
	Sources/CPortalCurl/CPortalCurlRequest.c
rg -Fq 'CURLOPT_NETRC' Sources/CPortalCurl/CPortalCurl.c
rg -Fq '.provenLastFieldWins' Sources/PowerVPNPortal/CPortalCurlDriver.swift
rg -Fq 'pvcurl_request_get_diagnostics' \
	Sources/CPortalCurl/include/CPortalCurl.h
rg -Fq 'set_cookie_field_count' Sources/CPortalCurl/CPortalCurlHeaders.c
rg -Fq 'duplicate_set_cookie_rejected' \
	Sources/CPortalCurl/CPortalCurlHeaders.c
rg -Fq 'set_cookie_selection' Sources/CPortalCurl/CPortalCurlHeaders.c
rg -Fq 'pvcurl_request_get_diagnostics' \
	Sources/PowerVPNPortal/CPortalCurlDriver.swift
rg -Fq 'fileprivate init(' \
	Sources/PowerVPNPortal/PortalRequestFactory.swift
for operation in password resource session logout; do
	rg -Fq "request.hasOperationProof(.$operation)" \
		Sources/PowerVPNPortal/CurlPortalTransport.swift
	rg -Fq "request.hasOperationProof(.$operation)" \
		Sources/PowerVPNPortal/LeadSecPortalTransport.swift
done
rg -Fq 'request.url.user == nil' Sources/PowerVPNPortal/CurlPortalTransport.swift
rg -Fq 'let transport = try CurlPortalTransport' \
	Sources/PowerVPNPortal/PortalLoginRuntime.swift
rg -Fq 'PortalFixedTOFUAuthority.currentProfile()' \
	Sources/PowerVPNProduct/ProductReadinessRuntime.swift

for script in scripts/verify/checkpoint_r2_raw_headers.sh \
	scripts/verify/cportalcurl_trust_contract.sh; do
	sh -n "$script"
	shellcheck "$script"
done

c_header_cases='single_cookie last_cookie_wins missing_cookie
optional_password_post_without_cookie optional_password_post_with_single_cookie
interim_response obs_fold trailer control_byte line_cap total_cap cookie_cap second_response_block'
for case_name in $c_header_cases; do
	rg -Fq "static void test_$case_name(void)" \
		Tests/CPortalCurlTests/CPortalCurlHeaderTests.c
done
c_status_cases='status_mapping exact_authority_rejected_before_request_creation
borrowed_body_and_exact_headers post_allows_optional_set_cookie
get_has_no_entity_headers cancel_before_perform_is_network_free runtime_preflight'
for case_name in $c_status_cases; do
	rg -Fq "static void test_$case_name(void)" \
		Tests/CPortalCurlTests/CPortalCurlStatusTests.c
done

test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/powervpn-r2-raw-headers.XXXXXX")
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM
xcrun clang -std=c11 -Wall -Wextra -Werror -pedantic \
	-mmacosx-version-min=14.0 -I Sources/CPortalCurl/include \
	-I Sources/CPortalCurl -fsyntax-only \
	Sources/CPortalCurl/CPortalCurl.c \
	Sources/CPortalCurl/CPortalCurlTrust.c \
	Sources/CPortalCurl/CPortalCurlRequest.c \
	Sources/CPortalCurl/CPortalCurlHeaders.c
xcrun clang -std=c11 -Wall -Wextra -Werror -pedantic \
	-mmacosx-version-min=14.0 \
	-I Sources/CPortalCurl/include -I Sources/CPortalCurl \
	Sources/CPortalCurl/CPortalCurlHeaders.c \
	Tests/CPortalCurlTests/CPortalCurlHeaderTests.c \
	-o "$test_tmp/cportalcurl-header-tests"
"$test_tmp/cportalcurl-header-tests"
xcrun clang -std=c11 -Wall -Wextra -Werror -pedantic \
	-mmacosx-version-min=14.0 \
	-I Sources/CPortalCurl/include -I Sources/CPortalCurl \
	Sources/CPortalCurl/CPortalCurl.c \
	Sources/CPortalCurl/CPortalCurlTrust.c \
	Sources/CPortalCurl/CPortalCurlRequest.c \
	Sources/CPortalCurl/CPortalCurlHeaders.c \
	Tests/CPortalCurlTests/CPortalCurlStatusTests.c \
	-lcurl -o "$test_tmp/cportalcurl-status-tests"
"$test_tmp/cportalcurl-status-tests"
file "$test_tmp/cportalcurl-status-tests" | rg -q 'Mach-O 64-bit executable arm64'
otool -L "$test_tmp/cportalcurl-status-tests" | \
	rg -q '^[[:space:]]*/usr/lib/libcurl\.4\.dylib '

scripts/verify/cportalcurl_trust_contract.sh

swift_test_list=$(swift test list)
printf '%s\n' "$swift_test_list" >"$test_tmp/swift-test-list.txt"
swift_cases='PowerVPNPortalTests.CurlPortalTransportTests/allFourOperationsUseOneFixedProfileCurlLane()
PowerVPNPortalTests.CurlPortalTransportTests/exactPasswordPostMakesSetCookieOptionalAtRawFramingBoundary()
PowerVPNPortalTests.CurlPortalTransportTests/rawPasswordHTTP200WithoutCookieClassifiesRejectionAndChallenge()
PowerVPNPortalTests.CurlPortalTransportTests/acceptedPasswordHTTP200ToleratesMissingOrUnsupportedCookie(_:)
PowerVPNPortalTests.CurlPortalTransportTests/acceptedPasswordHTTP200WithOneCookieProceedsThroughWorkflow()
PowerVPNPortalTests.DarwinTerminalCredentialDriverPTYTests/taskCancellationRestoresTerminalWithinTwoHundredMilliseconds()
PowerVPNPortalTests.TerminalCredentialTransactionGatePTYTests/wholeCredentialTransactionsCannotOverlapOnTheSameTerminal()
PowerVPNPortalTests.SetCookieWireOrderTests/unrelatedThenSessionUsesOnlyFinalFieldForEveryScopedRequest()
PowerVPNPortalTests.SetCookieWireOrderTests/sessionThenUnrelatedUsesFallbackWithoutRescuingEarlySession()
PowerVPNPortalTests.SetCookieWireOrderTests/swappingTwoSessionFieldsSwapsEveryScopedCookie()
PowerVPNPortalTests.SetCookieWireOrderTests/cResponseProjectsOnlyFinalCountAndLastWinsProvenance()
PowerVPNPortalTests.LeadSecPortalTransportTests/allFourExactOperationsUseOnlyTheSharedPinnedLane()
PowerVPNPortalTests.PortalFixedTOFUVerifierTests/cAdapterSealsApprovedPinAndSavedLeaf()
PowerVPNPortalTests.InstalledConfigDiscoveryTests/missingArtifactFailsClosed()
PowerVPNPortalTests.InstalledConfigDiscoveryTests/invalidSchemeHostAndVersionFailClosed()
PowerVPNPortalTests.PortalLoginWorkflowTests/nonacceptingPasswordDecisionsNeverStoreSessionOrRequestResources()
PowerVPNProductTests.AuthenticatedPortalSnapshotMapperTests/helperSessionIDComesFromResourceTreeAndOutputStaysValueFree()
PowerVPNProductTests.ProductPortalDryRunAcquisitionStatusTests/everyRejectedPortalStatusMapsToItsRedactedAcquisitionStatus()
PowerVPNPortalTests.PortalLoginReportTests/cFailuresKeepExactValueFreeCategoriesAndBoundedHeaderCounters()
PowerVPNPortalTests.PortalLoginReportTests/malformedFinalCookieFailureSurvivesPasswordWorkflowWithoutValues()
PowerVPNPortalTests.SecureTerminalCredentialsTests/passwordCancellationErasesPartialUsernameAndBothCBuffers()
PowerVPNPortalTests.SecureTerminalCredentialsTests/cancellationImmediatelyAfterGateAcquisitionPromptsNothingAndReleasesGate()
PowerVPNPortalTests.PortalLoginRuntimeTests/transportPreflightFailureOccursBeforeTTY()
PowerVPNProductTests.ProductPortalDryRunAcquisitionStatusTests/rejectedAcquisitionPublishesOnlyExactTransportDiscriminator()
PowerVPNProductTests.ProductPortalDryRunAcquisitionStatusTests/invalidRequestReportsAcquisitionNotRequested()
PowerVPNProductTests.ProductPortalDryRunAcquisitionStatusTests/preCancelledRequestReportsAcquisitionNotRequested()
PowerVPNProductTests.ProductPortalDryRunRuntimeTests/acceptedSnapshotProvesRouteAndClosesValueFree()
PowerVPNProductTests.ProductReadinessRuntimeTests/currentMachineShapeReturnsOneConcreteSnapshotBlocker()
PowerVPNPortalTests.PortalDryRunCommandTests/acceptedReportEmitsOnlyValueFreeContract()'
for case_name in $swift_cases; do
	rg -Fqx "$case_name" "$test_tmp/swift-test-list.txt"
done

swift test --filter \
	'CurlPortalTransportTests|DarwinTerminalCredentialDriverPTYTests|TerminalCredentialTransactionGatePTYTests|SecureTerminalCredentialsTests|SetCookieWireOrderTests|LeadSecPortalTransportTests|PortalFixedTOFUVerifierTests|InstalledConfigDiscoveryTests|PortalLoginReportTests|PortalLoginRuntimeTests|PortalLoginWorkflowTests|PortalDryRunCommandTests|AuthenticatedPortalSnapshotMapperTests|ProductPortalDryRunAcquisitionStatusTests|ProductPortalDryRunRuntimeTests|ProductReadinessRuntimeTests|X509SPKIExtractorTests'
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

bin_path=$(swift build --show-bin-path --arch arm64)/powervpn
file "$bin_path" | rg -q 'Mach-O 64-bit executable arm64'
otool -L "$bin_path" | rg -q '^[[:space:]]*/usr/lib/libcurl\.4\.dylib '
if otool -L "$bin_path" | rg -q '/(opt/homebrew|usr/local)/.*libcurl'; then
	echo 'error: non-system libcurl linkage' >&2
	exit 1
fi

scripts/verify_no_secrets.sh
git diff --check "$base"
printf 'PASS: Rescue R2 raw-header-framing offline candidate (synthetic only; integrated review findings applied)\n'
