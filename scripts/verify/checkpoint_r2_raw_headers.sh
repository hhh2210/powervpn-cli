#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"

base=3e3855086e31ddf9a5c208591eddd10fd31d1465

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
		docs/evidence/checkpoint-r2-validation.md | \
		docs/evidence/checkpoint-r2-raw-header-framing.md | \
		docs/progress/GOAL_STATUS.md | \
		fixtures/redacted/r2-reviewed-candidate-manifest-v1.json | \
		Sources/CPortalCurl/CPortalCurl.c | \
		Sources/CPortalCurl/CPortalCurlHeaders.c | \
		Sources/CPortalCurl/CPortalCurlInternal.h | \
		Sources/CPortalCurl/CPortalCurlRequest.c | \
		Sources/CPortalCurl/include/CPortalCurl.h | \
		Sources/PowerVPNPortal/CPortalCurlPasswordDriver.swift | \
		Sources/PowerVPNPortal/CurlPasswordPortalTransport.swift | \
		Sources/PowerVPNPortal/LeadSecPortalTransport.swift | \
		Sources/PowerVPNPortal/PortalRequestFactory.swift | \
		Sources/PowerVPNPortal/PortalTransport.swift | \
		Sources/PowerVPNPortal/PortalLoginRuntime.swift | \
		Tests/CPortalCurlTests/CPortalCurlHeaderTests.c | \
		Tests/CPortalCurlTests/CPortalCurlStatusTests.c | \
		Tests/PowerVPNPortalTests/CurlPasswordPortalTransportTests.swift | \
		Tests/PowerVPNPortalTests/LeadSecPortalTransportTests.swift | \
		Tests/PowerVPNPortalTests/PortalRequestFactoryTests.swift | \
		scripts/lib/r2_portal_runtime.sh | scripts/run_r2_portal_login.sh | \
		scripts/verify/r2_live_harness_tests.sh | scripts/verify/checkpoint_r2.sh | \
		scripts/verify/checkpoint_r2_raw_headers.sh | scripts/verify_checkpoint.sh)
		;;
	*)
		echo "error: unexpected R2 raw-header artifact: $file" >&2
		exit 1
		;;
	esac
done

required_files='Sources/CPortalCurl/CPortalCurl.c
Sources/CPortalCurl/CPortalCurlHeaders.c
Sources/CPortalCurl/CPortalCurlInternal.h
Sources/CPortalCurl/CPortalCurlRequest.c
Sources/CPortalCurl/include/CPortalCurl.h
Sources/PowerVPNPortal/CPortalCurlPasswordDriver.swift
Sources/PowerVPNPortal/CurlPasswordPortalTransport.swift
Sources/PowerVPNPortal/LeadSecPortalTransport.swift
Tests/CPortalCurlTests/CPortalCurlHeaderTests.c
Tests/CPortalCurlTests/CPortalCurlStatusTests.c
Tests/PowerVPNPortalTests/CurlPasswordPortalTransportTests.swift
Tests/PowerVPNPortalTests/LeadSecPortalTransportTests.swift
docs/evidence/checkpoint-r2-raw-header-framing.md'
for file in $required_files; do
	[ -f "$file" ] || {
		echo "error: missing R2 raw-header artifact: $file" >&2
		exit 1
	}
done

for file in $changed_files; do
	case "$file" in
	*.c | *.h | *.swift)
		[ -f "$file" ] || continue
		[ "$(wc -l <"$file" | tr -d ' ')" -lt 300 ] || {
			echo "error: R2 raw-header C/Swift file exceeds 299 lines: $file" >&2
			exit 1
		}
		;;
	esac
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
    ["PowerVPNCore", "PowerVPNPortal"]
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
Sources/CPortalCurl/include/CPortalCurl.h
Sources/PowerVPNPortal/CPortalCurlPasswordDriver.swift
Sources/PowerVPNPortal/CurlPasswordPortalTransport.swift
Sources/PowerVPNPortal/LeadSecPortalTransport.swift
Sources/PowerVPNPortal/PortalLoginRuntime.swift'

# These APIs would bypass the in-process, system-trust-only contract.
# Splitting the newline-delimited repo paths is intentional.
# shellcheck disable=SC2086
if rg -n \
	'(/usr/bin/curl|\bProcess\b|NSTask|ProcessInfo\.processInfo\.environment|\b(getenv|setenv|putenv|system|popen|fork|exec[lv]p?)\s*\(|CURLOPT_(CAINFO|CAPATH|SSLCERT|SSLKEY|PROXYUSERPWD|PROXYAUTH|USERPWD|USERNAME|PASSWORD)|\b(proxy|insecure|caFile|caPath|clientCertificate|credential|authorization)[[:space:]]*:)' \
	$raw_sources; then
	echo 'error: subprocess, environment, proxy, insecure, custom-CA, or credential input surface' >&2
	exit 1
fi
if rg -n -i \
	'(proxy|insecure|ca_?(info|path|file)|client_?cert|credential|authorization|userpwd)' \
	Sources/CPortalCurl/include/CPortalCurl.h; then
	echo 'error: forbidden caller-controlled security input in CPortalCurl API' >&2
	exit 1
fi

rg -q 'CURLOPT_PROXY[^\n]*""' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_NOPROXY[^\n]*"\*"' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_PROTOCOLS_STR[^\n]*"https"' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_REDIR_PROTOCOLS_STR[^\n]*"https"' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_FOLLOWLOCATION[^\n]*0L' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_MAXREDIRS[^\n]*0L' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_SSL_VERIFYPEER[^\n]*1L' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_SSL_VERIFYHOST[^\n]*2L' Sources/CPortalCurl/CPortalCurl.c
rg -q 'CURLOPT_NETRC[^\n]*CURL_NETRC_IGNORED' Sources/CPortalCurl/CPortalCurl.c
rg -Fq '.foundationFoldedValue' Sources/PowerVPNPortal/URLSessionPortalTransport.swift
rg -Fq 'throw PortalTransportError.setCookieFramingUnavailable' \
	Sources/PowerVPNPortal/URLSessionPortalTransport.swift
rg -Fq '.provenSingleWireHeader' \
	Sources/PowerVPNPortal/CurlPasswordPortalTransport.swift
rg -Fq 'fileprivate init(_ operation: PortalRequestOperation)' \
	Sources/PowerVPNPortal/PortalRequestFactory.swift
rg -Fq 'request.hasOperationProof(.password)' \
	Sources/PowerVPNPortal/CurlPasswordPortalTransport.swift
for operation in password resource session logout; do
	rg -Fq "request.hasOperationProof(.$operation)" \
		Sources/PowerVPNPortal/LeadSecPortalTransport.swift
done
rg -Fq 'request.url.user == nil, request.url.password == nil' \
	Sources/PowerVPNPortal/CurlPasswordPortalTransport.swift
rg -Fq 'request.url.user == nil, request.url.password == nil' \
	Sources/PowerVPNPortal/LeadSecPortalTransport.swift
rg -Fq 'let passwordTransport = try CurlPasswordPortalTransport' \
	Sources/PowerVPNPortal/PortalLoginRuntime.swift
rg -Fq 'return LeadSecPortalTransport' \
	Sources/PowerVPNPortal/PortalLoginRuntime.swift

for script in scripts/verify/checkpoint_r2_raw_headers.sh scripts/verify_checkpoint.sh; do
	sh -n "$script"
done
shellcheck scripts/verify/checkpoint_r2_raw_headers.sh

c_header_cases='single_cookie duplicate_cookie missing_cookie interim_response
obs_fold trailer control_byte line_cap total_cap cookie_cap second_response_block'
for case_name in $c_header_cases; do
	rg -Fq "static void test_$case_name(void)" \
		Tests/CPortalCurlTests/CPortalCurlHeaderTests.c
done
c_status_cases='status_mapping userinfo_rejected_and_output_cleared
borrowed_body_and_exact_headers cancel_before_perform_is_network_free
runtime_preflight'
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
	Sources/CPortalCurl/CPortalCurlRequest.c \
	Sources/CPortalCurl/CPortalCurlHeaders.c \
	Tests/CPortalCurlTests/CPortalCurlStatusTests.c \
	-lcurl -o "$test_tmp/cportalcurl-status-tests"
"$test_tmp/cportalcurl-status-tests"
file "$test_tmp/cportalcurl-status-tests" | rg -q 'Mach-O 64-bit executable arm64'
otool -L "$test_tmp/cportalcurl-status-tests" | \
	rg -q '^[[:space:]]*/usr/lib/libcurl\.4\.dylib '

swift_test_list=$(swift test list)
swift_cases='CurlPasswordPortalTransportTests/cRuntimePreflightIsNetworkFreeAndAvailableBeforeCredentialInput
CurlPasswordPortalTransportTests/exactPasswordPostReturnsProvenSingleWireHeaderProjection
CurlPasswordPortalTransportTests/directNearMissesNeverReachDriverAndEraseInputs
CurlPasswordPortalTransportTests/taskCancellationReachesBlockingDriverAndErasesInputs
CurlPasswordPortalTransportTests/transportCancellationReachesActiveBlockingDriver
CurlPasswordPortalTransportTests/cStatusesMapToClosedValueFreeTransportErrors
CurlPasswordPortalTransportTests/foreignDriverErrorsAreCollapsedWithoutPayload
LeadSecPortalTransportTests/exactPasswordPostUsesOnlyRawHeaderLane
LeadSecPortalTransportTests/resourceSessionAndLogoutStayOnFoundationLane
LeadSecPortalTransportTests/nearMissesAreRejectedBeforeEitherLane
LeadSecPortalTransportTests/directBodyCookieAndUserAgentNearMissesReachNeitherLane
LeadSecPortalTransportTests/cancellationIsForwardedToBothLanes
PortalRequestFactoryTests/emitsExactSealedR2Requests
FoundationPortalURLSessionReuseTests/passwordRequestFailsBeforeFoundationOpensTheNetworkSeam'
for case_name in $swift_cases; do
	printf '%s\n' "$swift_test_list" | rg -Fq "PowerVPNPortalTests.$case_name()"
done

swift test --filter 'CurlPasswordPortalTransportTests|LeadSecPortalTransportTests|PortalRequestFactoryTests'
swift test --filter passwordRequestFailsBeforeFoundationOpensTheNetworkSeam
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
