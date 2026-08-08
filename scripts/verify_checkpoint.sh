#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
checkpoint=${1:-}
jobs=${JOBS:-8}

case "$checkpoint" in
	4a)
		;;
	5)
		cd "$repo_root"
		checkpoint_base=${POWERVPN_CHECKPOINT_BASE:-c1e6e5f8dd52028d647e75dc8010c83ba7ee5dec}
		git cat-file -e "$checkpoint_base^{commit}"
		git merge-base --is-ancestor "$checkpoint_base" HEAD
		test -n "$(
			git diff --name-only "$checkpoint_base"
			git ls-files --others --exclude-standard
		)"
		fixture=fixtures/redacted/protocol-correlation-value-free-v1.json
		runtime_fixture=fixtures/redacted/protocol-correlation-runtime-metadata-v1.json
		jq -e '
		  .schemaVersion == 1 and
		  .fixtureClass == "value_free_protocol_correlation" and
		  .redactionMode == "metadata_only_at_collection" and
		  .source == "synthetic" and
		  .containsSecrets == false and
		  .containsReplayableCapture == false and
		  (.events | length) > 0
		' "$fixture" >/dev/null
		jq -e '
		  .source == "runtime_metadata" and
		  .containsSecrets == false and
		  .containsReplayableCapture == false and
		  ([.events[].boundary] | index("control_plane") != null) and
		  ([.events[].boundary] | index("xpc") != null)
		' "$runtime_fixture" >/dev/null
		swift test --filter valueFreeCorrelationRoundTripPreservesObservationOrder
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
		swift run powervpn oracle correlate "$fixture" --json |
			jq -e '.valid == true and .issues == []' >/dev/null
		swift run powervpn oracle correlate "$runtime_fixture" --json |
			jq -e '.valid == true and .issues == []' >/dev/null
		scripts/verify_no_secrets.sh
		git diff --check "$checkpoint_base"
		exit 0
		;;
	*)
		echo "usage: $0 4a|5" >&2
		exit 64
		;;
esac

source_tree=${POWERVPN_STRONGSWAN_SOURCE:-/Users/larry_1/scratch-data/powervpn-strongswan/strongswan-6.0.7-expandrule}
build_tree=${POWERVPN_STRONGSWAN_BUILD:-/Users/larry_1/scratch-data/powervpn-strongswan/build-6.0.7-expandrule-arm64}
expected_base=5973ff8e41deef4e015e1138a2de688acedf6f75
tool_path=/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/gettext/bin:/opt/homebrew/bin:/usr/bin:/bin

test -d "$source_tree/.git" -o -f "$source_tree/.git"
test -d "$build_tree"
test "$(git -C "$source_tree" rev-parse HEAD)" = "$expected_base"

changed=$(git -C "$source_tree" status --porcelain=v1 | cut -c4-)
test -n "$changed"
for file in $changed
do
	case "$file" in
		src/libcharon/Makefile.am|\
		src/libcharon/encoding/payloads/expandrule_*|\
		src/libcharon/tests/Makefile.am|\
		src/libcharon/tests/libcharon_tests.h|\
		src/libcharon/tests/suites/expandrule_test_fixtures.h|\
		src/libcharon/tests/suites/test_expandrule_codec*.c)
			;;
		*)
			echo "error: unexpected CP4A source artifact: $file" >&2
			exit 1
			;;
	esac
done

env PATH="$tool_path" make -j"$jobs" -C "$build_tree/src/libcharon" libcharon.la
env PATH="$tool_path" make -j"$jobs" -C "$build_tree/src/libstrongswan/tests" libtest.la
env PATH="$tool_path" make -j"$jobs" -C "$build_tree/src/libcharon/tests" libcharon_tests
env PATH="$tool_path" make -C "$build_tree/src/libcharon/tests" check TESTS=libcharon_tests
env PATH="$tool_path" make -j"$jobs" -C "$build_tree" check

git -C "$source_tree" diff --check
file "$build_tree/src/libcharon/.libs/libcharon.0.dylib" | grep -q 'arm64'

for file in $changed
do
	if [ -f "$source_tree/$file" ]; then
		gitleaks dir "$source_tree/$file" --no-banner --redact \
			--max-target-megabytes 5 --timeout 30
	fi
done

cd "$repo_root"
fixture_json=fixtures/redacted/expandrule-synthetic-v1.json
fixture_header=$source_tree/src/libcharon/tests/suites/expandrule_test_fixtures.h
jq -e '
  (.vectors | length) == 7 and
  ([.vectors[].id] | unique | length) == 7 and
  all(.vectors[]; ((.hex | length) / 2) == .byteLength) and
  ([.vectors[].contexts[]] | length) == 9 and
  ([.vectors[].contexts[] | select(.form == "QM_ADD_SNAPSHOT")] | length) == 5 and
  ([.vectors[].contexts[] | select(.form == "INFO_ADD_DELTA")] | length) == 1 and
  ([.vectors[].contexts[] | select(.form == "INFO_DELETE_DELTA")] | length) == 1 and
  ([.vectors[].contexts[] | select(.form == "INFO_REVOKE_V1")] | length) == 1 and
  ([.vectors[].contexts[] | select(.form == "INFO_REVOKE_LEGACY")] | length) == 1 and
  all(.vectors[].contexts[];
    if .form == "QM_ADD_SNAPSHOT" then
      .direction == "client_to_server" and .currentPayloadType == 18 and
      (.dialect == "dialect0" or .dialect == "dialect1") and
      (.family == "ipv4" or .family == "ipv6")
    elif .form == "INFO_ADD_DELTA" then
      .direction == "client_to_server" and .currentPayloadType == 18 and
      (.dialect == "dialect0" or .dialect == "dialect1") and
      (.family == "ipv4" or .family == "ipv6") and
      ((.primaryCount + .secondaryCount) == 1)
    elif .form == "INFO_DELETE_DELTA" then
      .direction == "client_to_server" and .currentPayloadType == 19 and
      (.dialect == "dialect0" or .dialect == "dialect1") and
      (.family == "ipv4" or .family == "ipv6") and
      ((.primaryCount + .secondaryCount) == 1)
    elif .form == "INFO_REVOKE_V1" then
      .direction == "server_to_client" and .currentPayloadType == 19 and
      .dialect == null and .family == null
    elif .form == "INFO_REVOKE_LEGACY" then
      .direction == "server_to_client" and .currentPayloadType == 17 and
      .dialect == null and .family == null and .encodeAllowed == false
    else false end
  )
' "$fixture_json" >/dev/null

test "$(grep -c '^[[:space:]]*{ \"' "$fixture_header")" -eq 7
jq -r '.vectors[] | [.id, .hex, (.byteLength | tostring)] | @tsv' "$fixture_json" |
while IFS="$(printf '\t')" read -r id hex byte_length
do
	grep -Fq "{ \"$id\", \"$hex\", $byte_length," "$fixture_header"
done
swift test
swift build --arch arm64
scripts/verify_no_secrets.sh
git diff --check
