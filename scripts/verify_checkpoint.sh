#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
checkpoint=${1:-}
jobs=${JOBS:-8}

case "$checkpoint" in
	4a)
		;;
	6)
		exec "$repo_root/scripts/verify_checkpoint_6.sh"
		;;
	7a)
		exec "$repo_root/scripts/verify/checkpoint_7a.sh"
		;;
	4b)
		cd "$repo_root"
		checkpoint_base=${POWERVPN_CHECKPOINT_BASE:-82731013bb97f3dbfcc6f45df099e79e45dc3b64}
		cp4a_repo_commit=c1e6e5f8dd52028d647e75dc8010c83ba7ee5dec
		cp4a_upstream_commit=1fda864cca91da0aa9a87dd96e1823c3962dbd09
		cp4a_patch_sha256=b46031db4589865deef87433fe62ef2437ae0a55fe2f3fe42fa171c240d1aa6e
		wire_fixture=fixtures/redacted/expandrule-synthetic-v1.json
		promotion_fixture=fixtures/redacted/semantic-promotion-gate-v1.json
		patch_file=patches/strongswan-6.0.7/0001-Add-strict-IKEv1-expandrule-wire-codec.patch
		source_tree=${POWERVPN_STRONGSWAN_SOURCE:-/Users/larry_1/scratch-data/powervpn-strongswan/strongswan-6.0.7-expandrule}
		build_tree=${POWERVPN_STRONGSWAN_BUILD:-/Users/larry_1/scratch-data/powervpn-strongswan/build-6.0.7-expandrule-arm64}
		tool_path=/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/gettext/bin:/opt/homebrew/bin:/usr/bin:/bin

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
				GOAL.md|\
				docs/evidence/checkpoint-4b-semantic-promotion.md|\
				docs/progress/GOAL_STATUS.md|\
				docs/protocol-ike.md|\
				fixtures/redacted/semantic-promotion-gate-v1.json|\
				scripts/verify_checkpoint.sh)
					;;
				*)
					echo "error: unexpected CP4B artifact: $file" >&2
					exit 1
					;;
			esac
		done

		test -d "$source_tree/.git" -o -f "$source_tree/.git"
		test -d "$build_tree"
		test "$(git -C "$source_tree" rev-parse HEAD)" = "$cp4a_upstream_commit"
		test -z "$(git -C "$source_tree" status --porcelain=v1)"
		git show "$cp4a_repo_commit:$wire_fixture" | cmp - "$wire_fixture"
		git show "$cp4a_repo_commit:$patch_file" | cmp - "$patch_file"
		test "$(shasum -a 256 "$patch_file" | awk '{print $1}')" = "$cp4a_patch_sha256"

		jq -e '
		  . as $root |
		  (reduce .evidenceCatalog[] as $e ({}; .[$e.id] = $e)) as $catalog |
		  .schemaVersion == 1 and
		  .fixtureClass == "expandrule_semantic_promotion_gate" and
		  .provenance == "value_free_static_and_runtime_metadata_only" and
		  .containsSecrets == false and
		  .containsReplayableCapture == false and
		  .sourceCheckpoints.cp4aRepositoryCommit == "c1e6e5f8dd52028d647e75dc8010c83ba7ee5dec" and
		  .sourceCheckpoints.cp4aUpstreamCommit == "1fda864cca91da0aa9a87dd96e1823c3962dbd09" and
		  .sourceCheckpoints.cp5RepositoryCommit == "82731013bb97f3dbfcc6f45df099e79e45dc3b64" and
		  .policy.minimumIndependentDirectMappingClasses == 2 and
		  .policy.staticEvidenceAcrossVendorBinariesCountsAsOneClass == true and
		  .policy.shapeOrNameSimilarityQualifies == false and
		  .policy.syntheticVectorsQualifyForSemantics == false and
		  .policy.absenceObservationQualifies == false and
		  ([.evidenceCatalog[].id] | length) == ([.evidenceCatalog[].id] | unique | length) and
		  ([.candidates[].id] | length) == ([.candidates[].id] | unique | length) and
		  ([.candidates[] | [
		    .id,
		    .wireSlot,
		    .syntaxName,
		    .candidateSemantic,
		    .decision,
		    .reasonCode,
		    .independentDirectMappingClassCount
		  ]] | sort_by(.[0])) == [
		    ["dialect0-primary-as-route-prefix", "client.dialect0.primary_record", "dialect0PrimaryRecord", "route_prefix", "retain_neutral", "one_direct_mapping_class_only", 1],
		    ["dialect0-secondary-as-resource-name-or-id", "client.dialect0.secondary_opaque", "dialect0SecondaryOpaque", "resource_name_or_id", "retain_opaque", "one_direct_mapping_class_and_identity_ambiguous", 1],
		    ["dialect1-primary-as-map-id", "client.dialect1.primary_opaque", "dialect1PrimaryOpaque", "map_id", "retain_opaque", "one_direct_mapping_class_only", 1],
		    ["dialect1-secondary-as-map-id", "client.dialect1.secondary_opaque", "dialect1SecondaryOpaque", "map_id", "retain_opaque", "one_direct_mapping_class_only", 1],
		    ["leading-address-as-virtual-ip", "client.leading_address", "leadingAddress", "virtual_ip", "retain_neutral", "one_direct_mapping_class_only", 1],
		    ["primary-count-as-route-count", "client.primary_count", "primaryCount", "route_count", "retain_neutral", "candidate_disconfirmed_by_static_category_count", 0],
		    ["secondary-count-as-resource-count", "client.secondary_count", "secondaryCount", "resource_count", "retain_neutral", "category_business_semantics_unknown", 0],
		    ["server-revoke-as-resource-match-key", "server_revoke.opaque_value", "serverRevokeOpaque", "resource_match_key", "retain_opaque", "no_control_or_xpc_producer_link", 0]
		  ] and
		  all(.candidates[];
		    . as $candidate |
		    ($candidate.decision == "retain_neutral" or $candidate.decision == "retain_opaque" or $candidate.decision == "promote") and
		    ([$candidate.evidenceIds[] as $id | select($catalog[$id] == null)] | length) == 0 and
		    ([$candidate.directMappingEvidenceIds[] as $id |
		      select(($candidate.evidenceIds | index($id)) == null)] | length) == 0 and
		    ([$candidate.directMappingEvidenceIds[] as $id |
		      select($catalog[$id].supportsDirectMapping != true)] | length) == 0 and
		    ([$candidate.directMappingEvidenceIds[] as $id |
		      select(
		        $catalog[$id].wireSlot != $candidate.wireSlot or
		        $catalog[$id].candidateSemantic != $candidate.candidateSemantic
		      )] | length) == 0 and
		    ([$candidate.directMappingEvidenceIds[] as $id | $catalog[$id].class] | unique | sort) ==
		      ($candidate.directMappingClasses | unique | sort) and
		    $candidate.independentDirectMappingClassCount ==
		      ($candidate.directMappingClasses | unique | length) and
		    (if $candidate.decision == "promote" then
		       $candidate.independentDirectMappingClassCount >= $root.policy.minimumIndependentDirectMappingClasses
		     else
		       $candidate.independentDirectMappingClassCount < $root.policy.minimumIndependentDirectMappingClasses
		     end)
		  ) and
		  ([.candidates[] | select(.decision == "promote") | .id] | sort) ==
		    ([.promotions[].candidateId] | sort) and
		  .promotions == [] and
		  .wireSchemaChanged == false
		' "$promotion_fixture" >/dev/null

		codec_surface=$(
			rg --files "$source_tree/src/libcharon" |
				rg '/(expandrule_[^/]+|test_expandrule_codec[^/]*)\.(c|h)$'
		)
		if rg -n -i \
			'(map_?id|resource_?(id|name)|route_?count|tunnel_?name|virtual_?ip)' \
			$codec_surface
		then
			echo "error: CP4A codec surface contains an unapproved semantic promotion" >&2
			exit 1
		fi

		fixture_header=$source_tree/src/libcharon/tests/suites/expandrule_test_fixtures.h
		test "$(grep -c '^[[:space:]]*{ \"' "$fixture_header")" -eq 7
		jq -r '.vectors[] | [.id, .hex, (.byteLength | tostring)] | @tsv' "$wire_fixture" |
		while IFS="$(printf '\t')" read -r id hex byte_length
		do
			grep -Fq "{ \"$id\", \"$hex\", $byte_length," "$fixture_header"
		done

		env PATH="$tool_path" TESTS_SUITES='expandrule codec' \
			make -C "$build_tree/src/libcharon/tests" check TESTS=libcharon_tests
		swift test
		swift build --arch arm64
		scripts/verify_no_secrets.sh
		git diff --check "$checkpoint_base"
		exit 0
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
		echo "usage: $0 4a|4b|5|6|7a" >&2
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
