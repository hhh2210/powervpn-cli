#!/bin/sh

# Closed artifact graph for the R2 TLS evidence candidate. The caller sources
# r2_tls_evidence_runtime.sh first so paths and r2tls_hash_file are available.

r2tls_relative_path_safe() {
	case "$1" in
	''|/*|*..*|*[[:space:]]*) return 1 ;;
	esac
}

r2tls_hash_relative_files() (
	[ "$#" -gt 0 ] || exit 1
	r2tls_hash_lines=$(
		for r2tls_relative_path; do
			r2tls_relative_path_safe "$r2tls_relative_path" || exit 1
			r2tls_absolute_path=$R2TLS_REPO_ROOT/$r2tls_relative_path
			[ -f "$r2tls_absolute_path" ] && [ ! -L "$r2tls_absolute_path" ] || exit 1
			printf '%s  %s\n' "$(r2tls_hash_file "$r2tls_absolute_path")" \
				"$r2tls_relative_path" || exit 1
		done
	) || exit 1
	[ -n "$r2tls_hash_lines" ] || exit 1
	printf '%s\n' "$r2tls_hash_lines" | /usr/bin/shasum -a 256 | awk '{print $1}'
)

r2tls_regular_tree_files() (
	[ "$#" -gt 0 ] || exit 1
	for r2tls_tree_root; do
		[ -d "$r2tls_tree_root" ] && [ ! -L "$r2tls_tree_root" ] || exit 1
		r2tls_tree_entries=$(find "$r2tls_tree_root" -mindepth 1 -print) || exit 1
		r2tls_old_ifs=$IFS; IFS='
'
		# shellcheck disable=SC2086
		set -- $r2tls_tree_entries
		IFS=$r2tls_old_ifs
		for r2tls_tree_entry; do
			if [ -d "$r2tls_tree_entry" ] && [ ! -L "$r2tls_tree_entry" ]; then
				continue
		fi
			[ -f "$r2tls_tree_entry" ] && [ ! -L "$r2tls_tree_entry" ] || exit 1
			printf '%s\n' "${r2tls_tree_entry#"$R2TLS_REPO_ROOT/"}"
		done
	done
)

r2tls_source_aggregate() (
	r2tls_source_files=$(
		printf '%s\n' Package.swift
		r2tls_regular_tree_files "$R2TLS_REPO_ROOT/Sources/PowerVPNTLSEvidence" \
			"$R2TLS_REPO_ROOT/Sources/PowerVPNTLSEvidenceCLI"
	) || exit 1
	r2tls_source_files=$(printf '%s\n' "$r2tls_source_files" | LC_ALL=C sort -u)
	r2tls_old_ifs=$IFS; IFS='
'
	# Reviewed paths contain no whitespace; r2tls_hash_relative_files rejects it.
	# shellcheck disable=SC2086
	set -- $r2tls_source_files
	IFS=$r2tls_old_ifs
	r2tls_hash_relative_files "$@"
)

r2tls_tests_aggregate() (
	r2tls_test_root=$R2TLS_REPO_ROOT/Tests/PowerVPNTLSEvidenceTests
	r2tls_test_files=$(r2tls_regular_tree_files "$r2tls_test_root") || exit 1
	r2tls_test_files=$(printf '%s\n' "$r2tls_test_files" | LC_ALL=C sort)
	r2tls_old_ifs=$IFS; IFS='
'
	# shellcheck disable=SC2086
	set -- $r2tls_test_files
	IFS=$r2tls_old_ifs
	r2tls_hash_relative_files "$@"
)

r2tls_runtime_scripts_aggregate() (
	r2tls_runtime_files=$(
		printf '%s\n' scripts/run_r2_tls_evidence.sh
		r2tls_runtime_entries=$(find "$R2TLS_REPO_ROOT/scripts/lib" -maxdepth 1 \
			-name 'r2_tls_evidence_*.sh' -print) || exit 1
		r2tls_old_ifs=$IFS; IFS='
'
		# shellcheck disable=SC2086
		set -- $r2tls_runtime_entries
		IFS=$r2tls_old_ifs
		for r2tls_runtime_entry; do
			[ -f "$r2tls_runtime_entry" ] && [ ! -L "$r2tls_runtime_entry" ] || exit 1
			printf '%s\n' "${r2tls_runtime_entry#"$R2TLS_REPO_ROOT/"}"
		done
	) || exit 1
	r2tls_runtime_files=$(printf '%s\n' "$r2tls_runtime_files" | LC_ALL=C sort -u)
	r2tls_old_ifs=$IFS; IFS='
'
	# shellcheck disable=SC2086
	set -- $r2tls_runtime_files
	IFS=$r2tls_old_ifs
	r2tls_hash_relative_files "$@"
)

r2tls_shell_tests_aggregate() (
	r2tls_shell_test_entries=$(find "$R2TLS_REPO_ROOT/scripts/verify" -maxdepth 1 \
		-name 'r2_tls_evidence_*tests.sh' -print) || exit 1
	r2tls_old_ifs=$IFS; IFS='
'
	# shellcheck disable=SC2086
	set -- $r2tls_shell_test_entries
	IFS=$r2tls_old_ifs
	r2tls_shell_test_files=$(
		for r2tls_shell_test_entry; do
			[ -f "$r2tls_shell_test_entry" ] && [ ! -L "$r2tls_shell_test_entry" ] || exit 1
			printf '%s\n' "${r2tls_shell_test_entry#"$R2TLS_REPO_ROOT/"}"
		done
	) || exit 1
	r2tls_old_ifs=$IFS; IFS='
'
	# shellcheck disable=SC2086
	set -- $r2tls_shell_test_files
	IFS=$r2tls_old_ifs
	r2tls_hash_relative_files "$@"
)

r2tls_snapshot_inputs_aggregate() {
	r2tls_hash_relative_files scripts/snapshot_network_state.sh \
		scripts/lib/native_charon_runtime.sh scripts/lib/route_snapshot.sh \
		scripts/lib/network_snapshot.sh
}

r2tls_verifier_inputs_aggregate() {
	r2tls_hash_relative_files .gitleaks.toml GOAL.md scripts/verify/checkpoint_r2_tls_evidence.sh \
		scripts/verify_checkpoint.sh scripts/verify_no_secrets.sh
}

r2tls_review_bundle_inputs_aggregate() {
	r2tls_hash_relative_files scripts/export_r2_tls_review_bundle.sh \
		scripts/lib/r2_tls_evidence_review_bundle.sh
}

r2tls_candidate_manifest_exact() {
	[ -f "$R2TLS_MANIFEST" ] && [ ! -L "$R2TLS_MANIFEST" ] &&
		[ "$(stat -f '%u:%Lp' "$R2TLS_MANIFEST")" = "$(id -u):644" ] || return 1
	[ -f "$R2TLS_PARENT_MANIFEST" ] && [ ! -L "$R2TLS_PARENT_MANIFEST" ] &&
		[ "$(stat -f '%u:%Lp' "$R2TLS_PARENT_MANIFEST")" = "$(id -u):644" ] || return 1
	r2tls_source_sha=$(r2tls_source_aggregate) || return 1
	r2tls_tests_sha=$(r2tls_tests_aggregate) || return 1
	r2tls_runtime_scripts_sha=$(r2tls_runtime_scripts_aggregate) || return 1
	r2tls_shell_tests_sha=$(r2tls_shell_tests_aggregate) || return 1
	r2tls_runner_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/run_r2_tls_evidence.sh") || return 1
	r2tls_runtime_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_runtime.sh") || return 1
	r2tls_manifest_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_manifest.sh") || return 1
	r2tls_attempts_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_attempts.sh") || return 1
	r2tls_result_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_result.sh") || return 1
	r2tls_monitor_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/lib/r2_tls_evidence_monitor.sh") || return 1
	r2tls_harness_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/verify/r2_tls_evidence_harness_tests.sh") || return 1
	r2tls_attempt_tests_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/verify/r2_tls_evidence_attempt_tests.sh") || return 1
	r2tls_manifest_tests_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/verify/r2_tls_evidence_manifest_tests.sh") || return 1
	r2tls_verifier_sha=$(r2tls_hash_file "$R2TLS_REPO_ROOT/scripts/verify/checkpoint_r2_tls_evidence.sh") || return 1
	r2tls_snapshot_sha=$(r2tls_hash_file "$R2TLS_SNAPSHOT") || return 1
	r2tls_snapshot_inputs_sha=$(r2tls_snapshot_inputs_aggregate) || return 1
	r2tls_verifier_inputs_sha=$(r2tls_verifier_inputs_aggregate) || return 1
	r2tls_review_bundle_inputs_sha=$(r2tls_review_bundle_inputs_aggregate) || return 1
	[ -f /usr/bin/openssl ] && [ ! -L /usr/bin/openssl ] && [ -x /usr/bin/openssl ] || return 1
	r2tls_test_openssl_sha=$(r2tls_hash_file /usr/bin/openssl) || return 1
	r2tls_cli_sha=$(r2tls_hash_file "$R2TLS_CLI") || return 1
	r2tls_parent_sha=$(r2tls_hash_file "$R2TLS_PARENT_MANIFEST") || return 1
	r2tls_attempt1_manifest_sha=$(r2tls_hash_file "$R2TLS_ATTEMPT1_MANIFEST") || return 1
	r2tls_attempt1_result_sha=$(r2tls_hash_file "$R2TLS_ATTEMPT1_RESULT") || return 1
	r2tls_attempt2_manifest_sha=$(r2tls_hash_file "$R2TLS_ATTEMPT2_MANIFEST") || return 1
	r2tls_attempt2_result_sha=$(r2tls_hash_file "$R2TLS_ATTEMPT2_RESULT") || return 1
	r2tls_review=$(jq -r '.reviewState // empty' "$R2TLS_MANIFEST") || return 1
	case "$r2tls_review" in
	post_attempt2_narrow_review_pending | post_attempt2_narrow_review_completed_no_findings | \
		post_attempt2_narrow_review_completed_findings_applied) ;;
	*) return 1 ;;
	esac
	jq -e --arg source "$r2tls_source_sha" --arg tests "$r2tls_tests_sha" \
		--arg runner "$r2tls_runner_sha" --arg runtime "$r2tls_runtime_sha" \
		--arg manifest "$r2tls_manifest_sha" --arg attempts "$r2tls_attempts_sha" \
		--arg result "$r2tls_result_sha" \
		--arg monitor "$r2tls_monitor_sha" --arg harness "$r2tls_harness_sha" \
		--arg attemptTests "$r2tls_attempt_tests_sha" --arg manifestTests "$r2tls_manifest_tests_sha" \
		--arg verifier "$r2tls_verifier_sha" \
		--arg snapshot "$r2tls_snapshot_sha" --arg snapshotInputs "$r2tls_snapshot_inputs_sha" \
		--arg verifierInputs "$r2tls_verifier_inputs_sha" \
		--arg reviewBundleInputs "$r2tls_review_bundle_inputs_sha" \
		--arg runtimeScripts "$r2tls_runtime_scripts_sha" --arg shellTests "$r2tls_shell_tests_sha" \
		--arg testOpenSSL "$r2tls_test_openssl_sha" --arg cli "$r2tls_cli_sha" \
		--arg parent "$r2tls_parent_sha" --arg attempt1Manifest "$r2tls_attempt1_manifest_sha" \
		--arg attempt1Result "$r2tls_attempt1_result_sha" \
		--arg attempt2Manifest "$r2tls_attempt2_manifest_sha" \
		--arg attempt2Result "$r2tls_attempt2_result_sha" --arg review "$r2tls_review" '
    keys == ["artifacts","attempt1AuthorizedManifestSHA256",
      "attempt1RunEvidenceAggregateSHA256","attempt1RuntimeFixtureSHA256",
      "attempt2AuthorizedManifestSHA256","attempt2RunEvidenceAggregateSHA256",
      "attempt2RuntimeFixtureSHA256","baseCommit","evidenceClass",
      "parentR2ManifestSHA256","reviewState","runtimeSourceAggregateSHA256",
      "schemaVersion"] and .schemaVersion == 2 and
    .evidenceClass == "r2_tls_peer_evidence_post_attempt2_candidate" and
    .baseCommit == "440657873b6fcb91a88262fb8df0e874f7919ec2" and
    .reviewState == $review and .parentR2ManifestSHA256 == $parent and
    .attempt1AuthorizedManifestSHA256 == $attempt1Manifest and
    .attempt1RuntimeFixtureSHA256 == $attempt1Result and
    .attempt1RunEvidenceAggregateSHA256 ==
      "aef7d3b7734b132f6b5d1bb3fc498d7609d3424c0808a5a029af0e4076d687c9" and
    .attempt2AuthorizedManifestSHA256 == $attempt2Manifest and
    .attempt2RuntimeFixtureSHA256 == $attempt2Result and
    .attempt2RunEvidenceAggregateSHA256 ==
      "21eb127eae03c6c49a56538e285cab0215e00d7122a1c8c0d8184d646bbdcce2" and
    .runtimeSourceAggregateSHA256 == $source and
    .artifacts == {arm64CLISHA256:$cli,attemptsLibrarySHA256:$attempts,
      attemptTestsSHA256:$attemptTests,harnessTestsSHA256:$harness,
      manifestLibrarySHA256:$manifest,manifestTestsSHA256:$manifestTests,
      monitorLibrarySHA256:$monitor,
      networkSnapshotInputsAggregateSHA256:$snapshotInputs,
      networkSnapshotSHA256:$snapshot,runnerSHA256:$runner,
      resultLibrarySHA256:$result,reviewBundleInputsAggregateSHA256:$reviewBundleInputs,
      runtimeLibrarySHA256:$runtime,runtimeScriptsAggregateSHA256:$runtimeScripts,
      shellTestsAggregateSHA256:$shellTests,tlsEvidenceTestsAggregateSHA256:$tests,
      testOpenSSLExecutableSHA256:$testOpenSSL,
      verifierInputsAggregateSHA256:$verifierInputs,verifierSHA256:$verifier}
  ' "$R2TLS_MANIFEST" >/dev/null || return 1
	R2TLS_CANDIDATE_MANIFEST_SHA256=$(r2tls_hash_file "$R2TLS_MANIFEST") || return 1
	R2TLS_REVIEW_COMPLETE=false
	case "$r2tls_review" in
	post_attempt2_narrow_review_completed_no_findings | \
		post_attempt2_narrow_review_completed_findings_applied) R2TLS_REVIEW_COMPLETE=true ;;
	esac
	export R2TLS_CANDIDATE_MANIFEST_SHA256 R2TLS_REVIEW_COMPLETE
}

r2tls_candidate_manifest_matches_approval() {
	[ -n "$1" ] && r2tls_candidate_manifest_exact &&
		[ "$R2TLS_CANDIDATE_MANIFEST_SHA256" = "$1" ]
}
