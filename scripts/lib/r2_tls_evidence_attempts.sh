#!/bin/sh

# Closed lineage and one-shot authorization gate for TLS evidence attempt 3.
# The caller must source r2_tls_evidence_runtime.sh first.

R2TLS_ATTEMPT3_EXPERIMENT=attempt3-after-inconclusive-v2
R2TLS_ATTEMPT1_FIXTURE=$R2TLS_ATTEMPT1_RESULT
R2TLS_ATTEMPT1_ARCHIVE=$R2TLS_ATTEMPT1_MANIFEST
R2TLS_ATTEMPT2_FIXTURE=$R2TLS_ATTEMPT2_RESULT
R2TLS_ATTEMPT2_ARCHIVE=$R2TLS_ATTEMPT2_MANIFEST
R2TLS_ATTEMPT1_FIXTURE_SHA256=27a0b7a511addff9888041c94c94b1a3ba9f408ff0a15b3941dcb7d4f6e3d61b
R2TLS_ATTEMPT1_ARCHIVE_SHA256=e8b622cb4600ae5e603364accd13dffcd45d1a4aa6a48afe69401fee314cd5d4
R2TLS_ATTEMPT2_FIXTURE_SHA256=8766a176e542173bf7b53b79ca005cde0c222a5d2c699871e6aeafd329761219
R2TLS_ATTEMPT2_ARCHIVE_SHA256=b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354
R2TLS_ATTEMPT1_RUN_AGGREGATE_SHA256=aef7d3b7734b132f6b5d1bb3fc498d7609d3424c0808a5a029af0e4076d687c9
R2TLS_ATTEMPT2_RUN_AGGREGATE_SHA256=21eb127eae03c6c49a56538e285cab0215e00d7122a1c8c0d8184d646bbdcce2

r2tls_attempt3_experiment_exact() { [ "$1" = "$R2TLS_ATTEMPT3_EXPERIMENT" ]; }
r2tls_attempt3_environment_exact() {
	r2tls_attempt3_experiment_exact "${POWERVPN_R2_TLS_EVIDENCE_EXPERIMENT:-}"
}

r2tls_attempt_run_aggregate() (
	run_dir=$1
	[ -d "$run_dir" ] && [ ! -L "$run_dir" ] &&
		[ "$(stat -f '%u:%Lp' "$run_dir")" = "$(id -u):700" ] || exit 1
	[ "$(find "$run_dir" -mindepth 1 -maxdepth 1 -print | awk 'END {print NR+0}')" -eq 5 ] || exit 1
	hash_lines=$(
		for basename in monitor.json network-after.json network-before.json report.json result.json; do
			artifact=$run_dir/$basename
			[ -f "$artifact" ] && [ ! -L "$artifact" ] &&
				[ "$(stat -f '%u:%Lp' "$artifact")" = "$(id -u):600" ] || exit 1
			printf '%s  %s\n' "$(r2tls_hash_file "$artifact")" "$basename" || exit 1
		done
	) || exit 1
	printf '%s\n' "$hash_lines" | /usr/bin/shasum -a 256 | awk '{print $1}'
)

r2tls_attempt3_repo_lineage_exact() {
	for lineage_fixture in "$R2TLS_ATTEMPT1_FIXTURE" "$R2TLS_ATTEMPT1_ARCHIVE" \
		"$R2TLS_ATTEMPT2_FIXTURE" "$R2TLS_ATTEMPT2_ARCHIVE"; do
		[ -f "$lineage_fixture" ] && [ ! -L "$lineage_fixture" ] &&
			[ "$(stat -f '%u:%Lp' "$lineage_fixture")" = "$(id -u):644" ] || return 1
	done
	[ "$(r2tls_hash_file "$R2TLS_ATTEMPT1_FIXTURE")" = "$R2TLS_ATTEMPT1_FIXTURE_SHA256" ] &&
		[ "$(r2tls_hash_file "$R2TLS_ATTEMPT1_ARCHIVE")" = "$R2TLS_ATTEMPT1_ARCHIVE_SHA256" ] &&
		[ "$(r2tls_hash_file "$R2TLS_ATTEMPT2_FIXTURE")" = "$R2TLS_ATTEMPT2_FIXTURE_SHA256" ] &&
		[ "$(r2tls_hash_file "$R2TLS_ATTEMPT2_ARCHIVE")" = "$R2TLS_ATTEMPT2_ARCHIVE_SHA256" ] || return 1
	jq -e --arg manifest "$R2TLS_ATTEMPT1_ARCHIVE_SHA256" --arg result "$R2TLS_ATTEMPT1_FIXTURE_SHA256" '
    .schemaVersion==1 and .evidenceClass=="r2_tls_peer_evidence_post_attempt1_candidate" and
    .reviewState=="post_attempt1_narrow_review_completed_findings_applied" and
    .attempt1AuthorizedManifestSHA256==$manifest and .attempt1RuntimeFixtureSHA256==$result
  ' "$R2TLS_ATTEMPT2_ARCHIVE" >/dev/null || return 1
	jq -e --arg manifest "$R2TLS_ATTEMPT2_ARCHIVE_SHA256" '
    .schemaVersion==2 and .evidenceClass=="r2_tls_peer_live_window" and
    .candidateManifestSHA256==$manifest and .experimentAttempt==2 and
    .predecessorValidated and .manifestExact and .complete and (.checkpointPass|not)
  ' "$R2TLS_ATTEMPT2_FIXTURE" >/dev/null
}

r2tls_attempt3_predecessor_exact() (
	predecessor_root=$1
	[ -d "$predecessor_root" ] && [ ! -L "$predecessor_root" ] &&
		[ "$(stat -f '%u:%Lp' "$predecessor_root")" = "$(id -u):700" ] || return 1
	r2tls_attempt3_repo_lineage_exact || return 1
	[ "$(find "$predecessor_root" -mindepth 1 -maxdepth 1 -print | awk 'END {print NR+0}')" -eq 2 ] || return 1
	predecessor_runs=$(find "$predecessor_root" -mindepth 1 -maxdepth 1 -name 'run-*' -type d -print) || return 1
	[ "$(printf '%s\n' "$predecessor_runs" | awk 'NF {n++} END {print n+0}')" -eq 2 ] || return 1
	attempt1_count=0; attempt2_count=0
	old_ifs=$IFS; IFS='
'
	# shellcheck disable=SC2086
	set -- $predecessor_runs
	IFS=$old_ifs
	for predecessor_run; do
		result=$predecessor_run/result.json
		if /usr/bin/cmp -s "$result" "$R2TLS_ATTEMPT1_FIXTURE"; then
			expected_aggregate=$R2TLS_ATTEMPT1_RUN_AGGREGATE_SHA256
			attempt1_count=$((attempt1_count + 1))
		elif /usr/bin/cmp -s "$result" "$R2TLS_ATTEMPT2_FIXTURE"; then
			expected_aggregate=$R2TLS_ATTEMPT2_RUN_AGGREGATE_SHA256
			attempt2_count=$((attempt2_count + 1))
		else return 1; fi
		[ "$(r2tls_attempt_run_aggregate "$predecessor_run")" = "$expected_aggregate" ] || return 1
	done
	[ "$attempt1_count" -eq 1 ] && [ "$attempt2_count" -eq 1 ]
)

r2tls_attempt3_consume_authorization() {
	consume_root=$1; approved_sha=$2; candidate_sha=$3
	[ "${#approved_sha}" -eq 64 ] || return 1
	case "$approved_sha" in *[!0-9a-f]*) return 1 ;; esac
	[ "$approved_sha" = "$candidate_sha" ] && r2tls_attempt3_predecessor_exact "$consume_root" || return 1
	consume_marker=$consume_root/.attempt3-consumed-$approved_sha
	(umask 077; mkdir "$consume_marker") 2>/dev/null || return 1
	chmod 700 "$consume_marker" || { rmdir "$consume_marker"; return 1; }
	[ ! -L "$consume_marker" ] &&
		[ "$(stat -f '%u:%Lp' "$consume_marker")" = "$(id -u):700" ] || return 1
	R2TLS_ATTEMPT3_CONSUMPTION_MARKER=$consume_marker
	export R2TLS_ATTEMPT3_CONSUMPTION_MARKER
}
