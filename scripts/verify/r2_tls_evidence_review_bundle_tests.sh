#!/bin/sh

set -eu
umask 077

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
# shellcheck source=scripts/lib/r2_tls_evidence_review_bundle.sh
. "$repo_root/scripts/lib/r2_tls_evidence_review_bundle.sh"
test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
test_root=$(mktemp -d "$test_parent/r2tls-review-test.XXXXXX"); chmod 700 "$test_root"
cleanup() {
	exit_status=$?; trap - EXIT HUP INT TERM
	find "$test_root" -type l -delete 2>/dev/null || true
	find "$test_root" -type p -delete 2>/dev/null || true
	find "$test_root" -type f -delete 2>/dev/null || true
	find "$test_root" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	exit "$exit_status"
}
trap cleanup EXIT HUP INT TERM

mini=$test_root/repo; mkdir "$mini"; git -C "$mini" init -q -b rescue-state-machine
git -C "$mini" config user.name review-test; git -C "$mini" config user.email review@example.invalid
printf '%s\n' base >"$mini/BASE.txt"; git -C "$mini" add BASE.txt
GIT_AUTHOR_DATE=2026-01-01T00:00:00Z GIT_COMMITTER_DATE=2026-01-01T00:00:00Z \
	git -C "$mini" commit -q -m base
base=$(git -C "$mini" rev-parse HEAD)
make_file() { mkdir -p "$mini/$(dirname -- "$1")"; printf '%s\n' "${2:-$1}" >"$mini/$1"; }
for path in .gitleaks.toml Package.swift GOAL.md README.md docs/evidence/checkpoint-r2-validation.md \
	docs/progress/GOAL_STATUS.md scripts/export_r2_tls_review_bundle.sh \
	scripts/snapshot_network_state.sh scripts/verify/checkpoint_r2_tls_evidence.sh \
	scripts/verify_checkpoint.sh scripts/verify_no_secrets.sh \
	scripts/lib/native_charon_runtime.sh scripts/lib/route_snapshot.sh \
	scripts/lib/network_snapshot.sh scripts/lib/r2_tls_evidence_attempts.sh \
	scripts/lib/r2_tls_evidence_deadline.sh scripts/lib/r2_tls_evidence_manifest.sh \
	scripts/lib/r2_tls_evidence_monitor.sh scripts/lib/r2_tls_evidence_review_bundle.sh \
	scripts/lib/r2_tls_evidence_runtime.sh scripts/verify/r2_tls_evidence_attempt_tests.sh \
	scripts/verify/r2_tls_evidence_review_bundle_tests.sh \
	Sources/PowerVPNTLSEvidence/A.swift Sources/PowerVPNTLSEvidenceCLI/B.swift \
	Tests/PowerVPNTLSEvidenceTests/T.swift Tests/PowerVPNTLSEvidenceTests/Fixtures/test.pem; do
	make_file "$path"
done
for path in Sources/PowerVPNPortal/Excluded.swift vendor/strongswan/Excluded.swift \
	docs/evidence/checkpoint-cp7.md scratch-data/raw-network.log \
	private/credentials.txt private/portal.sqlite; do
	make_file "$path" 'must not enter the review bundle'
done
make_file scripts/run_r2_tls_evidence.sh '# forbidden live runner fixture'
chmod 755 "$mini"/scripts/*.sh "$mini"/scripts/lib/*.sh "$mini"/scripts/verify/*.sh
for path in r2-tls-evidence-parent-r2-manifest-v1.json \
	r2-tls-evidence-authorized-manifest-v1.json r2-tls-peer-runtime-v1.json \
	r2-tls-evidence-attempt2-authorized-manifest-v1.json r2-tls-peer-runtime-attempt2-v1.json; do
	make_file "fixtures/redacted/$path" '{}'
done
synthetic_cli=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
jq -nS --arg base "$base" --arg cli "$synthetic_cli" \
	'{schemaVersion:1,evidenceClass:"r2_tls_peer_evidence_post_attempt2_candidate",
    baseCommit:$base,reviewState:"post_attempt2_narrow_review_pending",
    artifacts:{arm64CLISHA256:$cli}}' \
	>"$mini/fixtures/redacted/r2-tls-evidence-reviewed-manifest-v1.json"
git -C "$mini" add .
GIT_AUTHOR_DATE=2026-01-02T00:00:00Z GIT_COMMITTER_DATE=2026-01-02T00:00:00Z \
	git -C "$mini" commit -q -m candidate
head=$(git -C "$mini" rev-parse HEAD)
manifest=$(r2tls_review_hash "$mini/fixtures/redacted/r2-tls-evidence-reviewed-manifest-v1.json")
summary=$test_root/summary.json
jq -nS --arg head "$head" --arg manifest "$manifest" --arg cli "$synthetic_cli" '
  {schemaVersion:1,evidenceClass:"r2_tls_review_verifier_summary",sourceCommit:$head,
   candidateManifestSHA256:$manifest,reviewState:"post_attempt2_narrow_review_pending",
   manifestExact:true,reviewComplete:false,fullOfflineVerifierPassed:true,exitStatus:0,
   verifierCommand:"POWERVPN_R2_TLS_REVIEW_CANDIDATE=post-attempt2-pending-v2 scripts/verify_checkpoint.sh r2-tls-evidence",
   swiftTests:{tlsEvidence:37,portal:120,core:109,total:266},arm64ProductSHA256:$cli,
   networkScope:"localhost_and_synthetic_only",liveInvoked:false}
' >"$summary"; chmod 600 "$summary"
mkdir "$test_root/out-one" "$test_root/out-two" "$test_root/tmp"
R2TLS_REVIEW_TMP_PARENT=$test_root/tmp \
	r2tls_review_bundle_build "$mini" "$test_root/out-one" "$summary" >/dev/null
R2TLS_REVIEW_TMP_PARENT=$test_root/tmp \
	r2tls_review_bundle_build "$mini" "$test_root/out-two" "$summary" >/dev/null
archive=$(find "$test_root/out-one" -name '*.zip' -type f)
archive_two=$(find "$test_root/out-two" -name '*.zip' -type f)
bundle_name=PowerVPN-R2-TLS-review-bundle-$(printf '%s' "$manifest" | cut -c1-12)
[ "$(basename -- "$archive")" = "$bundle_name.zip" ]
cmp "$archive" "$archive_two" >/dev/null
cmp "$archive.sha256" "$archive_two.sha256" >/dev/null
(cd "$(dirname -- "$archive")" && \
	/usr/bin/shasum -a 256 -c "$(basename -- "$archive").sha256" >/dev/null)
/usr/bin/unzip -tqq "$archive"
entries=$test_root/entries; zipinfo -1 "$archive" >"$entries"
[ -z "$(LC_ALL=C sort -c "$entries" 2>&1 || true)" ]
collected=$test_root/collected; expected_entries=$test_root/expected-entries
r2tls_review_collect_paths "$mini" "$head" "$collected"
{
	while IFS= read -r path; do printf '%s/%s\n' "$bundle_name" "$path"; done <"$collected"
	for path in BUNDLE_MANIFEST.json DIFFSTAT.txt REVIEW.patch REVIEW_SCOPE.md \
		REVISION.txt SHA256SUMS VERIFIER_SUMMARY.json; do
		printf '%s/%s\n' "$bundle_name" "$path"
	done
} | LC_ALL=C sort >"$expected_entries"
cmp "$expected_entries" "$entries" >/dev/null
if grep -E '(^|/)(\.git|\.build|__MACOSX|scratch-data|private|PowerVPNPortal|strongswan)(/|$)|/\._|cp7' \
	"$entries"; then exit 1; fi
zip_verbose=$test_root/zipinfo; zipinfo -v "$archive" >"$zip_verbose"
if grep -E 'UT extra field|Unix UID/GID' "$zip_verbose"; then exit 1; fi
timestamps=$test_root/timestamps
sed -n 's/.*file last modified on (DOS date\/time):[[:space:]]*//p' \
	"$zip_verbose" >"$timestamps"
[ -s "$timestamps" ]
if grep -Ev '^1980 Jan 1 00:00:00$' "$timestamps"; then exit 1; fi
modes=$test_root/modes
sed -n 's/.*Unix file attributes (\([0-9][0-9]*\) octal).*/\1/p' \
	"$zip_verbose" >"$modes"
[ "$(wc -l <"$modes" | tr -d ' ')" -eq "$(wc -l <"$entries" | tr -d ' ')" ]
if grep -Ev '^(100644|100755)$' "$modes"; then exit 1; fi
extract=$test_root/extract; mkdir "$extract"; /usr/bin/unzip -q "$archive" -d "$extract"
bundle=$(find "$extract" -mindepth 1 -maxdepth 1 -type d)
(cd "$bundle" && /usr/bin/shasum -a 256 -c SHA256SUMS >/dev/null)
[ ! -e "$test_root/live-sentinel" ]
if r2tls_review_path_safe /Users/example/private.json || \
	r2tls_review_path_safe ../escape.json || r2tls_review_path_safe source.bin; then exit 1; fi
if rg -n '/Users/|generated_at|generation_time' "$bundle"/REVISION.txt \
	"$bundle"/BUNDLE_MANIFEST.json "$bundle"/VERIFIER_SUMMARY.json; then exit 1; fi
bad_summary=$test_root/bad-summary.json
jq '.candidateManifestSHA256=("f"*64)' "$summary" >"$bad_summary"
mkdir "$test_root/out-bad"
if R2TLS_REVIEW_TMP_PARENT=$test_root/tmp \
	r2tls_review_bundle_build "$mini" "$test_root/out-bad" "$bad_summary" >/dev/null 2>&1; then exit 1; fi
printf '%s\n' dirty >>"$mini/README.md"; mkdir "$test_root/out-dirty"
if R2TLS_REVIEW_TMP_PARENT=$test_root/tmp \
	r2tls_review_bundle_build "$mini" "$test_root/out-dirty" "$summary" >/dev/null 2>&1; then exit 1; fi
git -C "$mini" cat-file blob HEAD:README.md >"$mini/README.md"
mkfifo "$mini/Tests/PowerVPNTLSEvidenceTests/special.fifo"
mkdir "$test_root/out-fifo"
if R2TLS_REVIEW_TMP_PARENT=$test_root/tmp \
	r2tls_review_bundle_build "$mini" "$test_root/out-fifo" "$summary" >/dev/null 2>&1; then exit 1; fi
rm "$mini/Tests/PowerVPNTLSEvidenceTests/special.fifo"
ln -s A.swift "$mini/Sources/PowerVPNTLSEvidence/linked.swift"
git -C "$mini" add Sources/PowerVPNTLSEvidence/linked.swift
GIT_AUTHOR_DATE=2026-01-03T00:00:00Z GIT_COMMITTER_DATE=2026-01-03T00:00:00Z \
	git -C "$mini" commit -q -m symlink
head=$(git -C "$mini" rev-parse HEAD)
jq --arg head "$head" '.sourceCommit=$head' "$summary" >"$test_root/symlink-summary.json"
mkdir "$test_root/out-link"
if R2TLS_REVIEW_TMP_PARENT=$test_root/tmp \
	r2tls_review_bundle_build "$mini" "$test_root/out-link" \
	"$test_root/symlink-summary.json" >/dev/null 2>&1; then exit 1; fi

printf '%s\n' 'R2 TLS review bundle tests: PASS (synthetic Git repo only)'
