#!/bin/sh

# Deterministic, review-only exporter. Callers must pass a clean Git repository,
# a closed verifier summary, and an existing output directory.

r2tls_review_fail() { echo "error: $*" >&2; return 1; }
r2tls_review_hash() { /usr/bin/shasum -a 256 "$1" | awk '{print $1}'; }

r2tls_review_path_safe() {
	case "$1" in
	'' | /* | *..* | *[[:space:]]* | .git/* | .build/* | *__MACOSX* | */._*) return 1 ;;
	esac
	case "$1" in
	.gitleaks.toml | Package.swift | *.swift | *.sh | *.md | *.json | *.pem) return 0 ;;
	*) return 1 ;;
	esac
}

r2tls_review_append_tree() (
	review_repo=$1; review_head=$2; review_prefix=$3; review_output=$4
	git -C "$review_repo" ls-tree -r --name-only "$review_head" -- "$review_prefix" \
		>>"$review_output"
)

r2tls_review_collect_paths() (
	review_repo=$1; review_head=$2; review_output=$3
	review_raw=$review_output.raw; review_candidates=$review_output.candidates
	: >"$review_raw"; : >"$review_candidates"
	printf '%s\n' .gitleaks.toml Package.swift GOAL.md README.md \
		docs/evidence/checkpoint-r2-validation.md docs/progress/GOAL_STATUS.md \
		scripts/export_r2_tls_review_bundle.sh scripts/run_r2_tls_evidence.sh \
		scripts/snapshot_network_state.sh scripts/verify/checkpoint_r2_tls_evidence.sh \
		scripts/verify_checkpoint.sh scripts/verify_no_secrets.sh \
		scripts/lib/native_charon_runtime.sh scripts/lib/route_snapshot.sh \
		scripts/lib/network_snapshot.sh \
		fixtures/redacted/r2-tls-evidence-parent-r2-manifest-v1.json \
		fixtures/redacted/r2-tls-evidence-reviewed-manifest-v1.json \
		fixtures/redacted/r2-tls-evidence-authorized-manifest-v1.json \
		fixtures/redacted/r2-tls-peer-runtime-v1.json \
		fixtures/redacted/r2-tls-evidence-attempt2-authorized-manifest-v1.json \
		fixtures/redacted/r2-tls-peer-runtime-attempt2-v1.json >>"$review_raw"
	r2tls_review_append_tree "$review_repo" "$review_head" \
		Sources/PowerVPNTLSEvidence "$review_raw" || return 1
	r2tls_review_append_tree "$review_repo" "$review_head" \
		Sources/PowerVPNTLSEvidenceCLI "$review_raw" || return 1
	r2tls_review_append_tree "$review_repo" "$review_head" \
		Tests/PowerVPNTLSEvidenceTests "$review_raw" || return 1
	git -C "$review_repo" ls-tree -r --name-only "$review_head" -- scripts/lib \
		>>"$review_candidates" || return 1
	git -C "$review_repo" ls-tree -r --name-only "$review_head" -- scripts/verify \
		>>"$review_candidates" || return 1
	while IFS= read -r review_path; do
		case "$review_path" in
		scripts/lib/r2_tls_evidence_*.sh | scripts/verify/r2_tls_evidence_*tests.sh)
			printf '%s\n' "$review_path" >>"$review_raw"
			;;
		esac
	done <"$review_candidates"
	LC_ALL=C sort -u "$review_raw" >"$review_output"
	[ -s "$review_output" ] || return 1
)

r2tls_review_materialize() (
	review_repo=$1; review_head=$2; review_paths=$3; review_root=$4
	while IFS= read -r review_path; do
		r2tls_review_path_safe "$review_path" || return 1
		review_record=$(git -C "$review_repo" ls-tree "$review_head" -- "$review_path") || return 1
		review_mode=${review_record%% *}; review_record_tail=${review_record#* }
		review_type=${review_record_tail%% *}
		[ "$review_mode" != "$review_record" ] && [ "$review_type" = blob ] || return 1
		case "$review_mode" in 100644 | 100755) ;; *) return 1 ;; esac
		mkdir -p "$review_root/$(dirname -- "$review_path")" || return 1
		git -C "$review_repo" cat-file blob "$review_head:$review_path" \
			>"$review_root/$review_path" || return 1
		if [ "$review_mode" = 100755 ]; then chmod 755 "$review_root/$review_path"
		else chmod 644 "$review_root/$review_path"; fi
	done <"$review_paths"
)

r2tls_review_validate_summary() (
	review_summary=$1; review_head=$2; review_manifest=$3; review_state=$4; review_cli=$5
	jq -e --arg head "$review_head" --arg manifest "$review_manifest" \
		--arg state "$review_state" --arg cli "$review_cli" '
    keys==["arm64ProductSHA256","candidateManifestSHA256","evidenceClass",
      "exitStatus","fullOfflineVerifierPassed","liveInvoked","manifestExact",
      "networkScope","reviewComplete","reviewState","schemaVersion","sourceCommit",
      "swiftTests","verifierCommand"] and .schemaVersion==1 and
    .evidenceClass=="r2_tls_review_verifier_summary" and .sourceCommit==$head and
    .candidateManifestSHA256==$manifest and .reviewState==$state and
    .arm64ProductSHA256==$cli and .exitStatus==0 and .fullOfflineVerifierPassed==true and
    .manifestExact==true and .reviewComplete==false and .liveInvoked==false and
    .networkScope=="localhost_and_synthetic_only" and
    .verifierCommand=="POWERVPN_R2_TLS_REVIEW_CANDIDATE=post-attempt2-pending-v2 scripts/verify_checkpoint.sh r2-tls-evidence" and
    .swiftTests=={core:109,portal:120,tlsEvidence:37,total:266}
  ' "$review_summary" >/dev/null
)

r2tls_review_write_metadata() (
	review_repo=$1; review_head=$2; review_paths=$3; review_root=$4; review_summary=$5
	review_manifest_file=$review_root/fixtures/redacted/r2-tls-evidence-reviewed-manifest-v1.json
	review_manifest=$(r2tls_review_hash "$review_manifest_file") || return 1
	review_state=$(jq -r '.reviewState // empty' "$review_manifest_file") || return 1
	review_base=$(jq -r '.baseCommit // empty' "$review_manifest_file") || return 1
	review_cli=$(jq -r '.artifacts.arm64CLISHA256 // empty' "$review_manifest_file") || return 1
	case "$review_manifest$review_cli$review_base" in *[!0-9a-f]*) return 1 ;; esac
	[ "${#review_manifest}" -eq 64 ] && [ "${#review_cli}" -eq 64 ] && \
		[ "${#review_base}" -eq 40 ] || return 1
	git -C "$review_repo" merge-base --is-ancestor "$review_base" "$review_head" || return 1
	r2tls_review_validate_summary "$review_summary" "$review_head" "$review_manifest" \
		"$review_state" "$review_cli" || return 1
	jq -S . "$review_summary" >"$review_root/VERIFIER_SUMMARY.json" || return 1
	printf '%s\n' "schema_version=1" "source_commit=$review_head" \
		"base_commit=$review_base" "branch=rescue-state-machine" \
		"candidate_manifest_sha256=$review_manifest" "review_state=$review_state" \
		"goal_status=active" "worktree_clean=true" >"$review_root/REVISION.txt"
	cat >"$review_root/REVIEW_SCOPE.md" <<EOF
# PowerVPN R2 TLS review-only bundle

- Review source commit: \`$review_head\`
- Candidate manifest: \`$review_manifest\`
State: **external review pending; live hard NO-GO; Goal active**

Review only the bounded TLS evidence implementation, lifecycle, deadlines,
monitor, report invariants, predecessor gate, artifact closure, and cleanup.
Do not request credentials, run portal login, run a live TLS attempt, contact
vendor helpers, weaken trust, or reinterpret an inconclusive result.
EOF
	jq -nS --arg head "$review_head" --arg base "$review_base" \
		--arg manifest "$review_manifest" --arg state "$review_state" '
    {schemaVersion:1,evidenceClass:"r2_tls_review_only_bundle",sourceCommit:$head,
     baseCommit:$base,candidateManifestSHA256:$manifest,reviewState:$state,
     goalActive:true,reviewOnly:true,liveAuthorized:false,containsSecrets:false,
     containsLiveRawEvidence:false,containsSyntheticCertificateFixtures:true,
     exclusions:[".git",".build","compiled binaries","scratch runtime",
       "raw live network, route, certificate, or log material","credentials and TTY",
       "Keychain and databases","xattrs and AppleDouble","unrelated source trees"]}
  ' >"$review_root/BUNDLE_MANIFEST.json"
	tr '\n' '\0' <"$review_paths" | xargs -0 git -C "$review_repo" diff --binary \
		--full-index --no-ext-diff "$review_base" "$review_head" -- \
		>"$review_root/REVIEW.patch" || return 1
	tr '\n' '\0' <"$review_paths" | xargs -0 git -C "$review_repo" diff --stat \
		--no-ext-diff "$review_base" "$review_head" -- \
		>"$review_root/DIFFSTAT.txt" || return 1
)

r2tls_review_zip_once() (
	review_repo=$1; review_summary=$2; review_workspace=$3; review_zip=$4; review_name=$5
	review_head=$(git -C "$review_repo" rev-parse HEAD) || return 1
	review_paths=$review_workspace/paths; review_root=$review_workspace/$review_name
	mkdir -p "$review_root" || return 1
	r2tls_review_collect_paths "$review_repo" "$review_head" "$review_paths" || return 1
	r2tls_review_materialize "$review_repo" "$review_head" "$review_paths" "$review_root" || return 1
	r2tls_review_write_metadata "$review_repo" "$review_head" "$review_paths" \
		"$review_root" "$review_summary" || return 1
	review_sums=$review_workspace/SHA256SUMS
	(
		cd "$review_root" || exit 1
		find . -type f -print | sed 's|^./||' | LC_ALL=C sort |
			while IFS= read -r review_file; do
				review_sha=$(r2tls_review_hash "$review_file") || exit 1
				printf '%s  %s\n' "$review_sha" "$review_file"
			 done
	) >"$review_sums" || return 1
	mv "$review_sums" "$review_root/SHA256SUMS" || return 1
	chmod 644 "$review_root/REVIEW_SCOPE.md" "$review_root/BUNDLE_MANIFEST.json" \
		"$review_root/REVISION.txt" "$review_root/VERIFIER_SUMMARY.json" \
		"$review_root/REVIEW.patch" "$review_root/DIFFSTAT.txt" \
		"$review_root/SHA256SUMS" || return 1
	find "$review_root" -type d -exec chmod 755 {} \; || return 1
	TZ=UTC find "$review_root" -exec touch -t 198001010000 {} + || return 1
	(
		cd "$review_workspace" || exit 1
		find "$review_name" -type f -print | LC_ALL=C sort >zip-files
		TZ=UTC COPYFILE_DISABLE=1 /usr/bin/zip -X -q -9 "$review_zip" -@ <zip-files
	) || return 1
)

r2tls_review_bundle_build() (
	set -eu; umask 077; export LC_ALL=C
	review_repo=$(CDPATH='' cd -- "$1" && pwd -P); review_output=$(CDPATH='' cd -- "$2" && pwd -P)
	review_summary=$3
	review_special=$(find "$review_repo" \
		\( -path "$review_repo/.git" -o -path "$review_repo/.build" -o \
		-path "$review_repo/.swiftpm" -o -path "$review_repo/build" -o \
		-path "$review_repo/prefix" -o -path "$review_repo/runtime" \) -prune -o \
		! -type d ! -type f ! -type l -print -quit)
	[ -z "$review_special" ] || exit 1
	[ -z "$(git -C "$review_repo" status --porcelain=v1 --untracked-files=all)" ] || exit 1
	[ -f "$review_summary" ] && [ ! -L "$review_summary" ] || exit 1
	review_manifest=$(git -C "$review_repo" show HEAD:fixtures/redacted/r2-tls-evidence-reviewed-manifest-v1.json |
		/usr/bin/shasum -a 256 | awk '{print $1}') || exit 1
	review_prefix=$(printf '%s' "$review_manifest" | cut -c1-12)
	review_name=PowerVPN-R2-TLS-review-bundle-$review_prefix
	review_final=$review_output/$review_name.zip; review_outer=$review_final.sha256
	[ ! -e "$review_final" ] && [ ! -e "$review_outer" ] || exit 1
	review_tmp_parent=${R2TLS_REVIEW_TMP_PARENT:-${TMPDIR:-/private/tmp}}
	review_tmp_parent=$(CDPATH='' cd -- "$review_tmp_parent" && pwd -P)
	review_tmp=$(mktemp -d "$review_tmp_parent/r2tls-review.XXXXXX"); chmod 700 "$review_tmp"
	trap 'find "$review_tmp" -type f -delete 2>/dev/null || true; find "$review_tmp" -depth -type d -exec rmdir {} \; 2>/dev/null || true' EXIT HUP INT TERM
	mkdir "$review_tmp/one" "$review_tmp/two"
	r2tls_review_zip_once "$review_repo" "$review_summary" "$review_tmp/one" \
		"$review_tmp/one.zip" "$review_name"
	r2tls_review_zip_once "$review_repo" "$review_summary" "$review_tmp/two" \
		"$review_tmp/two.zip" "$review_name"
	cmp "$review_tmp/one.zip" "$review_tmp/two.zip" >/dev/null || exit 1
	/usr/bin/unzip -tqq "$review_tmp/one.zip" || exit 1
	mv "$review_tmp/one.zip" "$review_final"; chmod 644 "$review_final"
	printf '%s  %s\n' "$(r2tls_review_hash "$review_final")" "$(basename -- "$review_final")" \
		>"$review_outer"; chmod 644 "$review_outer"
	printf '%s\n' "$review_final"
)
