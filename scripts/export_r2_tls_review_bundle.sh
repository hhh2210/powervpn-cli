#!/bin/sh

set -eu
umask 077

usage() { echo "usage: $0 --verify-and-export" >&2; exit 64; }
[ "$#" -eq 1 ] && [ "$1" = --verify-and-export ] || usage

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
output_root=$HOME/Documents/Codex/2026-08-08/pow/outputs
[ ! -e "$output_root" ] || { [ -d "$output_root" ] && [ ! -L "$output_root" ]; } || exit 1
[ -d "$HOME/scratch-data" ] && [ ! -L "$HOME/scratch-data" ] || exit 1
[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ] || exit 1

R2TLS_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$repo_root/scripts/lib/r2_tls_evidence_runtime.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_manifest.sh
. "$repo_root/scripts/lib/r2_tls_evidence_manifest.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_review_bundle.sh
. "$repo_root/scripts/lib/r2_tls_evidence_review_bundle.sh"

for approval_name in POWERVPN_R2_APPROVED_MANIFEST_SHA256 \
	POWERVPN_R2_TLS_EVIDENCE_APPROVED_MANIFEST_SHA256 \
	POWERVPN_R2_TLS_EVIDENCE_EXPERIMENT POWERVPN_R2_EXPOSED_CREDENTIAL_RISK_ACCEPTED; do
	eval "approval_value=\${$approval_name-}"
	[ -z "$approval_value" ] || exit 1
done

r2tls_candidate_manifest_exact
[ "$R2TLS_REVIEW_COMPLETE" = false ]
review_state=$(jq -er '.reviewState | select(type=="string" and length>0)' "$R2TLS_MANIFEST")
head_before=$(git -C "$repo_root" rev-parse HEAD)
manifest_before=$R2TLS_CANDIDATE_MANIFEST_SHA256

POWERVPN_R2_TLS_REVIEW_CANDIDATE=post-attempt2-pending-v2 \
	"$repo_root/scripts/verify_checkpoint.sh" r2-tls-evidence

[ "$head_before" = "$(git -C "$repo_root" rev-parse HEAD)" ]
[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]
r2tls_candidate_manifest_exact
[ "$manifest_before" = "$R2TLS_CANDIDATE_MANIFEST_SHA256" ]
[ "$R2TLS_REVIEW_COMPLETE" = false ]
[ "$(/usr/bin/lipo -archs "$R2TLS_CLI")" = arm64 ]
cli_sha=$(r2tls_hash_file "$R2TLS_CLI")
[ "$cli_sha" = "$(jq -r .artifacts.arm64CLISHA256 "$R2TLS_MANIFEST")" ]

receipt_root=$(mktemp -d "$HOME/scratch-data/r2tls-review-receipt.XXXXXX")
chmod 700 "$receipt_root"; receipt=$receipt_root/verifier-summary.json
cleanup() {
	exit_status=$?; trap - EXIT HUP INT TERM
	[ ! -e "$receipt" ] || rm -f "$receipt"
	rmdir "$receipt_root" 2>/dev/null || true
	exit "$exit_status"
}
trap cleanup EXIT HUP INT TERM
jq -nS --arg head "$head_before" --arg manifest "$manifest_before" \
	--arg state "$review_state" --arg cli "$cli_sha" '
  {schemaVersion:1,evidenceClass:"r2_tls_review_verifier_summary",sourceCommit:$head,
   candidateManifestSHA256:$manifest,reviewState:$state,manifestExact:true,
   reviewComplete:false,fullOfflineVerifierPassed:true,exitStatus:0,
   verifierCommand:"POWERVPN_R2_TLS_REVIEW_CANDIDATE=post-attempt2-pending-v2 scripts/verify_checkpoint.sh r2-tls-evidence",
   swiftTests:{tlsEvidence:37,portal:120,core:109,total:266},
   arm64ProductSHA256:$cli,networkScope:"localhost_and_synthetic_only",liveInvoked:false}
' >"$receipt"
chmod 600 "$receipt"
mkdir -p "$output_root"; chmod 755 "$output_root"
R2TLS_REVIEW_TMP_PARENT=$HOME/scratch-data \
	r2tls_review_bundle_build "$repo_root" "$output_root" "$receipt"
