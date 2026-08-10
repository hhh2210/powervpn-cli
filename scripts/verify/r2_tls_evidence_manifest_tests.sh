#!/bin/sh

set -eu
umask 077

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
R2TLS_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$repo_root/scripts/lib/r2_tls_evidence_runtime.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_manifest.sh
. "$repo_root/scripts/lib/r2_tls_evidence_manifest.sh"

test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
test_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r2-tls-manifest.XXXXXX")
chmod 700 "$test_root"
cleanup() {
	exit_status=$?; trap - EXIT HUP INT TERM
	find "$test_root" -type l -delete 2>/dev/null || true
	find "$test_root" -type f -delete 2>/dev/null || true
	find "$test_root" -type p -delete 2>/dev/null || true
	find "$test_root" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	exit "$exit_status"
}
trap cleanup EXIT HUP INT TERM

mini=$test_root/repo
mkdir -p "$mini/Sources/PowerVPNTLSEvidence" \
	"$mini/Sources/PowerVPNTLSEvidenceCLI" \
	"$mini/Tests/PowerVPNTLSEvidenceTests/Fixtures" \
	"$mini/scripts/lib" "$mini/scripts/verify"
printf '%s\n' package >"$mini/Package.swift"
printf '%s\n' source-a >"$mini/Sources/PowerVPNTLSEvidence/A.swift"
printf '%s\n' source-b >"$mini/Sources/PowerVPNTLSEvidenceCLI/B.swift"
printf '%s\n' test-a >"$mini/Tests/PowerVPNTLSEvidenceTests/A.swift"
printf '%s\n' fixture >"$mini/Tests/PowerVPNTLSEvidenceTests/Fixtures/input.bin"
for relative in .gitleaks.toml scripts/snapshot_network_state.sh scripts/lib/native_charon_runtime.sh \
	scripts/lib/route_snapshot.sh scripts/lib/network_snapshot.sh GOAL.md \
	scripts/run_r2_tls_evidence.sh scripts/export_r2_tls_review_bundle.sh \
	scripts/lib/r2_tls_evidence_runtime.sh scripts/lib/r2_tls_evidence_review_bundle.sh \
	scripts/verify/r2_tls_evidence_harness_tests.sh \
	scripts/verify/checkpoint_r2_tls_evidence.sh scripts/verify_checkpoint.sh \
	scripts/verify_no_secrets.sh; do
	mkdir -p "$(dirname -- "$mini/$relative")"
	printf '%s\n' "$relative" >"$mini/$relative"
done

R2TLS_REPO_ROOT=$mini
source_before=$(r2tls_source_aggregate)
printf '%s\n' source-c >"$mini/Sources/PowerVPNTLSEvidence/C.swift"
source_after=$(r2tls_source_aggregate)
[ "$source_before" != "$source_after" ]
ln -s A.swift "$mini/Sources/PowerVPNTLSEvidence/alias.swift"
if r2tls_source_aggregate >/dev/null 2>&1; then exit 1; fi
rm "$mini/Sources/PowerVPNTLSEvidence/alias.swift"
mkfifo "$mini/Sources/PowerVPNTLSEvidence/special.fifo"
if r2tls_source_aggregate >/dev/null 2>&1; then exit 1; fi
rm "$mini/Sources/PowerVPNTLSEvidence/special.fifo"

tests_before=$(r2tls_tests_aggregate)
printf '%s\n' extra >"$mini/Tests/PowerVPNTLSEvidenceTests/extra.dat"
tests_after=$(r2tls_tests_aggregate)
[ "$tests_before" != "$tests_after" ]
ln -s A.swift "$mini/Tests/PowerVPNTLSEvidenceTests/alias.swift"
if r2tls_tests_aggregate >/dev/null 2>&1; then exit 1; fi
rm "$mini/Tests/PowerVPNTLSEvidenceTests/alias.swift"
mkfifo "$mini/Tests/PowerVPNTLSEvidenceTests/special.fifo"
if r2tls_tests_aggregate >/dev/null 2>&1; then exit 1; fi
rm "$mini/Tests/PowerVPNTLSEvidenceTests/special.fifo"

runtime_before=$(r2tls_runtime_scripts_aggregate)
printf '%s\n' helper >"$mini/scripts/lib/r2_tls_evidence_new.sh"
runtime_after=$(r2tls_runtime_scripts_aggregate)
[ "$runtime_before" != "$runtime_after" ]

shell_tests_before=$(r2tls_shell_tests_aggregate)
printf '%s\n' test >"$mini/scripts/verify/r2_tls_evidence_new_tests.sh"
shell_tests_after=$(r2tls_shell_tests_aggregate)
[ "$shell_tests_before" != "$shell_tests_after" ]

snapshot_before=$(r2tls_snapshot_inputs_aggregate)
printf '%s\n' changed >>"$mini/scripts/lib/network_snapshot.sh"
snapshot_after=$(r2tls_snapshot_inputs_aggregate)
[ "$snapshot_before" != "$snapshot_after" ]

verifier_before=$(r2tls_verifier_inputs_aggregate)
printf '%s\n' changed >>"$mini/scripts/verify_no_secrets.sh"
verifier_after=$(r2tls_verifier_inputs_aggregate)
[ "$verifier_before" != "$verifier_after" ]

review_bundle_before=$(r2tls_review_bundle_inputs_aggregate)
printf '%s\n' changed >>"$mini/scripts/lib/r2_tls_evidence_review_bundle.sh"
review_bundle_after=$(r2tls_review_bundle_inputs_aggregate)
[ "$review_bundle_before" != "$review_bundle_after" ]

if r2tls_hash_relative_files ../escape >/dev/null 2>&1; then exit 1; fi
if r2tls_hash_relative_files '/absolute' >/dev/null 2>&1; then exit 1; fi

printf '%s\n' 'R2 TLS evidence manifest tests: PASS (synthetic files only)'
