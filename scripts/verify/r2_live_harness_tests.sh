#!/bin/sh
# shellcheck disable=SC2016

set -eu
umask 077

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
harness="$repo_root/scripts/run_r2_portal_login.sh"
runtime="$repo_root/scripts/lib/r2_portal_runtime.sh"
R2_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_portal_runtime.sh
. "$runtime"

assert_system_unchanged() {
	[ "$(r2_launchd_runs)" -eq "$runs_anchor" ] && r2_launchd_inactive &&
		r2_process_absent PowerVPN && r2_helpers_absent && r2_native_charon_absent
}
scratch_identity() {
	if [ -d "$R2_SCRATCH_ROOT" ]; then
		find "$R2_SCRATCH_ROOT" -mindepth 1 -maxdepth 2 -print 2>/dev/null |
			LC_ALL=C sort | shasum -a 256 | awk '{print $1}'
	else
		printf absent
	fi
}
synthetic_report() {
	jq -n '{schemaVersion:1,mode:"r2_username_password_portal_login",status:"accepted",operations:{loginRequested:true,loginAccepted:true,sessionCheckRequested:true,sessionCheckAccepted:true,resourceListRequested:true,resourceListAccepted:true,logoutRequested:true,logoutAccepted:true},ownedMaterial:{credentialsErased:true,requestBodiesErased:true,responseBodiesErased:true,sessionMaterialErased:true},safety:{credentialSource:"controlling_tty_no_echo",endpointSource:"sealed_installed_configuration",systemTrustRequired:true,redirectsAllowed:false,credentialInArguments:false,credentialInEnvironment:false,credentialWrittenToFile:false,endpointValueRetainedInEvidence:false,platformSerialValueRetainedInEvidence:false,rawRequestRetainedInEvidence:false,rawResponseRetainedInEvidence:false,sessionValueRetainedInEvidence:false,resourceValueRetainedInEvidence:false,portalHTTPSAllowed:true,helperMutationRequested:false,xpcUsed:false,viciUsed:false,ikeTrafficRequested:false,appOwnedCopiesErasureClaimed:true,foundationInternalCopiesErasureClaimed:false},transactionAccepted:true}'
}

runs_anchor=$(r2_launchd_runs) || exit 1
[ "$runs_anchor" -eq 19 ] || {
	echo 'error: R2 synthetic tests require launchd runs exactly 19' >&2
	exit 1
}
assert_system_unchanged

[ -x "$harness" ] && [ -f "$runtime" ]
[ "$(wc -l <"$harness" | tr -d ' ')" -lt 300 ]
[ "$(wc -l <"$runtime" | tr -d ' ')" -lt 300 ]
[ "$(wc -l <"$0" | tr -d ' ')" -lt 300 ]
sh -n "$harness" "$runtime" "$0"
shellcheck -x "$harness" "$runtime" "$0"
grep -Fq 'R2_CLI="$R2_REPO_ROOT/.build/debug/powervpn"' "$runtime"
grep -Fq 'R2_PORTAL_ENDPOINT=166.111.143.19:4443' "$runtime"
grep -Fq 'POWERVPN_R2_APPROVED_MANIFEST_SHA256' "$harness"
grep -Fq 'r2_candidate_manifest_exact' "$runtime"
grep -Fq '"$R2_CLI" login </dev/null >"$fifo" 2>/dev/tty' "$harness"
grep -Fq 'exec /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin' "$harness"
grep -Fq 'mkfifo "$fifo"' "$harness"
grep -Fq 'r2_reconstruct_report "$fifo" "$report"' "$harness"
if grep -Eq '(^|[[:space:]])read([[:space:]]|$)' "$harness" "$runtime"; then exit 1; fi
if grep -Eq '(^|[[:space:]])(sudo|security)[[:space:]]' "$harness" "$runtime"; then exit 1; fi
if grep -Fq '/bin/kill' "$harness" "$runtime"; then exit 1; fi
assert_system_unchanged

set +e
preflight=$($harness --preflight-only)
preflight_rc=$?
set -e
review_state=$(jq -r '.reviewState' "$R2_MANIFEST")
manifest_sha=$(r2_hash_file "$R2_MANIFEST")
if [ "$review_state" = integrated_review_pending ]; then
	[ "$preflight_rc" -eq 1 ]
	expected_safe=false; expected_review=false
else
	[ "$review_state" = integrated_review_completed_findings_applied ]
	[ "$preflight_rc" -eq 0 ]
	expected_safe=true; expected_review=true
fi
printf '%s\n' "$preflight" | jq -e --arg manifest "$manifest_sha" \
	--argjson safe "$expected_safe" --argjson reviewed "$expected_review" '
  keys==["candidateManifestSHA256","cliReady","cold","containsSecrets","dependenciesReady","evidenceClass","loginStarted","manifestExact","manifestReviewComplete","networkSnapshotTaken","safeToLogin","schemaVersion"] and
  .schemaVersion==1 and .evidenceClass=="r2_portal_cold_preflight" and
  .loginStarted==false and .networkSnapshotTaken==false and
  .cold=={guiAbsent:true,vendorHelpersAbsent:true,nativeCharonAbsent:true,portalCLIAbsent:true,helperLaunchdInactive:true,helperLaunchdRuns:19} and
  .cliReady==true and .dependenciesReady==true and .manifestExact==true and
  .containsSecrets==false and .candidateManifestSHA256==$manifest and
  .safeToLogin==$safe and .manifestReviewComplete==$reviewed
' >/dev/null
assert_system_unchanged

scratch_before=$(scratch_identity)
set +e
env -u POWERVPN_R2_APPROVED_MANIFEST_SHA256 \
	-u POWERVPN_R2_ROTATED_CREDENTIAL_CONFIRMATION "$harness" >/dev/null 2>&1
default_live_rc=$?
set -e
if [ "$expected_review" = true ]; then
	[ "$default_live_rc" -eq 4 ]
else
	[ "$default_live_rc" -eq 3 ]
fi
[ "$(scratch_identity)" = "$scratch_before" ]
assert_system_unchanged

valid_fixture='p123
f10
PTCP
n10.0.0.2:51000->166.111.143.19:4443'
[ "$(printf '%s\n' "$valid_fixture" | r2_summarize_lsof)" = "1	0	true" ]
bad_fixture='p123
f10
PTCP
n10.0.0.2:51000->203.0.113.1:443
f11
PUDP
n10.0.0.2:52000->203.0.113.2:53'
[ "$(printf '%s\n' "$bad_fixture" | r2_summarize_lsof)" = "1	1	false" ]

test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
fixture_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r2-fixture.XXXXXX")
chmod 700 "$fixture_root"
before="$fixture_root/before.json"; after="$fixture_root/after.json"; changed="$fixture_root/changed.json"
jq -n '{schemaVersion:1,timestamp:"before",powerVPNProcessCount:0,nativeCharonPids:[],productionIKEPortsBoundByNative:false,containsSecrets:false,containsRawRoutes:false,containsRawSAState:false}' >"$before"
jq '.timestamp="after"' "$before" >"$after"
jq '.dnsSHA256="changed"' "$after" >"$changed"
chmod 600 "$before" "$after" "$changed"
r2_network_stable "$before" "$after"
if r2_network_stable "$before" "$changed"; then exit 1; fi

fifo="$fixture_root/report.fifo"; report="$fixture_root/report.json"
mkfifo "$fifo"; chmod 600 "$fifo"
synthetic_report >"$fifo" & writer_pid=$!
r2_reconstruct_report "$fifo" "$report"
wait "$writer_pid"
[ "$(stat -f '%Lp' "$report")" = 600 ]
jq -e '.transactionAccepted==true and .status=="accepted" and .safety.credentialInArguments==false' "$report" >/dev/null
[ "$(wc -l <"$report" | tr -d ' ')" -eq 1 ]

bad_fifo="$fixture_root/bad.fifo"; bad_report="$fixture_root/bad.json"
mkfifo "$bad_fifo"; chmod 600 "$bad_fifo"
synthetic_report | jq '.unexpected=true' >"$bad_fifo" & bad_writer_pid=$!
set +e
r2_reconstruct_report "$bad_fifo" "$bad_report"
bad_report_rc=$?
set -e
wait "$bad_writer_pid"
[ "$bad_report_rc" -ne 0 ] && [ ! -e "$bad_report" ]
assert_system_unchanged

signal_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r2-harness-test.XXXXXX")
chmod 700 "$signal_root"
POWERVPN_R2_TEST_ACTIVE_MONITOR_SIGNAL=reviewed-no-network-v1 \
	POWERVPN_R2_TEST_SCRATCH_ROOT="$signal_root" \
	"$harness" --preflight-only >"$signal_root/stdout" 2>"$signal_root/stderr" &
harness_pid=$!
ready_attempt=0
while [ -z "$(find "$signal_root" -name .monitor-ready -type f -print -quit)" ] &&
	[ "$ready_attempt" -lt 500 ]; do
	ready_attempt=$((ready_attempt + 1)); sleep 0.01
done
[ "$ready_attempt" -lt 500 ]
/bin/kill -TERM "$harness_pid"
set +e
wait "$harness_pid"; signal_rc=$?
set -e
[ "$signal_rc" -eq 143 ]
signal_file=$(find "$signal_root" -name incomplete-signal.json -type f -print)
monitor_file=$(find "$signal_root" -name portal-monitor.json -type f -print)
[ "$(printf '%s\n' "$signal_file" | awk 'NF {n++} END {print n+0}')" -eq 1 ]
[ "$(stat -f '%Lp' "$signal_file")" = 600 ] && [ "$(stat -f '%Lp' "$monitor_file")" = 600 ]
jq -e 'keys==["complete","containsRawPortal","containsSecrets","evidenceClass","harnessKillSent","monitorStopped","networkCommandStarted","schemaVersion","signalExitStatus"] and .schemaVersion==1 and .evidenceClass=="r2_incomplete_signal_cleanup" and .complete==false and .signalExitStatus==143 and .monitorStopped==true and .networkCommandStarted==false and .harnessKillSent==false and .containsSecrets==false and .containsRawPortal==false' "$signal_file" >/dev/null
jq -e '.targetObserved==true and .inspectionSucceeded==true and .portalTCPObserved==false and .maximumTCPCount==0 and .maximumUDPCount==0 and .vendorHelperObserved==false and .nativeCharonObserved==false' "$monitor_file" >/dev/null
[ -z "$(find "$signal_root" \( -name '*.fifo' -o -name 'network-*.json' -o -name cli-report.json -o -name result.json \) -print)" ]
assert_system_unchanged

find "$fixture_root" "$signal_root" -type f -delete
find "$fixture_root" "$signal_root" -type p -delete
find "$fixture_root" "$signal_root" -depth -type d -exec rmdir {} \;
assert_system_unchanged
printf '%s\n' 'R2 live harness synthetic tests: PASS (no CLI, XPC, helper, or network command run)'
