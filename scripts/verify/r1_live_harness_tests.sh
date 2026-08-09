#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
harness="$repo_root/scripts/run_r1_xpc_probe.sh"
runtime_lib="$repo_root/scripts/lib/r1_xpc_runtime.sh"
experiment_lib="$repo_root/scripts/lib/r1_xpc_experiments.sh"
scratch_root="$HOME/scratch-data/powervpn-r1"
R1_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r1_xpc_runtime.sh
. "$runtime_lib"
# shellcheck source=scripts/lib/r1_xpc_experiments.sh
. "$experiment_lib"

launchd_runs() {
	/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
		awk '$1 == "runs" && $2 == "=" && $3 ~ /^[0-9]+$/ { count++; value=$3 }
		     END { if (count == 1) print value; else exit 1 }'
}
helper_identity() {
	if pids=$(/usr/bin/pgrep -x com.leadsec.charon-xpc 2>/dev/null); then
		printf '%s\n' "$pids" | sort -n | shasum -a 256 | awk '{print $1}'
	else
		[ "$?" -eq 1 ] || return 1
		printf absent
	fi
}
scratch_identity() {
	if [ -d "$scratch_root" ]; then
		find "$scratch_root" -mindepth 1 -maxdepth 2 -print 2>/dev/null |
			LC_ALL=C sort | shasum -a 256 | awk '{print $1}'
	else
		printf absent
	fi
}

[ -x "$harness" ]
[ "$(wc -l <"$harness" | tr -d ' ')" -lt 300 ]
[ "$(wc -l <"$runtime_lib" | tr -d ' ')" -lt 300 ]
[ "$(wc -l <"$experiment_lib" | tr -d ' ')" -lt 300 ]
sh -n "$harness"
shellcheck -x "$harness" "$runtime_lib" "$experiment_lib"
# shellcheck disable=SC2016
[ "$(grep -F -c '"$R1_CLI" xpc get-version --timeout-ms 3000 --json' "$harness")" -eq 1 ]
if grep -Eq -- '--(service|rpc|payload)([[:space:]]|=)' "$harness"; then exit 1; fi
if grep -Eq '(^|[[:space:]])(cat|tail|head)[[:space:]]' "$harness"; then exit 1; fi
grep -Fq "trap 'signal_exit 129' HUP" "$harness"
grep -Fq "trap 'signal_exit 130' INT" "$harness"
grep -Fq "trap 'signal_exit 143' TERM" "$harness"
grep -Fq -- '--experiment-2-generation-binding' "$harness"
grep -Fq -- '--experiment-3-first-terminal' "$harness"

runs_before=$(launchd_runs)
helper_before=$(helper_identity)
scratch_before=$(scratch_identity)
set +e
report=$($harness --preflight-only)
report_rc=$?
set -e
runs_after=$(launchd_runs)
helper_after=$(helper_identity)
scratch_after=$(scratch_identity)

printf '%s\n' "$report" | jq -e '
  .schemaVersion == 1 and .evidenceClass == "r1_xpc_cold_preflight" and
  (.safeToProbe | type) == "boolean" and .xpcSent == false and
  (.cold | keys | sort) == ["dnsRecoveryLstatENOENT","guiAbsent","helperAbsent","launchdInactive","otherVendorHelpersAbsent","vendorLogRegularAndBounded"] and
  (.artifactsExact | type) == "boolean" and .containsSecrets == false
' >/dev/null
safe=$(printf '%s\n' "$report" | jq -r '.safeToProbe')
if [ "$safe" = true ]; then [ "$report_rc" -eq 0 ]; else [ "$report_rc" -ne 0 ]; fi
[ "$runs_before" = "$runs_after" ]
[ "$helper_before" = "$helper_after" ]
[ "$scratch_before" = "$scratch_after" ]
[ "$helper_before" = absent ]
r1_process_absent com.leadsec.ipsec-xpc
r1_process_absent com.leadsec.sh-xpc

set +e
"$R1_CLI" xpc get-version --timeout-ms 3000 --unknown --json >/dev/null 2>&1
unknown_rc=$?
"$R1_CLI" xpc get-version --timeout-ms 3000 --timeout-ms 3000 --json >/dev/null 2>&1
duplicate_rc=$?
"$R1_CLI" xpc get-version --json --timeout-ms 3000 >/dev/null 2>&1
wrong_order_rc=$?
set -e
[ "$unknown_rc" -ne 0 ] && [ "$duplicate_rc" -ne 0 ] && [ "$wrong_order_rc" -ne 0 ]
[ "$(launchd_runs)" = "$runs_before" ] && [ "$(helper_identity)" = absent ]
r1_process_absent com.leadsec.ipsec-xpc
r1_process_absent com.leadsec.sh-xpc

lstat_root=$(/usr/bin/mktemp -d "${TMPDIR:-/private/tmp}/powervpn-r1-lstat.XXXXXX")
r1_lstat_enoent "$lstat_root/absent"
: >"$lstat_root/regular"
if r1_lstat_enoent "$lstat_root/regular"; then exit 1; fi
ln -s "$lstat_root/missing-target" "$lstat_root/dangling"
if r1_lstat_enoent "$lstat_root/dangling"; then exit 1; fi
rm -f "$lstat_root/regular" "$lstat_root/dangling"
rmdir "$lstat_root"
[ "$(r1_lsof_tcp_udp_count "$$" 1 '')" -eq 0 ]
lsof_fixture="COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
helper $$ user 1u IPv4 0x0 0t0 TCP localhost:1"
[ "$(r1_lsof_tcp_udp_count "$$" 0 "$lsof_fixture")" -eq 1 ]
if r1_lsof_tcp_udp_count "$$" 1 permission_denied >/dev/null; then exit 1; fi

if [ "$safe" = true ]; then
	r1_candidate_manifest_exact
	printf '%s\n' "$R1_CANDIDATE_MANIFEST_SHA256" | grep -Eq '^[0-9a-f]{64}$'
	bad_manifest=$(/usr/bin/mktemp "${TMPDIR:-/private/tmp}/powervpn-r1-manifest.XXXXXX")
	jq '.unexpected=true' "$R1_CANDIDATE_MANIFEST" >"$bad_manifest"
	real_manifest=$R1_CANDIDATE_MANIFEST
	R1_CANDIDATE_MANIFEST=$bad_manifest
	if r1_candidate_manifest_exact; then exit 1; fi
	R1_CANDIDATE_MANIFEST=$real_manifest
	rm -f "$bad_manifest"
	set +e
	"$harness" >/dev/null 2>&1
	default_retry_rc=$?
	set -e
	[ "$default_retry_rc" -eq 6 ]
	[ "$(launchd_runs)" = "$runs_before" ] && [ "$(helper_identity)" = absent ]
	test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
	test_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r1-harness-test.XXXXXX")
	chmod 700 "$test_root"
	interrupt_output="$test_root/stdout"
	POWERVPN_R1_TEST_ACTIVE_MONITOR_SIGNAL=reviewed-no-xpc \
		POWERVPN_R1_TEST_SCRATCH_ROOT="$test_root" \
		"$harness" --preflight-only >"$interrupt_output" 2>/dev/null &
	preflight_pid=$!
	ready_attempt=0
	while [ -z "$(find "$test_root" -name .monitor-ready -type f -print -quit)" ] &&
		[ "$ready_attempt" -lt 500 ]; do
		ready_attempt=$((ready_attempt + 1)); sleep 0.01
	done
	[ "$ready_attempt" -lt 500 ]
	/bin/kill -TERM "$preflight_pid"
	set +e
	wait "$preflight_pid"
	interrupt_rc=$?
	set -e
	[ "$interrupt_rc" -eq 143 ]
	signal_file=$(find "$test_root" -name incomplete-signal.json -type f -print)
	[ "$(printf '%s\n' "$signal_file" | awk 'NF {n++} END {print n+0}')" -eq 1 ]
	[ "$(stat -f '%Lp' "$signal_file")" = 600 ]
	jq -e 'keys==["complete","containsRawXPC","containsSecrets","evidenceClass","helper","monitorStopped","schemaVersion","signalExitStatus"] and .schemaVersion==1 and .evidenceClass=="r1_incomplete_signal_cleanup" and .complete==false and .signalExitStatus==143 and .monitorStopped==true and .helper=={absentWithinDeadlineWithoutHarnessKill:true,harnessKillSent:false} and .containsSecrets==false and .containsRawXPC==false' "$signal_file" >/dev/null
	[ -z "$(find "$test_root" \( -name .monitor-ready -o -name .monitor-stop -o -name probe.json -o -name result.json \) -print)" ]
	[ "$(launchd_runs)" = "$runs_before" ] && [ "$(helper_identity)" = absent ]
	set +e
	POWERVPN_R1_TEST_ACTIVE_MONITOR_SIGNAL=reviewed-no-xpc \
		POWERVPN_R1_TEST_SCRATCH_ROOT="$test_root" \
		"$harness" --preflight-only >/dev/null 2>&1
	retry_rc=$?
	set -e
	[ "$retry_rc" -eq 6 ]
	[ "$(launchd_runs)" = "$runs_before" ] && [ "$(helper_identity)" = absent ]
	find "$test_root" -type f -delete
	find "$test_root" -depth -type d -exec rmdir {} \;

	gate_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r1-harness-test.XXXXXX")
	chmod 700 "$gate_root"
	gate_run="$gate_root/run-synthetic-attempt-1"
	mkdir "$gate_run"; chmod 700 "$gate_run"
	jq -n '{schemaVersion:1,evidenceClass:"read_only_vendor_charon_get_version",mode:"cold_start_exact_xpc",status:"transport_failed",transportOutcome:"accepted",exactReplySchema:true,versionByteLength:5,versionMatchesLockedBuild:true,getVersionSuccess:true,emptyDispatcherTailObserved:false,emptyReplyAcknowledgementObserved:false,helperGenerationRelation:"launched_and_exited",replyPeerMatchesObservedGeneration:false,connectionCancelRequested:true,preflight:{guiProcessAbsent:true,helperProcessAbsent:true,otherVendorHelperProcessesAbsent:true,helperLaunchdInactive:true,dnsRecoveryFileAbsent:true,vendorLogRotationSafe:true},safety:{loginRequested:false,serverContactRequested:false,startConnectionRequested:false,routeMutationRequested:false,saMutationRequested:false,utunMutationRequested:false,rawXPCSerialized:false,containsSecrets:false},transactionAccepted:false}' >"$gate_run/probe.json"
	jq -n '{processSeen:true,inspectionSucceeded:false,maxTCPUDPCount:0}' >"$gate_run/helper-monitor.json"
	jq -n '{schemaVersion:1,evidenceClass:"value_free_local_network_snapshot",routeCanonicalizationVersion:1,interfaceInventorySHA256:"interface",utunNames:[],ipv4PersistentRouteCount:1,ipv4PersistentRouteSHA256:"v4",ipv6PersistentRouteCount:1,ipv6PersistentRouteSHA256:"v6",defaultRouteInterface:"default",defaultRouteSHA256:"route",dnsSHA256:"dns",surgeProcessCount:1,surgeProcessIdentitySHA256:"surge",surgeExtensionProcessCount:1,surgeExtensionProcessIdentitySHA256:"extension",surgeHelperProcessCount:1,surgeHelperProcessIdentitySHA256:"helper",surgeCLIProcessCount:0,surgeCLIProcessIdentitySHA256:"cli",powerVPNProcessCount:0,espPortState:"available",espPortSHA256:"esp",containsSecrets:false,containsRawRoutes:false,containsRawSAState:false}' >"$gate_run/network-before.json"
	cp "$gate_run/network-before.json" "$gate_run/network-after.json"
	chmod 600 "$gate_run"/*.json
	gate_report=$(POWERVPN_R1_TEST_EXPERIMENT2_GATE_ONLY=reviewed-no-xpc \
		POWERVPN_R1_TEST_SCRATCH_ROOT="$gate_root" \
		"$harness" --experiment-2-generation-binding)
	printf '%s\n' "$gate_report" | jq -e '.experimentAttempt==2 and .predecessorValidated==true and .xpcSent==false' >/dev/null
	[ "$(launchd_runs)" = "$runs_before" ] && [ "$(helper_identity)" = absent ]
	: >"$gate_run/result.json"; chmod 600 "$gate_run/result.json"
	set +e
	POWERVPN_R1_TEST_EXPERIMENT2_GATE_ONLY=reviewed-no-xpc \
		POWERVPN_R1_TEST_SCRATCH_ROOT="$gate_root" \
		"$harness" --experiment-2-generation-binding >/dev/null 2>&1
	bad_gate_rc=$?
	set -e
	[ "$bad_gate_rc" -eq 7 ]
	[ "$(launchd_runs)" = "$runs_before" ] && [ "$(helper_identity)" = absent ]
	find "$gate_root" -type f -delete
	find "$gate_root" -depth -type d -exec rmdir {} \;

	gate3_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r1-harness-test.XXXXXX")
	chmod 700 "$gate3_root"
	selected=0
	for source_run in "$scratch_root"/run-*; do
		if r1_lstat_enoent "$source_run/result.json" ||
			jq -e '.experimentAttempt==2 and .checkpointPass==false' "$source_run/result.json" >/dev/null 2>&1; then
			destination="$gate3_root/$(basename "$source_run")"
			mkdir "$destination"; chmod 700 "$destination"
			cp "$source_run"/*.json "$destination/"; chmod 600 "$destination"/*.json
			selected=$((selected + 1))
		fi
	done
	[ "$selected" -eq 2 ]
	gate3_report=$(POWERVPN_R1_TEST_EXPERIMENT3_GATE_ONLY=reviewed-no-xpc \
		POWERVPN_R1_TEST_SCRATCH_ROOT="$gate3_root" "$harness" --experiment-3-first-terminal)
	printf '%s\n' "$gate3_report" | jq -e '.experimentAttempt==3 and .predecessorsValidated==true and .xpcSent==false' >/dev/null
	result2=$(find "$gate3_root" -name result.json -type f -print)
	jq '.checkpointPass=true' "$result2" >"$gate3_root/tampered"; mv "$gate3_root/tampered" "$result2"; chmod 600 "$result2"
	set +e
	POWERVPN_R1_TEST_EXPERIMENT3_GATE_ONLY=reviewed-no-xpc POWERVPN_R1_TEST_SCRATCH_ROOT="$gate3_root" "$harness" --experiment-3-first-terminal >/dev/null 2>&1
	bad_gate3_rc=$?
	set -e
	[ "$bad_gate3_rc" -eq 8 ] && [ "$(launchd_runs)" = "$runs_before" ] && [ "$(helper_identity)" = absent ]
	find "$gate3_root" -type f -delete
	find "$gate3_root" -depth -type d -exec rmdir {} \;
fi

probe_output=$(/usr/bin/mktemp "${TMPDIR:-/private/tmp}/powervpn-r1-probe.XXXXXX")
tampered_probe=$(/usr/bin/mktemp "${TMPDIR:-/private/tmp}/powervpn-r1-probe-extra.XXXXXX")
jq -n '{schemaVersion:1,evidenceClass:"read_only_vendor_charon_get_version",mode:"cold_start_exact_xpc",status:"accepted",transportOutcome:"accepted",exactReplySchema:true,versionByteLength:5,versionMatchesLockedBuild:true,getVersionSuccess:true,emptyDispatcherTailObserved:false,emptyReplyAcknowledgementObserved:false,helperGenerationRelation:"launched",replyPeerMatchesObservedGeneration:true,connectionCancelRequested:true,preflight:{guiProcessAbsent:true,helperProcessAbsent:true,otherVendorHelperProcessesAbsent:true,helperLaunchdInactive:true,dnsRecoveryFileAbsent:true,vendorLogRotationSafe:true},safety:{loginRequested:false,serverContactRequested:false,startConnectionRequested:false,routeMutationRequested:false,saMutationRequested:false,utunMutationRequested:false,rawXPCSerialized:false,containsSecrets:false},transactionAccepted:true}' >"$probe_output"
r1_extract_probe "$probe_output"
[ "$R1_PROBE_VALID" = true ] && [ "$R1_ACCEPTED_EXACT" = true ]
[ "$R1_CONNECTION_CANCEL_REQUESTED" = true ] && [ "$R1_GENERATION_RELATION" = launched ]
jq '.status="transport_failed" | .helperGenerationRelation="launched_and_exited" | .replyPeerMatchesObservedGeneration=false | .transactionAccepted=false' "$probe_output" >"$tampered_probe"
r1_extract_probe "$tampered_probe"
failed_extract_rc=$?
[ "$failed_extract_rc" -eq 0 ] && [ "$R1_PROBE_VALID" = true ] && [ "$R1_ACCEPTED_EXACT" = false ]
jq 'del(.versionByteLength) | .status="transport_failed" | .transportOutcome="connection_interrupted" | .exactReplySchema=false | .versionMatchesLockedBuild=false | .getVersionSuccess=false | .helperGenerationRelation="launched_and_exited" | .replyPeerMatchesObservedGeneration=false | .transactionAccepted=false' "$probe_output" >"$tampered_probe"
r1_extract_probe "$tampered_probe"
[ "$R1_PROBE_VALID" = true ] && [ "$R1_TRANSPORT" = connection_interrupted ] &&
	[ "$R1_VERSION_LENGTH" = null ] && [ "$R1_GENERATION_RELATION" = launched_and_exited ] &&
	[ "$R1_CONNECTION_CANCEL_REQUESTED" = true ]
jq '.extra=true' "$probe_output" >"$tampered_probe"
r1_extract_probe "$tampered_probe"
[ "$R1_PROBE_VALID" = false ] && [ "$R1_ACCEPTED_EXACT" = false ]
jq 'del(.extra) | .safety.extra=true' "$tampered_probe" >"$probe_output"
r1_extract_probe "$probe_output"
[ "$R1_PROBE_VALID" = false ] && [ "$R1_ACCEPTED_EXACT" = false ]
rm -f "$probe_output" "$tampered_probe"

schema_output=$(/usr/bin/mktemp "${TMPDIR:-/private/tmp}/powervpn-r1-schema.XXXXXX")
R1_EXPERIMENT_ATTEMPT=3
R1_CHECKPOINT_PASS=true
R1_ARTIFACT_STABLE=true
R1_TRANSPORT=accepted
R1_EXACT=true
R1_VERSION_LENGTH=5
R1_VERSION_MATCH=true
R1_VERSION_SUCCESS=true
R1_CONNECTION_CANCEL_REQUESTED=true
R1_PEER_MATCH=true
R1_GENERATION_RELATION=launched_and_exited
R1_TRANSACTION=true
R1_PROCESS_SEEN=true
R1_INSPECTION_SUCCEEDED=true
R1_MAX_FDS=0
R1_NATURAL_EXIT=true
R1_LAUNCHD_RUNS_DELTA=1
R1_NETWORK_STABLE=true
R1_SERVER_TRAFFIC=false
R1_SERVER_TRAFFIC_STATE=observed_no_tcp_udp_fds
R1_SAD_SPD_STATE=unavailable_unprivileged
R1_SAD_SPD_CLAIMED=false
R1_CANDIDATE_MANIFEST_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
R1_GUI_ABSENT=true
R1_HELPER_ABSENT=true
R1_OTHER_HELPERS_ABSENT=true
R1_LAUNCHD_COLD=true
R1_DNS_ABSENT=true
R1_LOG_SAFE=true
R1_ARTIFACT_EXACT=true
R1_LOG_BEFORE_ABSENT=false
R1_LOG_AFTER_SAFE=true
R1_LOG_CHANGED=true
r1_write_result "$schema_output"
[ "$(stat -f '%Lp' "$schema_output")" = 600 ]
jq -e '
  keys == ["artifactIdentityStable","candidateManifestSHA256","checkpointPass","coldPreflight","containsRawXPC","containsSecrets","evidenceClass","experimentAttempt","helper","network","r1Transaction","sadSpd","schemaVersion","vendorLog"] and
  .schemaVersion == 1 and .evidenceClass == "r1_read_only_vendor_xpc_runtime" and
  .experimentAttempt == 3 and .checkpointPass == true and .artifactIdentityStable == true and
  .candidateManifestSHA256 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and .containsSecrets == false and .containsRawXPC == false and
  .coldPreflight == {guiAbsent:true,helperAbsent:true,otherVendorHelpersAbsent:true,launchdInactive:true,dnsRecoveryLstatENOENT:true,vendorLogRegularAndBounded:true,artifactsExact:true} and
  .r1Transaction == {transportOutcome:"accepted",exactReplySchema:true,versionByteLength:5,versionMatchesLockedBuild:true,getVersionSuccess:true,connectionCancelRequested:true,replyPeerMatchesObservedGeneration:true,helperGenerationRelation:"launched_and_exited",transactionAccepted:true} and
  .helper == {processObserved:true,inspectionSucceeded:true,maximumTCPUDPFDCount:0,absentWithinDeadlineWithoutHarnessKill:true,launchdRunsDelta:1} and
  .network == {stable:true,serverTrafficObservationState:"observed_no_tcp_udp_fds",serverTrafficObserved:false} and
  .sadSpd == {directComparisonState:"unavailable_unprivileged",claimedStable:false} and
  .vendorLog == {beforeAbsent:false,afterSafe:true,metadataChanged:true,contentsRead:false}
' "$schema_output" >/dev/null
R1_CHECKPOINT_PASS=false; R1_TRANSPORT=connection_interrupted; R1_EXACT=false
R1_VERSION_LENGTH=null; R1_VERSION_MATCH=false; R1_VERSION_SUCCESS=false
R1_PEER_MATCH=false; R1_TRANSACTION=false; R1_INSPECTION_SUCCEEDED=false
R1_SERVER_TRAFFIC=null; R1_SERVER_TRAFFIC_STATE=unavailable_inspection_failed
r1_write_result "$schema_output"
jq -e '.checkpointPass==false and .r1Transaction.transportOutcome=="connection_interrupted" and .r1Transaction.versionByteLength==null and .network.serverTrafficObservationState=="unavailable_inspection_failed" and .network.serverTrafficObserved==null' "$schema_output" >/dev/null
rm -f "$schema_output"

shellcheck -x "$0" "$runtime_lib" "$experiment_lib"
printf '%s\n' 'R1 live harness dry-preflight tests: PASS (no XPC sent)'
