#!/bin/sh

# Closed, value-free predecessor gates for explicitly authorized R1 experiments.
# shellcheck disable=SC2034,SC2154

r1_lsof_tcp_udp_count() {
	pid=$1
	lsof_status=$2
	lsof_output=$3
	if [ "$lsof_status" -eq 0 ]; then
		printf '%s\n' "$lsof_output" | awk -v pid="$pid" '
          NR==1 {header=($1=="COMMAND"&&$2=="PID"); next}
          $2!=pid {bad=1} NR>1 {n++}
          END {if(!header||bad||n==0) exit 1; print n}'
	elif [ "$lsof_status" -eq 1 ] && [ -z "$lsof_output" ] &&
		/bin/ps -p "$pid" -o pid= 2>/dev/null | grep -q '[0-9]'; then
		printf 0
	else
		return 1
	fi
}

r1_validate_evidence_run() {
	run=$1
	expected_count=$2
	shift 2
	[ -d "$run" ] && [ ! -L "$run" ] &&
		[ "$(stat -f '%u:%Lp' "$run")" = "$(id -u):700" ] || return 1
	[ "$(find "$run" -mindepth 1 -maxdepth 1 -print | awk 'END {print NR+0}')" -eq "$expected_count" ] || return 1
	for evidence in "$@"; do
		evidence_path="$run/$evidence"
		[ -f "$evidence_path" ] && [ ! -L "$evidence_path" ] &&
			[ "$(stat -f '%u:%Lp' "$evidence_path")" = "$(id -u):600" ] || return 1
	done
}

r1_validate_snapshot_pair() {
	run=$1
	for snapshot_file in "$run/network-before.json" "$run/network-after.json"; do
		jq -e '.schemaVersion==1 and .evidenceClass=="value_free_local_network_snapshot" and .containsSecrets==false and .containsRawRoutes==false and .containsRawSAState==false' "$snapshot_file" >/dev/null || return 1
	done
	r1_network_stable "$run/network-before.json" "$run/network-after.json"
}

r1_validate_attempt_1_run() {
	run=$1
	r1_validate_evidence_run "$run" 4 probe.json helper-monitor.json \
		network-before.json network-after.json || return 1
	r1_lstat_enoent "$run/result.json" || return 1
	r1_extract_probe "$run/probe.json"
	[ "$R1_PROBE_VALID" = true ] && [ "$R1_ACCEPTED_EXACT" = false ] &&
		[ "$R1_TRANSPORT" = accepted ] && [ "$R1_EXACT" = true ] &&
		[ "$R1_VERSION_LENGTH" = 5 ] && [ "$R1_VERSION_MATCH" = true ] &&
		[ "$R1_VERSION_SUCCESS" = true ] && [ "$R1_CONNECTION_CANCEL_REQUESTED" = true ] &&
		[ "$R1_GENERATION_RELATION" = launched_and_exited ] && [ "$R1_PEER_MATCH" = false ] &&
		[ "$R1_TRANSACTION" = false ] || return 1
	jq -e '.status=="transport_failed"' "$run/probe.json" >/dev/null || return 1
	jq -e 'keys==["inspectionSucceeded","maxTCPUDPCount","processSeen"] and .processSeen==true and .inspectionSucceeded==false and .maxTCPUDPCount==0' "$run/helper-monitor.json" >/dev/null || return 1
	r1_validate_snapshot_pair "$run"
}

r1_validate_attempt_2_run() {
	run=$1
	r1_validate_evidence_run "$run" 5 probe.json helper-monitor.json \
		network-before.json network-after.json result.json || return 1
	r1_extract_probe "$run/probe.json"
	[ "$R1_PROBE_VALID" = true ] && [ "$R1_ACCEPTED_EXACT" = false ] &&
		[ "$R1_TRANSPORT" = connection_interrupted ] && [ "$R1_EXACT" = false ] &&
		[ "$R1_VERSION_LENGTH" = null ] && [ "$R1_VERSION_MATCH" = false ] &&
		[ "$R1_VERSION_SUCCESS" = false ] && [ "$R1_CONNECTION_CANCEL_REQUESTED" = true ] &&
		[ "$R1_GENERATION_RELATION" = launched_and_exited ] && [ "$R1_PEER_MATCH" = false ] &&
		[ "$R1_TRANSACTION" = false ] || return 1
	jq -e '.status=="transport_failed"' "$run/probe.json" >/dev/null || return 1
	jq -e 'keys==["inspectionSucceeded","maxTCPUDPCount","processSeen"] and .processSeen==true and .inspectionSucceeded==false and .maxTCPUDPCount==0' "$run/helper-monitor.json" >/dev/null || return 1
	jq -e '
      keys==["artifactIdentityStable","candidateManifestSHA256","checkpointPass","coldPreflight","containsRawXPC","containsSecrets","evidenceClass","experimentAttempt","helper","network","r1Transaction","sadSpd","schemaVersion","vendorLog"] and
      .schemaVersion==1 and .evidenceClass=="r1_read_only_vendor_xpc_runtime" and .experimentAttempt==2 and .checkpointPass==false and .artifactIdentityStable==true and
      .candidateManifestSHA256=="df7ce809af534418a6cef5a6c5b899a43bccb88d204b57b482827571ff22aa86" and .containsSecrets==false and .containsRawXPC==false and
      .coldPreflight=={guiAbsent:true,helperAbsent:true,otherVendorHelpersAbsent:true,launchdInactive:true,dnsRecoveryLstatENOENT:true,vendorLogRegularAndBounded:true,artifactsExact:true} and
      .r1Transaction=={transportOutcome:"not_run",exactReplySchema:false,versionByteLength:null,versionMatchesLockedBuild:false,getVersionSuccess:false,connectionCancelRequested:false,replyPeerMatchesObservedGeneration:false,helperGenerationRelation:"unavailable",transactionAccepted:false} and
      .helper=={processObserved:true,inspectionSucceeded:false,maximumTCPUDPFDCount:0,absentWithinDeadlineWithoutHarnessKill:true,launchdRunsDelta:1} and
      .network=={stable:true,serverTrafficObserved:true} and .sadSpd=={directComparisonState:"unavailable_unprivileged",claimedStable:false} and
      .vendorLog=={beforeAbsent:false,afterSafe:true,metadataChanged:true,contentsRead:false}
    ' "$run/result.json" >/dev/null || return 1
	r1_validate_snapshot_pair "$run"
}

r1_retained_runs() {
	find "$1" -mindepth 1 -maxdepth 1 -name 'run-*' -print | LC_ALL=C sort
}

r1_helpers_absent() {
	r1_process_absent com.leadsec.charon-xpc && r1_process_absent com.leadsec.ipsec-xpc &&
		r1_process_absent com.leadsec.sh-xpc
}

r1_validate_experiment_2_predecessor() {
	runs=$(r1_retained_runs "$1") || return 1
	[ "$(printf '%s\n' "$runs" | awk 'NF {n++} END {print n+0}')" -eq 1 ] || return 1
	r1_validate_attempt_1_run "$runs" && r1_helpers_absent
}

r1_validate_experiment_3_predecessors() {
	runs=$(r1_retained_runs "$1") || return 1
	[ "$(printf '%s\n' "$runs" | awk 'NF {n++} END {print n+0}')" -eq 2 ] || return 1
	attempt_1=
	attempt_2=
	for run in $runs; do
		if r1_lstat_enoent "$run/result.json"; then attempt_1=$run
		elif [ -f "$run/result.json" ] && [ ! -L "$run/result.json" ]; then attempt_2=$run
		else return 1
		fi
	done
	[ -n "$attempt_1" ] && [ -n "$attempt_2" ] || return 1
	r1_validate_attempt_1_run "$attempt_1" && r1_validate_attempt_2_run "$attempt_2" &&
		r1_helpers_absent
}
