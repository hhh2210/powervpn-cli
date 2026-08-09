#!/bin/sh
# Shared, value-free preflight and evidence helpers for the R1 runner.
# shellcheck disable=SC2034,SC2154
R1_CLI="$R1_REPO_ROOT/.build/debug/powervpn"
R1_SNAPSHOT="$R1_REPO_ROOT/scripts/snapshot_network_state.sh"
R1_APP=/Applications/PowerVPN.app
R1_APP_EXE="$R1_APP/Contents/MacOS/PowerVPN"
R1_HELPER=/Library/PrivilegedHelperTools/com.leadsec.charon-xpc
R1_BUNDLED_HELPER="$R1_APP/Contents/Library/LaunchServices/com.leadsec.charon-xpc"
R1_HELPER_PLIST=/Library/LaunchDaemons/com.leadsec.charon-xpc.plist
R1_VENDOR_LOG=/var/log/vsgvpn.log
R1_DNS_RECOVERY=/tmp/vpntmp.log
R1_SCRATCH_ROOT="$HOME/scratch-data/powervpn-r1"
R1_CANDIDATE_MANIFEST="$R1_REPO_ROOT/fixtures/redacted/r1-reviewed-candidate-manifest-v1.json"; R1_EXPERIMENT_LIBRARY="$R1_REPO_ROOT/scripts/lib/r1_xpc_experiments.sh"

r1_hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
r1_process_absent() {
	if /usr/bin/pgrep -x "$1" >/dev/null 2>&1; then
		return 1
	else
		[ "$?" -eq 1 ]
	fi
}

r1_lstat_enoent() {
	/usr/bin/python3 -c 'import errno, os, sys
try:
    os.lstat(sys.argv[1])
except OSError as error:
    raise SystemExit(0 if error.errno == errno.ENOENT else 2)
raise SystemExit(1)' "$1"
}

r1_launchd_inactive() {
	if ! launchd_text=$(/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null); then
		return 1
	fi
	printf '%s\n' "$launchd_text" | grep -qx '[[:space:]]*active count = 0' || return 1
	printf '%s\n' "$launchd_text" | grep -qx '[[:space:]]*state = not running' || return 1
	! printf '%s\n' "$launchd_text" | grep -q '^[[:space:]]pid = '
}

r1_launchd_runs() {
	/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
		awk '$1=="runs" && $2=="=" && $3~/^[0-9]+$/ {n++; value=$3}
		     END {if(n==1) print value; else exit 1}'
}

r1_vendor_log_metadata() {
	if r1_lstat_enoent "$R1_VENDOR_LOG"; then
		printf absent
		return 0
	fi
	[ -f "$R1_VENDOR_LOG" ] && [ ! -L "$R1_VENDOR_LOG" ] || return 1
	log_size=$(/usr/bin/stat -f '%z' "$R1_VENDOR_LOG") || return 1
	[ "$log_size" -le 31457280 ] || return 1
	/usr/bin/stat -f '%HT|%z|%m|%c|%i|%p|%u|%g' "$R1_VENDOR_LOG"
}

r1_signature_exact() {
	signed_path=$1
	signed_identifier=$2
	signed_cdhash=$3
	/usr/bin/codesign --verify --deep --strict "$signed_path" >/dev/null 2>&1 || return 1
	signature=$(/usr/bin/codesign -dv --verbose=4 "$signed_path" 2>&1) || return 1
	printf '%s\n' "$signature" | grep -qx "Identifier=$signed_identifier" || return 1
	printf '%s\n' "$signature" | grep -qx 'TeamIdentifier=M75ATYZ92T' || return 1
	printf '%s\n' "$signature" | grep -qx "CDHash=$signed_cdhash"
}

r1_plist_exact() {
	[ -f "$R1_HELPER_PLIST" ] && [ ! -L "$R1_HELPER_PLIST" ] || return 1
	[ "$(/usr/bin/stat -f '%u:%g:%Lp' "$R1_HELPER_PLIST")" = 0:0:644 ] || return 1
	[ "$(r1_hash_file "$R1_HELPER_PLIST")" = 3d753e4b3dc1bcbfceb01598b24d144f05a4dca1074a2e09eb9e5874ddfaa5c9 ] || return 1
	/usr/bin/plutil -convert json -o - "$R1_HELPER_PLIST" | jq -e '
      (keys | sort) == ["Label","MachServices","Program","ProgramArguments","RunAtLoad","StandardErrorPath","StandardOutPath","WaitForDebugger"] and
      .Label == "com.leadsec.charon-xpc" and .MachServices == {"com.leadsec.charon-xpc":true} and
      .Program == "/Library/PrivilegedHelperTools/com.leadsec.charon-xpc" and
      .ProgramArguments == ["/Library/PrivilegedHelperTools/com.leadsec.charon-xpc"] and
      .RunAtLoad == false and .WaitForDebugger == false and
      .StandardOutPath == "/var/log/vsgvpn.log" and .StandardErrorPath == "/var/log/vsgvpn.log"
    ' >/dev/null
}

r1_runtime_source_aggregate() {
	runtime_records=$(
		for source in \
			Sources/PowerVPNCLI/main.swift Sources/PowerVPNCLI/VendorXPCCommand.swift \
			Sources/PowerVPNCore/RawVendorXPCTransport.swift \
			Sources/PowerVPNCore/VendorHelperGeneration.swift \
			Sources/PowerVPNCore/VendorXPCModels.swift Sources/PowerVPNCore/VendorXPCProbe.swift; do
			[ -f "$R1_REPO_ROOT/$source" ] && [ ! -L "$R1_REPO_ROOT/$source" ] || exit 1
			printf '%s  %s\n' "$(r1_hash_file "$R1_REPO_ROOT/$source")" "$source"
		done
	) || return 1
	printf '%s\n' "$runtime_records" | shasum -a 256 | awk '{print $1}'
}

r1_candidate_manifest_exact() {
	[ -f "$R1_CANDIDATE_MANIFEST" ] && [ ! -L "$R1_CANDIDATE_MANIFEST" ] || return 1
	runtime_sha=$(r1_runtime_source_aggregate) || return 1
	runner_sha=$(r1_hash_file "$R1_REPO_ROOT/scripts/run_r1_xpc_probe.sh") || return 1
	library_sha=$(r1_hash_file "$R1_REPO_ROOT/scripts/lib/r1_xpc_runtime.sh") || return 1
	experiment_sha=$(r1_hash_file "$R1_EXPERIMENT_LIBRARY") || return 1
	cli_sha=$(r1_hash_file "$R1_CLI") || return 1
	jq -e --arg runtime "$runtime_sha" --arg runner "$runner_sha" --arg library "$library_sha" --arg experiment "$experiment_sha" \
		--arg cli "$cli_sha" '
      keys == ["artifacts","baseCommit","evidenceClass","reviewState","runtimeSourceAggregateSHA256","schemaVersion"] and
      (.artifacts|keys) == ["arm64CLISHA256","experimentLibrarySHA256","launchDaemonPlistSHA256","librarySHA256","runnerSHA256","vendorAppSHA256","vendorBundledHelperSHA256","vendorInstalledHelperSHA256"] and
      .schemaVersion == 1 and .evidenceClass == "r1_reviewed_candidate_manifest" and
      .baseCommit == "a0a465c215a2f949f71b3448ad78e6d0c41e6af0" and .reviewState == "integrated_review_completed_findings_applied" and
      .runtimeSourceAggregateSHA256 == $runtime and .artifacts.runnerSHA256 == $runner and
      .artifacts.librarySHA256 == $library and .artifacts.experimentLibrarySHA256 == $experiment and .artifacts.arm64CLISHA256 == $cli and
      .artifacts.vendorAppSHA256 == "069dee7b624ff2d8a3714bfed06aa6444ad45406d102b5933b987b88a39c7a46" and
      .artifacts.vendorInstalledHelperSHA256 == "ce25374f028216374d386c91a7ee8fea8146b4bfd80f5fde6a59954700555404" and
      .artifacts.vendorBundledHelperSHA256 == "ce25374f028216374d386c91a7ee8fea8146b4bfd80f5fde6a59954700555404" and
      .artifacts.launchDaemonPlistSHA256 == "3d753e4b3dc1bcbfceb01598b24d144f05a4dca1074a2e09eb9e5874ddfaa5c9"
    ' "$R1_CANDIDATE_MANIFEST" >/dev/null || return 1
	R1_CANDIDATE_MANIFEST_SHA256=$(r1_hash_file "$R1_CANDIDATE_MANIFEST")
}

r1_artifacts_exact() {
	[ -f "$R1_CLI" ] && [ -x "$R1_CLI" ] && [ "$(/usr/bin/lipo -archs "$R1_CLI")" = arm64 ] || return 1
	[ -f "$R1_APP_EXE" ] && [ ! -L "$R1_APP_EXE" ] || return 1
	[ "$(r1_hash_file "$R1_APP_EXE")" = 069dee7b624ff2d8a3714bfed06aa6444ad45406d102b5933b987b88a39c7a46 ] || return 1
	[ "$(/usr/bin/lipo -archs "$R1_APP_EXE")" = x86_64 ] || return 1
	[ "$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$R1_APP/Contents/Info.plist")" = 3.2.1 ] || return 1
	[ "$(/usr/bin/plutil -extract CFBundleVersion raw -o - "$R1_APP/Contents/Info.plist")" = 24572 ] || return 1
	r1_signature_exact "$R1_APP" com.leadsec.PowerVPN-Mac 4e0d443652680f85a4e028123eb92d3117a550b0 || return 1
	for pinned_helper in "$R1_HELPER" "$R1_BUNDLED_HELPER"; do
		[ -f "$pinned_helper" ] && [ ! -L "$pinned_helper" ] || return 1
		[ "$(r1_hash_file "$pinned_helper")" = ce25374f028216374d386c91a7ee8fea8146b4bfd80f5fde6a59954700555404 ] || return 1
		[ "$(/usr/bin/lipo -archs "$pinned_helper")" = x86_64 ] || return 1
		r1_signature_exact "$pinned_helper" com.leadsec.charon-xpc 4dd0cbfe2d745a1eb0c6ef4cfbda89b257d5c31e || return 1
	done
	r1_plist_exact || return 1
	r1_candidate_manifest_exact
}

r1_cold_preflight() {
	R1_GUI_ABSENT=false
	R1_HELPER_ABSENT=false
	R1_OTHER_HELPERS_ABSENT=false
	R1_LAUNCHD_COLD=false
	R1_DNS_ABSENT=false
	R1_LOG_SAFE=false
	R1_ARTIFACT_EXACT=false
	r1_process_absent PowerVPN && R1_GUI_ABSENT=true
	r1_process_absent com.leadsec.charon-xpc && R1_HELPER_ABSENT=true
	if r1_process_absent com.leadsec.ipsec-xpc &&
		r1_process_absent com.leadsec.sh-xpc; then
		R1_OTHER_HELPERS_ABSENT=true
	fi
	r1_launchd_inactive && R1_LAUNCHD_COLD=true
	r1_lstat_enoent "$R1_DNS_RECOVERY" && R1_DNS_ABSENT=true
	r1_vendor_log_metadata >/dev/null && R1_LOG_SAFE=true
	r1_artifacts_exact && R1_ARTIFACT_EXACT=true
	R1_PREFLIGHT_SAFE=false
	[ "$R1_GUI_ABSENT" = true ] && [ "$R1_HELPER_ABSENT" = true ] &&
		[ "$R1_OTHER_HELPERS_ABSENT" = true ] &&
		[ "$R1_LAUNCHD_COLD" = true ] && [ "$R1_DNS_ABSENT" = true ] &&
		[ "$R1_LOG_SAFE" = true ] && [ "$R1_ARTIFACT_EXACT" = true ] && R1_PREFLIGHT_SAFE=true
	return 0
}

r1_preflight_json() {
	jq -n --argjson safe "$R1_PREFLIGHT_SAFE" --argjson gui "$R1_GUI_ABSENT" \
		--argjson helper "$R1_HELPER_ABSENT" --argjson launchd "$R1_LAUNCHD_COLD" \
		--argjson others "$R1_OTHER_HELPERS_ABSENT" \
		--argjson dns "$R1_DNS_ABSENT" --argjson log "$R1_LOG_SAFE" \
		--argjson artifacts "$R1_ARTIFACT_EXACT" \
		'{schemaVersion:1,evidenceClass:"r1_xpc_cold_preflight",safeToProbe:$safe,xpcSent:false,cold:{guiAbsent:$gui,helperAbsent:$helper,otherVendorHelpersAbsent:$others,launchdInactive:$launchd,dnsRecoveryLstatENOENT:$dns,vendorLogRegularAndBounded:$log},artifactsExact:$artifacts,containsSecrets:false}'
}

r1_prepare_scratch_root() {
	[ -d "$HOME/scratch-data" ] && [ ! -L "$HOME/scratch-data" ] || return 1
	[ -e "$R1_SCRATCH_ROOT" ] || mkdir "$R1_SCRATCH_ROOT"
	[ -d "$R1_SCRATCH_ROOT" ] && [ ! -L "$R1_SCRATCH_ROOT" ] &&
		[ "$(/usr/bin/stat -f '%u:%Lp' "$R1_SCRATCH_ROOT")" = "$(id -u):700" ]
}

r1_create_sentinel() {
	[ ! -e "$1" ] && [ ! -L "$1" ] || return 1
	(set -C; umask 077; : >"$1") || return 1
	chmod 600 "$1"
}

r1_network_stable() {
	before=$1
	after=$2
	jq -e --slurpfile before "$before" '
      .routeCanonicalizationVersion == $before[0].routeCanonicalizationVersion and
      .interfaceInventorySHA256 == $before[0].interfaceInventorySHA256 and .utunNames == $before[0].utunNames and
      .ipv4PersistentRouteCount == $before[0].ipv4PersistentRouteCount and .ipv4PersistentRouteSHA256 == $before[0].ipv4PersistentRouteSHA256 and
      .ipv6PersistentRouteCount == $before[0].ipv6PersistentRouteCount and .ipv6PersistentRouteSHA256 == $before[0].ipv6PersistentRouteSHA256 and
      .defaultRouteInterface == $before[0].defaultRouteInterface and .defaultRouteSHA256 == $before[0].defaultRouteSHA256 and .dnsSHA256 == $before[0].dnsSHA256 and
      .surgeProcessCount == $before[0].surgeProcessCount and .surgeProcessIdentitySHA256 == $before[0].surgeProcessIdentitySHA256 and
      .surgeExtensionProcessCount == $before[0].surgeExtensionProcessCount and .surgeExtensionProcessIdentitySHA256 == $before[0].surgeExtensionProcessIdentitySHA256 and
      .surgeHelperProcessCount == $before[0].surgeHelperProcessCount and .surgeHelperProcessIdentitySHA256 == $before[0].surgeHelperProcessIdentitySHA256 and
      .surgeCLIProcessCount == $before[0].surgeCLIProcessCount and .surgeCLIProcessIdentitySHA256 == $before[0].surgeCLIProcessIdentitySHA256 and
      .powerVPNProcessCount == 0 and $before[0].powerVPNProcessCount == 0 and
      .espPortState == $before[0].espPortState and (if .espPortState == "available" then .espPortSHA256 == $before[0].espPortSHA256 else true end)
    ' "$after" >/dev/null
}

r1_sad_spd_evidence() {
	before=$1
	after=$2
	R1_SAD_SPD_STATE=indeterminate
	R1_SAD_SPD_CLAIMED=false
	sad_before=$(jq -r '.setkeyState' "$before")
	sad_after=$(jq -r '.setkeyState' "$after")
	spd_before=$(jq -r '.setkeyPolicyState' "$before")
	spd_after=$(jq -r '.setkeyPolicyState' "$after")
	if [ "$sad_before" = unavailable_unprivileged ] && [ "$sad_after" = unavailable_unprivileged ] &&
		[ "$spd_before" = unavailable_unprivileged ] && [ "$spd_after" = unavailable_unprivileged ]; then
		R1_SAD_SPD_STATE=unavailable_unprivileged
	elif [ "$sad_before" = available ] && [ "$sad_after" = available ] &&
		[ "$spd_before" = available ] && [ "$spd_after" = available ] &&
		[ "$(jq -r '.setkeySHA256' "$before")" = "$(jq -r '.setkeySHA256' "$after")" ] &&
		[ "$(jq -r '.setkeyPolicySHA256' "$before")" = "$(jq -r '.setkeyPolicySHA256' "$after")" ]; then
		R1_SAD_SPD_STATE=direct_comparison_stable
		R1_SAD_SPD_CLAIMED=true
	fi
}

r1_extract_probe() {
	probe=$1
	R1_PROBE_VALID=false
	R1_ACCEPTED_EXACT=false
	R1_TRANSACTION=false
	R1_TRANSPORT=not_run
	R1_EXACT=false
	R1_VERSION_LENGTH=null
	R1_VERSION_MATCH=false
	R1_VERSION_SUCCESS=false
	R1_CONNECTION_CANCEL_REQUESTED=false
	R1_PEER_MATCH=false
	R1_GENERATION_RELATION=unavailable
	jq -e '
      (keys == ["connectionCancelRequested","emptyDispatcherTailObserved","emptyReplyAcknowledgementObserved","evidenceClass","exactReplySchema","getVersionSuccess","helperGenerationRelation","mode","preflight","replyPeerMatchesObservedGeneration","safety","schemaVersion","status","transactionAccepted","transportOutcome","versionByteLength","versionMatchesLockedBuild"] or
       keys == ["connectionCancelRequested","emptyDispatcherTailObserved","emptyReplyAcknowledgementObserved","evidenceClass","exactReplySchema","getVersionSuccess","helperGenerationRelation","mode","preflight","replyPeerMatchesObservedGeneration","safety","schemaVersion","status","transactionAccepted","transportOutcome","versionMatchesLockedBuild"]) and
      (.preflight|keys) == ["dnsRecoveryFileAbsent","guiProcessAbsent","helperLaunchdInactive","helperProcessAbsent","otherVendorHelperProcessesAbsent","vendorLogRotationSafe"] and
      (.safety|keys) == ["containsSecrets","loginRequested","rawXPCSerialized","routeMutationRequested","saMutationRequested","serverContactRequested","startConnectionRequested","utunMutationRequested"] and
      .schemaVersion==1 and .evidenceClass=="read_only_vendor_charon_get_version" and .mode=="cold_start_exact_xpc" and
      (.status|type)=="string" and (.transportOutcome|type)=="string" and (.exactReplySchema|type)=="boolean" and
      ((has("versionByteLength")|not) or (.versionByteLength|type)=="number") and (.versionMatchesLockedBuild|type)=="boolean" and (.getVersionSuccess|type)=="boolean" and
      (.emptyDispatcherTailObserved|type)=="boolean" and (.emptyReplyAcknowledgementObserved|type)=="boolean" and
      (.helperGenerationRelation|type)=="string" and (.replyPeerMatchesObservedGeneration|type)=="boolean" and
      (.connectionCancelRequested|type)=="boolean" and (.transactionAccepted|type)=="boolean" and
      .preflight=={guiProcessAbsent:true,helperProcessAbsent:true,otherVendorHelperProcessesAbsent:true,helperLaunchdInactive:true,dnsRecoveryFileAbsent:true,vendorLogRotationSafe:true} and
      .safety=={loginRequested:false,serverContactRequested:false,startConnectionRequested:false,routeMutationRequested:false,saMutationRequested:false,utunMutationRequested:false,rawXPCSerialized:false,containsSecrets:false}
    ' "$probe" >/dev/null 2>&1 || return 0
	R1_PROBE_VALID=true
	R1_TRANSACTION=$(jq -r '.transactionAccepted' "$probe")
	R1_TRANSPORT=$(jq -r '.transportOutcome' "$probe")
	R1_EXACT=$(jq -r '.exactReplySchema' "$probe")
	R1_VERSION_LENGTH=$(jq -r '.versionByteLength' "$probe")
	R1_VERSION_MATCH=$(jq -r '.versionMatchesLockedBuild' "$probe")
	R1_VERSION_SUCCESS=$(jq -r '.getVersionSuccess' "$probe")
	R1_CONNECTION_CANCEL_REQUESTED=$(jq -r '.connectionCancelRequested' "$probe")
	R1_PEER_MATCH=$(jq -r '.replyPeerMatchesObservedGeneration' "$probe")
	R1_GENERATION_RELATION=$(jq -r '.helperGenerationRelation' "$probe")
	jq -e '.status=="accepted" and .transportOutcome=="accepted" and .exactReplySchema==true and
      .versionByteLength==5 and .versionMatchesLockedBuild==true and .getVersionSuccess==true and
      .connectionCancelRequested==true and .replyPeerMatchesObservedGeneration==true and
      .transactionAccepted==true' "$probe" >/dev/null && R1_ACCEPTED_EXACT=true
	return 0
}

r1_write_result() {
	result=$1
	jq -n --argjson pass "$R1_CHECKPOINT_PASS" --argjson attempt "$R1_EXPERIMENT_ATTEMPT" --argjson artifacts "$R1_ARTIFACT_STABLE" --argjson coldArtifacts "$R1_ARTIFACT_EXACT" \
		--arg manifest "$R1_CANDIDATE_MANIFEST_SHA256" \
		--arg transport "$R1_TRANSPORT" --argjson exact "$R1_EXACT" --argjson length "$R1_VERSION_LENGTH" \
		--argjson versionMatch "$R1_VERSION_MATCH" --argjson versionSuccess "$R1_VERSION_SUCCESS" \
		--argjson cancel "$R1_CONNECTION_CANCEL_REQUESTED" --argjson peerMatch "$R1_PEER_MATCH" \
		--arg generation "$R1_GENERATION_RELATION" --argjson runsDelta "$R1_LAUNCHD_RUNS_DELTA" \
		--argjson transaction "$R1_TRANSACTION" --argjson seen "$R1_PROCESS_SEEN" \
		--argjson inspected "$R1_INSPECTION_SUCCEEDED" --argjson max "$R1_MAX_FDS" \
		--argjson natural "$R1_NATURAL_EXIT" --argjson network "$R1_NETWORK_STABLE" \
		--argjson traffic "$R1_SERVER_TRAFFIC" --arg trafficState "$R1_SERVER_TRAFFIC_STATE" --arg sadSpd "$R1_SAD_SPD_STATE" \
		--argjson claimed "$R1_SAD_SPD_CLAIMED" --argjson gui "$R1_GUI_ABSENT" \
		--argjson helperAbsent "$R1_HELPER_ABSENT" --argjson others "$R1_OTHER_HELPERS_ABSENT" \
		--argjson launchd "$R1_LAUNCHD_COLD" --argjson dns "$R1_DNS_ABSENT" \
		--argjson logSafe "$R1_LOG_SAFE" --argjson beforeAbsent "$R1_LOG_BEFORE_ABSENT" \
		--argjson afterSafe "$R1_LOG_AFTER_SAFE" --argjson logChanged "$R1_LOG_CHANGED" \
		'{schemaVersion:1,evidenceClass:"r1_read_only_vendor_xpc_runtime",experimentAttempt:$attempt,checkpointPass:$pass,artifactIdentityStable:$artifacts,candidateManifestSHA256:$manifest,containsSecrets:false,containsRawXPC:false,coldPreflight:{guiAbsent:$gui,helperAbsent:$helperAbsent,otherVendorHelpersAbsent:$others,launchdInactive:$launchd,dnsRecoveryLstatENOENT:$dns,vendorLogRegularAndBounded:$logSafe,artifactsExact:$coldArtifacts},r1Transaction:{transportOutcome:$transport,exactReplySchema:$exact,versionByteLength:$length,versionMatchesLockedBuild:$versionMatch,getVersionSuccess:$versionSuccess,connectionCancelRequested:$cancel,replyPeerMatchesObservedGeneration:$peerMatch,helperGenerationRelation:$generation,transactionAccepted:$transaction},helper:{processObserved:$seen,inspectionSucceeded:$inspected,maximumTCPUDPFDCount:$max,absentWithinDeadlineWithoutHarnessKill:$natural,launchdRunsDelta:$runsDelta},network:{stable:$network,serverTrafficObservationState:$trafficState,serverTrafficObserved:$traffic},sadSpd:{directComparisonState:$sadSpd,claimedStable:$claimed},vendorLog:{beforeAbsent:$beforeAbsent,afterSafe:$afterSafe,metadataChanged:$logChanged,contentsRead:false}}' >"$result"
	chmod 600 "$result"
}

r1_write_signal_evidence() {
	signal_file=$1
	signal_status=$2
	helper_absent=$3
	jq -n --argjson status "$signal_status" --argjson absent "$helper_absent" \
		'{schemaVersion:1,evidenceClass:"r1_incomplete_signal_cleanup",complete:false,signalExitStatus:$status,monitorStopped:true,helper:{absentWithinDeadlineWithoutHarnessKill:$absent,harnessKillSent:false},containsSecrets:false,containsRawXPC:false}' >"$signal_file"
	chmod 600 "$signal_file"
}
