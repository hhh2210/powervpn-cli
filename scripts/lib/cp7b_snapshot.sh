#!/bin/sh

pvn_cp7b_preflight_snapshots_stable() {
	first=$1
	second=$2
	jq -e --slurpfile first "$first" '
	      .setkeyState == "available" and .setkeyPolicyState == "available" and
	      .espPortState == "available" and
	      .routeCanonicalizationVersion == 1 and
	      .routeCanonicalizationVersion == $first[0].routeCanonicalizationVersion and
	      .setkeySHA256 == $first[0].setkeySHA256 and
	      .setkeyPolicySHA256 == $first[0].setkeyPolicySHA256 and
	      .espPortSHA256 == $first[0].espPortSHA256 and
	      .interfaceInventorySHA256 == $first[0].interfaceInventorySHA256 and
	      .ipv4PersistentRouteCount == $first[0].ipv4PersistentRouteCount and
	      .ipv4PersistentRouteSHA256 == $first[0].ipv4PersistentRouteSHA256 and
	      .ipv6PersistentRouteCount == $first[0].ipv6PersistentRouteCount and
	      .ipv6PersistentRouteSHA256 == $first[0].ipv6PersistentRouteSHA256 and
      .defaultRouteInterface == $first[0].defaultRouteInterface and
      .defaultRouteSHA256 == $first[0].defaultRouteSHA256 and
      .dnsSHA256 == $first[0].dnsSHA256 and
      .utunNames == $first[0].utunNames and
      .surgeProcessCount == $first[0].surgeProcessCount and
      .surgeProcessIdentitySHA256 == $first[0].surgeProcessIdentitySHA256 and
      .surgeExtensionProcessCount == $first[0].surgeExtensionProcessCount and
      .surgeExtensionProcessIdentitySHA256 == $first[0].surgeExtensionProcessIdentitySHA256 and
      .surgeHelperProcessCount == $first[0].surgeHelperProcessCount and
      .surgeHelperProcessIdentitySHA256 == $first[0].surgeHelperProcessIdentitySHA256 and
      .surgeCLIProcessCount == $first[0].surgeCLIProcessCount and
      .surgeCLIProcessIdentitySHA256 == $first[0].surgeCLIProcessIdentitySHA256 and
      .powerVPNProcessCount == $first[0].powerVPNProcessCount and
      .powerVPNProcessIdentitySHA256 == $first[0].powerVPNProcessIdentitySHA256 and
      .nativeCharonPids == [] and .productionIKEPortsBoundByNative == false and
      .runtimeStatePresent == false and .ownedVICISocketPresent == false and
      .compiledPIDFilePresent == false and .generationDirectoryCount == 0
	    ' "$second" >/dev/null
}

pvn_cp7b_capture_stable_preflight() {
	first=$1
	second=$2
	PVN_CP7B_PREFLIGHT_FAILURE=root_preflight_first_snapshot_failed
	export PVN_CP7B_PREFLIGHT_FAILURE
	pvn_snapshot_json >"$first" || return 1
	sleep 1
	PVN_CP7B_PREFLIGHT_FAILURE=root_preflight_second_snapshot_failed
	pvn_snapshot_json >"$second" || return 1
	chmod 600 "$first" "$second"
	PVN_CP7B_PREFLIGHT_FAILURE=root_preflight_snapshot_unstable
	pvn_cp7b_preflight_snapshots_stable "$first" "$second" || return 1
	PVN_CP7B_PREFLIGHT_FAILURE=none
}

pvn_cp7b_during_snapshot_safe() {
	before=$1
	during=$2
	jq -e --slurpfile before "$before" '
	      .routeCanonicalizationVersion == 1 and
	      .routeCanonicalizationVersion == $before[0].routeCanonicalizationVersion and
	      .setkeySHA256 == $before[0].setkeySHA256 and
      .setkeyPolicySHA256 == $before[0].setkeyPolicySHA256 and
      .espPortSHA256 == $before[0].espPortSHA256 and
      .interfaceInventorySHA256 == $before[0].interfaceInventorySHA256 and
	      .ipv4PersistentRouteCount == $before[0].ipv4PersistentRouteCount and
	      .ipv4PersistentRouteSHA256 == $before[0].ipv4PersistentRouteSHA256 and
	      .ipv6PersistentRouteCount == $before[0].ipv6PersistentRouteCount and
	      .ipv6PersistentRouteSHA256 == $before[0].ipv6PersistentRouteSHA256 and
      .defaultRouteInterface == $before[0].defaultRouteInterface and
      .defaultRouteSHA256 == $before[0].defaultRouteSHA256 and
      .dnsSHA256 == $before[0].dnsSHA256 and
      .utunNames == $before[0].utunNames and
      .surgeProcessCount == $before[0].surgeProcessCount and
      .surgeProcessIdentitySHA256 == $before[0].surgeProcessIdentitySHA256 and
      .surgeExtensionProcessCount == $before[0].surgeExtensionProcessCount and
      .surgeExtensionProcessIdentitySHA256 == $before[0].surgeExtensionProcessIdentitySHA256 and
      .surgeHelperProcessCount == $before[0].surgeHelperProcessCount and
      .surgeHelperProcessIdentitySHA256 == $before[0].surgeHelperProcessIdentitySHA256 and
      .surgeCLIProcessCount == $before[0].surgeCLIProcessCount and
      .surgeCLIProcessIdentitySHA256 == $before[0].surgeCLIProcessIdentitySHA256 and
      .powerVPNProcessCount == $before[0].powerVPNProcessCount and
      .powerVPNProcessIdentitySHA256 == $before[0].powerVPNProcessIdentitySHA256 and
      (.nativeCharonPids | length) == 1 and
      .runtimeStatePresent == true and .ownedVICISocketPresent == true and
      .compiledPIDFilePresent == true and .generationDirectoryCount == 1 and
      .productionIKEPortsBoundByNative == false and
      .syntheticRouteObserved == $before[0].syntheticRouteObserved
    ' "$during" >/dev/null
}

pvn_cp7b_after_snapshot_safe() {
	before=$1
	after=$2
	jq -e --slurpfile before "$before" '
	      .routeCanonicalizationVersion == 1 and
	      .routeCanonicalizationVersion == $before[0].routeCanonicalizationVersion and
	      .setkeySHA256 == $before[0].setkeySHA256 and
      .setkeyPolicySHA256 == $before[0].setkeyPolicySHA256 and
      .espPortSHA256 == $before[0].espPortSHA256 and
      .interfaceInventorySHA256 == $before[0].interfaceInventorySHA256 and
	      .ipv4PersistentRouteCount == $before[0].ipv4PersistentRouteCount and
	      .ipv4PersistentRouteSHA256 == $before[0].ipv4PersistentRouteSHA256 and
	      .ipv6PersistentRouteCount == $before[0].ipv6PersistentRouteCount and
	      .ipv6PersistentRouteSHA256 == $before[0].ipv6PersistentRouteSHA256 and
      .defaultRouteInterface == $before[0].defaultRouteInterface and
      .defaultRouteSHA256 == $before[0].defaultRouteSHA256 and
      .dnsSHA256 == $before[0].dnsSHA256 and
      .utunNames == $before[0].utunNames and
      .surgeProcessCount == $before[0].surgeProcessCount and
      .surgeProcessIdentitySHA256 == $before[0].surgeProcessIdentitySHA256 and
      .surgeExtensionProcessCount == $before[0].surgeExtensionProcessCount and
      .surgeExtensionProcessIdentitySHA256 == $before[0].surgeExtensionProcessIdentitySHA256 and
      .surgeHelperProcessCount == $before[0].surgeHelperProcessCount and
      .surgeHelperProcessIdentitySHA256 == $before[0].surgeHelperProcessIdentitySHA256 and
      .surgeCLIProcessCount == $before[0].surgeCLIProcessCount and
      .surgeCLIProcessIdentitySHA256 == $before[0].surgeCLIProcessIdentitySHA256 and
      .powerVPNProcessCount == $before[0].powerVPNProcessCount and
      .powerVPNProcessIdentitySHA256 == $before[0].powerVPNProcessIdentitySHA256 and
      .nativeCharonPids == [] and .runtimeStatePresent == false and
      .ownedVICISocketPresent == false and .compiledPIDFilePresent == false and
      .generationDirectoryCount == 0 and
      .productionIKEPortsBoundByNative == false and
      .syntheticRouteObserved == $before[0].syntheticRouteObserved
	    ' "$after" >/dev/null
}

pvn_cp7b_remove_evidence_dir() {
	evidence_root=$1
	shift
	for evidence_path in "$@"; do
		[ ! -e "$evidence_path" ] || rm -f -- "$evidence_path"
	done
	[ ! -d "$evidence_root" ] || rmdir "$evidence_root"
}

pvn_cp7b_udp_fd_count() {
	pid=$1
	case "$pid" in
	'' | *[!0-9]*) return 1 ;;
	esac
	(
		umask 077
		lsof_output=$(/usr/bin/mktemp "${TMPDIR:-/private/tmp}/powervpn-cp7b-lsof.XXXXXX") || exit 1
		trap 'rm -f -- "$lsof_output"' EXIT HUP INT TERM
		[ -f "$lsof_output" ] && [ ! -L "$lsof_output" ] &&
			[ "$(stat -f '%u' "$lsof_output")" -eq "$(id -u)" ] || exit 1
		/usr/sbin/lsof -nP -a -p "$pid" >"$lsof_output" 2>/dev/null || exit 1
		awk -v expected_pid="$pid" '
		  NR == 1 { header = ($1 == "COMMAND" && $2 == "PID"); next }
		  $2 != expected_pid { bad = 1 }
		  /[[:space:]]UDP[[:space:]]/ { count++ }
		  END { if (!header || bad || NR < 2) exit 1; print count + 0 }
		' "$lsof_output"
	)
}

pvn_cp7b_loaded_plugins_exact() {
	log_file=$1
	awk -v expected='openssl nonce kernel-pfkey kernel-pfroute socket-dynamic vici' '
	  index($0, "loaded plugins:") {
	    count++
	    actual = substr($0, index($0, "loaded plugins:") + length("loaded plugins:"))
	    sub(/^[[:space:]]*/, "", actual)
	    sub(/[[:space:]\r]*$/, "", actual)
	    if (actual != expected) bad = 1
	  }
	  END { exit (count != 1 || bad) }
	' "$log_file"
}

pvn_cp7b_report_json() {
	report_manifest_sha=$(pvn_sha256_file "$PVN_CP7B_MANIFEST") || return 1
	report_source_commit=$(jq -er '.artifacts.sourceCommit |
	  select(test("^[0-9a-f]{40}$"))' "$PVN_CP7B_MANIFEST") || return 1
	report_config_sha=$(jq -er '.artifacts.configSHA256 |
	  select(test("^[0-9a-f]{64}$"))' "$PVN_CP7B_MANIFEST") || return 1
	jq -n \
		--argjson success "$1" \
		--argjson attempt "$2" \
		--argjson durationSeconds "$3" \
		--arg failureCategory "$4" \
		--argjson cleanupComplete "$5" \
		--argjson afterStateSafe "$6" \
		--argjson udpSocketCount "$7" \
		--arg requestSHA "$8" \
		--arg responseSHA "$9" \
		--arg approvalManifestSHA256 "$report_manifest_sha" \
		--arg sourceCommit "$report_source_commit" \
		--arg configSHA256 "$report_config_sha" \
		'{
		  schemaVersion: 1,
		  evidenceClass: "cp7b_privileged_serverless_backend_runtime",
		  backend: "pfkey-pfroute",
		  socketProvider: "socket-dynamic",
		  approvalManifestSHA256: $approvalManifestSHA256,
		  sourceCommit: $sourceCommit,
		  configSHA256: $configSHA256,
		  success: $success,
		  attempt: $attempt,
		  durationSeconds: $durationSeconds,
		  failureCategory: $failureCategory,
		  viciVersion: {
		    requestPayloadSHA256: $requestSHA,
		    responsePayloadSHA256: $responseSHA
		  },
		  safety: {
		    udpSocketCount: $udpSocketCount,
		    serverTraffic: false,
		    credentialRead: false,
		    initiateCalled: false,
		    installCalled: false,
		    globalSADStable: $afterStateSafe,
			    globalSPDStable: $afterStateSafe,
			    espPortStable: $afterStateSafe,
			    persistentRouteProjectionStable: $afterStateSafe,
			    defaultRouteDNSAndUtunStable: $afterStateSafe,
		    powerVPNAndSurgeProcessStable: $afterStateSafe,
		    cleanupComplete: $cleanupComplete
		  },
		  containsSecrets: false,
		  containsRawRoutes: false,
		  containsRawSAState: false,
		  containsServerEndpoint: false
			}'
}

pvn_cp7b_preflight_failure_report_json() {
	report_manifest_sha=$(pvn_sha256_file "$PVN_CP7B_MANIFEST") || return 1
	report_source_commit=$(jq -er '.artifacts.sourceCommit |
	  select(test("^[0-9a-f]{40}$"))' "$PVN_CP7B_MANIFEST") || return 1
	report_config_sha=$(jq -er '.artifacts.configSHA256 |
	  select(test("^[0-9a-f]{64}$"))' "$PVN_CP7B_MANIFEST") || return 1
	jq -n --arg failureCategory "$1" --argjson attempt "$2" \
		--argjson durationSeconds "$3" --arg approvalManifestSHA256 "$report_manifest_sha" \
		--arg sourceCommit "$report_source_commit" --arg configSHA256 "$report_config_sha" '
		{
		  schemaVersion: 1,
		  evidenceClass: "cp7b_privileged_preflight_failure",
		  backend: "pfkey-pfroute", socketProvider: "socket-dynamic",
		  approvalManifestSHA256: $approvalManifestSHA256,
		  sourceCommit: $sourceCommit, configSHA256: $configSHA256,
		  success: false, attempt: $attempt, durationSeconds: $durationSeconds,
		  failureCategory: $failureCategory,
		  reachability: {
		    rootWorker: true,
		    privilegedSnapshotPair: ($failureCategory == "root_preflight_snapshot_unstable"),
		    gatedLauncher: false, daemon: false, backendConstructor: false,
		    vici: false, server: false
		  },
		  safety: {
		    serverTraffic: false, credentialRead: false, initiateCalled: false,
		    installCalled: false, retryLedgerRetained: true, cleanupComplete: true
		  },
		  containsSecrets: false, containsRawRoutes: false,
		  containsRawSAState: false, containsServerEndpoint: false
		}'
}

pvn_cp7b_surge_environment_hash() {
	surge_cli=$1
	pvn_cp7b_surge_environment_output=$("$surge_cli" --raw environment)
	printf '%s\n' "$pvn_cp7b_surge_environment_output" |
		jq -e 'type == "object" and (.error // null) == null' >/dev/null || {
		unset pvn_cp7b_surge_environment_output
		return 1
	}
	printf '%s\n' "$pvn_cp7b_surge_environment_output" | pvn_hash_stdin
	unset pvn_cp7b_surge_environment_output
}
