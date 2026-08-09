#!/bin/sh

# Shared value-free safety, monitoring, and report helpers for the R2 runner.
# The caller must set R2_REPO_ROOT before sourcing this file.
# shellcheck disable=SC2034,SC2086
R2_CLI="$R2_REPO_ROOT/.build/debug/powervpn"
R2_SNAPSHOT="$R2_REPO_ROOT/scripts/snapshot_network_state.sh"
R2_MANIFEST="$R2_REPO_ROOT/fixtures/redacted/r2-reviewed-candidate-manifest-v1.json"
R2_SCRATCH_ROOT="$HOME/scratch-data/powervpn-r2"
R2_PORTAL_ENDPOINT=166.111.143.19:4443
R2_EXPECTED_LAUNCHD_RUNS=19
R2_CONFIRMATION_TOKEN=reviewed-nonsecret-rotated-credential-confirmation-v1
R2_CP7A_CHARON="$HOME/scratch-data/powervpn-strongswan/install-6.0.7-cp7a-arm64/libexec/ipsec/charon"
R2_CP7B_CHARON="$HOME/scratch-data/powervpn-strongswan/runtime-6.0.7-cp7b/closure/libexec/ipsec/charon"

r2_hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
r2_source_aggregate() {
	source_lines=$(
		for file in Package.swift Sources/PowerVPNCLI/main.swift \
			Sources/PowerVPNCLI/PortalLoginCommand.swift; do
			[ -f "$R2_REPO_ROOT/$file" ] && [ ! -L "$R2_REPO_ROOT/$file" ] || exit 1
			sha=$(r2_hash_file "$R2_REPO_ROOT/$file") || exit 1
			printf '%s  %s\n' "$sha" "$file"
		done
		source_files=$(find "$R2_REPO_ROOT/Sources/PowerVPNPortal" \
			"$R2_REPO_ROOT/Sources/CPortalCurl" -type f \
			\( -name '*.swift' -o -name '*.c' -o -name '*.h' \) \
			-print | LC_ALL=C sort) || exit 1
		[ -n "$source_files" ] || exit 1
		old_ifs=$IFS
		IFS='
'
		# Paths in this reviewed source tree contain no whitespace.
		# shellcheck disable=SC2086
		set -- $source_files
		IFS=$old_ifs
		for file_path
		do
			if printf '%s' "$file_path" | grep -q '[[:space:]]'; then exit 1; fi
			[ ! -L "$file_path" ] || exit 1
			relative=${file_path#"$R2_REPO_ROOT/"}
			sha=$(r2_hash_file "$file_path") || exit 1
			printf '%s  %s\n' "$sha" "$relative"
		done
	) || return 1
	[ -n "$source_lines" ] || return 1
	printf '%s\n' "$source_lines" | shasum -a 256 | awk '{print $1}'
}
r2_raw_tests_aggregate() {
	test_lines=$(
		for file in Tests/CPortalCurlTests/CPortalCurlHeaderTests.c \
			Tests/CPortalCurlTests/CPortalCurlStatusTests.c \
			Tests/PowerVPNPortalTests/CurlPasswordPortalTransportTests.swift \
			Tests/PowerVPNPortalTests/LeadSecPortalTransportTests.swift \
			Tests/PowerVPNPortalTests/PortalRequestFactoryTests.swift \
			Tests/PowerVPNPortalTests/FoundationPortalURLSessionReuseTests.swift; do
			[ -f "$R2_REPO_ROOT/$file" ] && [ ! -L "$R2_REPO_ROOT/$file" ] || exit 1
			printf '%s  %s\n' "$(r2_hash_file "$R2_REPO_ROOT/$file")" "$file" || exit 1
		done
	) || return 1
	printf '%s\n' "$test_lines" | shasum -a 256 | awk '{print $1}'
}
r2_candidate_manifest_exact() {
	[ -f "$R2_MANIFEST" ] && [ ! -L "$R2_MANIFEST" ] &&
		[ "$(stat -f '%u:%Lp' "$R2_MANIFEST")" = "$(id -u):644" ] || return 1
	source_aggregate=$(CDPATH='' cd -- "$R2_REPO_ROOT" && r2_source_aggregate) || return 1
	runner_sha=$(r2_hash_file "$R2_REPO_ROOT/scripts/run_r2_portal_login.sh") || return 1
	runtime_sha=$(r2_hash_file "$R2_REPO_ROOT/scripts/lib/r2_portal_runtime.sh") || return 1
	tests_sha=$(r2_hash_file "$R2_REPO_ROOT/scripts/verify/r2_live_harness_tests.sh") || return 1
	snapshot_sha=$(r2_hash_file "$R2_SNAPSHOT") || return 1
	raw_verifier_sha=$(r2_hash_file "$R2_REPO_ROOT/scripts/verify/checkpoint_r2_raw_headers.sh") || return 1
	raw_tests_sha=$(r2_raw_tests_aggregate) || return 1
	cli_sha=$(r2_hash_file "$R2_CLI") || return 1
	app_sha=$(r2_hash_file /Applications/PowerVPN.app/Contents/MacOS/PowerVPN) || return 1
	info_sha=$(r2_hash_file /Applications/PowerVPN.app/Contents/Info.plist) || return 1
	db_sha=$(r2_hash_file "$HOME/Library/Application Support/com.leadsec.PowerVPN-Mac/Users/users.sqlite") || return 1
	prefs_sha=$(r2_hash_file "$HOME/Library/Preferences/com.leadsec.PowerVPN-Mac.plist") || return 1
	review_state=$(jq -r '.reviewState // empty' "$R2_MANIFEST") || return 1
	case "$review_state" in
	integrated_review_pending | integrated_review_completed_findings_applied) ;;
	*) return 1 ;;
	esac
	jq -e --arg source "$source_aggregate" --arg runner "$runner_sha" \
		--arg runtime "$runtime_sha" --arg tests "$tests_sha" --arg snapshot "$snapshot_sha" \
		--arg raw "$raw_verifier_sha" --arg rawtests "$raw_tests_sha" --arg cli "$cli_sha" \
		--arg app "$app_sha" --arg info "$info_sha" --arg db "$db_sha" \
		--arg prefs "$prefs_sha" --arg review "$review_state" '
    keys == ["artifacts", "baseCommit", "evidenceClass", "reviewState",
      "runtimeSourceAggregateSHA256", "schemaVersion"] and
    .schemaVersion == 1 and
    .evidenceClass == "r2_reviewed_portal_login_candidate" and
    .baseCommit == "71fe9eee3d70ef45897002271b4f0a03851e3aff" and
    .reviewState == $review and
    .runtimeSourceAggregateSHA256 == $source and
    .artifacts == {arm64CLISHA256:$cli,harnessTestsSHA256:$tests,
      installedAppSHA256:$app,installedDatabaseSHA256:$db,
      installedInfoPlistSHA256:$info,installedPreferencesSHA256:$prefs,
      networkSnapshotSHA256:$snapshot,rawHeaderVerifierSHA256:$raw,
      rawHeaderTestsAggregateSHA256:$rawtests,runnerSHA256:$runner,
      runtimeLibrarySHA256:$runtime}
  ' "$R2_MANIFEST" >/dev/null || return 1
	R2_CANDIDATE_MANIFEST_SHA256=$(r2_hash_file "$R2_MANIFEST") || return 1
	R2_RUNTIME_SOURCE_AGGREGATE_SHA256=$source_aggregate
	R2_MANIFEST_REVIEW_COMPLETE=false
	[ "$review_state" = integrated_review_completed_findings_applied ] &&
		R2_MANIFEST_REVIEW_COMPLETE=true
	export R2_CANDIDATE_MANIFEST_SHA256 R2_RUNTIME_SOURCE_AGGREGATE_SHA256 \
		R2_MANIFEST_REVIEW_COMPLETE
}
r2_process_absent() {
	if /usr/bin/pgrep -x "$1" >/dev/null 2>&1; then
		return 1
	else
		[ "$?" -eq 1 ]
	fi
}
r2_command_absent() {
	/bin/ps -axo command= | awk -v executable="$1" '
    { sub(/^[[:space:]]*/, "") }
    $0 == executable || index($0, executable " ") == 1 { found = 1 }
    END { exit found }
  '
}
r2_helpers_absent() {
	r2_process_absent com.leadsec.charon-xpc &&
		r2_process_absent com.leadsec.ipsec-xpc &&
		r2_process_absent com.leadsec.sh-xpc
}
r2_native_charon_absent() {
	r2_process_absent charon && r2_command_absent "$R2_CP7A_CHARON" &&
		r2_command_absent "$R2_CP7B_CHARON"
}
r2_cli_absent() { r2_command_absent "$R2_CLI login"; }

r2_launchd_runs() {
	/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
		awk '$1 == "runs" && $2 == "=" && $3 ~ /^[0-9]+$/ { count++; value=$3 }
         END { if (count == 1) print value; else exit 1 }'
}
r2_launchd_inactive() {
	launchd_text=$(/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null) || return 1
	printf '%s\n' "$launchd_text" | grep -qx '[[:space:]]*active count = 0' || return 1
	printf '%s\n' "$launchd_text" | grep -qx '[[:space:]]*state = not running' || return 1
	! printf '%s\n' "$launchd_text" | grep -q '^[[:space:]]pid = '
}
r2_cli_ready() {
	[ -f "$R2_CLI" ] && [ -x "$R2_CLI" ] && [ ! -L "$R2_CLI" ] &&
		[ "$(/usr/bin/lipo -archs "$R2_CLI")" = arm64 ]
}

r2_cold_preflight() {
	R2_GUI_ABSENT=false; R2_HELPERS_ABSENT=false; R2_NATIVE_ABSENT=false
	R2_CLI_ABSENT=false; R2_LAUNCHD_INACTIVE=false; R2_LAUNCHD_EXACT=false
	R2_CLI_READY=false; R2_DEPENDENCIES_READY=false; R2_MANIFEST_EXACT=false
	R2_MANIFEST_REVIEW_COMPLETE=false
	R2_CANDIDATE_MANIFEST_SHA256=; R2_LAUNCHD_RUNS=-1
	r2_process_absent PowerVPN && R2_GUI_ABSENT=true
	r2_helpers_absent && R2_HELPERS_ABSENT=true
	r2_native_charon_absent && R2_NATIVE_ABSENT=true
	r2_cli_absent && R2_CLI_ABSENT=true
	r2_launchd_inactive && R2_LAUNCHD_INACTIVE=true
	R2_LAUNCHD_RUNS=$(r2_launchd_runs) || R2_LAUNCHD_RUNS=-1
	[ "$R2_LAUNCHD_INACTIVE" = true ] &&
		[ "$R2_LAUNCHD_RUNS" -eq "$R2_EXPECTED_LAUNCHD_RUNS" ] && R2_LAUNCHD_EXACT=true
	r2_cli_ready && R2_CLI_READY=true
	r2_candidate_manifest_exact && R2_MANIFEST_EXACT=true
	command -v jq >/dev/null && [ -x /usr/sbin/lsof ] &&
		[ -x "$R2_SNAPSHOT" ] && R2_DEPENDENCIES_READY=true
	R2_PREFLIGHT_SAFE=false
	[ "$R2_GUI_ABSENT" = true ] && [ "$R2_HELPERS_ABSENT" = true ] &&
		[ "$R2_NATIVE_ABSENT" = true ] && [ "$R2_CLI_ABSENT" = true ] &&
		[ "$R2_LAUNCHD_EXACT" = true ] && [ "$R2_CLI_READY" = true ] &&
		[ "$R2_MANIFEST_EXACT" = true ] &&
		[ "$R2_MANIFEST_REVIEW_COMPLETE" = true ] &&
		[ "$R2_DEPENDENCIES_READY" = true ] && R2_PREFLIGHT_SAFE=true
	return 0
}
r2_preflight_json() {
	jq -n --argjson safe "$R2_PREFLIGHT_SAFE" --argjson gui "$R2_GUI_ABSENT" \
		--argjson helpers "$R2_HELPERS_ABSENT" --argjson native "$R2_NATIVE_ABSENT" \
		--argjson cliAbsent "$R2_CLI_ABSENT" --argjson inactive "$R2_LAUNCHD_INACTIVE" \
		--argjson runs "$R2_LAUNCHD_RUNS" --argjson cliReady "$R2_CLI_READY" \
		--argjson dependencies "$R2_DEPENDENCIES_READY" \
		--argjson manifestExact "$R2_MANIFEST_EXACT" \
		--argjson reviewComplete "$R2_MANIFEST_REVIEW_COMPLETE" \
		--arg manifest "$R2_CANDIDATE_MANIFEST_SHA256" \
		'{schemaVersion:1,evidenceClass:"r2_portal_cold_preflight",safeToLogin:$safe,loginStarted:false,networkSnapshotTaken:false,cold:{guiAbsent:$gui,vendorHelpersAbsent:$helpers,nativeCharonAbsent:$native,portalCLIAbsent:$cliAbsent,helperLaunchdInactive:$inactive,helperLaunchdRuns:$runs},cliReady:$cliReady,dependenciesReady:$dependencies,manifestExact:$manifestExact,manifestReviewComplete:$reviewComplete,candidateManifestSHA256:(if $manifest=="" then null else $manifest end),containsSecrets:false}'
}

r2_prepare_scratch_root() {
	[ -d "$HOME/scratch-data" ] && [ ! -L "$HOME/scratch-data" ] || return 1
	if [ ! -e "$R2_SCRATCH_ROOT" ]; then
		(umask 077; mkdir "$R2_SCRATCH_ROOT") || return 1
	fi
	[ -d "$R2_SCRATCH_ROOT" ] && [ ! -L "$R2_SCRATCH_ROOT" ] &&
		[ "$(/usr/bin/stat -f '%u:%Lp' "$R2_SCRATCH_ROOT")" = "$(id -u):700" ]
}
r2_create_sentinel() {
	[ ! -e "$1" ] && [ ! -L "$1" ] || return 1
	(set -C; umask 077; : >"$1") || return 1
	chmod 600 "$1"
}
r2_capture_network() {
	[ ! -e "$1" ] && [ ! -L "$1" ] || return 1
	(umask 077; POWERVPN_STRONGSWAN_ROOT="$HOME/scratch-data/powervpn-strongswan" \
		"$R2_SNAPSHOT" >"$1") || return 1
	chmod 600 "$1"
}
r2_network_stable() {
	jq -e --slurpfile before "$1" '
    ($before | length) == 1 and .schemaVersion == 1 and
    (. | del(.timestamp)) == ($before[0] | del(.timestamp)) and
    .powerVPNProcessCount == 0 and .nativeCharonPids == [] and
    .productionIKEPortsBoundByNative == false and .containsSecrets == false and
    .containsRawRoutes == false and .containsRawSAState == false
  ' "$2" >/dev/null
}

r2_summarize_lsof() {
	awk -v endpoint="$R2_PORTAL_ENDPOINT" '
    BEGIN { only=1 }
    /^P/ { protocol=substr($0,2); next }
    /^n/ {
      name=substr($0,2)
      if (protocol == "TCP") {
        tcp++; suffix="->" endpoint
		if (length(name) < length(suffix) || substr(name,length(name)-length(suffix)+1) != suffix) only=0
      } else if (protocol == "UDP") { udp++; only=0 }
      else { only=0 }
    }
    END { printf "%d\t%d\t%s\n", tcp+0, udp+0, only ? "true" : "false" }
  '
}
r2_lsof_summary() {
	set +e
	fd_output=$(/usr/sbin/lsof -nP -a -p "$1" -iTCP -iUDP -F Pn 2>/dev/null)
	fd_rc=$?
	set -e
	if [ "$fd_rc" -eq 1 ] && [ -z "$fd_output" ]; then
		printf '0\t0\ttrue\n'
		return 0
	fi
	[ "$fd_rc" -eq 0 ] || return 1
	printf '%s\n' "$fd_output" | r2_summarize_lsof
}
r2_monitor_portal() (
	target_pid=$1; ready_file=$2; stop_file=$3; output_file=$4
	seen=false; inspected=false; failed=false; only=true; portal=false
	max_tcp=0; max_udp=0; helper_seen=false; native_seen=false
	r2_create_sentinel "$ready_file" || exit 1
	while [ ! -e "$stop_file" ]; do
		if /bin/ps -p "$target_pid" -o pid= 2>/dev/null | grep -q '[0-9]'; then
			seen=true
			if summary=$(r2_lsof_summary "$target_pid"); then
				# The tab-delimited summary is generated internally from integer/boolean tokens.
				old_ifs=$IFS; IFS=$(printf '\t'); set -- $summary; IFS=$old_ifs
				[ "$#" -eq 3 ] || failed=true
				if [ "$#" -eq 3 ]; then
					inspected=true; [ "$1" -le "$max_tcp" ] || max_tcp=$1
					[ "$2" -le "$max_udp" ] || max_udp=$2
					[ "$1" -eq 0 ] || portal=true; [ "$3" = true ] || only=false
				fi
			elif /bin/ps -p "$target_pid" -o pid= 2>/dev/null | grep -q '[0-9]'; then failed=true
			fi
		fi
		r2_helpers_absent || helper_seen=true
		r2_native_charon_absent || native_seen=true
		sleep 0.01
	done
	inspection=false
	[ "$seen" = true ] && [ "$inspected" = true ] && [ "$failed" = false ] && inspection=true
	jq -n --argjson seen "$seen" --argjson inspected "$inspection" --argjson only "$only" \
		--argjson portal "$portal" --argjson tcp "$max_tcp" --argjson udp "$max_udp" \
		--argjson helper "$helper_seen" --argjson native "$native_seen" \
		'{targetObserved:$seen,inspectionSucceeded:$inspected,onlySealedPortalTCP:$only,portalTCPObserved:$portal,maximumTCPCount:$tcp,maximumUDPCount:$udp,vendorHelperObserved:$helper,nativeCharonObserved:$native}' >"$output_file"
	chmod 600 "$output_file"
)

r2_reconstruct_report() {
	input_fifo=$1; output_file=$2; safe_stage="$output_file.safe.$$"
	[ -p "$input_fifo" ] && [ ! -e "$output_file" ] && [ ! -L "$output_file" ] || return 1
	jq -ce '
    if keys == ["mode","operations","ownedMaterial","safety","schemaVersion","status","transactionAccepted"] and
      .schemaVersion == 1 and .mode == "r2_username_password_portal_login" and
      (.status | IN("accepted","configuration_rejected","credential_input_rejected","transport_rejected","tls_rejected","redirect_rejected","login_rejected","challenge_required","login_response_rejected","session_rejected","resource_list_rejected","logout_rejected","cancelled","internal_failure")) and
      (.operations | keys) == ["loginAccepted","loginRequested","logoutAccepted","logoutRequested","resourceListAccepted","resourceListRequested","sessionCheckAccepted","sessionCheckRequested"] and all(.operations[]; type == "boolean") and
      (.ownedMaterial | keys) == ["credentialsErased","requestBodiesErased","responseBodiesErased","sessionMaterialErased"] and all(.ownedMaterial[]; type == "boolean") and
      .safety == {appOwnedSecureBuffersErasureObserved:true,credentialInArguments:false,credentialInEnvironment:false,credentialSource:"controlling_tty_no_echo",credentialWrittenToFile:false,endpointSource:"sealed_installed_configuration",endpointValueRetainedInEvidence:false,helperMutationRequested:false,ikeTrafficRequested:false,platformSerialValueRetainedInEvidence:false,portalHTTPSAllowed:true,rawRequestRetainedInEvidence:false,rawResponseRetainedInEvidence:false,redirectsAllowed:false,resourceValueRetainedInEvidence:false,sessionValueRetainedInEvidence:false,swiftAndFoundationBridgeCopiesErasureClaimed:false,systemTrustRequired:true,viciUsed:false,xpcUsed:false} and
      (.transactionAccepted | type) == "boolean"
    then {schemaVersion,mode,status,operations,ownedMaterial,safety,transactionAccepted}
    else error("closed portal report schema rejected") end
  ' <"$input_fifo" >"$safe_stage" 2>/dev/null || { rm -f "$safe_stage"; return 1; }
	chmod 600 "$safe_stage"
	jq -cse 'if length == 1 then .[0] else error("single report required") end' \
		"$safe_stage" >"$output_file" 2>/dev/null || { rm -f "$safe_stage" "$output_file"; return 1; }
	chmod 600 "$output_file"; rm -f "$safe_stage"
}
