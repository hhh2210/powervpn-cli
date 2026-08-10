#!/bin/sh
# Shared value-free gates for the credential-free R2 TLS peer-evidence runner.
# The caller must set R2TLS_REPO_ROOT before sourcing this file.
# shellcheck disable=SC2034
R2TLS_CLI="$R2TLS_REPO_ROOT/.build/debug/powervpn-tls-evidence"
R2TLS_MANIFEST="$R2TLS_REPO_ROOT/fixtures/redacted/r2-tls-evidence-reviewed-manifest-v1.json"
R2TLS_PARENT_MANIFEST="$R2TLS_REPO_ROOT/fixtures/redacted/r2-tls-evidence-parent-r2-manifest-v1.json"
R2TLS_ATTEMPT1_MANIFEST="$R2TLS_REPO_ROOT/fixtures/redacted/r2-tls-evidence-authorized-manifest-v1.json"
R2TLS_ATTEMPT1_RESULT="$R2TLS_REPO_ROOT/fixtures/redacted/r2-tls-peer-runtime-v1.json"
R2TLS_ATTEMPT2_MANIFEST="$R2TLS_REPO_ROOT/fixtures/redacted/r2-tls-evidence-attempt2-authorized-manifest-v1.json"
R2TLS_ATTEMPT2_RESULT="$R2TLS_REPO_ROOT/fixtures/redacted/r2-tls-peer-runtime-attempt2-v1.json"
R2TLS_SNAPSHOT="$R2TLS_REPO_ROOT/scripts/snapshot_network_state.sh"
R2TLS_SCRATCH_ROOT="$HOME/scratch-data/powervpn-r2-tls-evidence"
R2TLS_ENDPOINT=166.111.143.19:4443
R2TLS_EXPECTED_LAUNCHD_RUNS=19
R2TLS_CP7A_CHARON="$HOME/scratch-data/powervpn-strongswan/install-6.0.7-cp7a-arm64/libexec/ipsec/charon"
R2TLS_CP7B_CHARON="$HOME/scratch-data/powervpn-strongswan/runtime-6.0.7-cp7b/closure/libexec/ipsec/charon"

r2tls_hash_file() { /usr/bin/shasum -a 256 "$1" | awk '{print $1}'; }

r2tls_process_absent() {
	if /usr/bin/pgrep -x "$1" >/dev/null 2>&1; then return 1; else [ "$?" -eq 1 ]; fi
}
r2tls_command_absent() {
	/bin/ps -axo command= | awk -v executable="$1" '
    { sub(/^[[:space:]]*/, "") }
    $0 == executable || index($0, executable " ") == 1 { found=1 }
    END { exit found }
  '
}
r2tls_helpers_absent() {
	r2tls_process_absent com.leadsec.charon-xpc &&
		r2tls_process_absent com.leadsec.ipsec-xpc &&
		r2tls_process_absent com.leadsec.sh-xpc
}
r2tls_native_absent() {
	r2tls_process_absent charon && r2tls_command_absent "$R2TLS_CP7A_CHARON" &&
		r2tls_command_absent "$R2TLS_CP7B_CHARON"
}
r2tls_cli_absent() { r2tls_command_absent "$R2TLS_CLI"; }
r2tls_launchd_runs() {
	/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null |
		awk '$1=="runs" && $2=="=" && $3~/^[0-9]+$/ {n++;v=$3}
      END {if(n==1) print v; else exit 1}'
}
r2tls_launchd_inactive() {
	text=$(/bin/launchctl print system/com.leadsec.charon-xpc 2>/dev/null) || return 1
	printf '%s\n' "$text" | grep -qx '[[:space:]]*active count = 0' || return 1
	printf '%s\n' "$text" | grep -qx '[[:space:]]*state = not running' || return 1
	! printf '%s\n' "$text" | grep -q '^[[:space:]]pid = '
}
r2tls_cli_ready() {
	[ -f "$R2TLS_CLI" ] && [ -x "$R2TLS_CLI" ] && [ ! -L "$R2TLS_CLI" ] &&
		[ "$(/usr/bin/lipo -archs "$R2TLS_CLI")" = arm64 ]
}
r2tls_cold_preflight() {
	R2TLS_GUI_ABSENT=false; R2TLS_HELPERS_ABSENT=false; R2TLS_NATIVE_ABSENT=false
	R2TLS_CLI_ABSENT=false; R2TLS_LAUNCHD_EXACT=false; R2TLS_CLI_READY=false
	R2TLS_DEPENDENCIES_READY=false; R2TLS_MANIFEST_EXACT=false
	R2TLS_PREDECESSOR_READY=false
	R2TLS_REVIEW_COMPLETE=false; R2TLS_CANDIDATE_MANIFEST_SHA256=
	R2TLS_LAUNCHD_RUNS=-1
	r2tls_process_absent PowerVPN && R2TLS_GUI_ABSENT=true
	r2tls_helpers_absent && R2TLS_HELPERS_ABSENT=true
	r2tls_native_absent && R2TLS_NATIVE_ABSENT=true
	r2tls_cli_absent && R2TLS_CLI_ABSENT=true
	R2TLS_LAUNCHD_RUNS=$(r2tls_launchd_runs) || R2TLS_LAUNCHD_RUNS=-1
	r2tls_launchd_inactive && [ "$R2TLS_LAUNCHD_RUNS" -eq "$R2TLS_EXPECTED_LAUNCHD_RUNS" ] &&
		R2TLS_LAUNCHD_EXACT=true
	r2tls_cli_ready && R2TLS_CLI_READY=true
	r2tls_candidate_manifest_exact && R2TLS_MANIFEST_EXACT=true
	command -v r2tls_attempt3_predecessor_exact >/dev/null 2>&1 &&
		r2tls_attempt3_predecessor_exact "$R2TLS_SCRATCH_ROOT" &&
		R2TLS_PREDECESSOR_READY=true
	command -v jq >/dev/null && [ -x /usr/sbin/lsof ] && [ -x /usr/bin/perl ] &&
		r2tls_monotonic_milliseconds >/dev/null && [ -x "$R2TLS_SNAPSHOT" ] &&
		R2TLS_DEPENDENCIES_READY=true
	R2TLS_PREFLIGHT_SAFE=false
	[ "$R2TLS_GUI_ABSENT" = true ] && [ "$R2TLS_HELPERS_ABSENT" = true ] &&
		[ "$R2TLS_NATIVE_ABSENT" = true ] && [ "$R2TLS_CLI_ABSENT" = true ] &&
		[ "$R2TLS_LAUNCHD_EXACT" = true ] && [ "$R2TLS_CLI_READY" = true ] &&
		[ "$R2TLS_DEPENDENCIES_READY" = true ] && [ "$R2TLS_MANIFEST_EXACT" = true ] &&
		[ "$R2TLS_PREDECESSOR_READY" = true ] &&
		[ "$R2TLS_REVIEW_COMPLETE" = true ] && R2TLS_PREFLIGHT_SAFE=true
	return 0
}
r2tls_preflight_json() {
	jq -n --argjson safe "$R2TLS_PREFLIGHT_SAFE" --argjson gui "$R2TLS_GUI_ABSENT" \
		--argjson helpers "$R2TLS_HELPERS_ABSENT" --argjson native "$R2TLS_NATIVE_ABSENT" \
		--argjson cliAbsent "$R2TLS_CLI_ABSENT" --argjson launchd "$R2TLS_LAUNCHD_EXACT" \
		--argjson runs "$R2TLS_LAUNCHD_RUNS" --argjson cliReady "$R2TLS_CLI_READY" \
		--argjson dependencies "$R2TLS_DEPENDENCIES_READY" \
		--argjson predecessor "$R2TLS_PREDECESSOR_READY" \
		--argjson exact "$R2TLS_MANIFEST_EXACT" --argjson reviewed "$R2TLS_REVIEW_COMPLETE" \
		--arg manifest "$R2TLS_CANDIDATE_MANIFEST_SHA256" \
		'{schemaVersion:1,evidenceClass:"r2_tls_peer_cold_preflight",safeToObserve:$safe,
      networkStarted:false,cold:{guiAbsent:$gui,vendorHelpersAbsent:$helpers,
      nativeCharonAbsent:$native,evidenceCLIAbsent:$cliAbsent,
      helperLaunchdInactiveAndExactRuns:$launchd,helperLaunchdRuns:$runs},
      cliReady:$cliReady,dependenciesReady:$dependencies,manifestExact:$exact,
      predecessorReady:$predecessor,
      manifestReviewComplete:$reviewed,candidateManifestSHA256:
      (if $manifest=="" then null else $manifest end),containsSecrets:false}'
}
r2tls_prepare_scratch_root() {
	[ -d "$HOME/scratch-data" ] && [ ! -L "$HOME/scratch-data" ] || return 1
	[ -e "$R2TLS_SCRATCH_ROOT" ] || (umask 077; mkdir "$R2TLS_SCRATCH_ROOT") || return 1
	[ -d "$R2TLS_SCRATCH_ROOT" ] && [ ! -L "$R2TLS_SCRATCH_ROOT" ] &&
		[ "$(stat -f '%u:%Lp' "$R2TLS_SCRATCH_ROOT")" = "$(id -u):700" ]
}
r2tls_create_sentinel() {
	[ ! -e "$1" ] && [ ! -L "$1" ] || return 1
	(set -C; umask 077; : >"$1") || return 1
	chmod 600 "$1"
}
r2tls_capture_network() {
	[ ! -e "$1" ] && [ ! -L "$1" ] || return 1
	(umask 077; POWERVPN_STRONGSWAN_ROOT="$HOME/scratch-data/powervpn-strongswan" \
		"$R2TLS_SNAPSHOT" >"$1") || return 1
	chmod 600 "$1"
}
r2tls_network_projection_stable() {
	jq -e --slurpfile before "$1" '
    ($before|length)==1 and .schemaVersion==1 and
    (. | del(.timestamp,.ipv4RouteSHA256)) ==
      ($before[0] | del(.timestamp,.ipv4RouteSHA256)) and
    .powerVPNProcessCount==0 and .nativeCharonPids==[] and
    .productionIKEPortsBoundByNative==false and
    .containsSecrets==false and .containsRawRoutes==false and
    .containsRawSAState==false
  ' "$2" >/dev/null
}
r2tls_filter_report() {
	input_file=$1; output_file=$2
	{ [ -f "$input_file" ] || [ -p "$input_file" ]; } && [ ! -L "$input_file" ] &&
		[ ! -e "$output_file" ] && [ ! -L "$output_file" ] || return 1
	jq -ce '
	    def hex: type=="string" and test("^[0-9a-f]{64}$");
	    def cat: IN("accepted","hostname_mismatch","expired","not_yet_valid",
	      "revoked","untrusted_chain","other_failure","unavailable");
	    def ep: .evidenceProgress as $e |
	      ($e|keys)==["basicEvaluationCompleted","basicEvaluationStarted","duplicateVerifyCallbackObserved",
	        "evaluationDeadlineExpired","metadataChainAccessAttempted","metadataChainAccessible","peerDERCopyCompleted",
	        "sslEvaluationCompleted","sslEvaluationStarted","transportEvidenceComplete","trustEvidenceComplete",
	        "verifyCompletionInvokedWithFalse","verifyCompletionReturned"] and
	      ([$e[]]|all(type=="boolean")) and
	      ([ (($e.metadataChainAccessible|not) or $e.metadataChainAccessAttempted),
	         (($e.peerDERCopyCompleted|not) or $e.metadataChainAccessible),
	         (($e.verifyCompletionReturned|not) or $e.verifyCompletionInvokedWithFalse),
	         (($e.sslEvaluationStarted|not) or ($e.peerDERCopyCompleted and $e.verifyCompletionReturned)),
	         (($e.basicEvaluationStarted|not) or ($e.peerDERCopyCompleted and $e.verifyCompletionReturned)),
	         (($e.sslEvaluationCompleted|not) or $e.sslEvaluationStarted),
	         (($e.basicEvaluationCompleted|not) or $e.basicEvaluationStarted),
	         (($e.evaluationDeadlineExpired|not) or ($e.sslEvaluationStarted or $e.basicEvaluationStarted)) ]|all) and
	      $e.transportEvidenceComplete==($e.metadataChainAccessible and $e.peerDERCopyCompleted and $e.verifyCompletionReturned and ($e.duplicateVerifyCallbackObserved|not)) and
	      $e.trustEvidenceComplete==($e.peerDERCopyCompleted and $e.sslEvaluationCompleted and $e.basicEvaluationCompleted and ($e.evaluationDeadlineExpired|not) and ($e.duplicateVerifyCallbackObserved|not));
	    . as $report | if (keys == ["applicationDataSent","basicTrustAccepted","basicTrustCategory",
	      "chainLength","containsIssuer","containsRawCertificate","containsSAN","containsSecrets",
	      "containsSerial","containsSubject","evidenceClass","evidenceProgress",
	      "leafCertificateSHA256","leafSPKISHA256","orderedCertificateSHA256",
	      "schemaVersion","sslTrustAccepted","sslTrustCategory","status","transportProgress",
	      "verifyAccepted"] and .schemaVersion==3 and
	    .evidenceClass=="r2_tls_peer_value_free" and
    (.status|IN("observed","timed_out","cancelled","unavailable","invalid_evidence")) and
    (.chainLength|type)=="number" and (.chainLength|floor)==.chainLength and
    (.orderedCertificateSHA256|type)=="array" and
    (.sslTrustAccepted|type)=="boolean" and (.basicTrustAccepted|type)=="boolean" and
    (.sslTrustCategory|cat) and (.basicTrustCategory|cat) and
    .applicationDataSent==false and .verifyAccepted==false and
    .containsRawCertificate==false and .containsSubject==false and
    .containsIssuer==false and .containsSAN==false and .containsSerial==false and
	    .containsSecrets==false and ep and (.transportProgress|keys)==[
      "connectionStarted","failedObserved","preparingObserved","readyObserved",
      "verifyCallbackObserved","waitingObserved"] and
    all(.transportProgress[];type=="boolean") and
	    (((.evidenceProgress.metadataChainAccessAttempted or
	      .evidenceProgress.duplicateVerifyCallbackObserved)|not) or
	      .transportProgress.verifyCallbackObserved) and
    ((.transportProgress.readyObserved and .transportProgress.failedObserved)|not) and
    (.transportProgress.connectionStarted or
      ([.transportProgress.preparingObserved,.transportProgress.waitingObserved,
        .transportProgress.verifyCallbackObserved,.transportProgress.failedObserved,
        .transportProgress.readyObserved]|all(.==false))) and
	    (if .status=="observed" then .chainLength>=1 and .chainLength<=16 and
      .chainLength==(.orderedCertificateSHA256|length) and
      all(.orderedCertificateSHA256[];hex) and (.leafCertificateSHA256|hex) and
      .leafCertificateSHA256==.orderedCertificateSHA256[0] and
      (.leafSPKISHA256|hex) and
      (.sslTrustAccepted==(.sslTrustCategory=="accepted")) and
      (.basicTrustAccepted==(.basicTrustCategory=="accepted")) and
	      .transportProgress.verifyCallbackObserved and (.transportProgress.readyObserved|not) and
	      .evidenceProgress.transportEvidenceComplete and .evidenceProgress.trustEvidenceComplete
	    else (.evidenceProgress.trustEvidenceComplete|not) and
	      .chainLength==0 and .orderedCertificateSHA256==[] and
      .leafCertificateSHA256==null and .leafSPKISHA256==null and
      .sslTrustAccepted==false and .sslTrustCategory=="unavailable" and
      .basicTrustAccepted==false and .basicTrustCategory=="unavailable" and
      ((.transportProgress.readyObserved|not) or .status=="invalid_evidence") end))
    then $report else error("closed TLS evidence report rejected") end
  ' <"$input_file" >"$output_file" 2>/dev/null || { rm -f "$output_file"; return 1; }
	chmod 600 "$output_file"
}
r2tls_reconstruct_report() {
	[ -p "$1" ] || return 1
	r2tls_filter_report "$1" "$2"
}
r2tls_monotonic_milliseconds() {
	/usr/bin/perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC \
		-e 'print int(clock_gettime(CLOCK_MONOTONIC)*1000),qq(\n)'
}
r2tls_deadline_open() {
	[ -n "${R2TLS_DEADLINE_FILE:-}" ] && [ ! -e "$R2TLS_DEADLINE_FILE" ]
}
r2tls_deadline_guard() {
	case "$5" in '' | *[!0-9]*) return 1 ;; esac
	case "$6" in '' | *[!0-9]*) return 1 ;; esac
	exec /usr/bin/perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC \
		-MFcntl=:DEFAULT -e '
	    my ($ready,$expired,$stop,$ack,$milliseconds,$runner)=@ARGV;
	    my $stopping=0; my $stop_status=0;
	    $SIG{TERM}=sub {
	      return unless -f $stop;
	      my $ack_fh;
	      if (!sysopen($ack_fh,$ack,O_WRONLY|O_CREAT|O_EXCL,0600)) {
	        $stopping=1; $stop_status=72; return;
	      }
	      my $ack_value="$$\n";
	      $stop_status=73 if syswrite($ack_fh,$ack_value)!=length($ack_value);
	      $stop_status=74 if !close($ack_fh) && !$stop_status;
	      $stopping=1;
	    };
	    my $deadline=clock_gettime(CLOCK_MONOTONIC)+($milliseconds/1000);
    sysopen(my $ready_fh,$ready,O_WRONLY|O_CREAT|O_EXCL,0600) or die "ready";
    close($ready_fh) or die "ready-close";
	    while (!$stopping && (my $remaining=$deadline-clock_gettime(CLOCK_MONOTONIC))>0) {
	      select(undef,undef,undef,$remaining);
	    }
	    exit $stop_status if $stopping;
    sysopen(my $expired_fh,$expired,O_WRONLY|O_CREAT|O_EXCL,0600) or die "expired";
    close($expired_fh) or die "expired-close";
    kill(15,$runner) or die "signal";
	  ' "$1" "$2" "$3" "$4" "$5" "$6"
}
r2tls_runner_owned_process_alive() {
	/bin/ps -p "$1" -o ppid= -o state= 2>/dev/null |
		awk -v parent="$2" '$1==parent && $2!~/^Z/ {seen=1} END {exit !seen}'
}
r2tls_runner_wait_owned_process() {
	wait_pid=$1; wait_limit=$2; wait_attempt=0
	while r2tls_runner_owned_process_alive "$wait_pid" "$$" &&
		[ "$wait_attempt" -lt "$wait_limit" ] && r2tls_deadline_open; do
		wait_attempt=$((wait_attempt + 1)); sleep 0.01
	done
	! r2tls_runner_owned_process_alive "$wait_pid" "$$"
}
r2tls_runner_force_stop_owned() {
	force_pid=$1; force_grace=$2
	r2tls_runner_owned_process_alive "$force_pid" "$$" || return 0
	/bin/kill -TERM "$force_pid" 2>/dev/null || true
	if ! r2tls_runner_wait_owned_process "$force_pid" "$force_grace"; then
		/bin/kill -KILL "$force_pid" 2>/dev/null || true; harness_kill=true
		force_attempt=0
		while r2tls_runner_owned_process_alive "$force_pid" "$$" &&
			[ "$force_attempt" -lt 10 ]; do
			force_attempt=$((force_attempt + 1)); sleep 0.01
		done
		! r2tls_runner_owned_process_alive "$force_pid" "$$" || return 1
	fi
}
