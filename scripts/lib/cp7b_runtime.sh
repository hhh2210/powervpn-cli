#!/bin/sh

pvn_cp7b_init_paths() {
	repo_root=$1
	PVN_CP7B_SCRATCH_ROOT=/Users/larry_1/scratch-data/powervpn-strongswan
	PVN_CP7B_SOURCE="$PVN_CP7B_SCRATCH_ROOT/strongswan-6.0.7-cp7b"
	PVN_CP7B_BUILD="$PVN_CP7B_SCRATCH_ROOT/build-6.0.7-cp7b-arm64"
	PVN_CP7B_COMPILED_PIDDIR="$PVN_CP7B_SCRATCH_ROOT/runtime-6.0.7-cp7b"
	PVN_CP7B_RUNTIME_ROOT=$PVN_CP7B_COMPILED_PIDDIR
	PVN_CP7B_PREFIX="$PVN_CP7B_RUNTIME_ROOT/closure"
	if [ "${POWERVPN_CP7B_TEST_MODE:-0}" = 1 ]; then
		[ "$(id -u)" -ne 0 ] || pvn_fail "CP7B test overrides are forbidden as root" || return 1
		PVN_CP7B_RUNTIME_ROOT=${POWERVPN_CP7B_RUNTIME_ROOT:-"$PVN_CP7B_RUNTIME_ROOT"}
	fi
	PVN_CP7B_BINARY="$PVN_CP7B_PREFIX/libexec/ipsec/charon"
	PVN_CP7B_SWANCTL="$PVN_CP7B_PREFIX/sbin/swanctl"
	PVN_CP7B_LIBSTRONGSWAN="$PVN_CP7B_PREFIX/lib/ipsec/libstrongswan.0.dylib"
	PVN_CP7B_LIBCHARON="$PVN_CP7B_PREFIX/lib/ipsec/libcharon.0.dylib"
	PVN_CP7B_OPENSSL_PLUGIN="$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-openssl.so"
	PVN_CP7B_NONCE_PLUGIN="$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-nonce.so"
	PVN_CP7B_LIBCRYPTO="$PVN_CP7B_PREFIX/lib/private/libcrypto.3.dylib"
	PVN_CP7B_LAUNCHER="$PVN_CP7B_PREFIX/libexec/ipsec/cp7b-gated-launcher"
	PVN_CP7B_PYTHON_ROOT="$PVN_CP7B_SOURCE/src/libcharon/plugins/vici/python"
	PVN_CP7B_RUNTIME_SCRIPT="$repo_root/scripts/lib/cp7b_runtime.sh"
	PVN_CP7B_CLOSURE_SCRIPT="$repo_root/scripts/lib/cp7b_closure.sh"
	PVN_CP7B_STATE_SCRIPT="$repo_root/scripts/lib/cp7b_state.sh"
	PVN_CP7B_ATTEMPTS_SCRIPT="$repo_root/scripts/lib/cp7b_attempts.sh"
	PVN_CP7B_SNAPSHOT_SCRIPT="$repo_root/scripts/lib/cp7b_snapshot.sh"
	PVN_CP7B_BUNDLE_SCRIPT="$repo_root/scripts/lib/cp7b_bundle.sh"
	PVN_CP7B_NATIVE_SCRIPT="$repo_root/scripts/lib/native_charon_runtime.sh"
	PVN_CP7B_NETWORK_SCRIPT="$repo_root/scripts/lib/network_snapshot.sh"
	PVN_CP7B_WORKER="$repo_root/scripts/libexec/cp7b_backend_window.sh"
	PVN_CP7B_ROOT_ENTRY="$repo_root/scripts/libexec/cp7b_root_entry.sh"
	PVN_CP7B_EMERGENCY_SOURCE="$repo_root/scripts/libexec/cp7b_emergency_stop.sh"
	PVN_CP7B_AUTHORIZER="$repo_root/scripts/libexec/authorize_cp7b.applescript"
	PVN_CP7B_ORACLE="$repo_root/scripts/verify/official_vici_runtime.py"
	PVN_CP7B_READONLY_PROBE="$repo_root/scripts/libexec/cp7b_vici_readonly.py"
	PVN_CP7B_MANIFEST="$repo_root/fixtures/redacted/cp7b-approval-manifest-v1.json"
	PVN_CP7B_PY_INIT="$PVN_CP7B_PYTHON_ROOT/vici/__init__.py"
	PVN_CP7B_PY_COMMAND_WRAPPERS="$PVN_CP7B_PYTHON_ROOT/vici/command_wrappers.py"
	PVN_CP7B_PY_EVENT_LISTENER="$PVN_CP7B_PYTHON_ROOT/vici/event_listener.py"
	PVN_CP7B_PY_EXCEPTION="$PVN_CP7B_PYTHON_ROOT/vici/exception.py"
	PVN_CP7B_PY_PROTOCOL="$PVN_CP7B_PYTHON_ROOT/vici/protocol.py"
	PVN_CP7B_PY_SESSION="$PVN_CP7B_PYTHON_ROOT/vici/session.py"
	PVN_CP7B_REVIEWED_INPUT_OWNER=502
	PVN_CP7B_ARTIFACT_OWNER=502
	PVN_CP7B_EXPECTED_SOURCE_COMMIT=a81298234753f314dbf2c4f2867a9a144006bd8c
	PVN_CP7B_STATE_FILE="$PVN_CP7B_RUNTIME_ROOT/current.state"
	PVN_CP7B_PID_FILE="$PVN_CP7B_RUNTIME_ROOT/charon.pid"
	PVN_CP7B_SOCKET="$PVN_CP7B_RUNTIME_ROOT/charon.vici"
	PVN_CP7B_LEDGER="$PVN_CP7B_RUNTIME_ROOT/pfkey-attempt-ledger"

	PVN_SCRATCH_ROOT=$PVN_CP7B_SCRATCH_ROOT
	PVN_PREFIX=$PVN_CP7B_PREFIX
	PVN_SOURCE=$PVN_CP7B_SOURCE
	PVN_BINARY=$PVN_CP7B_BINARY
	PVN_RUNTIME_ROOT=$PVN_CP7B_RUNTIME_ROOT
	PVN_STATE_FILE=$PVN_CP7B_STATE_FILE
	PVN_PID_FILE=$PVN_CP7B_PID_FILE
	export PVN_CP7B_SCRATCH_ROOT PVN_CP7B_PREFIX PVN_CP7B_SOURCE PVN_CP7B_BUILD
	export PVN_CP7B_COMPILED_PIDDIR PVN_CP7B_RUNTIME_ROOT PVN_CP7B_BINARY PVN_CP7B_SWANCTL
	export PVN_CP7B_LIBSTRONGSWAN PVN_CP7B_LIBCHARON PVN_CP7B_OPENSSL_PLUGIN
	export PVN_CP7B_NONCE_PLUGIN PVN_CP7B_LIBCRYPTO PVN_CP7B_LAUNCHER
	export PVN_CP7B_PYTHON_ROOT PVN_CP7B_RUNTIME_SCRIPT PVN_CP7B_CLOSURE_SCRIPT
	export PVN_CP7B_STATE_SCRIPT
	export PVN_CP7B_ATTEMPTS_SCRIPT PVN_CP7B_SNAPSHOT_SCRIPT PVN_CP7B_BUNDLE_SCRIPT
	export PVN_CP7B_NATIVE_SCRIPT
	export PVN_CP7B_NETWORK_SCRIPT PVN_CP7B_WORKER PVN_CP7B_ROOT_ENTRY
	export PVN_CP7B_EMERGENCY_SOURCE PVN_CP7B_AUTHORIZER PVN_CP7B_ORACLE
	export PVN_CP7B_READONLY_PROBE
	export PVN_CP7B_MANIFEST PVN_CP7B_PY_INIT PVN_CP7B_PY_COMMAND_WRAPPERS
	export PVN_CP7B_PY_EVENT_LISTENER PVN_CP7B_PY_EXCEPTION PVN_CP7B_PY_PROTOCOL
	export PVN_CP7B_PY_SESSION PVN_CP7B_REVIEWED_INPUT_OWNER PVN_CP7B_ARTIFACT_OWNER
	export PVN_CP7B_EXPECTED_SOURCE_COMMIT PVN_CP7B_STATE_FILE
	export PVN_CP7B_PID_FILE PVN_CP7B_SOCKET PVN_CP7B_LEDGER
	export PVN_SCRATCH_ROOT PVN_PREFIX PVN_SOURCE PVN_BINARY PVN_RUNTIME_ROOT
	export PVN_STATE_FILE PVN_PID_FILE
}

pvn_cp7b_render_config() {
	socket_path=$1
	pvn_validate_unix_socket_path "$socket_path" || return 1
	printf '%s\n' \
		'charon {' \
		'    load_modular = no' \
		'    load = openssl! nonce! kernel-pfkey! kernel-pfroute! socket-dynamic! vici!' \
		'    threads = 5' \
		'    port = 0' \
		'    port_nat_t = 0' \
		'    install_routes = no' \
		'    install_virtual_ip = no' \
		'    interfaces_use = lo0' \
		'    initiator_only = yes' \
		'    plugins {' \
		'        vici {' \
		"            socket = unix://$socket_path" \
		'        }' \
		'    }' \
		'}'
}

pvn_cp7b_config_sha256() {
	pvn_cp7b_render_config "$PVN_CP7B_SOCKET" | pvn_hash_stdin
}

pvn_cp7b_require_safe_file() {
	file=$1
	expected_owner=${2:-$PVN_CP7B_REVIEWED_INPUT_OWNER}
	[ -f "$file" ] && [ ! -L "$file" ] ||
		pvn_fail "reviewed CP7B input is missing or a symlink: $file" || return 1
	[ "$(stat -f '%u' "$file")" -eq "$expected_owner" ] ||
		pvn_fail "reviewed CP7B input owner changed: $file" || return 1
	mode=$(stat -f '%Lp' "$file")
	case "$mode" in
	*2 | *3 | *6 | *7 | ?[2367]?)
		pvn_fail "reviewed CP7B input is group/world writable: $file" || return 1
		;;
	esac
}

pvn_cp7b_verify_manifest_policy() {
	pvn_cp7b_require_safe_file "$PVN_CP7B_MANIFEST" || return 1
	jq -e '
      keys == [
        "approval", "artifacts", "backend", "containsRawRoutes",
        "containsReplayableCapture", "containsSecrets", "fixtureClass",
        "review", "safety", "schemaVersion", "source", "window"
      ] and
      .schemaVersion == 1 and
      .fixtureClass == "cp7b_privileged_backend_approval_manifest" and
      .source == "static_preflight_and_scratch_build" and
      .backend == {
        ipsec: "kernel-pfkey",
        network: "kernel-pfroute",
        socket: "socket-dynamic"
      } and
      .approval.preflightAuthorized == true and
      .approval.privilegedExecutionAuthorized == false and
      .review.state == "passed_integrated_preflight_review" and
      .window.maxLaunches == 2 and .window.maxDurationSeconds == 300 and
      .safety.udpSocketExpectedCount == 0 and
      .safety.serverTraffic == false and .safety.credentials == false and
      .safety.initiate == false and .safety.installRoutes == false and
	      .safety.installVirtualIP == false and .safety.keepPowerVPNRunning == true and
	      .safety.keepSurgeRunning == true and .safety.nativeTouchID == true and
	      .safety.rootOwnedExecutionClosure == true and
	      .safety.samePIDGatedExec == true and .safety.fullWindowDeadline == true and
	      .safety.failClosedObservation == true and .safety.resultBoundToManifest == true and
	      .containsSecrets == false and .containsReplayableCapture == false and
      .containsRawRoutes == false
    ' "$PVN_CP7B_MANIFEST" >/dev/null ||
		pvn_fail "CP7B approval manifest schema or safety policy is invalid" || return 1

	[ "$(jq -r '.artifacts.sourceCommit' "$PVN_CP7B_MANIFEST")" = \
		"$PVN_CP7B_EXPECTED_SOURCE_COMMIT" ] ||
		pvn_fail "CP7B source commit is not the reviewed commit" || return 1
	[ "$(pvn_cp7b_config_sha256)" = \
		"$(jq -r '.artifacts.configSHA256' "$PVN_CP7B_MANIFEST")" ] ||
		pvn_fail "CP7B config bytes differ from the reviewed config" || return 1
}

pvn_cp7b_verify_manifest_entries() {
	for entry in "$@"
	do
		file=${entry%%:*}
		remainder=${entry#*:}
		key=${remainder%%:*}
		owner=${remainder#*:}
		[ "$owner" != "$remainder" ] || owner=$PVN_CP7B_REVIEWED_INPUT_OWNER
		pvn_cp7b_require_safe_file "$file" "$owner" || return 1
		[ "$(pvn_sha256_file "$file")" = "$(jq -r ".artifacts.$key" "$PVN_CP7B_MANIFEST")" ] ||
			pvn_fail "reviewed CP7B hash mismatch: $key" || return 1
	done
}

pvn_cp7b_verify_manifest_closure() {
	pvn_cp7b_require_closure_tree "$PVN_CP7B_ARTIFACT_OWNER" || return 1
	pvn_cp7b_verify_manifest_entries \
		"$PVN_CP7B_BINARY:charonSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_SWANCTL:swanctlSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_LIBSTRONGSWAN:libstrongswanSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_LIBCHARON:libcharonSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_OPENSSL_PLUGIN:opensslPluginSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_NONCE_PLUGIN:noncePluginSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_LIBCRYPTO:opensslLibcryptoSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_LAUNCHER:gatedLauncherSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-kernel-pfkey.so:kernelPFArtifactSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-kernel-pfroute.so:pfrouteSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-socket-dynamic.so:socketDynamicSHA256:$PVN_CP7B_ARTIFACT_OWNER" \
		"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-vici.so:viciSHA256:$PVN_CP7B_ARTIFACT_OWNER"
}

pvn_cp7b_verify_manifest_reviewed_inputs() {
	pvn_cp7b_verify_manifest_entries \
		"$PVN_CP7B_RUNTIME_SCRIPT:runtimeScriptSHA256:$PVN_CP7B_REVIEWED_INPUT_OWNER" \
		"$PVN_CP7B_CLOSURE_SCRIPT:closureScriptSHA256:$PVN_CP7B_REVIEWED_INPUT_OWNER" \
		"$PVN_CP7B_STATE_SCRIPT:stateScriptSHA256:$PVN_CP7B_REVIEWED_INPUT_OWNER" \
		"$PVN_CP7B_ATTEMPTS_SCRIPT:attemptsScriptSHA256:$PVN_CP7B_REVIEWED_INPUT_OWNER" \
		"$PVN_CP7B_SNAPSHOT_SCRIPT:snapshotScriptSHA256:$PVN_CP7B_REVIEWED_INPUT_OWNER" \
		"$PVN_CP7B_BUNDLE_SCRIPT:bundleScriptSHA256:$PVN_CP7B_REVIEWED_INPUT_OWNER" \
		"$PVN_CP7B_NATIVE_SCRIPT:nativeScriptSHA256:$PVN_CP7B_REVIEWED_INPUT_OWNER" \
		"$PVN_CP7B_NETWORK_SCRIPT:networkScriptSHA256:$PVN_CP7B_REVIEWED_INPUT_OWNER" \
		"$PVN_CP7B_WORKER:workerSHA256" \
		"$PVN_CP7B_ROOT_ENTRY:rootEntrySHA256" \
		"$PVN_CP7B_EMERGENCY_SOURCE:emergencySHA256" \
		"$PVN_CP7B_AUTHORIZER:authorizerSHA256:502" \
		"$PVN_CP7B_ORACLE:oracleSHA256" \
		"$PVN_CP7B_READONLY_PROBE:readOnlyProbeSHA256" \
		"$PVN_CP7B_PY_INIT:officialPyInitSHA256" \
		"$PVN_CP7B_PY_COMMAND_WRAPPERS:officialPyCommandWrappersSHA256" \
		"$PVN_CP7B_PY_EVENT_LISTENER:officialPyEventListenerSHA256" \
		"$PVN_CP7B_PY_EXCEPTION:officialPyExceptionSHA256" \
		"$PVN_CP7B_PY_PROTOCOL:officialProtocolSHA256" \
		"$PVN_CP7B_PY_SESSION:officialPySessionSHA256"
}

pvn_cp7b_verify_manifest() {
	pvn_cp7b_verify_manifest_policy || return 1
	pvn_cp7b_verify_manifest_closure || return 1
	pvn_cp7b_verify_manifest_reviewed_inputs
}

pvn_cp7b_verify_source_build_metadata() {
	if [ "$(id -u)" -ne 0 ]; then
		[ "$(git -C "$PVN_CP7B_SOURCE" rev-parse HEAD)" = \
			"$PVN_CP7B_EXPECTED_SOURCE_COMMIT" ] ||
			pvn_fail "CP7B strongSwan source commit changed" || return 1
		[ -z "$(git -C "$PVN_CP7B_SOURCE" status --porcelain=v1)" ] ||
			pvn_fail "CP7B strongSwan source worktree is dirty" || return 1
	fi
	grep -Fq -- "--with-piddir=$PVN_CP7B_COMPILED_PIDDIR" "$PVN_CP7B_BUILD/config.status" ||
		pvn_fail "CP7B charon piddir is not scratch-pinned" || return 1
	grep -Fq -- '--enable-socket-dynamic' "$PVN_CP7B_BUILD/config.status" ||
		pvn_fail "CP7B build does not enable socket-dynamic" || return 1
}

pvn_cp7b_verify_runtime_build() {
	pvn_cp7b_verify_source_build_metadata || return 1
	for artifact in "$PVN_CP7B_BINARY" "$PVN_CP7B_SWANCTL" \
		"$PVN_CP7B_LIBSTRONGSWAN" "$PVN_CP7B_LIBCHARON" \
		"$PVN_CP7B_OPENSSL_PLUGIN" "$PVN_CP7B_NONCE_PLUGIN" "$PVN_CP7B_LIBCRYPTO" \
		"$PVN_CP7B_LAUNCHER" \
		"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-kernel-pfkey.so" \
		"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-kernel-pfroute.so" \
		"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-socket-dynamic.so" \
		"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-vici.so"
	do
		file "$artifact" | grep -q 'Mach-O 64-bit.*arm64' ||
			pvn_fail "CP7B artifact is not arm64: $artifact" || return 1
	done
}

pvn_cp7b_verify_user_preflight() {
	[ -d "$PVN_CP7B_RUNTIME_ROOT" ] && [ ! -L "$PVN_CP7B_RUNTIME_ROOT" ] ||
		pvn_fail "CP7B runtime root is missing or a symlink" || return 1
	[ "$(stat -f '%Lp' "$PVN_CP7B_RUNTIME_ROOT")" = 700 ] ||
		pvn_fail "CP7B runtime root mode must be 700" || return 1
	runtime_owner=$(stat -f '%u' "$PVN_CP7B_RUNTIME_ROOT")
	case "$runtime_owner" in
	502)
		[ "$(stat -f '%u:%g:%Lp' "$PVN_CP7B_RUNTIME_ROOT")" = 502:20:700 ] ||
			pvn_fail "CP7B user-owned runtime identity changed" || return 1
		pvn_cp7b_verify_manifest || return 1
		pvn_cp7b_verify_runtime_build
		;;
	0)
		[ "$(stat -f '%u:%g:%Lp' "$PVN_CP7B_RUNTIME_ROOT")" = 0:0:700 ] ||
			pvn_fail "CP7B root-owned retry identity changed" || return 1
		# A protected retry is intentionally not traversable by the desktop user.
		# The root-owned bundle repeats the complete closure and manifest checks.
		pvn_cp7b_verify_manifest_policy || return 1
		pvn_cp7b_verify_manifest_reviewed_inputs || return 1
		pvn_cp7b_verify_source_build_metadata
		;;
	*) pvn_fail "CP7B runtime root owner changed" || return 1 ;;
	esac
}

pvn_cp7b_classify_log() {
	log_file=$1
	if grep -Fq 'unable to create PF_KEY socket' "$log_file"; then
		printf '%s\n' pfkey_socket_open_failed
	elif grep -Fq 'unable to register PF_KEY' "$log_file"; then
		printf '%s\n' pfkey_register_failed
	elif grep -Eq "feature .*critical plugin '(kernel-pfkey|kernel-pfroute|socket-dynamic|vici)' failed" "$log_file"; then
		printf '%s\n' critical_plugin_failed
	elif grep -Fq 'sending packet:' "$log_file"; then
		printf '%s\n' forbidden_packet_send
	else
		printf '%s\n' unknown
	fi
}
