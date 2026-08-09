#!/bin/sh

set -eu

repo_root=/Users/larry_1/Opensource/powervpn-cli
bundle_root=${PVN_CP7B_BUNDLE_ROOT:-}
case "$bundle_root" in
/Users/larry_1/scratch-data/powervpn-strongswan/runtime-6.0.7-cp7b/.bootstrap-*) ;;
*) echo "error: CP7B reviewed worker requires a root-owned bootstrap bundle" >&2; exit 1 ;;
esac
[ -d "$bundle_root" ] && [ ! -L "$bundle_root" ] &&
	[ "$(stat -f '%u' "$bundle_root")" -eq 0 ] || {
	echo "error: CP7B bootstrap bundle identity changed" >&2
	exit 1
}
. "$bundle_root/lib/native_charon_runtime.sh"
. "$bundle_root/lib/route_snapshot.sh"
. "$bundle_root/lib/network_snapshot.sh"
. "$bundle_root/lib/cp7b_runtime.sh"
. "$bundle_root/lib/cp7b_state.sh"
. "$bundle_root/lib/cp7b_attempts.sh"
. "$bundle_root/lib/cp7b_snapshot.sh"
. "$bundle_root/lib/cp7b_bundle.sh"
pvn_cp7b_init_paths "$repo_root"
pvn_cp7b_bind_root_bundle "$bundle_root"

# shellcheck disable=SC2329
cleanup_early_bundle() {
	rc=$?
	trap - EXIT HUP INT TERM
	pvn_cp7b_stop_deadline_guard
	pvn_cp7b_cleanup_root_bundle "$bundle_root" >/dev/null 2>&1 || true
	pvn_cp7b_restore_runtime_owner_if_clean >/dev/null 2>&1 || true
	exit "$rc"
}
trap cleanup_early_bundle EXIT HUP INT TERM

action=
manifest_sha=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--run-reviewed | --stop-reviewed) action=$1 ;;
	--manifest-sha256)
		shift
		[ "$#" -gt 0 ] || pvn_fail "--manifest-sha256 requires a value" || exit 2
		manifest_sha=$1
		;;
	*) pvn_fail "usage: $0 --run-reviewed|--stop-reviewed --manifest-sha256 <sha256>" || exit 2 ;;
	esac
	shift
done
[ -n "$action" ] && [ -n "$manifest_sha" ] || pvn_fail "action and manifest hash are required" || exit 2
case "$manifest_sha" in
*[!0-9a-f]* | '')
	pvn_fail "manifest hash must be 64 lowercase hexadecimal characters" || exit 2
	;;
esac
[ "${#manifest_sha}" -eq 64 ] ||
	pvn_fail "manifest hash must be 64 lowercase hexadecimal characters" || exit 2
[ "$(id -u)" -eq 0 ] || pvn_fail "CP7B reviewed worker requires root" || exit 1
[ "${POWERVPN_CP7B_TEST_MODE:-0}" != 1 ] || pvn_fail "CP7B root test override is forbidden" || exit 1
[ "$(pvn_sha256_file "$PVN_CP7B_MANIFEST")" = "$manifest_sha" ] ||
	pvn_fail "CP7B manifest does not match the approved hash" || exit 1

if [ "$action" = --stop-reviewed ]; then
	if [ ! -e "$PVN_CP7B_STATE_FILE" ]; then
		pvn_cp7b_clear_attempt_ledger
		trap - EXIT HUP INT TERM
		pvn_cp7b_cleanup_root_bundle "$bundle_root"
		pvn_cp7b_restore_runtime_owner_if_clean
		printf '%s\n' '{"schemaVersion":1,"alreadyStopped":true,"containsSecrets":false}'
		exit 0
	fi
	[ -x "$PVN_CP7B_RUNTIME_ROOT/emergency-stop" ] ||
		pvn_fail "root-owned CP7B emergency stop is missing" || exit 1
	"$PVN_CP7B_RUNTIME_ROOT/emergency-stop" --stop-preserve-ledger >/dev/null
	pvn_cp7b_clear_attempt_ledger
	trap - EXIT HUP INT TERM
	pvn_cp7b_cleanup_root_bundle "$bundle_root"
	pvn_cp7b_restore_runtime_owner_if_clean
	printf '%s\n' '{"schemaVersion":1,"stopped":true,"containsSecrets":false}'
	exit 0
fi

pvn_cp7b_verify_manifest
pvn_cp7b_verify_runtime_build
[ -d "$PVN_CP7B_RUNTIME_ROOT" ] && [ ! -L "$PVN_CP7B_RUNTIME_ROOT" ] ||
	pvn_fail "CP7B runtime root is missing or a symlink" || exit 1
[ "$(stat -f '%u' "$PVN_CP7B_RUNTIME_ROOT")" -eq 0 ] ||
	pvn_fail "CP7B runtime root must be root-owned during the reviewed window" || exit 1
[ "$(stat -f '%Lp' "$PVN_CP7B_RUNTIME_ROOT")" = 700 ] ||
	pvn_fail "CP7B runtime root mode must be 700" || exit 1
[ ! -e "$PVN_CP7B_STATE_FILE" ] || pvn_fail "CP7B state already exists" || exit 1
[ ! -e "$PVN_CP7B_PID_FILE" ] || pvn_fail "CP7B PID file already exists" || exit 1
[ ! -S "$PVN_CP7B_SOCKET" ] || pvn_fail "CP7B VICI socket already exists" || exit 1
[ ! -e "$PVN_CP7B_RUNTIME_ROOT/emergency-stop" ] ||
	pvn_fail "CP7B emergency stop already exists" || exit 1
[ "$(find "$PVN_CP7B_RUNTIME_ROOT" -mindepth 1 -maxdepth 1 -type d -name '.bootstrap-*' -print | awk 'END { print NR + 0 }')" -eq 1 ] ||
	pvn_fail "CP7B bootstrap ownership is ambiguous" || exit 1
[ "$(find "$PVN_CP7B_RUNTIME_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'generation-*' -print | awk 'END { print NR + 0 }')" -eq 0 ] ||
	pvn_fail "CP7B generation residue exists" || exit 1

umask 077
started_epoch=$(date +%s)
evidence_dir="$PVN_CP7B_RUNTIME_ROOT/.window-evidence.$$"
mkdir "$evidence_dir"
chmod 700 "$evidence_dir"
before_a="$evidence_dir/before-a.json"
before_b="$evidence_dir/before-b.json"
during="$evidence_dir/during.json"
during_post="$evidence_dir/during-post-probes.json"
after="$evidence_dir/after.json"
inventory_json="$evidence_dir/vici-inventory.json"
core_success="$evidence_dir/core-success"
udp_count_file="$evidence_dir/udp-count"
stage_file="$evidence_dir/stage"
finalized=false

# shellcheck disable=SC2329
cleanup_unfinished_window() {
	rc=$?
	trap - EXIT HUP INT TERM
	pvn_cp7b_stop_deadline_guard
	if [ "$finalized" != true ]; then
		if [ -e "$PVN_CP7B_STATE_FILE" ] && [ -x "$PVN_CP7B_RUNTIME_ROOT/emergency-stop" ]; then
			"$PVN_CP7B_RUNTIME_ROOT/emergency-stop" --stop-preserve-ledger >/dev/null 2>&1 || true
		elif [ -n "${run_dir:-}" ]; then
			for runtime_file in "${config_path:-}" "${log_path:-}" \
				"${gate_path:-}" "${handshake_path:-}" \
				"$PVN_CP7B_RUNTIME_ROOT/emergency-stop"
			do
				[ -z "$runtime_file" ] || [ ! -e "$runtime_file" ] || rm -f -- "$runtime_file"
			done
			[ ! -d "$run_dir" ] || rmdir "$run_dir" 2>/dev/null || true
		fi
		pvn_cp7b_remove_evidence_dir "$evidence_dir" "$before_a" "$before_b" \
			"$during" "$during_post" "$after" "$inventory_json" "$core_success" \
			"$udp_count_file" "$stage_file" >/dev/null 2>&1 || true
	fi
	[ ! -d "$bundle_root" ] ||
		pvn_cp7b_cleanup_root_bundle "$bundle_root" >/dev/null 2>&1 || true
	pvn_cp7b_restore_runtime_owner_if_clean >/dev/null 2>&1 || true
	exit "$rc"
}
trap cleanup_unfinished_window EXIT HUP INT TERM

pvn_cp7b_begin_attempt "$started_epoch"
pvn_cp7b_start_deadline_guard

if ! pvn_cp7b_capture_stable_preflight "$before_a" "$before_b"; then
	duration_seconds=$(($(date +%s) - PVN_CP7B_WINDOW_STARTED))
	report=$(pvn_cp7b_preflight_failure_report_json \
		"$PVN_CP7B_PREFLIGHT_FAILURE" "$PVN_CP7B_ATTEMPT" "$duration_seconds")
	pvn_cp7b_remove_evidence_dir "$evidence_dir" "$before_a" "$before_b" \
		"$during" "$during_post" "$after" "$inventory_json" "$core_success" \
		"$udp_count_file" "$stage_file"
	finalized=true
	pvn_cp7b_stop_deadline_guard
	pvn_cp7b_cleanup_root_bundle "$bundle_root"
	trap - EXIT HUP INT TERM
	printf '%s\n' "$report"
	exit 0
fi
pvn_cp7b_verify_manifest
printf '%s\n' preflight_stable >"$stage_file"

generation="$(date -u '+%Y%m%dT%H%M%SZ').$$"
run_dir="$PVN_CP7B_RUNTIME_ROOT/generation-$generation"
config_path="$run_dir/strongswan.conf"
log_path="$run_dir/charon.log"
gate_path="$run_dir/launch.gate"
handshake_path="$run_dir/launch.handshake"
emergency_path="$PVN_CP7B_RUNTIME_ROOT/emergency-stop"
mkdir "$run_dir"
chmod 700 "$run_dir"
cp "$PVN_CP7B_EMERGENCY_SOURCE" "$emergency_path"
chmod 700 "$emergency_path"
pvn_cp7b_render_config "$PVN_CP7B_SOCKET" >"$config_path"
chmod 600 "$config_path"
: >"$log_path"
chmod 600 "$log_path"
mkfifo -m 600 "$gate_path"
pvn_cp7b_validate_gate "$gate_path"
config_sha=$(pvn_sha256_file "$config_path")
[ "$config_sha" = "$(jq -r '.artifacts.configSHA256' "$PVN_CP7B_MANIFEST")" ] ||
	pvn_fail "rendered CP7B config hash changed" || exit 1
pvn_cp7b_write_state prepared "$generation" "$PVN_CP7B_ATTEMPT" 0 \
	0000000000000000000000000000000000000000000000000000000000000000 \
	"$config_path" "$config_sha" "$log_path" 0 "$manifest_sha" "$emergency_path" \
	"$gate_path" "$handshake_path"

core_rc=0
(
	set -eu
	pvn_cp7b_start_gated_target "$generation" "$PVN_CP7B_ATTEMPT" \
		"$config_path" "$config_sha" "$log_path" "$manifest_sha" \
		"$emergency_path" "$gate_path" "$handshake_path" "$stage_file"
	daemon_pid=$PVN_CP7B_OWNED_PID
	start_sha=$PVN_CP7B_PROCESS_START_SHA
	ready=false
	attempt=0
	while [ "$attempt" -lt 40 ]; do
		kill -0 "$daemon_pid" 2>/dev/null
		if [ -S "$PVN_CP7B_SOCKET" ] && lsof -a -p "$daemon_pid" -U 2>/dev/null |
			grep -Fq -- "$PVN_CP7B_SOCKET"
		then
			ready=true
			break
		fi
		attempt=$((attempt + 1))
		sleep 0.1
	done
	[ "$ready" = true ]
	chmod 600 "$PVN_CP7B_SOCKET"
	[ -f "$PVN_CP7B_PID_FILE" ]
	chmod 600 "$PVN_CP7B_PID_FILE"
	socket_inode=$(stat -f '%i' "$PVN_CP7B_SOCKET")
	pvn_cp7b_write_state ready "$generation" "$PVN_CP7B_ATTEMPT" "$daemon_pid" \
		"$start_sha" "$config_path" "$config_sha" "$log_path" "$socket_inode" \
		"$manifest_sha" "$emergency_path" "$gate_path" "$handshake_path"
	pvn_cp7b_verify_state_process
	printf '%s\n' vici_ready >"$stage_file"
	pvn_cp7b_loaded_plugins_exact "$log_path"
	printf '%s\n' plugins_verified >"$stage_file"
	[ "$(pvn_cp7b_udp_fd_count "$daemon_pid")" -eq 0 ]
	pvn_snapshot_json >"$during"
	chmod 600 "$during"
	pvn_cp7b_during_snapshot_safe "$before_b" "$during"
	printf '%s\n' pre_probe_snapshot_safe >"$stage_file"
	/usr/bin/python3 "$PVN_CP7B_READONLY_PROBE" --socket "$PVN_CP7B_SOCKET" \
		--python-root "$PVN_CP7B_PYTHON_ROOT" --oracle-root "$bundle_root" \
		--timeout-ms 2000 >"$inventory_json"
	jq -e '
	  .success == true and .implementation == "official_strongswan_python_vici" and
	  .versionResponseKeyNames == ["daemon","version","sysname","release","machine"] and
	  .statsResponsePresent == true and
	  .counts == {connections: 0, sas: 0, policies: 0} and
	  .credentialRead == false and .credentialSerialized == false and
	  .initiateCalled == false and .installCalled == false and
	  .containsSecrets == false and .containsRawState == false
	' "$inventory_json" >/dev/null
	printf '%s\n' vici_inventory_verified >"$stage_file"
	pvn_cp7b_udp_fd_count "$daemon_pid" >"$udp_count_file"
	[ "$(sed -n '1p' "$udp_count_file")" -eq 0 ]
	! grep -Fq 'sending packet:' "$log_path"
	pvn_snapshot_json >"$during_post"
	chmod 600 "$during_post"
	pvn_cp7b_during_snapshot_safe "$before_b" "$during_post"
	printf '%s\n' post_probe_snapshot_safe >"$stage_file"
	: >"$core_success"
) || core_rc=$?

failure_category=none
if [ "$core_rc" -ne 0 ]; then
	failure_category=$(pvn_cp7b_classify_log "$log_path")
	if [ "$failure_category" = unknown ] && [ -f "$stage_file" ]; then
		failure_category="after_$(sed -n '1p' "$stage_file")"
	fi
fi
cleanup_complete=false
if "$emergency_path" --stop-preserve-ledger >/dev/null 2>&1; then
	cleanup_complete=true
fi
pvn_snapshot_json >"$after"
chmod 600 "$after"
after_safe=false
if [ "$cleanup_complete" = true ] && pvn_cp7b_after_snapshot_safe "$before_b" "$after"; then
	after_safe=true
fi
duration_seconds=$(($(date +%s) - PVN_CP7B_WINDOW_STARTED))
state_safe=false
if [ "$core_rc" -eq 0 ] && [ -f "$core_success" ] && [ "$after_safe" = true ]; then
	state_safe=true
fi
window_success=false
if [ "$state_safe" = true ] && [ "$duration_seconds" -le 300 ]; then
	window_success=true
	pvn_cp7b_clear_attempt_ledger
fi
udp_count=-1
[ ! -f "$udp_count_file" ] || udp_count=$(sed -n '1p' "$udp_count_file")

report=$(pvn_cp7b_report_json "$window_success" "$PVN_CP7B_ATTEMPT" \
	"$duration_seconds" "$failure_category" "$cleanup_complete" "$state_safe" \
	"$udp_count" \
	"$(jq -r '.traces.version.requestPayloadSHA256 // ""' "$inventory_json" 2>/dev/null || true)" \
	"$(jq -r '.traces.version.responsePayloadSHA256 // ""' "$inventory_json" 2>/dev/null || true)")

pvn_cp7b_remove_evidence_dir "$evidence_dir" "$before_a" "$before_b" \
	"$during" "$during_post" "$after" "$inventory_json" "$core_success" \
	"$udp_count_file" "$stage_file"
finalized=true
pvn_cp7b_stop_deadline_guard
pvn_cp7b_cleanup_root_bundle "$bundle_root"
[ -e "$PVN_CP7B_LEDGER" ] || pvn_cp7b_restore_runtime_owner_if_clean
trap - EXIT HUP INT TERM
printf '%s\n' "$report"
[ "$cleanup_complete" = true ] || exit 1
exit 0
