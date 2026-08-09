#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
. "$repo_root/scripts/lib/route_snapshot.sh"
. "$repo_root/scripts/lib/network_snapshot.sh"
. "$repo_root/scripts/lib/cp7b_runtime.sh"
. "$repo_root/scripts/lib/cp7b_closure.sh"
. "$repo_root/scripts/lib/cp7b_bundle.sh"
. "$repo_root/scripts/lib/cp7b_snapshot.sh"
pvn_cp7b_init_paths "$repo_root"

operation_mode=
approved_sha=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--dry-run) operation_mode=dry-run ;;
	--execute-reviewed) operation_mode=execute ;;
	--manifest-sha256)
		shift
		[ "$#" -gt 0 ] || pvn_fail "--manifest-sha256 requires a value" || exit 2
		approved_sha=$1
		;;
	*) pvn_fail "usage: $0 --dry-run|--execute-reviewed --manifest-sha256 <sha256>" || exit 2 ;;
	esac
	shift
done
[ -n "$operation_mode" ] && [ -n "$approved_sha" ] ||
	pvn_fail "mode and manifest hash are required" || exit 2
readonly operation_mode approved_sha
[ "$(id -u)" -ne 0 ] || pvn_fail "authorization wrapper must run as the desktop user" || exit 1
[ "${POWERVPN_CP7B_TEST_MODE:-0}" != 1 ] || pvn_fail "reviewed CP7B execution forbids test mode" || exit 1
actual_sha=$(pvn_sha256_file "$PVN_CP7B_MANIFEST")
[ "$approved_sha" = "$actual_sha" ] || pvn_fail "approved CP7B manifest hash changed" || exit 1
pvn_cp7b_verify_user_preflight

exact_command="$repo_root/scripts/run_cp7b_backend.sh --execute-reviewed --manifest-sha256 $actual_sha"
if [ "$operation_mode" = dry-run ]; then
	printf '%s\n' \
		'mode=dry-run' \
		"manifest=$PVN_CP7B_MANIFEST" \
		"manifest_sha256=$actual_sha" \
		'backend=kernel-pfkey+kernel-pfroute' \
		'socket_provider=socket-dynamic' \
		'expected_udp_sockets=0' \
		'max_launches=2' \
		'max_duration_seconds=300' \
		'native_touch_id=yes' \
		'power_vpn=kept_running' \
		'surge=kept_running' \
		'server_traffic=forbidden' \
		"exact_command=$exact_command"
	exit 0
fi

surge_cli=/Applications/Surge.app/Contents/Applications/surge-cli
[ -x "$surge_cli" ] || pvn_fail "Surge CLI is missing" || exit 1
evidence_dir="$PVN_CP7B_SCRATCH_ROOT/cp7b-evidence-$(date -u '+%Y%m%dT%H%M%SZ').$$"
mkdir "$evidence_dir"
chmod 700 "$evidence_dir"
before="$evidence_dir/before.json"
after="$evidence_dir/after.json"
root_result="$evidence_dir/root-result.json"
result="$evidence_dir/result.json"
environment_before="$evidence_dir/surge-environment-before.sha256"
environment_after="$evidence_dir/surge-environment-after.sha256"
finalized=false

# shellcheck disable=SC2329
preserve_failed_evidence() {
	rc=$?
	trap - EXIT HUP INT TERM
	if [ "$finalized" != true ]; then
		printf '%s\n' "CP7B evidence preserved at $evidence_dir" >&2
	fi
	exit "$rc"
}
trap preserve_failed_evidence EXIT HUP INT TERM

pvn_snapshot_json >"$before"
pvn_cp7b_surge_environment_hash "$surge_cli" >"$environment_before"
"$surge_cli" --raw test dns | jq -e '(.error // null) == null' >/dev/null
chmod 600 "$before" "$environment_before"

/usr/bin/osascript "$PVN_CP7B_AUTHORIZER" --run-reviewed "$actual_sha" >"$root_result"
chmod 600 "$root_result"
expected_config_sha=$(jq -r '.artifacts.configSHA256' "$PVN_CP7B_MANIFEST")
jq -e --arg manifestSHA "$actual_sha" \
  --arg sourceCommit "$PVN_CP7B_EXPECTED_SOURCE_COMMIT" \
  --arg configSHA "$expected_config_sha" '
  .schemaVersion == 1 and
  .approvalManifestSHA256 == $manifestSHA and
  .sourceCommit == $sourceCommit and .configSHA256 == $configSHA and
  .containsSecrets == false and
  .containsRawRoutes == false and .containsRawSAState == false and
  .containsServerEndpoint == false' "$root_result" >/dev/null

pvn_snapshot_json >"$after"
pvn_cp7b_surge_environment_hash "$surge_cli" >"$environment_after"
"$surge_cli" --raw test dns | jq -e '(.error // null) == null' >/dev/null
chmod 600 "$after" "$environment_after"
surge_environment_stable=false
if cmp -s "$environment_before" "$environment_after"; then
	surge_environment_stable=true
fi

jq --argjson surgeEnvironmentStable "$surge_environment_stable" \
	'. + {unprivilegedSurgeEnvironmentStable: $surgeEnvironmentStable,
	  unprivilegedSurgeDNSBeforeAndAfter: true}' "$root_result" >"$result"
chmod 600 "$result"
rm -f -- "$root_result" "$environment_before" "$environment_after"

jq -e '.success == true and .safety.cleanupComplete == true and
  .unprivilegedSurgeEnvironmentStable == true and
  .unprivilegedSurgeDNSBeforeAndAfter == true' "$result" >/dev/null || {
	exit 1
}
finalized=true
trap - EXIT HUP INT TERM
printf '%s\n' "result=$result" 'cp7b_window=pass'
