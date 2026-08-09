#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
. "$repo_root/scripts/lib/route_snapshot.sh"
. "$repo_root/scripts/lib/network_snapshot.sh"
. "$repo_root/scripts/lib/cp7b_runtime.sh"
. "$repo_root/scripts/lib/cp7b_closure.sh"
pvn_cp7b_init_paths "$repo_root"

result=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--result)
		shift
		[ "$#" -gt 0 ] || pvn_fail "--result requires a path" || exit 2
		result=$1
		;;
	*) pvn_fail "usage: $0 --result <cp7b-result.json>" || exit 2 ;;
	esac
	shift
done
[ -n "$result" ] || pvn_fail "--result is required" || exit 2
case "$result" in
"$PVN_CP7B_SCRATCH_ROOT"/*) ;;
*) pvn_fail "CP7B result must stay below the protected scratch root" || exit 1 ;;
esac
[ -f "$result" ] && [ ! -L "$result" ] || pvn_fail "CP7B result is missing or a symlink" || exit 1
[ "$(stat -f '%u' "$result")" = "$(id -u)" ] || pvn_fail "CP7B result owner changed" || exit 1
[ "$(stat -f '%Lp' "$result")" = 600 ] || pvn_fail "CP7B result mode must be 600" || exit 1

[ ! -e "$PVN_CP7B_STATE_FILE" ] || pvn_fail "CP7B state remains" || exit 1
[ "$(stat -f '%u' "$PVN_CP7B_RUNTIME_ROOT")" = "$(id -u)" ] ||
	pvn_fail "CP7B runtime root was not returned to the desktop user" || exit 1
[ "$(stat -f '%Lp' "$PVN_CP7B_RUNTIME_ROOT")" = 700 ] ||
	pvn_fail "CP7B runtime root mode changed" || exit 1
[ ! -e "$PVN_CP7B_PID_FILE" ] || pvn_fail "CP7B PID file remains" || exit 1
[ ! -S "$PVN_CP7B_SOCKET" ] || pvn_fail "CP7B VICI socket remains" || exit 1
[ ! -e "$PVN_CP7B_RUNTIME_ROOT/emergency-stop" ] ||
	pvn_fail "CP7B emergency-stop bundle remains" || exit 1
[ ! -e "$PVN_CP7B_LEDGER" ] || pvn_fail "CP7B attempt ledger remains after PASS" || exit 1
[ "$(find "$PVN_CP7B_RUNTIME_ROOT" -mindepth 1 -maxdepth 1 -type d -name '.bootstrap-*' -print | awk 'END { print NR + 0 }')" -eq 0 ] ||
	pvn_fail "CP7B root bootstrap directory remains" || exit 1
[ "$(find "$PVN_CP7B_RUNTIME_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'generation-*' -print | awk 'END { print NR + 0 }')" -eq 0 ] ||
	pvn_fail "CP7B generation directory remains" || exit 1
[ "$(find "$PVN_CP7B_RUNTIME_ROOT" -mindepth 1 -maxdepth 1 -print)" = \
	"$PVN_CP7B_PREFIX" ] ||
	pvn_fail "CP7B runtime root differs from the reviewed closure baseline" || exit 1
pvn_cp7b_require_closure_tree "$(id -u)" || exit 1
[ "$(pvn_native_charon_pids | awk 'END { print NR + 0 }')" -eq 0 ] ||
	pvn_fail "CP7B native charon process remains" || exit 1

expected_manifest_sha=$(pvn_sha256_file "$PVN_CP7B_MANIFEST")
expected_source_commit=$(jq -er '.artifacts.sourceCommit |
  select(test("^[0-9a-f]{40}$"))' "$PVN_CP7B_MANIFEST") ||
	pvn_fail "CP7B manifest source binding is invalid" || exit 1
expected_config_sha=$(jq -er '.artifacts.configSHA256 |
  select(test("^[0-9a-f]{64}$"))' "$PVN_CP7B_MANIFEST") ||
	pvn_fail "CP7B manifest config binding is invalid" || exit 1

jq -e --arg manifest "$expected_manifest_sha" \
	--arg source "$expected_source_commit" --arg config "$expected_config_sha" '
  .schemaVersion == 1 and .success == true and
  .backend == "pfkey-pfroute" and .socketProvider == "socket-dynamic" and
  .approvalManifestSHA256 == $manifest and
  .sourceCommit == $source and .configSHA256 == $config and
  .durationSeconds <= 300 and .safety.udpSocketCount == 0 and
  .safety.serverTraffic == false and .safety.credentialRead == false and
  .safety.initiateCalled == false and .safety.installCalled == false and
  .safety.globalSADStable == true and .safety.globalSPDStable == true and
  .safety.espPortStable == true and
  .safety.persistentRouteProjectionStable == true and
  .safety.defaultRouteDNSAndUtunStable == true and
  .safety.powerVPNAndSurgeProcessStable == true and
  .safety.cleanupComplete == true and
  .unprivilegedSurgeEnvironmentStable == true and
  .unprivilegedSurgeDNSBeforeAndAfter == true and
  .containsSecrets == false and .containsRawRoutes == false and
  .containsRawSAState == false and .containsServerEndpoint == false
' "$result" >/dev/null || pvn_fail "CP7B result fails the zero-residue contract" || exit 1

printf '%s\n' '{"schemaVersion":1,"cp7bCleanTeardown":true,"containsSecrets":false}'
