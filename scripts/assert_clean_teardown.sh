#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$repo_root/scripts/lib/native_charon_runtime.sh"
pvn_init_runtime_paths

before=
after=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--before) shift; before=${1:-} ;;
	--after) shift; after=${1:-} ;;
	*) pvn_fail "usage: $0 --before <snapshot.json> --after <snapshot.json>" || exit 2 ;;
	esac
	shift
done
[ -n "$before" ] && [ -n "$after" ] ||
	pvn_fail "both --before and --after are required" || exit 2

jq -e '.schemaVersion == 1 and .containsSecrets == false and .containsRawRoutes == false' \
	"$before" "$after" >/dev/null
[ ! -e "$PVN_STATE_FILE" ] || pvn_fail "runtime state file remains after teardown" || exit 1
[ ! -e "$PVN_PID_FILE" ] || pvn_fail "compiled charon PID file remains after teardown" || exit 1
[ ! -S "$PVN_RUNTIME_ROOT/charon.vici" ] ||
	pvn_fail "fixed VICI socket remains after teardown" || exit 1
generation_count=0
if [ -d "$PVN_RUNTIME_ROOT" ]; then
	generation_count=$(find "$PVN_RUNTIME_ROOT" -mindepth 1 -maxdepth 1 \
		-type d -name 'generation-*' -print | awk 'END { print NR + 0 }')
fi
[ "$generation_count" -eq 0 ] || pvn_fail "generation directory remains after teardown" || exit 1

jq -e --slurpfile before "$before" '
  .runtimeStatePresent == false and
  .ownedVICISocketPresent == false and
  .compiledPIDFilePresent == false and
  .generationDirectoryCount == 0 and
  .productionIKEPortsBoundByNative == false and
  (.nativeCharonPids | length) == 0 and
  .syntheticRouteObserved == $before[0].syntheticRouteObserved and
  .defaultRouteInterface == $before[0].defaultRouteInterface and
  .dnsSHA256 == $before[0].dnsSHA256 and
  .surgeProcessCount == $before[0].surgeProcessCount and
  .surgeExtensionProcessCount == $before[0].surgeExtensionProcessCount and
  .surgeHelperProcessCount == $before[0].surgeHelperProcessCount and
  .surgeCLIProcessCount == $before[0].surgeCLIProcessCount and
  .powerVPNProcessCount == $before[0].powerVPNProcessCount and
  .setkeyState == $before[0].setkeyState and
  (if .setkeyState == "available" then .setkeySHA256 == $before[0].setkeySHA256 else true end) and
  ((.utunNames - $before[0].utunNames) | length) == 0
' "$after" >/dev/null || pvn_fail "post-run snapshot fails the CP7A clean-teardown gate" || exit 1

jq -n \
	--arg beforeRouteSHA "$(jq -r '.ipv4RouteSHA256' "$before")" \
	--arg afterRouteSHA "$(jq -r '.ipv4RouteSHA256' "$after")" \
	'{
	  schemaVersion: 1,
	  cleanTeardown: true,
	  generationOwnedResidue: false,
	  newUtun: false,
	  productionIKEPorts: false,
	  defaultRouteAndDNSStable: true,
	  surgeProcessStable: true,
	  powerVPNProcessStable: true,
	  saPolicyInventoryStableWhenReadable: true,
	  globalRouteTableHashEqual: ($beforeRouteSHA == $afterRouteSHA),
	  globalRouteTableHashIsInformational: true
	}'
