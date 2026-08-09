#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
. "$repo_root/scripts/lib/route_snapshot.sh"
. "$repo_root/scripts/lib/network_snapshot.sh"
. "$repo_root/scripts/lib/cp7b_snapshot.sh"

test_root=$(mktemp -d "$HOME/scratch-data/powervpn-strongswan/cp7b-route-tests.XXXXXX")
chmod 700 "$test_root"

cleanup() {
	rc=$?
	trap - EXIT HUP INT TERM
	for directory in "$test_root"/stage-*; do
		[ -d "$directory" ] || continue
		rm -f -- "$directory"/*
		rmdir "$directory"
	done
	for fixture in "$test_root"/*; do
		[ ! -e "$fixture" ] || rm -f -- "$fixture"
	done
	rmdir "$test_root"
	exit "$rc"
}
trap cleanup EXIT HUP INT TERM

fail() {
	echo "error: $*" >&2
	exit 1
}

project() {
	family=$1
	fixture=$2
	profile=$3
	records=$(pvn_route_records "$family" <"$fixture") || return 1
	case "$profile" in
	structural)
		printf '%s\n' "$records" |
			awk -F '\t' '{print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5}'
		;;
	persistent)
		printf '%s\n' "$records" |
			awk -F '\t' '$6 == 0 && $7 == 0 {print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5}'
		;;
	*) return 1 ;;
	esac | LC_ALL=C sort
}

projection_hash() {
	project "$1" "$2" "$3" | pvn_hash_stdin
}

projection_count() {
	project "$1" "$2" "$3" | awk 'END {print NR + 0}'
}

expect_rejected() {
	if pvn_route_records "$1" <"$2" >/dev/null 2>&1; then
		fail "malformed route fixture was accepted: $2"
	fi
}

base="$test_root/base.inet"
expire_changed="$test_root/expire-changed.inet"
was_cloned_added="$test_root/was-cloned-added.inet"
dynamic_added="$test_root/dynamic-added.inet"
parent_changed="$test_root/parent-changed.inet"
reordered="$test_root/reordered.inet"
duplicate="$test_root/duplicate.inet"
ipv6="$test_root/base.inet6"

printf '%s\n' \
	'Routing tables' '' 'Internet:' '' \
	'Destination Gateway Flags Netif Expire' \
	'default 192.0.2.1 UGScg en0' \
	'192.0.2.0/24 link#4 UCS en0' \
	'198.51.100.10 192.0.2.1 UHWI en0 9' \
	'203.0.113.0/24 link#9 UGScI utun9' >"$base"
sed 's/UHWI en0 9/UHWI en0 8/' "$base" >"$expire_changed"
sed '/198\.51\.100\.10/a\
198.51.100.11 192.0.2.1 UHWI en0' "$base" >"$was_cloned_added"
sed '/192\.0\.2\.0\/24/a\
198.51.100.0\/24 192.0.2.1 UDS en0' "$base" >"$dynamic_added"
sed 's#203\.0\.113\.0/24 link#203.0.113.0/24 192.0.2.1#' "$base" >"$parent_changed"
printf '%s\n' \
	'Routing tables' '' 'Internet:' '' \
	'Destination Gateway Flags Netif Expire' \
	'203.0.113.0/24 link#9 UGScI utun9' \
	'198.51.100.10 192.0.2.1 UHWI en0 9' \
	'default 192.0.2.1 UGScg en0' \
	'192.0.2.0/24 link#4 UCS en0' >"$reordered"
cp "$base" "$duplicate"
printf '%s\n' 'default 192.0.2.1 UGScg en0' >>"$duplicate"
printf '%s\n' \
	'Routing tables' '' 'Internet6:' '' \
	'Destination Gateway Flags Netif Expire' \
	'default fe80::1%en0 UGcg en0' \
	'2001:db8::/32 link#9 UCS utun9' \
	'fe80::1 link#1 UHLWI lo0 5' >"$ipv6"

[ "$(projection_count inet "$base" structural)" -eq 4 ]
[ "$(projection_count inet "$base" persistent)" -eq 3 ]
[ "$(projection_count inet6 "$ipv6" structural)" -eq 3 ]
[ "$(projection_count inet6 "$ipv6" persistent)" -eq 2 ]
[ "$(projection_hash inet "$base" structural)" = \
	"$(projection_hash inet "$expire_changed" structural)" ]
[ "$(projection_hash inet "$base" persistent)" = \
	"$(projection_hash inet "$expire_changed" persistent)" ]
[ "$(projection_hash inet "$base" structural)" != \
	"$(projection_hash inet "$was_cloned_added" structural)" ]
[ "$(projection_hash inet "$base" persistent)" = \
	"$(projection_hash inet "$was_cloned_added" persistent)" ]
[ "$(projection_hash inet "$base" persistent)" != \
	"$(projection_hash inet "$dynamic_added" persistent)" ]
[ "$(projection_hash inet "$base" persistent)" != \
	"$(projection_hash inet "$parent_changed" persistent)" ]
[ "$(projection_hash inet "$base" structural)" = \
	"$(projection_hash inet "$reordered" structural)" ]
[ "$(projection_count inet "$duplicate" persistent)" -eq 4 ]
[ "$(projection_hash inet "$base" persistent)" != \
	"$(projection_hash inet "$duplicate" persistent)" ]

make_invalid() {
	name=$1
	shift
	printf '%s\n' "$@" >"$test_root/$name"
	expect_rejected inet "$test_root/$name"
}

make_invalid missing-header \
	'Routing tables' 'Internet:' 'default 192.0.2.1 UGScg en0'
make_invalid wrong-family \
	'Routing tables' 'Internet6:' 'Destination Gateway Flags Netif Expire' \
	'default 192.0.2.1 UGScg en0'
make_invalid duplicate-header \
	'Routing tables' 'Internet:' 'Destination Gateway Flags Netif Expire' \
	'Destination Gateway Flags Netif Expire' 'default 192.0.2.1 UGScg en0'
make_invalid nf3 \
	'Routing tables' 'Internet:' 'Destination Gateway Flags Netif Expire' \
	'default 192.0.2.1 UGScg'
make_invalid nf6 \
	'Routing tables' 'Internet:' 'Destination Gateway Flags Netif Expire' \
	'default 192.0.2.1 UGScg en0 9 extra'
for invalid_expire in 0 -1 text; do
	make_invalid "expire-$invalid_expire" \
		'Routing tables' 'Internet:' 'Destination Gateway Flags Netif Expire' \
		"default 192.0.2.1 UGScg en0 $invalid_expire"
done
for invalid_flags in UZ UU SU; do
	make_invalid "flags-$invalid_flags" \
		'Routing tables' 'Internet:' 'Destination Gateway Flags Netif Expire' \
		"default 192.0.2.1 $invalid_flags en0"
done
make_invalid bad-netif \
	'Routing tables' 'Internet:' 'Destination Gateway Flags Netif Expire' \
	'default 192.0.2.1 UGScg 9tun'
make_invalid empty-table \
	'Routing tables' 'Internet:' 'Destination Gateway Flags Netif Expire'
zero_persistent="$test_root/zero-persistent"
printf '%s\n' 'Routing tables' 'Internet:' 'Destination Gateway Flags Netif Expire' \
	'198.51.100.10 192.0.2.1 UHWI en0 9' >"$zero_persistent"
pvn_route_records inet <"$zero_persistent" >/dev/null
if pvn_route_fingerprint_file inet "$zero_persistent" "$test_root" >/dev/null 2>&1; then
	fail "zero-persistent route table passed the CP7B profile"
fi

for stage in parse project sort count hash; do
	stage_root="$test_root/stage-$stage"
	mkdir "$stage_root"
	if (
		case "$stage" in
		parse) pvn_route_records() { return 1; } ;;
		project) pvn_route_project_file() { return 1; } ;;
		sort) pvn_route_sort_file() { return 1; } ;;
		count) pvn_route_count_file() { return 1; } ;;
		hash) pvn_checked_hash_file() { return 1; } ;;
		esac
		pvn_route_fingerprint_file inet "$base" "$stage_root" >/dev/null 2>&1
	); then
		fail "route fingerprint accepted injected $stage stage failure"
	fi
	rm -f -- "$stage_root"/*
	rmdir "$stage_root"
done

default_valid="$test_root/default-valid"
default_missing="$test_root/default-missing"
default_duplicate="$test_root/default-duplicate"
printf '%s\n' 'route to: default' 'destination: default' 'interface: en0' >"$default_valid"
printf '%s\n' 'route to: default' 'destination: default' >"$default_missing"
printf '%s\n' 'interface: en0' 'interface: utun8' >"$default_duplicate"
[ "$(pvn_default_route_interface <"$default_valid")" = en0 ]
if pvn_default_route_interface <"$default_missing" >/dev/null 2>&1 ||
	pvn_default_route_interface <"$default_duplicate" >/dev/null 2>&1; then
	fail "missing or duplicate default-route interface was accepted"
fi
default_command_fail="$test_root/default-command-fail"
default_command_ok="$test_root/default-command-ok"
printf '%s\n' '#!/bin/sh' 'exit 1' >"$default_command_fail"
printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'interface: en0'" >"$default_command_ok"
chmod 700 "$default_command_fail" "$default_command_ok"
if pvn_capture_default_route "$default_command_fail" >/dev/null 2>&1; then
	fail "failed default-route command produced a fingerprint"
fi
default_fingerprint=$(pvn_capture_default_route "$default_command_ok")
default_tab=$(printf '\t')
case "$default_fingerprint" in
"en0${default_tab}"[0-9a-f][0-9a-f]*) ;;
*) fail "default-route fingerprint is invalid" ;;
esac
if pvn_checked_hash_command /usr/bin/false >/dev/null 2>&1; then
	fail "failed command produced a checked hash"
fi

summary=$(jq -n \
	--arg hash "$(projection_hash inet "$base" persistent)" \
	--argjson count "$(projection_count inet "$base" persistent)" \
	'{routeCanonicalizationVersion:1,persistentRouteCount:$count,
	  persistentRouteSHA256:$hash,containsRawRoutes:false}')
for forbidden in 192.0.2.1 198.51.100.10 203.0.113.0/24; do
	if printf '%s\n' "$summary" | grep -Fq "$forbidden"; then
		fail "value-free route summary retained a fixture value"
	fi
done

gate_first="$test_root/gate-first.json"
gate_clone_churn="$test_root/gate-clone-churn.json"
gate_persistent_change="$test_root/gate-persistent-change.json"
jq -n '{
  setkeyState:"available",setkeyPolicyState:"available",espPortState:"available",
  setkeySHA256:"sad",setkeyPolicySHA256:"spd",espPortSHA256:"esp",
  routeCanonicalizationVersion:1,interfaceInventorySHA256:"interfaces",
  ipv4RouteCount:100,ipv4RouteSHA256:"structural-a",
  ipv4PersistentRouteCount:10,ipv4PersistentRouteSHA256:"persistent-v4",
  ipv6RouteCount:20,ipv6RouteSHA256:"structural-v6-a",
  ipv6PersistentRouteCount:12,ipv6PersistentRouteSHA256:"persistent-v6",
  defaultRouteInterface:"en0",defaultRouteSHA256:"default",dnsSHA256:"dns",
  utunNames:["utun8"],surgeProcessCount:1,surgeProcessIdentitySHA256:"surge",
  surgeExtensionProcessCount:1,surgeExtensionProcessIdentitySHA256:"extension",
  surgeHelperProcessCount:1,surgeHelperProcessIdentitySHA256:"helper",
  surgeCLIProcessCount:0,surgeCLIProcessIdentitySHA256:"cli",
  powerVPNProcessCount:1,powerVPNProcessIdentitySHA256:"powervpn",
  nativeCharonPids:[],productionIKEPortsBoundByNative:false,
  runtimeStatePresent:false,ownedVICISocketPresent:false,
  compiledPIDFilePresent:false,generationDirectoryCount:0
}' >"$gate_first"
jq '.ipv4RouteCount=117 | .ipv4RouteSHA256="structural-b" |
  .ipv6RouteCount=23 | .ipv6RouteSHA256="structural-v6-b"' \
	"$gate_first" >"$gate_clone_churn"
pvn_cp7b_preflight_snapshots_stable "$gate_first" "$gate_clone_churn"
jq '.ipv4PersistentRouteSHA256="persistent-route-changed"' \
	"$gate_clone_churn" >"$gate_persistent_change"
if pvn_cp7b_preflight_snapshots_stable "$gate_first" "$gate_persistent_change"; then
	fail "persistent route change passed the CP7B preflight gate"
fi

capture_first="$test_root/capture-first.json"
capture_second="$test_root/capture-second.json"
capture_source_second=$gate_clone_churn
capture_call=0
pvn_snapshot_json() {
	capture_call=$((capture_call + 1))
	if [ "$capture_call" -eq 1 ]; then
		/bin/cat "$gate_first"
	else
		/bin/cat "$capture_source_second"
	fi
}
pvn_cp7b_capture_stable_preflight "$capture_first" "$capture_second"
[ "$PVN_CP7B_PREFLIGHT_FAILURE" = none ]
capture_call=0
capture_source_second=$gate_persistent_change
if pvn_cp7b_capture_stable_preflight "$capture_first" "$capture_second"; then
	fail "unstable persistent route capture passed"
fi
[ "$PVN_CP7B_PREFLIGHT_FAILURE" = root_preflight_snapshot_unstable ]

trap - EXIT HUP INT TERM
for fixture in "$test_root"/*; do rm -f -- "$fixture"; done
rmdir "$test_root"
printf '%s\n' 'PASS: CP7B strict route snapshot canonicalization tests'
