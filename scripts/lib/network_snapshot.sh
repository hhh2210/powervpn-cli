#!/bin/sh

pvn_hash_stdin() {
	shasum -a 256 | awk '{print $1}'
}

pvn_json_string_array() {
	jq -Rsc 'split("\n") | map(select(length > 0))'
}

pvn_count_process() {
	pgrep -x "$1" 2>/dev/null | awk 'END { print NR + 0 }'
}

pvn_count_process_pattern() {
	pgrep -f "$1" 2>/dev/null | awk 'END { print NR + 0 }'
}

pvn_process_pids() {
	match_kind=$1
	match_value=$2
	case "$match_kind" in
	exact) match_option=-x ;;
	pattern) match_option=-f ;;
	*) return 1 ;;
	esac
	if matched_pids=$(pgrep "$match_option" "$match_value" 2>/dev/null); then
		printf '%s\n' "$matched_pids"
	else
		match_rc=$?
		[ "$match_rc" -eq 1 ] || return "$match_rc"
	fi
}

pvn_process_identity_sha256() {
	identity_kind=$1
	identity_match=$2
	identity_pids=$(pvn_process_pids "$identity_kind" "$identity_match") || return 1
	identity_records=$(
		for identity_pid in $identity_pids; do
			printf '%s\n' "$identity_pid" | grep -Eq '^[0-9]+$' || exit 1
			identity_start=$(LC_ALL=C ps -ww -p "$identity_pid" -o lstart= 2>/dev/null |
				sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
			identity_command=$(LC_ALL=C ps -ww -p "$identity_pid" -o command= 2>/dev/null |
				sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
			[ -n "$identity_start" ] && [ -n "$identity_command" ] || exit 1
			identity_start_sha=$(printf '%s' "$identity_start" | pvn_hash_stdin)
			identity_command_sha=$(printf '%s' "$identity_command" | pvn_hash_stdin)
			printf '%s\t%s\t%s\n' "$identity_pid" \
				"$identity_start_sha" "$identity_command_sha"
		done
	) || return 1
	printf '%s' "$identity_records" | LC_ALL=C sort -n -k1,1 | pvn_hash_stdin
}

pvn_native_charon_pids() {
	ps -axo pid=,command= | awk -v executable="$PVN_BINARY" '
		index($0, executable) {
			line = $0
			sub(/^[[:space:]]*/, "", line)
			split(line, fields, /[[:space:]]+/)
			command = line
			sub(/^[0-9]+[[:space:]]+/, "", command)
			if (command == executable || index(command, executable " ") == 1) print fields[1]
		}
	'
}

pvn_snapshot_json() {
	timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	interfaces=$(ifconfig -l)
	# shellcheck disable=SC2086
	utun_names=$(printf '%s\n' $interfaces | awk '/^utun/' | pvn_json_string_array)
	interface_hash=$(ifconfig -a 2>/dev/null | pvn_hash_stdin)
	inet_routes=$(netstat -rn -f inet 2>/dev/null)
	inet6_routes=$(netstat -rn -f inet6 2>/dev/null)
	inet_route_hash=$(printf '%s\n' "$inet_routes" | pvn_hash_stdin)
	inet6_route_hash=$(printf '%s\n' "$inet6_routes" | pvn_hash_stdin)
	inet_route_count=$(printf '%s\n' "$inet_routes" | awk '$1 ~ /^[0-9]/ { count++ } END { print count + 0 }')
	inet6_route_count=$(printf '%s\n' "$inet6_routes" | awk '$1 ~ /^[0-9a-fA-F]/ { count++ } END { print count + 0 }')
	default_route=$(route -n get default 2>/dev/null || true)
	default_interface=$(printf '%s\n' "$default_route" | awk '/interface:/{print $2; exit}')
	default_route_hash=$(printf '%s\n' "$default_route" | pvn_hash_stdin)
	dns_hash=$(scutil --dns 2>/dev/null | pvn_hash_stdin)
	synthetic_route=false
	if printf '%s\n%s\n' "$inet_routes" "$inet6_routes" |
		grep -Eq '(^|[[:space:]])(198\.51\.100|203\.0\.113)'
	then
		synthetic_route=true
	fi
	native_pids=$(pvn_native_charon_pids | pvn_json_string_array)
	runtime_state=false
	owned_socket=false
	owned_socket_inode=""
	fixed_socket_path="$PVN_RUNTIME_ROOT/charon.vici"
	if [ -S "$fixed_socket_path" ]; then
		owned_socket=true
		owned_socket_inode=$(stat -f '%i' "$fixed_socket_path")
	fi
	if [ -e "$PVN_STATE_FILE" ]; then
		runtime_state=true
		if pvn_validate_state_file "$PVN_STATE_FILE" >/dev/null 2>&1; then
			socket_path=$(pvn_state_value socket_path)
			if [ -S "$socket_path" ]; then
				owned_socket=true
				owned_socket_inode=$(stat -f '%i' "$socket_path")
			fi
		fi
	fi
	generation_count=0
	if [ -d "$PVN_RUNTIME_ROOT" ]; then
		generation_count=$(find "$PVN_RUNTIME_ROOT" -mindepth 1 -maxdepth 1 \
			-type d -name 'generation-*' -print 2>/dev/null | awk 'END { print NR + 0 }')
	fi
	compiled_pid=false
	[ ! -e "$PVN_PID_FILE" ] || compiled_pid=true
	surge_process_identity=$(pvn_process_identity_sha256 exact Surge) || return 1
	surge_extension_identity=$(pvn_process_identity_sha256 pattern \
		'/com\.nssurge\.surge-mac\.ne$') || return 1
	surge_helper_identity=$(pvn_process_identity_sha256 pattern \
		'^/Library/PrivilegedHelperTools/com\.nssurge\.surge-mac\.helper$') || return 1
	surge_cli_identity=$(pvn_process_identity_sha256 exact surge-cli) || return 1
	power_vpn_identity=$(pvn_process_identity_sha256 exact PowerVPN) || return 1
	production_ports=false
	for pid in $(printf '%s' "$native_pids" | jq -r '.[]'); do
		if lsof -nP -a -p "$pid" -iUDP 2>/dev/null | grep -Eq ':(500|4500)[[:space:]]'; then
			production_ports=true
		fi
	done
	setkey_state=unavailable_unprivileged
	setkey_hash=""
	setkey_policy_state=unavailable_unprivileged
	setkey_policy_hash=""
	if [ -x /usr/sbin/setkey ]; then
		if /usr/sbin/setkey -D >/dev/null 2>&1; then
			setkey_state=available
			setkey_hash=$(/usr/sbin/setkey -D 2>/dev/null | pvn_hash_stdin)
		fi
		if /usr/sbin/setkey -DP >/dev/null 2>&1; then
			setkey_policy_state=available
			setkey_policy_hash=$(/usr/sbin/setkey -DP 2>/dev/null | pvn_hash_stdin)
		fi
	fi
	esp_port_state=unavailable
	esp_port_hash=""
	if /usr/sbin/sysctl -n net.inet.ipsec.esp_port >/dev/null 2>&1; then
		esp_port_state=available
		esp_port_hash=$(
			/usr/sbin/sysctl -n net.inet.ipsec.esp_port 2>/dev/null | pvn_hash_stdin
		)
	fi

	jq -n \
		--arg timestamp "$timestamp" \
		--argjson utunNames "$utun_names" \
		--arg interfaceInventorySHA256 "$interface_hash" \
		--argjson ipv4RouteCount "$inet_route_count" \
		--arg ipv4RouteSHA256 "$inet_route_hash" \
		--argjson ipv6RouteCount "$inet6_route_count" \
		--arg ipv6RouteSHA256 "$inet6_route_hash" \
		--arg defaultRouteInterface "$default_interface" \
		--arg defaultRouteSHA256 "$default_route_hash" \
		--arg dnsSHA256 "$dns_hash" \
		--argjson syntheticRouteObserved "$synthetic_route" \
		--argjson nativeCharonPids "$native_pids" \
		--argjson runtimeStatePresent "$runtime_state" \
		--argjson ownedVICISocketPresent "$owned_socket" \
		--arg ownedVICISocketInode "$owned_socket_inode" \
		--argjson compiledPIDFilePresent "$compiled_pid" \
		--argjson generationDirectoryCount "$generation_count" \
		--argjson productionIKEPortsBoundByNative "$production_ports" \
		--argjson surgeProcessCount "$(pvn_count_process Surge)" \
		--arg surgeProcessIdentitySHA256 "$surge_process_identity" \
		--argjson surgeExtensionProcessCount "$(pvn_count_process_pattern '/com\.nssurge\.surge-mac\.ne$')" \
		--arg surgeExtensionProcessIdentitySHA256 "$surge_extension_identity" \
		--argjson surgeHelperProcessCount "$(pvn_count_process_pattern '^/Library/PrivilegedHelperTools/com\.nssurge\.surge-mac\.helper$')" \
		--arg surgeHelperProcessIdentitySHA256 "$surge_helper_identity" \
		--argjson surgeCLIProcessCount "$(pvn_count_process surge-cli)" \
		--arg surgeCLIProcessIdentitySHA256 "$surge_cli_identity" \
		--argjson powerVPNProcessCount "$(pvn_count_process PowerVPN)" \
		--arg powerVPNProcessIdentitySHA256 "$power_vpn_identity" \
		--arg setkeyState "$setkey_state" \
		--arg setkeySHA256 "$setkey_hash" \
		--arg setkeyPolicyState "$setkey_policy_state" \
		--arg setkeyPolicySHA256 "$setkey_policy_hash" \
		--arg espPortState "$esp_port_state" \
		--arg espPortSHA256 "$esp_port_hash" \
		'{
		  schemaVersion: 1,
		  evidenceClass: "value_free_local_network_snapshot",
		  timestamp: $timestamp,
		  utunNames: $utunNames,
		  interfaceInventorySHA256: $interfaceInventorySHA256,
		  ipv4RouteCount: $ipv4RouteCount,
		  ipv4RouteSHA256: $ipv4RouteSHA256,
		  ipv6RouteCount: $ipv6RouteCount,
		  ipv6RouteSHA256: $ipv6RouteSHA256,
		  defaultRouteInterface: $defaultRouteInterface,
		  defaultRouteSHA256: $defaultRouteSHA256,
		  dnsSHA256: $dnsSHA256,
		  syntheticRouteObserved: $syntheticRouteObserved,
		  nativeCharonPids: $nativeCharonPids,
		  runtimeStatePresent: $runtimeStatePresent,
		  ownedVICISocketPresent: $ownedVICISocketPresent,
		  ownedVICISocketInode: $ownedVICISocketInode,
		  compiledPIDFilePresent: $compiledPIDFilePresent,
		  generationDirectoryCount: $generationDirectoryCount,
		  productionIKEPortsBoundByNative: $productionIKEPortsBoundByNative,
		  surgeProcessCount: $surgeProcessCount,
		  surgeProcessIdentitySHA256: $surgeProcessIdentitySHA256,
		  surgeExtensionProcessCount: $surgeExtensionProcessCount,
		  surgeExtensionProcessIdentitySHA256: $surgeExtensionProcessIdentitySHA256,
		  surgeHelperProcessCount: $surgeHelperProcessCount,
		  surgeHelperProcessIdentitySHA256: $surgeHelperProcessIdentitySHA256,
		  surgeCLIProcessCount: $surgeCLIProcessCount,
		  surgeCLIProcessIdentitySHA256: $surgeCLIProcessIdentitySHA256,
		  powerVPNProcessCount: $powerVPNProcessCount,
		  powerVPNProcessIdentitySHA256: $powerVPNProcessIdentitySHA256,
		  setkeyState: $setkeyState,
		  setkeySHA256: $setkeySHA256,
		  setkeyPolicyState: $setkeyPolicyState,
		  setkeyPolicySHA256: $setkeyPolicySHA256,
		  espPortState: $espPortState,
		  espPortSHA256: $espPortSHA256,
		  containsSecrets: false,
		  containsRawRoutes: false,
		  containsRawSAState: false
		}'
}
