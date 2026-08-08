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
			-type d -name 'generation-*' -print | awk 'END { print NR + 0 }')
	fi
	compiled_pid=false
	[ ! -e "$PVN_PID_FILE" ] || compiled_pid=true
	production_ports=false
	for pid in $(printf '%s' "$native_pids" | jq -r '.[]'); do
		if lsof -nP -a -p "$pid" -iUDP 2>/dev/null | grep -Eq ':(500|4500)[[:space:]]'; then
			production_ports=true
		fi
	done
	setkey_state=unavailable_unprivileged
	setkey_hash=""
	if [ -x /usr/sbin/setkey ]; then
		setkey_output=$(/usr/sbin/setkey -D 2>/dev/null || true)
		if [ -n "$setkey_output" ]; then
			setkey_state=available
			setkey_hash=$(printf '%s\n' "$setkey_output" | pvn_hash_stdin)
		fi
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
		--argjson surgeExtensionProcessCount "$(pvn_count_process_pattern '/com\.nssurge\.surge-mac\.ne$')" \
		--argjson surgeHelperProcessCount "$(pvn_count_process_pattern '^/Library/PrivilegedHelperTools/com\.nssurge\.surge-mac\.helper$')" \
		--argjson surgeCLIProcessCount "$(pvn_count_process surge-cli)" \
		--argjson powerVPNProcessCount "$(pvn_count_process PowerVPN)" \
		--arg setkeyState "$setkey_state" \
		--arg setkeySHA256 "$setkey_hash" \
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
		  surgeExtensionProcessCount: $surgeExtensionProcessCount,
		  surgeHelperProcessCount: $surgeHelperProcessCount,
		  surgeCLIProcessCount: $surgeCLIProcessCount,
		  powerVPNProcessCount: $powerVPNProcessCount,
		  setkeyState: $setkeyState,
		  setkeySHA256: $setkeySHA256,
		  containsSecrets: false,
		  containsRawRoutes: false
		}'
}
