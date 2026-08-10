#!/bin/sh

# Exact-process, value-free network monitor for the R2 TLS evidence runner.
# The caller must source r2_tls_evidence_runtime.sh first.

r2tls_monitor_ps_field() {
	/bin/ps -ww -p "$1" -o "$2=" 2>/dev/null | awk '
    NR == 1 {
      sub(/^[[:space:]]*/, ""); sub(/[[:space:]]*$/, "")
      print; found=1
    }
    END { exit !found }
  '
}

r2tls_monitor_live_pid() {
	monitor_state=$(r2tls_monitor_ps_field "$1" state) || return 1
	case "$monitor_state" in Z*) return 1 ;; esac
}

r2tls_monitor_owned_live_child() {
	monitor_ppid=$(r2tls_monitor_ps_field "$1" ppid) || return 1
	[ "$monitor_ppid" = "$2" ] && r2tls_monitor_live_pid "$1"
}

r2tls_monitor_exact_identity() {
	monitor_pid=$1; monitor_parent=$2; monitor_comm_expected=$3; monitor_command_expected=$4
	r2tls_monitor_owned_live_child "$monitor_pid" "$monitor_parent" || return 1
	monitor_comm=$(r2tls_monitor_ps_field "$monitor_pid" comm) || return 1
	monitor_command=$(r2tls_monitor_ps_field "$monitor_pid" command) || return 1
	[ "$monitor_comm" = "$monitor_comm_expected" ] &&
		[ "$monitor_command" = "$monitor_command_expected" ] || return 1
	# Recheck ownership after the image fields to reject an exit/reuse race.
	r2tls_monitor_owned_live_child "$monitor_pid" "$monitor_parent"
}

r2tls_monitor_summarize_lsof() {
	awk -v endpoint="$R2TLS_ENDPOINT" '
	    BEGIN { only=1; state="process"; records=0; malformed=0 }
	    /^p[0-9]+$/ {
	      if (state!="process") malformed=1
	      else state="file"
	      next
	    }
	    /^f[^[:space:]]+$/ {
	      if (state!="file") malformed=1
	      else state="protocol"
	      next
	    }
	    /^P(TCP|UDP)$/ {
	      if (state!="protocol") malformed=1
	      else { protocol=substr($0,2); state="name" }
	      next
	    }
	    /^n/ {
	      if (state!="name" || length($0)==1) { malformed=1; next }
	      name=substr($0,2); sub(/ \([^)]*\)$/, "", name)
      if (protocol=="TCP") {
        tcp++; suffix="->" endpoint
        if (length(name)<length(suffix) ||
          substr(name,length(name)-length(suffix)+1)!=suffix) only=0
      } else if (protocol=="UDP") { udp++; only=0 }
	      records++; protocol=""; state="file"; next
	    }
	    { malformed=1 }
	    END {
	      if (state!="file" || records<1 || malformed) exit 2
	      printf "%d\t%d\t%s\n",tcp+0,udp+0,only?"true":"false"
	    }
	  '
}

r2tls_monitor_lsof_summary() {
	set +e
	monitor_lsof=$(/usr/sbin/lsof -nP -a -p "$1" -i -F Pn 2>/dev/null)
	monitor_lsof_rc=$?
	set -e
	if [ "$monitor_lsof_rc" -eq 1 ] && [ -z "$monitor_lsof" ]; then
		printf '0\t0\ttrue\n'
		return 0
	fi
	[ "$monitor_lsof_rc" -eq 0 ] || return 1
	printf '%s\n' "$monitor_lsof" | r2tls_monitor_summarize_lsof
}

# This indirection is overridden only by direct, no-network synthetic tests.
r2tls_monitor_socket_summary() { r2tls_monitor_lsof_summary "$1"; }

r2tls_monitor_exact_child() (
	target_pid=$1; runner_pid=$2; expected_comm=$3; expected_command=$4
	ready_file=$5; stop_file=$6; output_file=$7
	target=false; identity_stable=true; only=true; tcp_seen=false
	attempts=0; successes=0; failures=0; max_tcp=0; max_udp=0
	helper=false; native=false
	r2tls_monitor_owned_live_child "$target_pid" "$runner_pid" || exit 1
	r2tls_create_sentinel "$ready_file" || exit 1
	while [ ! -e "$stop_file" ]; do
		if r2tls_monitor_exact_identity "$target_pid" "$runner_pid" \
			"$expected_comm" "$expected_command"; then
			target=true; attempts=$((attempts + 1))
			if summary=$(r2tls_monitor_socket_summary "$target_pid") &&
				r2tls_monitor_exact_identity "$target_pid" "$runner_pid" \
					"$expected_comm" "$expected_command"; then
				old_ifs=$IFS; IFS=$(printf '\t')
				# shellcheck disable=SC2086
				set -- $summary
				IFS=$old_ifs
				if [ "$#" -ne 3 ]; then failures=$((failures + 1)); else
					successes=$((successes + 1))
					[ "$1" -le "$max_tcp" ] || max_tcp=$1
					[ "$2" -le "$max_udp" ] || max_udp=$2
					[ "$1" -eq 0 ] || tcp_seen=true
					[ "$3" = true ] || only=false
				fi
			elif r2tls_monitor_live_pid "$target_pid"; then
				failures=$((failures + 1))
				if ! r2tls_monitor_exact_identity "$target_pid" "$runner_pid" \
						"$expected_comm" "$expected_command"; then
					identity_stable=false
				fi
			fi
		elif [ "$target" = true ] && r2tls_monitor_live_pid "$target_pid"; then
			identity_stable=false
		fi
		r2tls_helpers_absent || helper=true
		r2tls_native_absent || native=true
		sleep 0.01
	done
	stable=false; [ "$target" = true ] && [ "$identity_stable" = true ] && stable=true
	inspection=false
	[ "$stable" = true ] && [ "$attempts" -gt 0 ] && [ "$successes" -gt 0 ] &&
		[ "$failures" -eq 0 ] && inspection=true
	jq -n --argjson seen "$target" --argjson exact "$target" --argjson stable "$stable" \
		--argjson inspected "$inspection" --argjson attempts "$attempts" \
		--argjson successes "$successes" --argjson failures "$failures" \
		--argjson only "$only" --argjson tcpSeen "$tcp_seen" --argjson tcp "$max_tcp" \
		--argjson udp "$max_udp" --argjson helper "$helper" --argjson native "$native" \
		'{schemaVersion:2,evidenceClass:"r2_tls_process_monitor",
      targetObserved:$seen,targetIdentityExact:$exact,targetIdentityStable:$stable,
      inspectionAttemptCount:$attempts,inspectionSuccessCount:$successes,
      inspectionFailureCount:$failures,inspectionSucceeded:$inspected,
      onlySealedEndpointTCP:$only,sealedEndpointTCPObserved:$tcpSeen,
      maximumTCPCount:$tcp,maximumUDPCount:$udp,vendorHelperObserved:$helper,
      nativeCharonObserved:$native}' >"$output_file"
	chmod 600 "$output_file"
)
