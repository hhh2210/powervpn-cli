#!/bin/sh

set -eu
umask 077

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
runner="$repo_root/scripts/run_r2_tls_evidence.sh"
R2TLS_REPO_ROOT=$repo_root
# shellcheck source=scripts/lib/r2_tls_evidence_runtime.sh
. "$repo_root/scripts/lib/r2_tls_evidence_runtime.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_monitor.sh
. "$repo_root/scripts/lib/r2_tls_evidence_monitor.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_result.sh
. "$repo_root/scripts/lib/r2_tls_evidence_result.sh"
# shellcheck source=scripts/lib/r2_tls_evidence_deadline.sh
. "$repo_root/scripts/lib/r2_tls_evidence_deadline.sh"

deadline_only=false
if [ "$#" -eq 1 ] && [ "$1" = --deadline-only ]; then deadline_only=true
elif [ "$#" -ne 0 ]; then exit 2
fi

test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
case_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r2-tls-runtime.XXXXXX")
chmod 700 "$case_root"
server_pid=; client_pid=; monitor_pid=; deadline_pid=; deadline_target_pid=
cleanup() {
	exit_status=$?; trap - EXIT HUP INT TERM
	for cleanup_pid in "$deadline_pid" "$deadline_target_pid" "$monitor_pid" \
		"$client_pid" "$server_pid"; do
		[ -z "$cleanup_pid" ] || ! r2tls_runner_owned_process_alive "$cleanup_pid" "$$" ||
			/bin/kill -KILL "$cleanup_pid" 2>/dev/null || true
		[ -z "$cleanup_pid" ] || wait "$cleanup_pid" 2>/dev/null || true
	done
	find "$case_root" -type f -delete 2>/dev/null || true
	find "$case_root" -type p -delete 2>/dev/null || true
	find "$case_root" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	exit "$exit_status"
}
trap cleanup EXIT HUP INT TERM

R2TLS_ENDPOINT=127.0.0.1:4443
sealed_fixture=$(printf '%s\n' p1 f3 PTCP \
	'n127.0.0.1:50000->127.0.0.1:4443 (ESTABLISHED)' |
	r2tls_monitor_summarize_lsof)
[ "$sealed_fixture" = "$(printf '1\t0\ttrue')" ]
mixed_fixture=$(printf '%s\n' p1 f3 PTCP \
	'n127.0.0.1:50000->127.0.0.1:4443 (ESTABLISHED)' f4 PUDP \
	'n127.0.0.1:50001' | r2tls_monitor_summarize_lsof)
[ "$mixed_fixture" = "$(printf '1\t1\tfalse')" ]
wrong_fixture=$(printf '%s\n' p1 f3 PTCP \
	'n127.0.0.1:50000->127.0.0.1:4444 (ESTABLISHED)' |
	r2tls_monitor_summarize_lsof)
[ "$wrong_fixture" = "$(printf '1\t0\tfalse')" ]
for malformed_fixture in \
	'f3\nPTCP\nn127.0.0.1:1->127.0.0.1:4443' \
	'p1\nPTCP\nn127.0.0.1:1->127.0.0.1:4443' \
	'p1\np1\nf3\nPTCP\nn127.0.0.1:1->127.0.0.1:4443' \
	'p1\nf3\nf4\nPTCP\nn127.0.0.1:1->127.0.0.1:4443' \
	'p1\nf3\nPTCP' 'n127.0.0.1:1->127.0.0.1:4443' \
	'p1\nf3\nPBOGUS\nn127.0.0.1:1' 'Xunknown'; do
	if printf '%b\n' "$malformed_fixture" | r2tls_monitor_summarize_lsof >/dev/null; then exit 1; fi
done

if [ "$deadline_only" = false ]; then
port_file="$case_root/port"
server_code='import socket,time,sys; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(1); open(sys.argv[1],"w").write(str(s.getsockname()[1])); c,_=s.accept(); time.sleep(3)'
/usr/bin/python3 -c "$server_code" "$port_file" & server_pid=$!
attempt=0
while [ ! -s "$port_file" ] && [ "$attempt" -lt 200 ]; do
	attempt=$((attempt + 1)); sleep 0.01
done
[ "$attempt" -lt 200 ]; port=$(cat "$port_file")
client_code='import socket,time,sys; s=socket.socket(); s.connect(("127.0.0.1",int(sys.argv[1]))); time.sleep(3)'
/usr/bin/python3 -c "$client_code" "$port" & client_pid=$!
attempt=0
while ! /usr/sbin/lsof -nP -a -p "$client_pid" -i -F Pn >/dev/null 2>&1 &&
	[ "$attempt" -lt 200 ]; do attempt=$((attempt + 1)); sleep 0.01; done
[ "$attempt" -lt 200 ]; R2TLS_ENDPOINT=127.0.0.1:$port
client_comm=$(r2tls_monitor_ps_field "$client_pid" comm)
client_command=$(r2tls_monitor_ps_field "$client_pid" command)
monitor_ready="$case_root/localhost.ready"; monitor_stop="$case_root/localhost.stop"
monitor_output="$case_root/localhost-monitor.json"
r2tls_monitor_exact_child "$client_pid" "$$" "$client_comm" "$client_command" \
	"$monitor_ready" "$monitor_stop" "$monitor_output" & monitor_pid=$!
attempt=0
while [ ! -f "$monitor_ready" ] && [ "$attempt" -lt 200 ]; do
	attempt=$((attempt + 1)); sleep 0.01
done
[ "$attempt" -lt 200 ]; sleep 0.05; r2tls_create_sentinel "$monitor_stop"
wait "$monitor_pid"; monitor_pid=
jq -e '.targetIdentityExact and .targetIdentityStable and .inspectionSucceeded and
  .sealedEndpointTCPObserved and .onlySealedEndpointTCP and
  .maximumTCPCount==1 and .maximumUDPCount==0' "$monitor_output" >/dev/null
/bin/kill -TERM "$client_pid" "$server_pid"; set +e
wait "$client_pid"; wait "$server_pid"; set -e; client_pid=; server_pid=

/bin/cp /bin/sleep "$case_root/exit-cli"; chmod 700 "$case_root/exit-cli"
"$case_root/exit-cli" 1000 & client_pid=$!
exit_comm=$(r2tls_monitor_ps_field "$client_pid" comm)
exit_command=$(r2tls_monitor_ps_field "$client_pid" command)
exit_ready="$case_root/exit.ready"; exit_stop="$case_root/exit.stop"
exit_output="$case_root/exit-monitor.json"
(
	r2tls_monitor_socket_summary() {
		/bin/kill -TERM "$1" 2>/dev/null || true; printf '0\t0\ttrue\n'
	}
	r2tls_monitor_exact_child "$client_pid" "$$" "$exit_comm" "$exit_command" \
		"$exit_ready" "$exit_stop" "$exit_output"
) & monitor_pid=$!
attempt=0
while /bin/ps -p "$client_pid" -o state= 2>/dev/null | grep -qv 'Z' &&
	[ "$attempt" -lt 200 ]; do attempt=$((attempt + 1)); sleep 0.01; done
set +e; wait "$client_pid"; set -e; client_pid=
r2tls_create_sentinel "$exit_stop"; wait "$monitor_pid"; monitor_pid=
jq -e '.targetObserved and .targetIdentityStable and .inspectionAttemptCount>=1 and
  .inspectionSuccessCount==0 and .inspectionFailureCount==0 and
  (.inspectionSucceeded|not)' "$exit_output" >/dev/null
fi

prepare_guard_case() {
	guard_name=$1; deadline_ready="$case_root/$guard_name.ready"
	deadline_expired="$case_root/$guard_name.expired"
	deadline_stop="$case_root/$guard_name.stop"; deadline_ack="$case_root/$guard_name.ack"
	R2TLS_DEADLINE_FILE=$deadline_expired; deadline_pid=; deadline_stopped=true
	deadline_acknowledged=false; harness_kill=false
}
wait_guard_ready() {
	guard_attempt=0
	while [ ! -f "$deadline_ready" ] && [ "$guard_attempt" -lt 100 ]; do
		guard_attempt=$((guard_attempt + 1)); sleep 0.01
	done
	[ "$guard_attempt" -lt 100 ]
}
stop_guard_target() {
	[ -z "$deadline_target_pid" ] || /bin/kill -TERM "$deadline_target_pid" 2>/dev/null || true
	[ -z "$deadline_target_pid" ] || { set +e; wait "$deadline_target_pid"; set -e; }
	deadline_target_pid=
}

prepare_guard_case near-deadline
/bin/sleep 5 & deadline_target_pid=$!
r2tls_deadline_guard "$deadline_ready" "$deadline_expired" "$deadline_stop" "$deadline_ack" \
	800 "$deadline_target_pid" 2>"$case_root/near-deadline.stderr" &
deadline_pid=$!; near_guard_pid=$deadline_pid; deadline_stopped=false
wait_guard_ready; sleep 0.55; stop_deadline_guard
[ "$deadline_stopped" = true ] && [ "$deadline_acknowledged" = true ] &&
	[ "$deadline_waited" = true ] && r2tls_deadline_ack_exact "$deadline_ack" "$near_guard_pid" &&
	[ "$harness_kill" = false ] && r2tls_deadline_open &&
	! /bin/kill -0 "$near_guard_pid" 2>/dev/null
stop_guard_target

prepare_guard_case expiry-wins
/bin/sleep 5 & deadline_target_pid=$!
r2tls_deadline_guard "$deadline_ready" "$deadline_expired" "$deadline_stop" "$deadline_ack" \
	80 "$deadline_target_pid" 2>"$case_root/expiry-wins.stderr" &
deadline_pid=$!; expiry_guard_pid=$deadline_pid; deadline_stopped=false
wait_guard_ready
guard_attempt=0
while [ ! -f "$deadline_expired" ] && [ "$guard_attempt" -lt 100 ]; do
	guard_attempt=$((guard_attempt + 1)); sleep 0.01
done
[ -f "$deadline_expired" ]
guard_attempt=0
while owned_aux_alive "$deadline_pid" && [ "$guard_attempt" -lt 100 ]; do
	guard_attempt=$((guard_attempt + 1)); sleep 0.01
done
if owned_aux_alive "$deadline_pid"; then exit 1; fi
stop_deadline_guard
[ "$deadline_stopped" = true ] && [ "$deadline_acknowledged" = false ] &&
	[ "$harness_kill" = false ] && ! r2tls_deadline_open &&
	! /bin/kill -0 "$expiry_guard_pid" 2>/dev/null
stop_guard_target

prepare_guard_case kill-escalation
/usr/bin/perl -e '$SIG{TERM}="IGNORE"; select undef,undef,undef,5' & deadline_pid=$!
kill_guard_pid=$deadline_pid; deadline_stopped=false; sleep 0.05
{ stop_deadline_guard; } 2>"$case_root/kill-escalation.stderr"
[ "$deadline_stopped" = true ] && [ "$deadline_acknowledged" = false ] &&
	[ "$harness_kill" = true ] && ! /bin/kill -0 "$kill_guard_pid" 2>/dev/null

all_true='true true true true true true true true true true true true true true true true true'
# shellcheck disable=SC2086
r2tls_execution_safety_pass $all_true
for unsafe_position in 1 8 11 12 13 14 15 16 17; do
	unsafe_states=; unsafe_index=0
	for unsafe_state in $all_true; do
		unsafe_index=$((unsafe_index + 1))
		[ "$unsafe_index" -ne "$unsafe_position" ] || unsafe_state=false
		unsafe_states="${unsafe_states}${unsafe_states:+ }$unsafe_state"
	done
	# shellcheck disable=SC2086
	if r2tls_execution_safety_pass $unsafe_states; then exit 1; fi
done

run_deadline_case() {
	deadline_selector=$1; deadline_binary=$2
	deadline_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-r2-tls-test.XXXXXX")
	chmod 700 "$deadline_root"; /bin/cp "$deadline_binary" "$deadline_root/fake-cli"
	chmod 700 "$deadline_root/fake-cli"; printf '{}\n' >"$deadline_root/fake-report.json"
	chmod 600 "$deadline_root/fake-report.json"
	started=$(r2tls_monotonic_milliseconds)
	set +e
	POWERVPN_R2_TLS_TEST_ACTIVE_MONITOR="$deadline_selector" \
		POWERVPN_R2_TLS_TEST_SCRATCH_ROOT="$deadline_root" \
		"$runner" --preflight-only >"$deadline_root/stdout" 2>"$deadline_root/stderr"
	deadline_rc=$?
	set -e; elapsed=$(($(r2tls_monotonic_milliseconds) - started))
	# Wall time includes the reviewed full-tree manifest rehash before the 300 ms
	# synthetic guard starts; keep that setup bounded without making load flaky.
	[ "$deadline_rc" -eq 124 ] && [ "$elapsed" -ge 250 ] && [ "$elapsed" -le 5000 ]
	deadline_evidence=$(find "$deadline_root" -name incomplete-deadline.json -type f -print)
	[ "$(printf '%s\n' "$deadline_evidence" | awk 'NF{n++} END{print n+0}')" -eq 1 ]
	jq -e '.schemaVersion==2 and .evidenceClass=="r2_tls_peer_incomplete_deadline" and
    .complete==false and .deadlineReached and (.networkStarted|not) and
    .ownedEvidenceCLIStopped and .monitorStopped and .validatorStopped and
    .gateWriterStopped and .phaseStopped and .deadlineGuardStopped and
    .helperKillSent==false and .containsSecrets==false and
    .containsRawCertificate==false' "$deadline_evidence" >/dev/null
	[ -z "$(find "$deadline_root" \( -type p -o -name '.monitor-*' -o \
		-name '.deadline-*' \) -print)" ]
	if /bin/ps -axo command= | grep -F "$deadline_root" | grep -v grep >/dev/null; then exit 1; fi
	find "$deadline_root" -type f -delete; find "$deadline_root" -type p -delete
	find "$deadline_root" -depth -type d -exec rmdir {} \;
}
run_deadline_case reviewed-no-network-deadline-gate-v1 /bin/sleep
run_deadline_case reviewed-no-network-deadline-validator-v1 /bin/cat

if [ "$deadline_only" = true ]; then
	printf '%s\n' 'R2 TLS monitor/deadline tests: PASS (offline synthetic only)'
else printf '%s\n' 'R2 TLS monitor/deadline tests: PASS (localhost and synthetic only)'; fi
