#!/bin/sh

pvn_cp7b_validate_attempt_ledger() {
	[ -f "$PVN_CP7B_LEDGER" ] && [ ! -L "$PVN_CP7B_LEDGER" ] ||
		pvn_fail "CP7B attempt ledger is missing or a symlink" || return 1
	[ "$(stat -f '%u' "$PVN_CP7B_LEDGER")" = "$(id -u)" ] ||
		pvn_fail "CP7B attempt ledger owner changed" || return 1
	[ "$(stat -f '%Lp' "$PVN_CP7B_LEDGER")" = 600 ] ||
		pvn_fail "CP7B attempt ledger mode changed" || return 1
	awk -F= '
		NF != 2 { bad = 1 }
		$1 !~ /^(schema|backend|window_started_epoch|attempts)$/ { bad = 1 }
		seen[$1]++ { bad = 1 }
		END { exit (bad || length(seen) != 4) }
	' "$PVN_CP7B_LEDGER" || pvn_fail "CP7B attempt ledger schema is invalid" || return 1
	[ "$(pvn_cp7b_state_value schema "$PVN_CP7B_LEDGER")" = 1 ] || return 1
	[ "$(pvn_cp7b_state_value backend "$PVN_CP7B_LEDGER")" = pfkey-pfroute ] || return 1
}

pvn_cp7b_begin_attempt() {
	now=$1
	if [ -e "$PVN_CP7B_LEDGER" ]; then
		pvn_cp7b_validate_attempt_ledger || return 1
		started=$(pvn_cp7b_state_value window_started_epoch "$PVN_CP7B_LEDGER")
		attempts=$(pvn_cp7b_state_value attempts "$PVN_CP7B_LEDGER")
	else
		started=$now
		attempts=0
	fi
	case "$started:$attempts" in
	*[!0-9:]*) pvn_fail "CP7B attempt ledger values are invalid" || return 1 ;;
	esac
	[ "$attempts" -lt 2 ] || pvn_fail "CP7B two-launch limit is exhausted" || return 1
	[ $((now - started)) -le 300 ] ||
		pvn_fail "CP7B five-minute approval window expired" || return 1
	attempts=$((attempts + 1))
	temp_ledger="$PVN_CP7B_RUNTIME_ROOT/.attempt-ledger.$$"
	{
		printf '%s\n' \
			'schema=1' \
			'backend=pfkey-pfroute' \
			"window_started_epoch=$started" \
			"attempts=$attempts"
	} >"$temp_ledger"
	chmod 600 "$temp_ledger"
	mv -f -- "$temp_ledger" "$PVN_CP7B_LEDGER"
	PVN_CP7B_ATTEMPT=$attempts
	PVN_CP7B_WINDOW_STARTED=$started
	export PVN_CP7B_ATTEMPT PVN_CP7B_WINDOW_STARTED
}

pvn_cp7b_clear_attempt_ledger() {
	if [ -e "$PVN_CP7B_LEDGER" ]; then
		pvn_cp7b_validate_attempt_ledger || return 1
		rm -f -- "$PVN_CP7B_LEDGER"
	fi
}
