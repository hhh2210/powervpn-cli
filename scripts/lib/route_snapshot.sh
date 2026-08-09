#!/bin/sh

pvn_checked_hash_file() {
	hash_output=$(/usr/bin/shasum -a 256 "$1") || return 1
	hash_value=${hash_output%% *}
	case "$hash_value" in
	'' | *[!0-9a-f]*) return 1 ;;
	esac
	[ "${#hash_value}" -eq 64 ] || return 1
	printf '%s\n' "$hash_value"
}

pvn_hash_stdin() (
	set -eu
	umask 077
	hash_root=$(mktemp -d "${TMPDIR:-/private/tmp}/powervpn-hash.XXXXXX")
	hash_input="$hash_root/input"
	trap 'rm -f -- "$hash_input"; rmdir "$hash_root"' EXIT HUP INT TERM
	/bin/cat >"$hash_input" || exit 1
	chmod 600 "$hash_input"
	pvn_checked_hash_file "$hash_input" || exit 1
)

pvn_checked_hash_command() (
	set -eu
	[ "$#" -gt 0 ]
	umask 077
	hash_root=$(mktemp -d "${TMPDIR:-/private/tmp}/powervpn-command-hash.XXXXXX")
	hash_input="$hash_root/input"
	trap 'rm -f -- "$hash_input"; rmdir "$hash_root"' EXIT HUP INT TERM
	"$@" >"$hash_input" || exit 1
	chmod 600 "$hash_input"
	pvn_checked_hash_file "$hash_input" || exit 1
)

pvn_route_records() {
	route_family=$1
	case "$route_family" in
	inet) route_banner=Internet: ;;
	inet6) route_banner=Internet6: ;;
	*) return 1 ;;
	esac
	LC_ALL=C awk -v family="$route_family" -v banner="$route_banner" '
		BEGIN { phase = 0; order = "UGHRDMmdCXLS12Wc3BbIiYrg" }
		NR == 1 { if ($0 != "Routing tables") bad = 1; next }
		/^[[:space:]]*$/ { next }
		phase == 0 { if ($0 != banner) bad = 1; phase = 1; next }
		phase == 1 {
			if (NF != 5 || $1 != "Destination" || $2 != "Gateway" ||
				$3 != "Flags" || $4 != "Netif" || $5 != "Expire") bad = 1
			phase = 2
			next
		}
		phase == 2 {
			if (NF != 4 && NF != 5) { bad = 1; next }
			if ($1 !~ /^[!-~]+$/ || $2 !~ /^[!-~]+$/ ||
				$3 !~ /^[[:alnum:]]+$/ || length($3) > 10 ||
				$4 !~ /^[[:alpha:]][[:alnum:]_.:-]*$/) { bad = 1; next }
			last = 0
			for (i = 1; i <= length($3); i++) {
				position = index(order, substr($3, i, 1))
				if (!position || position <= last) bad = 1
				last = position
			}
			if (NF == 5 && $5 != "!" && $5 !~ /^[1-9][0-9]*$/) bad = 1
			if (bad) next
			printf "%s\t%s\t%s\t%s\t%s\t%d\t%d\n", family, $1, $2, $3, $4,
				(NF == 5), (index($3, "W") != 0)
			rows++
			next
		}
		{ bad = 1 }
		END { exit (bad || phase != 2 || rows == 0) }
	'
}

pvn_route_project_file() {
	projection=$1
	record_file=$2
	case "$projection" in
	structural)
		awk -F '\t' 'NF == 7 {print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5}
		  NF != 7 {bad=1} END {exit bad}' "$record_file"
		;;
	persistent)
		awk -F '\t' 'NF == 7 && $6 == 0 && $7 == 0 {
		    print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5
		  } NF != 7 {bad=1} END {exit bad}' "$record_file"
		;;
	*) return 1 ;;
	esac
}

pvn_route_sort_file() {
	LC_ALL=C sort "$1" -o "$1"
}

pvn_route_count_file() {
	route_count=$(awk 'END {print NR + 0}' "$1") || return 1
	case "$route_count" in
	'' | *[!0-9]*) return 1 ;;
	esac
	printf '%s\n' "$route_count"
}

pvn_route_fingerprint_file() {
	route_family=$1
	raw_file=$2
	work_root=$3
	record_file="$work_root/$route_family.records"
	structural_file="$work_root/$route_family.structural"
	persistent_file="$work_root/$route_family.persistent"
	pvn_route_records "$route_family" <"$raw_file" >"$record_file" || return 1
	pvn_route_project_file structural "$record_file" >"$structural_file" || return 1
	pvn_route_project_file persistent "$record_file" >"$persistent_file" || return 1
	pvn_route_sort_file "$structural_file" || return 1
	pvn_route_sort_file "$persistent_file" || return 1
	structural_count=$(pvn_route_count_file "$structural_file") || return 1
	persistent_count=$(pvn_route_count_file "$persistent_file") || return 1
	[ "$persistent_count" -gt 0 ] || return 1
	structural_hash=$(pvn_checked_hash_file "$structural_file") || return 1
	persistent_hash=$(pvn_checked_hash_file "$persistent_file") || return 1
	synthetic=false
	if grep -Eq '(^|[[:space:]])(198\.51\.100|203\.0\.113)' "$raw_file"; then
		synthetic=true
	else
		grep_rc=$?
		[ "$grep_rc" -eq 1 ] || return 1
	fi
	printf '%s\t%s\t%s\t%s\t%s\n' "$structural_count" "$structural_hash" \
		"$persistent_count" "$persistent_hash" "$synthetic"
}

pvn_capture_route_fingerprint() (
	set -eu
	route_family=$1
	case "$route_family" in inet | inet6) ;; *) exit 1 ;; esac
	umask 077
	route_root=$(mktemp -d "${TMPDIR:-/private/tmp}/powervpn-route.XXXXXX")
	raw_file="$route_root/$route_family.raw"
	trap 'rm -f -- "$route_root"/*; rmdir "$route_root"' EXIT HUP INT TERM
	/usr/sbin/netstat -rn -f "$route_family" >"$raw_file" 2>/dev/null || exit 1
	chmod 600 "$raw_file"
	pvn_route_fingerprint_file "$route_family" "$raw_file" "$route_root" || exit 1
)

pvn_default_route_interface() {
	LC_ALL=C awk '
		$1 == "interface:" {
			count++
			if (NF != 2 || $2 !~ /^[[:alpha:]][[:alnum:]_.:-]*$/) bad = 1
			interface = $2
		}
		END { if (bad || count != 1) exit 1; print interface }
	'
}

pvn_capture_default_route() (
	set -eu
	route_command=${1:-/sbin/route}
	umask 077
	default_root=$(mktemp -d "${TMPDIR:-/private/tmp}/powervpn-default-route.XXXXXX")
	default_file="$default_root/default"
	trap 'rm -f -- "$default_file"; rmdir "$default_root"' EXIT HUP INT TERM
	"$route_command" -n get default >"$default_file" 2>/dev/null || exit 1
	chmod 600 "$default_file"
	default_interface=$(pvn_default_route_interface <"$default_file") || exit 1
	default_hash=$(pvn_checked_hash_file "$default_file") || exit 1
	printf '%s\t%s\n' "$default_interface" "$default_hash"
)
