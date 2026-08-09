#!/bin/sh

pvn_cp7b_bind_root_bundle() {
	bundle_root=$1
	case "$bundle_root" in
	"$PVN_CP7B_RUNTIME_ROOT"/.bootstrap-*) ;;
	*) pvn_fail "CP7B reviewed worker requires a fixed bootstrap bundle" || return 1 ;;
	esac
	[ -d "$bundle_root" ] && [ ! -L "$bundle_root" ] ||
		pvn_fail "CP7B bootstrap bundle is invalid" || return 1
	[ "$(stat -f '%u' "$bundle_root")" -eq 0 ] ||
		pvn_fail "CP7B bootstrap bundle is not root-owned" || return 1
	[ "$(stat -f '%Lp' "$bundle_root")" = 700 ] ||
		pvn_fail "CP7B bootstrap bundle mode is not 700" || return 1

	PVN_CP7B_RUNTIME_SCRIPT="$bundle_root/lib/cp7b_runtime.sh"
	PVN_CP7B_CLOSURE_SCRIPT="$bundle_root/lib/cp7b_closure.sh"
	PVN_CP7B_STATE_SCRIPT="$bundle_root/lib/cp7b_state.sh"
	PVN_CP7B_ATTEMPTS_SCRIPT="$bundle_root/lib/cp7b_attempts.sh"
	PVN_CP7B_SNAPSHOT_SCRIPT="$bundle_root/lib/cp7b_snapshot.sh"
	PVN_CP7B_BUNDLE_SCRIPT="$bundle_root/lib/cp7b_bundle.sh"
	PVN_CP7B_NATIVE_SCRIPT="$bundle_root/lib/native_charon_runtime.sh"
	PVN_CP7B_ROUTE_SCRIPT="$bundle_root/lib/route_snapshot.sh"
	PVN_CP7B_NETWORK_SCRIPT="$bundle_root/lib/network_snapshot.sh"
	PVN_CP7B_WORKER="$bundle_root/cp7b_backend_window.sh"
	PVN_CP7B_ROOT_ENTRY="$bundle_root/root-entry.sh"
	PVN_CP7B_EMERGENCY_SOURCE="$bundle_root/cp7b_emergency_stop.sh"
	PVN_CP7B_ORACLE="$bundle_root/official_vici_runtime.py"
	PVN_CP7B_READONLY_PROBE="$bundle_root/cp7b_vici_readonly.py"
	PVN_CP7B_MANIFEST="$bundle_root/approval-manifest.json"
	PVN_CP7B_PYTHON_ROOT="$bundle_root/python"
	PVN_CP7B_PY_INIT="$bundle_root/python/vici/__init__.py"
	PVN_CP7B_PY_COMMAND_WRAPPERS="$bundle_root/python/vici/command_wrappers.py"
	PVN_CP7B_PY_EVENT_LISTENER="$bundle_root/python/vici/event_listener.py"
	PVN_CP7B_PY_EXCEPTION="$bundle_root/python/vici/exception.py"
	PVN_CP7B_PY_PROTOCOL="$bundle_root/python/vici/protocol.py"
	PVN_CP7B_PY_SESSION="$bundle_root/python/vici/session.py"
	PVN_CP7B_REVIEWED_INPUT_OWNER=0
	PVN_CP7B_ARTIFACT_OWNER=0
	export PVN_CP7B_RUNTIME_SCRIPT PVN_CP7B_CLOSURE_SCRIPT PVN_CP7B_STATE_SCRIPT
	export PVN_CP7B_ATTEMPTS_SCRIPT
	export PVN_CP7B_SNAPSHOT_SCRIPT PVN_CP7B_BUNDLE_SCRIPT PVN_CP7B_NATIVE_SCRIPT
	export PVN_CP7B_ROUTE_SCRIPT
	export PVN_CP7B_NETWORK_SCRIPT PVN_CP7B_WORKER PVN_CP7B_ROOT_ENTRY
	export PVN_CP7B_EMERGENCY_SOURCE PVN_CP7B_ORACLE PVN_CP7B_READONLY_PROBE
	export PVN_CP7B_MANIFEST
	export PVN_CP7B_PYTHON_ROOT PVN_CP7B_PY_INIT PVN_CP7B_PY_COMMAND_WRAPPERS
	export PVN_CP7B_PY_EVENT_LISTENER PVN_CP7B_PY_EXCEPTION PVN_CP7B_PY_PROTOCOL
	export PVN_CP7B_PY_SESSION PVN_CP7B_REVIEWED_INPUT_OWNER PVN_CP7B_ARTIFACT_OWNER
	# The root-owned source path is fixed immediately above.
	# shellcheck disable=SC1090
	. "$PVN_CP7B_CLOSURE_SCRIPT"
}

pvn_cp7b_cleanup_root_bundle() {
	bundle_root=$1
	case "$bundle_root" in
	"$PVN_CP7B_RUNTIME_ROOT"/.bootstrap-*) ;;
	*) pvn_fail "refusing to clean an unexpected CP7B bootstrap path" || return 1 ;;
	esac
	[ -d "$bundle_root" ] && [ ! -L "$bundle_root" ] ||
		pvn_fail "CP7B bootstrap root is invalid" || return 1
	[ "$(stat -f '%u' "$bundle_root")" -eq 0 ] ||
		pvn_fail "CP7B bootstrap root is not root-owned" || return 1
	for file in \
		"$bundle_root/lib/cp7b_runtime.sh" \
		"$bundle_root/lib/cp7b_closure.sh" \
		"$bundle_root/lib/cp7b_state.sh" \
		"$bundle_root/lib/cp7b_attempts.sh" \
		"$bundle_root/lib/cp7b_snapshot.sh" \
		"$bundle_root/lib/cp7b_bundle.sh" \
		"$bundle_root/lib/native_charon_runtime.sh" \
		"$bundle_root/lib/route_snapshot.sh" \
		"$bundle_root/lib/network_snapshot.sh" \
		"$bundle_root/python/vici/__init__.py" \
		"$bundle_root/python/vici/command_wrappers.py" \
		"$bundle_root/python/vici/event_listener.py" \
		"$bundle_root/python/vici/exception.py" \
		"$bundle_root/python/vici/protocol.py" \
		"$bundle_root/python/vici/session.py" \
		"$bundle_root/cp7b_backend_window.sh" \
		"$bundle_root/cp7b_emergency_stop.sh" \
		"$bundle_root/official_vici_runtime.py" \
		"$bundle_root/cp7b_vici_readonly.py" \
		"$bundle_root/approval-manifest.json" \
		"$bundle_root/root-entry.sh"
	do
		[ ! -L "$file" ] || pvn_fail "refusing to clean a bootstrap symlink" || return 1
		[ ! -e "$file" ] || rm -f -- "$file"
	done
	rmdir "$bundle_root/python/vici" "$bundle_root/python" "$bundle_root/lib" "$bundle_root"
}
