#!/bin/sh

pvn_cp7b_require_allowed_alias() {
	alias_path=$1
	target_name=$2
	expected_owner=$3
	expected_group=$4
	expected_target="$(dirname -- "$alias_path")/$target_name"
	[ -L "$alias_path" ] ||
		pvn_fail "required CP7B closure alias is missing: $alias_path" || return 1
	[ "$(readlink "$alias_path")" = "$target_name" ] ||
		pvn_fail "CP7B closure alias target changed: $alias_path" || return 1
	[ "$(stat -f '%u:%g' "$alias_path")" = "$expected_owner:$expected_group" ] ||
		pvn_fail "CP7B closure alias ownership changed: $alias_path" || return 1
	[ -f "$expected_target" ] && [ ! -L "$expected_target" ] ||
		pvn_fail "CP7B closure alias target is not a regular file: $alias_path" || return 1
	[ "$(/bin/realpath "$alias_path")" = "$(/bin/realpath "$expected_target")" ] ||
		pvn_fail "CP7B closure alias escapes its pinned target: $alias_path" || return 1
}

pvn_cp7b_require_closure_tree() {
	expected_owner=$1
	case "$expected_owner" in
	0) expected_group=0 ;;
	502) expected_group=20 ;;
	*) pvn_fail "unsupported CP7B closure owner: $expected_owner" || return 1 ;;
	esac
	[ -d "$PVN_CP7B_PREFIX" ] && [ ! -L "$PVN_CP7B_PREFIX" ] ||
		pvn_fail "CP7B closure root is missing or a symlink" || return 1
	[ -z "$(find "$PVN_CP7B_PREFIX" -xdev ! -type d ! -type f ! -type l -print -quit)" ] ||
		pvn_fail "CP7B closure contains a non-regular filesystem object" || return 1
	[ -z "$(find "$PVN_CP7B_PREFIX" -xdev ! -user "$expected_owner" -print -quit)" ] ||
		pvn_fail "CP7B closure contains an object with the wrong owner" || return 1
	[ -z "$(find "$PVN_CP7B_PREFIX" -xdev ! -group "$expected_group" -print -quit)" ] ||
		pvn_fail "CP7B closure contains an object with the wrong group" || return 1
	[ -z "$(find "$PVN_CP7B_PREFIX" -xdev \( -type d -o -type f \) -perm +022 -print -quit)" ] ||
		pvn_fail "CP7B closure contains a group/world-writable object" || return 1
	[ -z "$(find "$PVN_CP7B_PREFIX" -xdev -type f -links +1 -print -quit)" ] ||
		pvn_fail "CP7B closure contains a multiply-linked regular file" || return 1

	alias_dir="$PVN_CP7B_PREFIX/lib/ipsec"
	pvn_cp7b_require_allowed_alias "$alias_dir/libipsec.dylib" \
		libipsec.0.dylib "$expected_owner" "$expected_group" || return 1
	pvn_cp7b_require_allowed_alias "$alias_dir/libvici.dylib" \
		libvici.0.dylib "$expected_owner" "$expected_group" || return 1
	pvn_cp7b_require_allowed_alias "$alias_dir/libstrongswan.dylib" \
		libstrongswan.0.dylib "$expected_owner" "$expected_group" || return 1
	pvn_cp7b_require_allowed_alias "$alias_dir/libcharon.dylib" \
		libcharon.0.dylib "$expected_owner" "$expected_group" || return 1
	[ -z "$(find "$PVN_CP7B_PREFIX" -xdev -type l \
		! -path "$alias_dir/libipsec.dylib" \
		! -path "$alias_dir/libvici.dylib" \
		! -path "$alias_dir/libstrongswan.dylib" \
		! -path "$alias_dir/libcharon.dylib" -print -quit)" ] ||
		pvn_fail "CP7B closure contains an unreviewed symlink" || return 1
}

pvn_cp7b_chown_closure_tree() {
	owner_group=$1
	find "$PVN_CP7B_PREFIX" -xdev -type d -exec chown "$owner_group" {} + || return 1
	find "$PVN_CP7B_PREFIX" -xdev -type f -exec chown "$owner_group" {} + || return 1
	find "$PVN_CP7B_PREFIX" -xdev -type l -exec chown -h "$owner_group" {} +
}

pvn_cp7b_take_closure_ownership() {
	[ "$(id -u)" -eq 0 ] || pvn_fail "CP7B closure takeover requires root" || return 1
	[ -d "$PVN_CP7B_RUNTIME_ROOT" ] && [ ! -L "$PVN_CP7B_RUNTIME_ROOT" ] ||
		pvn_fail "CP7B runtime root is invalid" || return 1
	[ "$(stat -f '%u:%g:%Lp' "$PVN_CP7B_RUNTIME_ROOT")" = 0:0:700 ] ||
		pvn_fail "CP7B runtime root must be protected before closure takeover" || return 1
	closure_owner=$(stat -f '%u' "$PVN_CP7B_PREFIX" 2>/dev/null || printf '%s' invalid)
	case "$closure_owner" in
	502)
		pvn_cp7b_require_closure_tree 502 || return 1
		pvn_cp7b_chown_closure_tree 0:0 ||
			pvn_fail "failed to take root ownership of the CP7B closure" || return 1
		;;
	0) ;;
	*) pvn_fail "CP7B closure owner is neither the reviewed user nor root" || return 1 ;;
	esac
	pvn_cp7b_require_closure_tree 0
}

pvn_cp7b_runtime_has_closure_baseline() {
	[ -d "$PVN_CP7B_PREFIX" ] && [ ! -L "$PVN_CP7B_PREFIX" ] || return 1
	[ "$(find "$PVN_CP7B_RUNTIME_ROOT" -mindepth 1 -maxdepth 1 -print |
		awk 'END { print NR + 0 }')" -eq 1 ] || return 1
}

pvn_cp7b_restore_runtime_owner_if_clean() {
	[ "$(id -u)" -eq 0 ] || pvn_fail "CP7B runtime ownership restore requires root" || return 1
	[ -d "$PVN_CP7B_RUNTIME_ROOT" ] && [ ! -L "$PVN_CP7B_RUNTIME_ROOT" ] ||
		pvn_fail "CP7B runtime root is invalid" || return 1
	[ "$(stat -f '%u:%g:%Lp' "$PVN_CP7B_RUNTIME_ROOT")" = 0:0:700 ] ||
		pvn_fail "CP7B runtime root is not protected by root" || return 1
	pvn_cp7b_runtime_has_closure_baseline ||
		pvn_fail "CP7B runtime ownership retained because non-baseline residue exists" || return 1
	closure_owner=$(stat -f '%u' "$PVN_CP7B_PREFIX")
	case "$closure_owner" in
	0)
		pvn_cp7b_require_closure_tree 0 || return 1
		pvn_cp7b_chown_closure_tree 502:20 ||
			pvn_fail "failed to restore CP7B closure ownership" || return 1
		;;
	502) ;;
	*) pvn_fail "CP7B closure ownership is ambiguous" || return 1 ;;
	esac
	pvn_cp7b_require_closure_tree 502 || return 1
	chown 502:20 "$PVN_CP7B_RUNTIME_ROOT"
	chmod 700 "$PVN_CP7B_RUNTIME_ROOT"
}
