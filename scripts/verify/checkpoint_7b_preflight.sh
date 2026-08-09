#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
. "$repo_root/scripts/lib/native_charon_runtime.sh"
. "$repo_root/scripts/lib/route_snapshot.sh"
. "$repo_root/scripts/lib/network_snapshot.sh"
. "$repo_root/scripts/lib/cp7b_runtime.sh"
. "$repo_root/scripts/lib/cp7b_closure.sh"
pvn_cp7b_init_paths "$repo_root"

lab_base=3231a3bfe992fcc5f84793543ce9c8687afcd7fa
upstream_base=5973ff8e41deef4e015e1138a2de688acedf6f75
cp6_commit=67c9810900e2d8486cb3b11495a8362433494ca0
cp7b_commit=a81298234753f314dbf2c4f2867a9a144006bd8c
cp6_patch_sha=6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213
cp7b_patch_sha=3c7615e5bf2ec284f04177e903b88fb3b452f1ce9d1f39968fd89c40ea6771c4
config_sha=64fbae7626306419a08018234bbb6bf5040f954e8ff6d2622b2f9969ca96fa20
series=patches/strongswan-6.0.7/series.json
cp7b_series=patches/strongswan-6.0.7/cp7b-series.json
patch1=patches/strongswan-6.0.7/0001-Add-strict-IKEv1-expandrule-wire-codec.patch
patch2=patches/strongswan-6.0.7/0002-Integrate-IKEv1-expandrule-payload-task-and-HASH.patch
patch3=patches/strongswan-6.0.7/0003-build-enable-RFC-3542-for-socket-dynamic-on-macOS.patch
manifest=fixtures/redacted/cp7b-approval-manifest-v1.json
cp6_source="$PVN_CP7B_SCRATCH_ROOT/strongswan-6.0.7-expandrule"
temp_root=

cleanup() {
	rc=$?
	trap - EXIT HUP INT TERM
	if [ -n "$temp_root" ]; then
		case "$temp_root" in
		"$PVN_CP7B_SCRATCH_ROOT"/verify-cp7b-preflight.*)
			rm -rf -- "$temp_root"
			;;
		*) pvn_fail "refusing to remove unexpected preflight scratch path: $temp_root" || rc=1 ;;
		esac
	fi
	exit "$rc"
}
trap cleanup EXIT HUP INT TERM

[ "$(id -u)" -ne 0 ] || pvn_fail "CP7B preflight must never run as root" || exit 1
[ -d "$PVN_CP7B_SCRATCH_ROOT" ] && [ ! -L "$PVN_CP7B_SCRATCH_ROOT" ] ||
	pvn_fail "protected PowerVPN scratch root is missing or a symlink" || exit 1
[ ! -e "$PVN_CP7B_STATE_FILE" ] || pvn_fail "CP7B runtime state exists; preflight is offline-only" || exit 1
[ ! -e "$PVN_CP7B_PID_FILE" ] || pvn_fail "CP7B PID file exists; preflight is offline-only" || exit 1
[ ! -S "$PVN_CP7B_SOCKET" ] || pvn_fail "CP7B VICI socket exists; preflight is offline-only" || exit 1
[ -z "$(pvn_native_charon_pids)" ] || pvn_fail "CP7B native charon is already running" || exit 1

git cat-file -e "$lab_base^{commit}"
git merge-base --is-ancestor "$lab_base" HEAD
changed_files=$(
	{
		git diff --name-only "$lab_base"
		git ls-files --others --exclude-standard
	} | sort -u
)
[ -n "$changed_files" ] || pvn_fail "CP7B preflight diff is empty" || exit 1
for file in $changed_files; do
	case "$file" in
	GOAL.md | README.md | \
		docs/evidence/checkpoint-7b-preflight.md | docs/evidence/live-test-plan.md | \
			docs/evidence/rollback.md | docs/progress/GOAL_STATUS.md | \
			fixtures/redacted/cp7b-first-live-preflight-summary-v1.json | \
			fixtures/redacted/cp7b-approval-manifest-v1.json | \
		patches/strongswan-6.0.7/0003-build-enable-RFC-3542-for-socket-dynamic-on-macOS.patch | \
		patches/strongswan-6.0.7/cp7b-series.json | \
		scripts/assert_clean_teardown.sh | scripts/assert_cp7b_teardown.sh | \
			scripts/build_strongswan.sh | scripts/lib/network_snapshot.sh | \
			scripts/lib/route_snapshot.sh | \
		scripts/lib/cp7b_attempts.sh | scripts/lib/cp7b_bundle.sh | \
		scripts/lib/cp7b_closure.sh | \
		scripts/lib/cp7b_runtime.sh | \
		scripts/lib/cp7b_snapshot.sh | scripts/lib/cp7b_state.sh | \
		scripts/libexec/authorize_cp7b.applescript | \
		scripts/libexec/cp7b_backend_window.sh | scripts/libexec/cp7b_emergency_stop.sh | \
		scripts/libexec/cp7b_gated_launcher.c | \
		scripts/libexec/cp7b_root_entry.sh | scripts/libexec/cp7b_vici_readonly.py | \
		scripts/run_cp7b_backend.sh | scripts/snapshot_network_state.sh | \
			scripts/stop_cp7b_backend.sh | scripts/verify/checkpoint_7b_preflight.sh | \
			scripts/verify/cp7b_closure_tests.sh | scripts/verify/cp7b_live_evidence_tests.sh | \
			scripts/verify/cp7b_manifest.jq | scripts/verify/cp7b_route_snapshot_tests.sh | \
		scripts/verify/cp7b_preflight_tests.sh | \
		scripts/verify_checkpoint.sh)
		;;
	*) pvn_fail "unexpected CP7B preflight artifact: $file" || exit 1 ;;
	esac
done

for source in "$cp6_source" "$PVN_CP7B_SOURCE"; do
	[ -d "$source/.git" ] || [ -f "$source/.git" ] ||
		pvn_fail "strongSwan source is not a Git worktree: $source" || exit 1
	[ -z "$(git -C "$source" status --porcelain=v1)" ] ||
		pvn_fail "strongSwan source worktree is dirty: $source" || exit 1
done
[ "$(git -C "$cp6_source" rev-parse HEAD)" = "$cp6_commit" ]
[ "$(git -C "$PVN_CP7B_SOURCE" rev-parse HEAD)" = "$cp7b_commit" ]
[ "$(git -C "$PVN_CP7B_SOURCE" rev-parse HEAD^)" = "$cp6_commit" ]
[ "$(CDPATH='' cd -- "$cp6_source" && pwd -P)" != \
	"$(CDPATH='' cd -- "$PVN_CP7B_SOURCE" && pwd -P)" ]

git show "$lab_base:$series" | cmp - "$series"
jq -e \
	--arg base "$upstream_base" --arg cp6 "$cp6_commit" \
	--arg cp6sha "$cp6_patch_sha" --arg cp7b "$cp7b_commit" \
	--arg cp7bsha "$cp7b_patch_sha" '
  keys == ["boundary", "cp7bPatch", "lockedCP6", "safety", "schemaVersion", "upstream"] and
  .schemaVersion == 1 and
  .upstream == {version: "6.0.7", baseCommit: $base} and
  .lockedCP6 == {
    commit: $cp6,
    seriesManifest: "series.json",
    patchSHA256: $cp6sha
  } and
  .cp7bPatch == {
    sequence: 3,
    path: "0003-build-enable-RFC-3542-for-socket-dynamic-on-macOS.patch",
    commit: $cp7b,
    sha256: $cp7bsha,
    scope: "macOS RFC 3542 compile definitions for the serverless socket-dynamic CP7B build"
  } and
  .boundary == {
    buildOnly: true,
    serverVisibleProtocolChanged: false,
    socketOpenedWithoutSend: false,
    privilegedBackendTested: false,
    serverTested: false
  } and
  .safety == {
    containsSecrets: false,
    containsReplayableCapture: false,
    containsVendorBinaryOrObject: false
  }
' "$cp7b_series" >/dev/null
[ "$(pvn_sha256_file "$patch2")" = "$cp6_patch_sha" ]
[ "$(pvn_sha256_file "$patch3")" = "$cp7b_patch_sha" ]

temp_root=$(mktemp -d "$PVN_CP7B_SCRATCH_ROOT/verify-cp7b-preflight.XXXXXX")
chmod 700 "$temp_root"
git -C "$PVN_CP7B_SOURCE" format-patch -1 --stdout "$cp7b_commit" >"$temp_root/0003.patch"
cmp "$temp_root/0003.patch" "$patch3"
git clone --quiet --no-hardlinks "$PVN_CP7B_SOURCE" "$temp_root/replay"
git -C "$temp_root/replay" checkout --quiet --detach "$upstream_base"
git -C "$temp_root/replay" am --quiet "$repo_root/$patch1" "$repo_root/$patch2"
[ "$(git -C "$temp_root/replay" rev-parse 'HEAD^{tree}')" = \
	"$(git -C "$cp6_source" rev-parse 'HEAD^{tree}')" ]
git -C "$temp_root/replay" am --quiet "$repo_root/$patch3"
[ "$(git -C "$temp_root/replay" rev-parse 'HEAD^{tree}')" = \
	"$(git -C "$PVN_CP7B_SOURCE" rev-parse 'HEAD^{tree}')" ]

scripts/build_strongswan.sh --verify-cp7b-runtime >/dev/null
[ "$PVN_CP7B_PREFIX" != "$PVN_CP7B_SCRATCH_ROOT/install-6.0.7-cp7a-arm64" ]
grep -Fq -- "--with-piddir=$PVN_CP7B_COMPILED_PIDDIR" "$PVN_CP7B_BUILD/config.status"
grep -Fq -- '--enable-socket-dynamic' "$PVN_CP7B_BUILD/config.status"

pvn_cp7b_render_config "$PVN_CP7B_SOCKET" >"$temp_root/config.actual"
[ "$(pvn_sha256_file "$temp_root/config.actual")" = "$config_sha" ]
if grep -Eq 'socket-default|kernel-libipsec|load-tester|keychain|files|sql|credential|initiate|start_action' \
	"$temp_root/config.actual"; then
	pvn_fail "CP7B config contains a forbidden plugin or action" || exit 1
fi

jq -e --arg cp6 "$cp6_commit" --arg cp7b "$cp7b_commit" --arg config "$config_sha" \
	-f scripts/verify/cp7b_manifest.jq "$manifest" >/dev/null

for entry in \
	"$PVN_CP7B_BINARY:charonSHA256" \
	"$PVN_CP7B_SWANCTL:swanctlSHA256" \
	"$PVN_CP7B_LIBSTRONGSWAN:libstrongswanSHA256" \
	"$PVN_CP7B_LIBCHARON:libcharonSHA256" \
	"$PVN_CP7B_OPENSSL_PLUGIN:opensslPluginSHA256" \
		"$PVN_CP7B_NONCE_PLUGIN:noncePluginSHA256" \
		"$PVN_CP7B_LIBCRYPTO:opensslLibcryptoSHA256" \
		"$PVN_CP7B_LAUNCHER:gatedLauncherSHA256" \
	"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-kernel-pfkey.so:kernelPFArtifactSHA256" \
	"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-kernel-pfroute.so:pfrouteSHA256" \
	"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-socket-dynamic.so:socketDynamicSHA256" \
	"$PVN_CP7B_PREFIX/lib/ipsec/plugins/libstrongswan-vici.so:viciSHA256" \
	"$PVN_CP7B_ORACLE:oracleSHA256" \
	"$PVN_CP7B_PY_INIT:officialPyInitSHA256" \
	"$PVN_CP7B_PY_COMMAND_WRAPPERS:officialPyCommandWrappersSHA256" \
	"$PVN_CP7B_PY_EVENT_LISTENER:officialPyEventListenerSHA256" \
	"$PVN_CP7B_PY_EXCEPTION:officialPyExceptionSHA256" \
	"$PVN_CP7B_PY_PROTOCOL:officialProtocolSHA256" \
	"$PVN_CP7B_PY_SESSION:officialPySessionSHA256"; do
	artifact=${entry%:*}
	key=${entry##*:}
	[ "$(pvn_sha256_file "$artifact")" = "$(jq -r ".artifacts.$key" "$manifest")" ] ||
		pvn_fail "CP7B manifest hash mismatch: $key" || exit 1
	descriptor=$(file "$artifact")
	case "$key" in
	charonSHA256 | swanctlSHA256 | libstrongswanSHA256 | libcharonSHA256 | \
		opensslPluginSHA256 | noncePluginSHA256 | opensslLibcryptoSHA256 | \
		gatedLauncherSHA256 | kernelPFArtifactSHA256 | pfrouteSHA256 | \
		socketDynamicSHA256 | viciSHA256)
		printf '%s\n' "$descriptor" | grep -q 'Mach-O 64-bit.*arm64' ||
			pvn_fail "CP7B artifact is not arm64: $artifact" || exit 1
		;;
	esac
done

review_state=$(jq -r '.review.state' "$manifest")
pending_sentinel=$(printf '__%s__' PENDING_REVIEW)
if [ "$review_state" = pending_integrated_preflight_review ]; then
	jq -e --arg pending "$pending_sentinel" '[
	      .artifacts.runtimeScriptSHA256, .artifacts.closureScriptSHA256,
	      .artifacts.stateScriptSHA256,
      .artifacts.attemptsScriptSHA256, .artifacts.snapshotScriptSHA256,
      .artifacts.bundleScriptSHA256,
	      .artifacts.nativeScriptSHA256, .artifacts.routeScriptSHA256,
	      .artifacts.networkScriptSHA256,
      .artifacts.workerSHA256, .artifacts.rootEntrySHA256,
      .artifacts.emergencySHA256, .artifacts.authorizerSHA256,
	      .artifacts.readOnlyProbeSHA256, .artifacts.gatedLauncherSHA256
    ] | all(. == $pending)' "$manifest" >/dev/null
	# The allowlist above proves these filenames contain no whitespace or glob syntax.
	# shellcheck disable=SC2086
	placeholder_files=$(rg -l '__[A-Z0-9_]+__' $changed_files | sort -u)
	[ "$placeholder_files" = "fixtures/redacted/cp7b-approval-manifest-v1.json
scripts/libexec/authorize_cp7b.applescript
scripts/libexec/cp7b_root_entry.sh" ] ||
		pvn_fail "pending review placeholders escaped the three bootstrap artifacts" || exit 1
else
	jq -e '.artifacts | to_entries | all(
      (.key == "sourceCommit" or .key == "sourceParentCP6Commit") or
      (.value | test("^[0-9a-f]{64}$"))
    )' "$manifest" >/dev/null
	placeholder_pattern='__[A-Z0-9_]+__|TO''DO|T''BD|FIX''ME'
	# shellcheck disable=SC2086
	if rg -n "$placeholder_pattern" $changed_files; then
		pvn_fail "reviewed CP7B candidate contains a placeholder" || exit 1
	fi
	pvn_cp7b_verify_manifest
fi

shell_files='scripts/assert_clean_teardown.sh scripts/assert_cp7b_teardown.sh scripts/build_strongswan.sh scripts/lib/route_snapshot.sh scripts/lib/network_snapshot.sh scripts/lib/cp7b_attempts.sh scripts/lib/cp7b_bundle.sh scripts/lib/cp7b_closure.sh scripts/lib/cp7b_runtime.sh scripts/lib/cp7b_snapshot.sh scripts/lib/cp7b_state.sh scripts/libexec/cp7b_backend_window.sh scripts/libexec/cp7b_emergency_stop.sh scripts/libexec/cp7b_root_entry.sh scripts/run_cp7b_backend.sh scripts/stop_cp7b_backend.sh scripts/verify/checkpoint_7b_preflight.sh scripts/verify/cp7b_closure_tests.sh scripts/verify/cp7b_live_evidence_tests.sh scripts/verify/cp7b_preflight_tests.sh scripts/verify/cp7b_route_snapshot_tests.sh'
for script in $shell_files scripts/verify_checkpoint.sh; do
	sh -n "$script"
done
# shellcheck disable=SC2086
shellcheck -x -e SC1091 $shell_files
shellcheck -x -e SC2086 scripts/verify_checkpoint.sh
/usr/bin/osacompile -o "$temp_root/authorize.scpt" \
	"$repo_root/scripts/libexec/authorize_cp7b.applescript"
[ -f "$temp_root/authorize.scpt" ]
/usr/bin/python3 -c 'import ast, pathlib; ast.parse(pathlib.Path(
  "scripts/libexec/cp7b_vici_readonly.py").read_text())'

for script in scripts/run_cp7b_backend.sh scripts/stop_cp7b_backend.sh; do
	# The literal shell source expression is intentionally searched without expansion.
	# shellcheck disable=SC2016
	dry_line=$(grep -n 'if \[ "$operation_mode" = dry-run \]' "$script" | cut -d: -f1)
	authorize_line=$(grep -n '/usr/bin/osascript' "$script" | cut -d: -f1)
	exit_line=$(awk -v start="$dry_line" -v finish="$authorize_line" \
		'NR > start && NR < finish && /exit 0/ { print NR; exit }' "$script")
	[ -n "$dry_line" ] && [ -n "$exit_line" ] && [ "$exit_line" -lt "$authorize_line" ] ||
		pvn_fail "CP7B dry-run does not exit before native authorization: $script" || exit 1
done

manifest_sha=$(pvn_sha256_file "$manifest")
scripts/stop_cp7b_backend.sh --dry-run --manifest-sha256 "$manifest_sha" \
	>"$temp_root/stop-dry-run.out"
grep -Fxq 'mode=dry-run' "$temp_root/stop-dry-run.out"
if [ "$review_state" = passed_integrated_preflight_review ]; then
	scripts/run_cp7b_backend.sh --dry-run --manifest-sha256 "$manifest_sha" \
		>"$temp_root/run-dry-run.out"
	grep -Fxq 'mode=dry-run' "$temp_root/run-dry-run.out"
else
	if scripts/run_cp7b_backend.sh --dry-run --manifest-sha256 "$manifest_sha" \
		>"$temp_root/run-dry-run.out" 2>&1; then
		pvn_fail "pending manifest unexpectedly opened the reviewed run path" || exit 1
	fi
fi

scripts/verify/cp7b_preflight_tests.sh
scripts/verify/cp7b_closure_tests.sh
scripts/verify/cp7b_route_snapshot_tests.sh
scripts/verify/cp7b_live_evidence_tests.sh
scripts/verify/native_charon_runtime_tests.sh
scripts/verify_no_secrets.sh
git diff --check "$lab_base"

[ ! -e "$PVN_CP7B_STATE_FILE" ]
[ ! -e "$PVN_CP7B_PID_FILE" ]
[ ! -S "$PVN_CP7B_SOCKET" ]
[ -z "$(pvn_native_charon_pids)" ]
printf '%s\n' \
	'PASS: CP7B offline preflight verifier' \
	"manifest_review_state=$review_state" \
	'privileged_execution_authorized=false' \
	'daemon_root_surge_server_actions=none'
