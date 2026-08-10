#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
wrapper="$repo_root/scripts/build_and_run.sh"
test_parent=$(CDPATH='' cd -- "${TMPDIR:-/private/tmp}" && pwd -P)
fixture_root=$(/usr/bin/mktemp -d "$test_parent/powervpn-build-run-test.XXXXXX")
fake_path="$fixture_root/fake-path"
fake_bin_path="$fixture_root/bin path"
swift_log="$fixture_root/swift.log"

cleanup() {
	/bin/rm -rf -- "$fixture_root"
}
trap cleanup EXIT HUP INT TERM

mkdir "$fake_path" "$fake_bin_path"

cat >"$fake_path/swift" <<'EOF'
#!/bin/sh
set -eu

{
	printf 'cwd=%s\n' "$PWD"
	printf 'argv='
	printf '<%s>' "$@"
	printf '\n'
} >>"$POWERVPN_TEST_SWIFT_LOG"

if [ "$#" -eq 5 ] && [ "$1" = build ] && [ "$2" = --arch ] &&
	[ "$3" = arm64 ] && [ "$4" = --product ] && [ "$5" = powervpn ]; then
	exit "${POWERVPN_TEST_BUILD_EXIT:-0}"
fi

if [ "$#" -eq 4 ] && [ "$1" = build ] && [ "$2" = --arch ] &&
	[ "$3" = arm64 ] && [ "$4" = --show-bin-path ]; then
	printf '%s\n' "$POWERVPN_TEST_BIN_PATH"
	exit 0
fi

exit 99
EOF

cat >"$fake_bin_path/powervpn" <<'EOF'
#!/bin/sh
set -eu

printf 'binary-cwd=%s\n' "$PWD"
printf 'binary-argv='
printf '<%s>' "$@"
printf '\n'
exit "${POWERVPN_TEST_BINARY_EXIT:-0}"
EOF

chmod 700 "$fake_path/swift" "$fake_bin_path/powervpn"

run_wrapper() {
	env \
		PATH="$fake_path:/usr/bin:/bin" \
		POWERVPN_TEST_SWIFT_LOG="$swift_log" \
		POWERVPN_TEST_BIN_PATH="$fake_bin_path" \
		"$wrapper" "$@"
}

assert_build_log() {
	cat >"$fixture_root/expected-swift.log" <<EOF
cwd=$repo_root
argv=<build><--arch><arm64><--product><powervpn>
cwd=$repo_root
argv=<build><--arch><arm64><--show-bin-path>
EOF
	cmp "$fixture_root/expected-swift.log" "$swift_log"
}

: >"$swift_log"
set +e
(
	export POWERVPN_TEST_BINARY_EXIT=23
	run_wrapper doctor --json 'argument with spaces'
) >"$fixture_root/passthrough.out" 2>"$fixture_root/passthrough.err"
passthrough_rc=$?
set -e
[ "$passthrough_rc" -eq 23 ]
if [ -s "$fixture_root/passthrough.err" ]; then
	cat "$fixture_root/passthrough.err" >&2
	exit 1
fi
cat >"$fixture_root/expected-passthrough.out" <<EOF
binary-cwd=$repo_root
binary-argv=<doctor><--json><argument with spaces>
EOF
cmp "$fixture_root/expected-passthrough.out" "$fixture_root/passthrough.out"
assert_build_log

: >"$swift_log"
run_wrapper >"$fixture_root/no-args.out" 2>"$fixture_root/no-args.err"
[ ! -s "$fixture_root/no-args.err" ]
cat >"$fixture_root/expected-no-args.out" <<EOF
binary-cwd=$repo_root
binary-argv=<--help>
EOF
cmp "$fixture_root/expected-no-args.out" "$fixture_root/no-args.out"
assert_build_log

: >"$swift_log"
set +e
(
	export POWERVPN_TEST_BUILD_EXIT=17
	run_wrapper --help
) >"$fixture_root/build-failure.out" 2>"$fixture_root/build-failure.err"
build_failure_rc=$?
set -e
[ "$build_failure_rc" -eq 17 ]
[ ! -s "$fixture_root/build-failure.out" ]
[ ! -s "$fixture_root/build-failure.err" ]
[ "$(wc -l <"$swift_log" | tr -d ' ')" -eq 2 ]
grep -Fxq 'argv=<build><--arch><arm64><--product><powervpn>' "$swift_log"

/bin/rm -f -- "$fake_bin_path/powervpn"
: >"$swift_log"
set +e
run_wrapper --help >"$fixture_root/missing.out" 2>"$fixture_root/missing.err"
missing_rc=$?
set -e
[ "$missing_rc" -eq 1 ]
[ ! -s "$fixture_root/missing.out" ]
grep -Fxq "error: built powervpn executable not found at $fake_bin_path/powervpn" \
	"$fixture_root/missing.err"
assert_build_log

printf '%s\n' 'PASS: arm64 product build/run wrapper tests (fake Swift and binary only)'
