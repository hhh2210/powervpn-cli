#!/bin/sh
set -eu

umask 077
repo_root=${CPORTALCURL_REPO_ROOT:-$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd -P)}
scratch_root=${CPORTALCURL_TRUST_SCRATCH_ROOT:-$HOME/scratch-data}
mkdir -p "$scratch_root"
work=$(mktemp -d "$scratch_root/powervpn-cportalcurl-trust.XXXXXX")
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

openssl_bin=$(command -v openssl)
python_bin=$(command -v python3)
for tool in xcrun file otool jq; do
  command -v "$tool" >/dev/null
 done

make_leaf() {
  name=$1
  "$openssl_bin" req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
    -subj /CN=GateWay -addext basicConstraints=critical,CA:FALSE \
    -keyout "$work/$name-key.pem" -out "$work/$name-cert.pem" \
    >/dev/null 2>&1
  chmod 600 "$work/$name-key.pem" "$work/$name-cert.pem"
}

make_leaf server
make_leaf wrong-anchor
correct_pin=$(
  "$openssl_bin" x509 -in "$work/server-cert.pem" -pubkey -noout |
    "$openssl_bin" pkey -pubin -outform DER |
    "$openssl_bin" dgst -sha256 -binary |
    "$openssl_bin" base64 -A
)
correct_pin="sha256//$correct_pin"
wrong_pin='sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

write_profile_header() {
  certificate=$1
  pin=$2
  port=$3
  destination=$4
  "$python_bin" - "$certificate" "$pin" "$port" "$destination" <<'PY'
import json
import pathlib
import sys

certificate, pin, port, destination = sys.argv[1:]
pem = pathlib.Path(certificate).read_text(encoding="ascii")
content = "\n".join(
    [
        "#ifndef CPORTALCURL_TEST_TRUST_PROFILE_H",
        "#define CPORTALCURL_TEST_TRUST_PROFILE_H",
        f"#define PVCURL_TEST_APPROVED_LEAF_PEM {json.dumps(pem)}",
        f"#define PVCURL_TEST_APPROVED_PIN {json.dumps(pin)}",
        f'#define PVCURL_TEST_APPROVED_URL_PREFIX "https://127.0.0.1:{port}/"',
        f'#define PVCURL_TEST_APPROVED_HOST "127.0.0.1:{port}"',
        "#endif",
        "",
    ]
)
pathlib.Path(destination).write_text(content, encoding="ascii")
PY
}

wait_for_file() {
  path=$1
  count=0
  while [ ! -s "$path" ]; do
    count=$((count + 1))
    [ "$count" -le 200 ] || return 1
    sleep 0.05
  done
}

run_case() {
  name=$1
  anchor=$2
  pin=$3
  expected_status=$4
  expected_http=$5
  expected_bytes=$6
  case_root="$work/$name"
  mkdir "$case_root"
  port_file="$case_root/port"
  result_file="$case_root/server.json"

  "$python_bin" \
    "$repo_root/Tests/CPortalCurlTests/LocalTLSTrustContractServer.py" \
    "$work/server-cert.pem" "$work/server-key.pem" \
    "$port_file" "$result_file" &
  server_pid=$!
  wait_for_file "$port_file"
  port=$(tr -d '\n' <"$port_file")
  write_profile_header "$anchor" "$pin" "$port" \
    "$case_root/CPortalCurlTestTrustProfile.h"

  xcrun clang -arch arm64 -mmacosx-version-min=14.0 \
    -std=c11 -Wall -Wextra -Werror -pedantic \
    -DPVCURL_ENABLE_TEST_TRUST_PROFILE \
    -I "$case_root" \
    -I "$repo_root/Sources/CPortalCurl/include" \
    -I "$repo_root/Sources/CPortalCurl" \
    "$repo_root/Sources/CPortalCurl/CPortalCurl.c" \
    "$repo_root/Sources/CPortalCurl/CPortalCurlTrust.c" \
    "$repo_root/Sources/CPortalCurl/CPortalCurlRequest.c" \
    "$repo_root/Sources/CPortalCurl/CPortalCurlHeaders.c" \
    "$repo_root/Tests/CPortalCurlTests/CPortalCurlTrustContractClient.c" \
    -lcurl -o "$case_root/client"
  file "$case_root/client" | grep -q 'Mach-O 64-bit executable arm64'
  otool -L "$case_root/client" | \
    grep -q '^[[:space:]]*/usr/lib/libcurl\.4\.dylib '

  "$case_root/client" "$port" "$expected_status" >"$case_root/client.out"
  wait "$server_pid"
  server_pid=
  grep -qx \
    "status=$expected_status http=$expected_http body=0" \
    "$case_root/client.out"
  if [ "$expected_bytes" = zero ]; then
    jq -e '.decryptedHTTPByteCount == 0 and
      .requestHeadersCompleted == false and .responseSent == false' \
      "$result_file" >/dev/null
  else
    jq -e '.decryptedHTTPByteCount > 0 and
      .requestHeadersCompleted == true and .responseSent == true' \
      "$result_file" >/dev/null
  fi
}

run_case correct "$work/server-cert.pem" "$correct_pin" 0 204 nonzero
run_case wrong-anchor "$work/wrong-anchor-cert.pem" "$correct_pin" 3 0 zero
run_case wrong-pin "$work/server-cert.pem" "$wrong_pin" 3 0 zero

printf '%s\n' \
  'CPortalCurl trust contract: PASS (production C path; loopback only; scratch keys removed on exit)'
