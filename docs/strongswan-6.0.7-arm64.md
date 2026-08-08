# strongSwan 6.0.7 arm64 build evidence

Date: 2026-08-08

Scope: scratch-only build; no system install, root launch, route change, or VPN
connection.

## Source

- Official repository: `https://github.com/strongswan/strongswan`
- Tag: `6.0.7`
- Commit: `5973ff8e41deef4e015e1138a2de688acedf6f75`
- Target prefix:
  `~/scratch-data/powervpn-strongswan/install-6.0.7-arm64`

The vendor 5.8.0 source checkout is a comparison baseline only. No vendor code
or binary was linked into the 6.0.7 build.

## Selected feature matrix

```text
libstrongswan:
  nonce x509 revocation constraints pubkey pkcs1 pem openssl pkcs8
  hmac kdf drbg

libcharon:
  kernel-libipsec kernel-pfkey kernel-pfroute socket-default vici
  eap-identity eap-md5 eap-gtc eap-mschapv2 xauth-generic osx-attr counters

protocols:
  IKEv1 IKEv2
```

## Result

`make -j8`, scratch-prefix `make install`, and `make check -j8` completed with
exit status 0. The enabled libstrongswan, libipsec, VICI/libcharon, and exchange
test suites all passed; expected RSA-PSS cases whose OpenSSL backend does not
support a static salt were reported as skips, not failures.

The following are Mach-O arm64 artifacts:

- `libexec/ipsec/charon`;
- `sbin/swanctl`;
- `libstrongswan-vici.so`;
- `libstrongswan-kernel-pfkey.so`;
- `libstrongswan-kernel-pfroute.so`;
- `libstrongswan-kernel-libipsec.so`.

`charon --version` prints `strongSwan 6.0.7`.

## Unprivileged load smoke

The smoke configuration used random local IKE ports and a VICI socket under
`~/scratch-data`; it contained no connection or credential configuration.

Observed results:

- PF_ROUTE, VICI, socket-default, OpenSSL, XAuth and selected EAP/credential
  plugins loaded successfully;
- PF_KEY stopped at its root capability check;
- in the alternate run, kernel-libipsec stopped at the same capability check;
- charon then aborted because no kernel-ipsec provider was available;
- no route, SA, utun, or live VPN configuration was created.

This is a PASS for arm64 build and dynamic plugin compatibility. It is not a
PASS for privileged backend startup, SA installation, private ADDRULE support,
or server interoperability.

## Reproducibility notes

The official Git build requires Homebrew Autotools/Gettext paths. The first
configure attempt failed because old system `gperf` could not report its length
type; installing Homebrew `gperf` 3.3 fixed the environment. The first make
attempt used the system Bison; pinning `/opt/homebrew/opt/bison/bin` fixed the
grammar build. These are toolchain corrections, not source patches.

The exact configure invocation and generated `config.status` remain in the
scratch build directory. They are intentionally not copied into the repo as a
machine-specific generated artifact.

## Reproducible wrapper

The repository now carries a scratch-root-enforcing wrapper:

```bash
scripts/build_strongswan.sh build
scripts/build_strongswan.sh --verify-only
```

The script rejects a source commit other than the official 6.0.7 commit,
rejects any source/build/prefix path outside the declared scratch root, runs the
same configure feature set, and finishes with an explicit Mach-O arm64 gate for
`charon`, `swanctl`, VICI, PF_KEY, PF_ROUTE, and kernel-libipsec.

On 2026-08-08 the full wrapper was forward-tested against the existing scratch
tree. Configure, build, scratch install, `make check`, and all six artifact
checks returned success. The selected artifact hashes and exact result are in
[`evidence/strongswan-6.0.7-build-manifest.json`](evidence/strongswan-6.0.7-build-manifest.json).
