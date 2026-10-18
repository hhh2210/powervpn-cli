# Security settings

Hardening decisions for powervpn-cli, following Apple's Enhanced Security guidance
(the `audit-xcode-security-settings` skill that ships with Xcode). This is a SwiftPM
package with an autotools runtime build, not an Xcode project, so each entry names the
compiler flag or entitlement that the Xcode setting expands to (from Xcode's
`Clang.xcspec`) and where it is applied.

What ships:

| Executable | Runs as | Exposure |
|---|---|---|
| `charon` and plugins (strongSwan 6.0.7, C) | root, child of the LaunchDaemon | parses IKE packets from the network |
| `powervpn-native-helper` (Swift, plus CPowerVPNXPCSession) | root, LaunchDaemon | local control and VICI sockets of the installing user |
| `powervpn` (Swift, plus CPortalCurl and system libcurl) | the user | Portal HTTPS responses, credentials file |

## Enabled settings

- Security compiler warnings on our own C targets (`Package.swift`, `hardenedC`):
  `-Werror=return-type`, `-Wuninitialized`, `-Wconditional-uninitialized`,
  `-Wimplicit-fallthrough`, `-Wshorten-64-to-32`, `-Werror=implicit-function-declaration`,
  and the Enhanced Security set `-Wshadow`, `-Wempty-body`, `-Wformat-nonliteral`,
  `-Warray-bounds`, `-Warray-bounds-pointer-arithmetic`, `-Wsuspicious-memaccess`,
  `-Wsizeof-array-div`, `-Wsizeof-pointer-div`, `-Wreturn-stack-address`,
  `-Wbuiltin-memcpy-chk-size`. Adoption found one `-Wshadow` (the XPC cancel handler's
  `error` parameter), fixed.
- Stack zero-initialization (`CLANG_ENABLE_STACK_ZERO_INIT`, `-ftrivial-auto-var-init=zero`):
  our C targets and strongSwan (`scripts/native/build_runtime.sh`).
- Type-aware allocation (`CLANG_ENABLE_C_TYPED_ALLOCATOR_SUPPORT`, `-ftyped-memory-operations`):
  our C targets when built with Swift 6.2 or later (older clang rejects the flag), and
  strongSwan when the compiler accepts it (probed in `build_runtime.sh`). A bottle built by
  an older Xcode does not get it.
- Enhanced Security entitlements on the two root executables. `scripts/native/install.sh`
  signs the installed, root-owned `powervpn-native-helper` and `runtime/libexec/ipsec/charon`
  ad hoc with:
  - `com.apple.security.hardened-process`
  - `com.apple.security.hardened-process.enhanced-security-version-string` = `2`
  - `com.apple.security.hardened-process.hardened-heap`
  - `com.apple.security.hardened-process.dyld-ro`
  - `com.apple.security.hardened-process.platform-restrictions-string` = `2`

  Signing happens after `installed-from` records the copied bytes, so `native status` still
  compares like with like. Checked before adoption: an ad hoc signed tool with these
  entitlements launches and still `dlopen`s an ad hoc signed plugin (macOS 27.2), and a
  copy of the real charon signed this way loads its plugins exactly like the unsigned one.
  Whether the kernel enforces each protection for an ad hoc signature was not
  independently verified.
- Pointer authentication for `powervpn` and `powervpn-native-helper`: the Homebrew formula
  builds them universal arm64 + arm64e (`--arch arm64 --arch arm64e`). On macOS 27.2 a
  third-party arm64e tool runs with pointer authentication active, and a universal tool runs
  its arm64e slice by default. CI builds and runs the universal binaries on every leg,
  including macOS 14. The README source build stays arm64-only: with the older SwiftPM build
  system a multi-architecture build lands outside `.build/release`, where `install.sh`
  looks by default.
- Static analyzer security checkers on our C code in CI: `security.FloatLoopCounter`,
  `security.insecureAPI.rand`, `security.insecureAPI.strcpy` (0 findings at adoption).
- CI fails if `powervpn-native-helper` references the runtime actor-isolation check
  (`_swift_task_isCurrentExecutor`): the 0.2.0 helper trapped on one.

## Disabled settings

- Security warnings for strongSwan: upstream code. Its warnings would be noise that this
  project does not act on; only the code-generation flags above apply to it.

## Deferred

Settings considered but not yet enabled. Revisit them later.

- Pointer authentication for `charon`: an arm64e charon cannot load Homebrew's arm64-only
  `openssl@3` libcrypto. Needs OpenSSL built from source as arm64e inside `build_runtime.sh`.
- Hardware memory tagging (`com.apple.security.hardened-process.checked-allocations`, soft
  mode first): needs an M5 or later Mac; the development Mac is an M4
  (`hw.optional.arm.FEAT_MTE = 0`), so it cannot be tested.
- Checked pointer arithmetic: iOS and watchOS hardware only.
- Additional diagnostics (`-Wconversion`, `-Wsign-compare`, `-Wassign-enum`, the
  experimental array-bound analyzer): noisier; not evaluated yet.
- C bounds safety (`-fbounds-safety`): needs annotations; candidates are the header and
  response parsers in CPortalCurl. See the `adopt-c-bounds-safety` skill.
