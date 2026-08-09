# Rescue R2 username/password portal-login gate

Status: **OFFLINE PASS — MANIFEST RESEALED; FULL VERIFIER PASS; LIVE HARD
NO-GO / NOT TESTED.** The integrated R2 offline-base review and independent
raw-header review are complete and all direct findings have been applied. The
reviewed candidate is manifest-bound and its full offline verifier passes. No
live request, successful TLS transfer, server interaction or credential use
occurred, so R2 remains active rather than live PASS.

## Scope

The only server-facing order implemented by this checkpoint is:

```text
POST password login
GET resource catalog
wait 60 seconds
GET session check
POST logout
```

There is no `start_connection`, XPC, VICI, IKE, UDP 500/4500, SA, policy,
route, utun, resource activation, retry, CAPTCHA bypass, or generic insecure
TLS mode. A CAPTCHA/challenge response is a closed `challenge_required`
outcome and stops the transaction.

## Installed configuration evidence

The selected address path was recovered statically from the exact installed
PowerVPN 3.2.1 build 24572: `address_selectedID == 0` selects
`VSGAddressModel ORDER BY pk DESC LIMIT 1`, and the app formats the selected
`address` and decimal `port` as an HTTPS origin. The profile version is the
literal `2.0`.

A bounded read-only confirmation used the exact upstream SQLCipher 3.4.0
CommonCrypto build against a mode-600 encrypted database copy. The vendor's
13-byte database passphrase was derived inside the producer process, delivered
only through a pipe, and zeroed; it did not enter argv, environment, a script,
stdout, stderr, or the repository. The only row query was:

```sql
SELECT quote(address), quote(port), pk
FROM VSGAddressModel
ORDER BY pk DESC
LIMIT 1;
```

No `VSGUsersModel` row was queried. The selected address/port matched the
sealed origin used by the candidate. Runtime discovery accepts no endpoint
argument: it verifies exact app, Info.plist, encrypted-database and preferences
artifacts, validates the selection and language state, then materializes only
that reviewed profile. A changed installation fails closed.

The installed app disables peer and hostname verification. R2 deliberately
does not reproduce that security defect: it requires the exact selected host
and macOS system trust, rejects all redirects before a second request, rejects
task-level authentication challenges, and has no `--insecure` path. This is an
explicit safe product boundary, not evidence that the vendor verified TLS.

## Password and session compatibility profile

Static disassembly of the exact installed binary establishes the default
password POST body:

```text
encode='1'&hardware_hash=<raw-platform-serial>&password=<base64>&terminal_type=mac&type=app&username=<base64>
```

Keys are lexicographically ordered, values are not percent-escaped, username
and password are independently standard-Base64 encoded, and `hardware_hash`
is the unmodified platform serial. The request uses `Content-Type: text/xml`.
R2 does not infer the unobserved `encode=2` version-preflight path.

Login accepts numeric hexadecimal `RESPONSE.RESULT.code == 0`; the known
verification-code challenge fails closed. A `VSG_SESSIONID` comes from the
password response's `Set-Cookie`, not the XML. The fresh isolated jar preserves
the observed vendor spacing and `ORIGINURL` suffix. Foundation still exposes
only a projected Set-Cookie value and cannot establish raw header multiplicity,
so that transport remains fail closed before `session.open`. The reviewed
system-libcurl seam observes bounded raw header fields and accepts only a
factory-proven exact password request with one final `Set-Cookie` field. Its
evidence is synthetic; server tolerance is not used as a substitute for
vendor-exact framing.

Resource acceptance mirrors the vendor's minimal gate: an empty or missing
resource list is allowed, while `0x80000020` and `RESPONSE.ERROR` reject. The
session query is exactly `key=hostid`; only exact `0x80000014` means invalid.
Logout is an empty-body POST with no upload Content-Type or Content-Length.

The installed preferences currently contain `currentLanguageKey=en-US`, but
the vendor compares it against `"en"`, misses, and returns language index zero.
The resulting compatibility cookie is therefore `zh_CN`. R2 preserves this
observed bug instead of normalizing it to the UI language.

## Memory and library boundary

Username, password, platform serial, request bodies, response bodies, parsed
XML scalar values and the session cookie are held in app-owned, explicitly
erasable buffers. The workflow reports erasure only after observing those
owned buffers at zero length and no active tracked request/response.

The URLRequest bridge explicitly constructs one transient Swift `String` from
the Cookie buffer, after which URLSession may create additional Foundation/CF
copies. None of those bridge/framework copies is claimed zeroized. The report
claims only `appOwnedSecureBuffersErasureObserved`; it separately fixes
`swiftAndFoundationBridgeCopiesErasureClaimed=false`. The retained projection
contains no endpoint, serial, cookie, body, resource value or credential
length.

## Offline acceptance and live boundary

The Swift package isolates `PowerVPNPortal`: it may depend only on the
package-local `CPortalCurl` target and cannot import `PowerVPNCore`, XPC, VICI
or helper code. `powervpn login` accepts no option or positional material;
invalid arguments are rejected before runtime construction. The live harness
clears the child environment, leaves stdin at `/dev/null`, supplies prompts
through the controlling TTY, reconstructs stdout through a FIFO and closed
`jq` schema, and retains only mode-600 value-free evidence.

Any future live harness would require all of these before a request could leave
the machine:

- reviewed candidate manifest SHA-256
  `00411979105d9023916af3eef5bda0f3886231a5ad74714c0e47d5197bf9e084`
  and a fresh authorization bound to that exact hash;
- exact manifest-bound network snapshot script;
- PowerVPN GUI, all vendor helpers and native charon absent;
- exact inactive launchd generation;
- a new-password rotation confirmation;
- direct controlling TTY;
- before/after network-state equality.

During the window, the CLI may have TCP only to the sealed portal origin. Any
UDP descriptor, helper/native-charon process, other remote TCP endpoint,
route/DNS/interface/utun drift, invalid report, or cleanup residue fails the
checkpoint.

One password was pasted into the Codex task text during R2 development. It is
treated as compromised, was not used by code or tests, and remains forbidden
from every future live window. The next action is for the user to rotate it
outside PowerVPN. After rotation, a fresh explicit approval must bind the exact
manifest hash above. The new username/password may be entered only through the
no-echo controlling TTY; credentials must never be sent through chat.

## Integrated review closure and offline acceptance

Exactly one cumulative R2 integrated review completed. Its five direct findings
were fixed:

1. real process signals now enter bounded task cancellation/cleanup;
2. request cancellation no longer destroys the transport needed for logout;
3. unknown or folded Set-Cookie framing fails closed before network dispatch;
4. the network snapshot dependency is included in manifest identity; and
5. the report limits its erasure claim to observed app-owned secure buffers.

The independent raw-header review returned exactly two direct findings, both
fixed: a factory-only unforgeable operation proof now excludes forged body,
Cookie and User-Agent near misses with zero transport-lane hits; TLS trust
classification is limited to peer/issuer verification while handshake and
cipher failures are `unavailable`. No second raw-header review ran.

The fixed cumulative candidate is bound by reviewed manifest SHA-256
`00411979105d9023916af3eef5bda0f3886231a5ad74714c0e47d5197bf9e084`
and runtime source aggregate SHA-256
`83c590c8ebb3c15b8e32d125bfbdef6c4b39aabd94ca9235c35aef140b67eee2`.
The same manifest binds runtime-library SHA-256
`d6c3f1696e18beac31ffd425e177febce5ec523a0f6a05c2f8bf6c9e8cf56152`
and raw-header-test aggregate SHA-256
`a6d98b928a9c0a63ded37b7b60120e9483fabddf8dea6a895a160276a4acab05`.
Its full offline verifier passed 120 Portal tests in 19 suites and 109 Core tests
in 10 suites (229 tests in 29 suites), the arm64 build, strict formatting, the
no-network signal harness, the secret scan and the exact manifest gate. The raw
sub-gates passed 11 direct C parser cases, 5 direct C status cases, 16 Swift
cases in 3 suites and the separate Foundation fail-closed regression.

This proves only the reviewed offline implementation and safety boundary. No
real credential, successful TLS transfer, portal TCP connection, helper, XPC,
VICI, IKE, UDP, route, policy, SA or utun action occurred. Server compatibility
and the R2 live workflow remain **NOT TESTED**; R2 is **HARD NO-GO** for live
login and the Goal remains active.

Next: the user rotates the compromised password outside PowerVPN, then provides
fresh approval bound to the exact manifest. Only the no-echo controlling TTY
may receive the new credentials; they must never be sent through chat.
