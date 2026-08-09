# Rescue R2 username/password portal-login gate

Status: **HARD NO-GO; LIVE NOT AUTHORIZED.** The one permitted integrated R2
review is complete and all five direct findings have been fixed, but the strict
post-review path rejects the password POST locally before `session.open`.
Foundation's projected `Set-Cookie` value cannot prove the raw response-header
multiplicity/framing required by the compatibility profile. No live request or
network connection occurred, and R2 remains active rather than PASS.

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
the observed vendor spacing and `ORIGINURL` suffix, but Foundation exposes only
a projected Set-Cookie value and cannot establish raw header multiplicity.
Treating that projection as a proven single wire field would violate the
compatibility invariant. The production path therefore rejects the request
before `session.open`; server tolerance cannot substitute for vendor-exact
framing evidence.

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

The Swift package has a dependency-free `PowerVPNPortal` target. It cannot
import `PowerVPNCore`, XPC, VICI or helper code. `powervpn login` accepts no
option or positional material; invalid arguments are rejected before runtime
construction. The live harness clears the child environment, leaves stdin at
`/dev/null`, supplies prompts through the controlling TTY, reconstructs stdout
through a FIFO and closed `jq` schema, and retains only mode-600 value-free
evidence.

Any future live harness would require all of these before a request could leave
the machine:

- reviewed candidate manifest and exact authorized manifest SHA-256;
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
from every future live window. No rotation or credential input is required now:
the next subcheckpoint is value-free and performs no password authentication.
Rotation outside PowerVPN plus a fresh macOS confirmation remains mandatory
before any later real login; a chat message is not accepted as that gate.

## Integrated review closure and current blocker

Exactly one cumulative R2 integrated review completed. Its five direct findings
were fixed:

1. real process signals now enter bounded task cancellation/cleanup;
2. request cancellation no longer destroys the transport needed for logout;
3. unknown or folded Set-Cookie framing fails closed before network dispatch;
4. the network snapshot dependency is included in manifest identity; and
5. the report limits its erasure claim to observed app-owned secure buffers.

The fixed cumulative candidate is bound by reviewed manifest SHA-256
`676e8062b3b29c83dc56e738c475452f029bc3e77f74261eea15878a618774eb`.
Its final offline verifier passed 108 Portal tests in 17 suites, 109 Core tests
in 10 suites, the arm64 build, strict formatting, the no-network signal harness,
the secret scan and the exact manifest gate. This proves the fixed offline
implementation and safety boundary only; it does not prove server compatibility.

The third fix intentionally exposes the remaining protocol-evidence blocker:
the current Foundation API surface cannot prove raw Set-Cookie field
multiplicity/framing. A synthetic production-path test stopped locally before
`session.open`; no real credential, portal TCP connection, helper, XPC, VICI,
IKE, UDP, route, policy, SA or utun action occurred.

Next checkpoint: an independent R2 raw-header-framing subcheckpoint that uses
no username/password and does not infer wire structure from Foundation's
projected value. Until that evidence exists, R2 is hard NO-GO, the runtime
fixture does not exist, and the Goal remains active.
