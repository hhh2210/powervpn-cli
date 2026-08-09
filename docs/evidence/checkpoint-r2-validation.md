# Rescue R2 username/password portal-login gate

Status: **OFFLINE CANDIDATE; LIVE NOT AUTHORIZED.** R2 replaces neither the
vendor helper nor the tunnel. It asks whether a fresh arm64 process can perform
the legal portal transaction using only username and password from a no-echo
controlling TTY, then erase its app-owned material and exit without starting a
helper or sending IKE traffic.

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
the observed vendor spacing and `ORIGINURL` suffix. Foundation exposes a
single projected Set-Cookie value, not raw header multiplicity; therefore the
cookie implementation remains a bounded compatibility hypothesis until the
resource and session requests are both accepted by the real server.

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

URLSession necessarily creates transient Foundation/CF copies for at least the
Cookie header and HTTP implementation. R2 does not claim those framework-
internal copies are zeroized. The retained report is a closed value-free JSON
projection and contains no endpoint, serial, cookie, body, resource value or
credential length.

## Offline acceptance and live boundary

The Swift package has a dependency-free `PowerVPNPortal` target. It cannot
import `PowerVPNCore`, XPC, VICI or helper code. `powervpn login` accepts no
option or positional material; invalid arguments are rejected before runtime
construction. The live harness clears the child environment, leaves stdin at
`/dev/null`, supplies prompts through the controlling TTY, reconstructs stdout
through a FIFO and closed `jq` schema, and retains only mode-600 value-free
evidence.

The harness requires all of these before a request can leave the machine:

- reviewed candidate manifest and exact authorized manifest SHA-256;
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
treated as compromised, was not used by code or tests, and is forbidden from
the live window. The user must rotate it outside PowerVPN and later enter only
the new value through the no-echo TTY. A chat message is not accepted as the
rotation gate.

The integrated review, reviewed manifest, real TTY run and retained runtime
fixture are pending. Until all four are complete, R2 is not PASS and the Goal
must remain active.
