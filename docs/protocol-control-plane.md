# Control-plane evidence

Status: static schema plus one legal value-free runtime correlation complete.
No credential or session value is recorded.

Detailed evidence and code locations are in
[`evidence/checkpoint-5-static-correlation.md`](evidence/checkpoint-5-static-correlation.md).

## Confirmed static request shapes

| Method/path | Ordered fields |
| --- | --- |
| `POST /vpn/user/auth/password` | `type`, `mac`, `verifycode`, `username`, `password` |
| `POST /vpn/user/auth/token` | `token` |
| `POST /vpn/user/auth/anonymity` | none proven |
| `GET /vpn/user/portal/intergration.xml` | `version:string` |
| `GET /vpn/user/check/session` | `key:string` |
| `POST /vpn/user/logout` | none proven |

The password-auth objects are only string-like by static inference; exact
runtime classes and lengths remain unknown. A live session-check response was
observed with HTTP 200, but other response statuses remain unknown.

## Confirmed object lineage

The app stores the same auth-result parameter object, passes it through resource
parsing, and later dispatches it to helpers in this order:

```text
auth result -> setParams:/parseSorce: -> startAllXPCCPnnections:
            -> cs -> nc -> ipsec
```

This confirms that portal state feeds the helper configuration containing
session, PSK, VIP, route/resource, map, and tunnel categories. It does not prove
the exact portal-field-to-helper-field mapping or the source/derivation of the
PSK.

## Independent state axes

Runtime evidence must record auth-session and control-channel transitions
independently. In particular:

- a WebSocket close must not imply session expiry;
- a session-check failure must not imply that an IKE SA has already stopped;
- helper establishment must not imply a valid current portal session.

The metadata-only model uses closed state enums and rejects discontinuous state
transitions. Unknown evidence remains explicitly `unknown`.

## WebSocket status

Static callback bodies only log and return. Endpoint, subprotocol, message
types/order, keepalive, resume, and even the callback's portal-versus-local role
remain unknown. The four WebSocket observer breakpoints had zero hits during
the bounded legal session; that is only `not observed`, not evidence that the
channel is absent. No generic `keepalive` string is promoted to protocol
evidence.

## Runtime capture contract

Only the following may be emitted at the plaintext serialization boundary:

```text
sequence + relative time
method + path template + status (when observed)
direction + operation
ordered field name + type + length/unit
auth/control/resource state transitions
evidence class + confidence
```

Forbidden schema slots include `value`, `body`, `headers`, `cookieValue`,
`authorization`, `rawDescription`, and `auditToken`. Raw captures, TLS key logs,
and replayable archives remain outside Git in a mode-700 scratch directory.
Known HTTP operations are validated against exact method/path and ordered field
profiles. An unknown path may be represented only as `/<UNKNOWN_PATH>`, and
unknown fields only as bounded `unknownFieldN` placeholders; literal identity
segments are rejected.

The synthetic contract fixture is
[`../fixtures/redacted/protocol-correlation-value-free-v1.json`](../fixtures/redacted/protocol-correlation-value-free-v1.json)
and the derived runtime subset is
[`../fixtures/redacted/protocol-correlation-runtime-metadata-v1.json`](../fixtures/redacted/protocol-correlation-runtime-metadata-v1.json).
They can be checked with:

```bash
swift run powervpn oracle correlate \
  fixtures/redacted/protocol-correlation-value-free-v1.json --json
swift run powervpn oracle correlate \
  fixtures/redacted/protocol-correlation-runtime-metadata-v1.json --json
```

The synthetic fixture proves only the safe data shape. The runtime fixture is a
three-event value-free subset of the legal observation and confirms:

- `GET /vpn/user/check/session` with ordered `key:string` metadata;
- a corresponding HTTP 200 response;
- no header, cookie, body, session value, endpoint, identity, or credential was
  retained.

The first observation window also reached a visible session-timeout failure
before the resource action. A fresh legal login then produced repeated HTTP 200
session checks. This is direct evidence that displayed resource/tunnel state
must not be used as a proxy for current control-session validity.

## Gate

Checkpoint 5's correlation gate is satisfied by the legal value-free runtime
observation while keeping unobserved facts explicit. Independent control-plane
reproduction still does not PASS until a fresh native process can legally
authenticate, check the session, list resources, and produce a runtime
TunnelSpec without the vendor GUI.
