# Control-plane evidence

Status: partial, read-only evidence only. No credential values are recorded.

## Verified

- The GUI has a session-check path for `/vpn/user/check/session`.
- Portal state is converted into helper configuration containing categories for
  a session, PSK, virtual IP, route/resource metadata, map ID, and tunnel name.
- Resource activation precedes a private IKEv1 `ADDRULE` exchange; resource
  names are therefore not equivalent to ordinary static traffic selectors.
- The existing GUI WebSocket failure/close callbacks log and return without
  entering session check or helper restart paths.

## Not yet verified

- The complete login request and response schema.
- Whether the PSK is returned directly, derived locally, or unwrapped from
  another portal field.
- WebSocket endpoint, subprotocol, message ordering, keepalive, and resume
  semantics.
- Certificate validation behavior required by the server.
- The exact mapping from a portal resource object to the opaque ADDRULE body.

## Next capture

Capture a single legal login with field values replaced at collection time:

```text
timestamp/category/method/path/status
cookie-name -> <redacted>
field-name  -> type + length only
resource    -> <RESOURCE_1>
endpoint    -> <VPN_ENDPOINT>
```

Do not preserve Authorization headers, Cookie values, bodies containing PSK or
session material, stable user IDs, or TLS key logs. The first deliverable is a
message schema and ordering table, not a replayable HTTP archive.

## Gate

Control-plane reproduction does not PASS until a fresh process can legally
authenticate, check the session, list resources, and produce a runtime
TunnelSpec without the vendor GUI. A static symbol or endpoint string is only
discovery evidence.
