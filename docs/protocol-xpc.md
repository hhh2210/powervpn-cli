# GUI to helper XPC evidence

Status: partial. Known method/action names exist, but a complete typed message
trace has not been captured.

## Verified actions

The vendor app exposes control paths corresponding to:

- start connection;
- stop connection;
- restart connection by helper type and tunnel name;
- start all helper connections;
- helper disconnect notification.

The helper is installed as an x86_64 system LaunchDaemon. Its service identity
is code-signed by the vendor and launchd applies a team/signing requirement.
Cross-architecture XPC serialization is not the main uncertainty; client
authorization and the exact dictionary contract are.

## Capture format

For each request/reply/event, record only:

```json
{
  "direction": "gui-to-helper",
  "sequence": 1,
  "action": "<ACTION>",
  "keys": {
    "<KEY>": "string|number|boolean|array|dictionary|data(length-only)"
  },
  "replyKeys": ["<KEY>"],
  "resultClass": "success|failure|disconnect"
}
```

Values, raw `xpc_object_t` descriptions, audit tokens, credentials, session
material, PSKs, and stable identifiers are forbidden in committed fixtures.

## Decision rule

This boundary is useful for understanding the oracle, but it is not the target
product API. If a small arm64 probe is rejected by the vendor signing check,
record the rejection and move on. Do not build a signature bypass or reproduce
the vendor XPC surface in the final daemon. The target boundary is a narrow,
owned app-to-daemon protocol followed by VICI plus the resource extension.
