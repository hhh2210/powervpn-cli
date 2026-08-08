# Capture policy

This directory stores only capture manifests and redacted summaries.

Raw HTTPS/WebSocket, XPC, and UDP 500/4500 captures may contain session IDs,
PSKs, cookies, identities, private resource metadata, or reusable authentication
material. Keep them outside Git in a dedicated mode-700 directory, for example:

```bash
mkdir -p ~/scratch-data/powervpn-captures
chmod 700 ~/scratch-data/powervpn-captures
```

Before a derived artifact enters this repository, verify that it contains no
raw payload bytes, credentials, stable identifiers, endpoint addresses, or
packet-derived secrets. Prefer a structured fact table over a sanitized pcap;
packet redaction is easy to get wrong.
