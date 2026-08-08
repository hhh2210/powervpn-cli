#!/usr/bin/env python3
"""Verify the synthetic CP6 VICI golden with strongSwan's own Python codec."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any


OFFICIAL_COMMIT = "5973ff8e41deef4e015e1138a2de688acedf6f75"
PROTOCOL_RELATIVE = Path("src/libcharon/plugins/vici/python/vici/protocol.py")
PROTOCOL_SHA256 = "f86247d58ce36a84a651bc7fcce9b5acd789b185c056e8fc6dc7015bfc07d3a5"
SOURCE_RELATIVE = Path("fixtures/redacted/tunnel-spec.vici-dry-run.json")
GOLDEN_RELATIVE = Path("fixtures/redacted/vici-load-conn-dry-run-v1.json")
PLACEHOLDER = re.compile(r"^<[A-Za-z][A-Za-z0-9_.:-]{0,63}>$")
SAFE_SOURCE_LITERALS = {
    "1",
    "main",
    "psk",
    "unknown",
    "keychain",
    "aes128-sha1-modp1024",
    "aes128-sha1",
    "ADDRULE",
    "DELRULE",
}
SAFE_TREE_LITERALS = SAFE_SOURCE_LITERALS | {"no", "dynamic", "none"}
EXPECTED_PROFILE = [
    ("section", "/<tunnel-name>"),
    ("value", "/<tunnel-name>/version"),
    ("value", "/<tunnel-name>/aggressive"),
    ("list", "/<tunnel-name>/remote_addrs"),
    ("list", "/<tunnel-name>/proposals"),
    ("section", "/<tunnel-name>/local"),
    ("value", "/<tunnel-name>/local/auth"),
    ("value", "/<tunnel-name>/local/id"),
    ("section", "/<tunnel-name>/remote"),
    ("value", "/<tunnel-name>/remote/auth"),
    ("value", "/<tunnel-name>/remote/id"),
    ("section", "/<tunnel-name>/children"),
    ("section", "/<tunnel-name>/children/<resource-name>"),
    ("list", "/<tunnel-name>/children/<resource-name>/local_ts"),
    ("list", "/<tunnel-name>/children/<resource-name>/remote_ts"),
    ("list", "/<tunnel-name>/children/<resource-name>/esp_proposals"),
    ("value", "/<tunnel-name>/children/<resource-name>/start_action"),
]
EXCLUDED_FIELDS = [
    "credentialReference",
    "sessionBinding",
    "mapID",
    "natTraversal",
    "modeConfig",
    "vendorIds",
    "routes",
    "resourceOperations",
    "resources[].ruleIdentifier",
]


class FixtureError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FixtureError(message)


def exact_keys(value: Any, expected: set[str], path: str) -> None:
    require(type(value) is dict, f"{path}: object required")
    require(set(value) == expected, f"{path}: closed key set mismatch")


def no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError("JSON document contains a duplicate object key")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicate_pairs)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise FixtureError(f"{path.name}: invalid JSON") from error
    require(type(value) is dict, f"{path.name}: root object required")
    return value, raw


def walk_strings(value: Any):
    if type(value) is str:
        yield value
    elif type(value) is list:
        for item in value:
            yield from walk_strings(item)
    elif type(value) is dict:
        for item in value.values():
            yield from walk_strings(item)


def validate_source(spec: dict[str, Any], raw: bytes, golden: dict[str, Any]) -> None:
    exact_keys(
        spec,
        {
            "schemaVersion", "gateway", "ikeVersion", "exchangeMode",
            "authentication", "localIdentifier", "remoteIdentifier", "tunnelName",
            "natTraversal", "credentialReference", "ikeProposal", "espProposal",
            "modeConfig", "vendorIds", "routes", "resourceOperations", "resources",
        },
        "TunnelSpec",
    )
    require(spec["schemaVersion"] == 1, "TunnelSpec: schemaVersion must be 1")
    require(spec["ikeVersion"] == 1, "TunnelSpec: IKE version must be 1")
    exact_keys(spec["authentication"], {"machine", "extended"}, "authentication")
    require(spec["authentication"]["machine"] == "psk", "authentication: machine must be psk")
    require(spec["authentication"]["extended"] == "unknown", "authentication: extended must be unknown")
    exact_keys(spec["credentialReference"], {"storage", "identifier"}, "credentialReference")
    require(spec["credentialReference"]["storage"] == "keychain", "credentialReference: keychain reference required")
    require(PLACEHOLDER.fullmatch(spec["credentialReference"]["identifier"]) is not None, "credentialReference: placeholder required")
    require(spec["natTraversal"] == "unknown", "TunnelSpec: NAT-T must remain unknown")
    require(spec["modeConfig"] == "unknown", "TunnelSpec: Mode Config must remain unknown")
    require(spec["vendorIds"] == [], "TunnelSpec: vendor IDs must be absent")
    require(spec["routes"] == [], "TunnelSpec: route projection must be absent")
    require(spec["resourceOperations"] == ["ADDRULE", "DELRULE"], "TunnelSpec: resource operation metadata mismatch")
    require(type(spec["resources"]) is list and len(spec["resources"]) == 1, "TunnelSpec: exactly one synthetic resource required")
    resource = spec["resources"][0]
    exact_keys(resource, {"name", "ruleIdentifier", "remoteTrafficSelectors"}, "resources[0]")
    require(type(resource["remoteTrafficSelectors"]) is list and len(resource["remoteTrafficSelectors"]) == 1, "resources[0]: exactly one selector required")
    for value in walk_strings(spec):
        require(value in SAFE_SOURCE_LITERALS or PLACEHOLDER.fullmatch(value) is not None, "TunnelSpec: unsafe non-placeholder string")
    expected_hash = golden["sourceTunnelSpec"]["sha256"]
    require(hashlib.sha256(raw).hexdigest() == expected_hash, "TunnelSpec: source digest mismatch")


def node_to_ordered(node: dict[str, Any], path: str, profile: list[tuple[str, str]], leaves: list[str]):
    require(type(node) is dict, f"{path}: node object required")
    kind = node.get("kind")
    require(kind in {"value", "list", "section"}, f"{path}: unsupported node kind")
    expected = {"kind", "name", {"value": "value", "list": "values", "section": "entries"}[kind]}
    exact_keys(node, expected, path)
    name = node["name"]
    require(type(name) is str and 0 < len(name.encode()) <= 255, f"{path}: invalid VICI name")
    current = f"{path}/{name}"
    profile.append((kind, current))
    if kind == "section":
        require(type(node["entries"]) is list, f"{current}: entries list required")
        result: OrderedDict[str, Any] = OrderedDict()
        for child in node["entries"]:
            child_name, child_value = node_to_ordered(child, current, profile, leaves)
            require(child_name not in result, f"{current}: duplicate VICI name")
            result[child_name] = child_value
        return name, result
    if kind == "list":
        values = node["values"]
        require(type(values) is list and values, f"{current}: non-empty values list required")
        require(all(type(item) is str and len(item.encode()) <= 65535 for item in values), f"{current}: invalid list value")
        leaves.extend(values)
        return name, values
    value = node["value"]
    require(type(value) is str and len(value.encode()) <= 65535, f"{current}: invalid scalar value")
    leaves.append(value)
    return name, value


def validate_golden(golden: dict[str, Any], repo: Path) -> tuple[OrderedDict[str, Any], dict[str, Any]]:
    exact_keys(
        golden,
        {
            "schemaVersion", "fixtureClass", "sourceTunnelSpec", "oracle", "safety",
            "command", "orderedTree", "resourceRuleMetadata", "canonicalMessage",
            "canonicalCommandPacket",
        },
        "golden",
    )
    require(golden["schemaVersion"] == 1, "golden: schemaVersion must be 1")
    require(golden["fixtureClass"] == "vici_load_conn_dry_run", "golden: fixture class mismatch")
    exact_keys(golden["sourceTunnelSpec"], {"path", "sha256"}, "sourceTunnelSpec")
    require(golden["sourceTunnelSpec"]["path"] == str(SOURCE_RELATIVE), "sourceTunnelSpec: path mismatch")
    exact_keys(golden["oracle"], {"implementation", "version", "sourceCommit", "protocolModule", "protocolModuleSha256"}, "oracle")
    require(golden["oracle"] == {
        "implementation": "strongSwan Python vici.protocol.Message/Packet",
        "version": "6.0.7",
        "sourceCommit": OFFICIAL_COMMIT,
        "protocolModule": str(PROTOCOL_RELATIVE),
        "protocolModuleSha256": PROTOCOL_SHA256,
    }, "oracle: provenance mismatch")
    exact_keys(golden["safety"], {"synthetic", "containsSecrets", "containsReplayableCapture", "usesNetworkOrSocket"}, "safety")
    require(golden["safety"] == {"synthetic": True, "containsSecrets": False, "containsReplayableCapture": False, "usesNetworkOrSocket": False}, "safety: unsafe fixture flags")
    require(golden["command"] == "load-conn", "golden: command must be load-conn")
    metadata = golden["resourceRuleMetadata"]
    exact_keys(metadata, {"semanticStatus", "includedInViciTree", "excludedTunnelSpecFields"}, "resourceRuleMetadata")
    require(metadata["semanticStatus"] == "unresolved_cp4b", "resourceRuleMetadata: CP4B state mismatch")
    require(metadata["includedInViciTree"] is False, "resourceRuleMetadata: must be outside VICI tree")
    require(metadata["excludedTunnelSpecFields"] == EXCLUDED_FIELDS, "resourceRuleMetadata: exclusion set mismatch")
    exact_keys(golden["canonicalMessage"], {"definition", "length", "sha256"}, "canonicalMessage")
    exact_keys(golden["canonicalCommandPacket"], {"definition", "includesTransportLengthPrefix", "length", "sha256"}, "canonicalCommandPacket")
    require(golden["canonicalCommandPacket"]["includesTransportLengthPrefix"] is False, "canonicalCommandPacket: Transport framing forbidden")
    require(type(golden["orderedTree"]) is list, "orderedTree: list required")
    profile: list[tuple[str, str]] = []
    leaves: list[str] = []
    tree: OrderedDict[str, Any] = OrderedDict()
    for node in golden["orderedTree"]:
        name, value = node_to_ordered(node, "", profile, leaves)
        require(name not in tree, "orderedTree: duplicate root name")
        tree[name] = value
    require(profile == EXPECTED_PROFILE, "orderedTree: closed profile mismatch")
    require(all(value in SAFE_TREE_LITERALS or PLACEHOLDER.fullmatch(value) is not None for value in leaves), "orderedTree: unsafe non-placeholder value")
    forbidden_names = {"vips", "local_addrs", "encap"} | set(EXCLUDED_FIELDS)
    require(not forbidden_names.intersection(name.rsplit("/", 1)[-1] for _, name in profile), "orderedTree: forbidden field present")
    return tree, metadata


def load_official_oracle(source: Path, oracle_meta: dict[str, Any]):
    protocol_path = source / PROTOCOL_RELATIVE
    require(protocol_path.is_file(), "oracle: protocol module missing")
    require(hashlib.sha256(protocol_path.read_bytes()).hexdigest() == oracle_meta["protocolModuleSha256"], "oracle: protocol module digest mismatch")
    result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    require(result.returncode == 0, "oracle: source is not a readable Git checkout")
    require(result.stdout.strip() == oracle_meta["sourceCommit"], "oracle: source commit mismatch")
    python_root = source / "src/libcharon/plugins/vici/python"
    sys.path.insert(0, str(python_root))
    from vici import protocol  # type: ignore[import-not-found]
    require(Path(protocol.__file__).resolve() == protocol_path.resolve(), "oracle: imported module path mismatch")
    return protocol


def verify(repo: Path, source_path: Path, golden_path: Path, strongswan_source: Path) -> tuple[int, str, int, str]:
    golden, _ = load_json(golden_path)
    spec, source_raw = load_json(source_path)
    tree, _ = validate_golden(golden, repo)
    validate_source(spec, source_raw, golden)
    protocol = load_official_oracle(strongswan_source, golden["oracle"])
    message = protocol.Message.serialize(tree)
    decoded = protocol.Message.deserialize(protocol.FiniteStream(message))
    require(protocol.Message.serialize(decoded) == message, "oracle: Message round trip mismatch")
    packet = protocol.Packet.request(golden["command"], message)
    message_hash = hashlib.sha256(message).hexdigest()
    packet_hash = hashlib.sha256(packet).hexdigest()
    require(len(message) == golden["canonicalMessage"]["length"], "canonicalMessage: length mismatch")
    require(message_hash == golden["canonicalMessage"]["sha256"], "canonicalMessage: digest mismatch")
    require(len(packet) == golden["canonicalCommandPacket"]["length"], "canonicalCommandPacket: length mismatch")
    require(packet_hash == golden["canonicalCommandPacket"]["sha256"], "canonicalCommandPacket: digest mismatch")
    return len(message), message_hash, len(packet), packet_hash


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=repo / SOURCE_RELATIVE)
    parser.add_argument("--golden", type=Path, default=repo / GOLDEN_RELATIVE)
    parser.add_argument("--strongswan-source", type=Path, default=Path.home() / "scratch-data/powervpn-strongswan/strongswan-6.0.7")
    args = parser.parse_args()
    try:
        message_length, message_hash, packet_length, packet_hash = verify(repo, args.source.resolve(), args.golden.resolve(), args.strongswan_source.resolve())
    except (FixtureError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: official strongSwan 6.0.7 VICI oracle; message length={message_length} sha256={message_hash}; command packet length={packet_length} sha256={packet_hash}; network/socket use=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
