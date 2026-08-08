#!/usr/bin/env python3
"""Value-free CP7B VICI inventory using strongSwan's official Python client."""

import argparse
import json
import socket
import sys
from collections import OrderedDict
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--python-root", required=True)
    parser.add_argument("--oracle-root", required=True)
    parser.add_argument("--timeout-ms", type=int, default=2000)
    args = parser.parse_args()
    if not 1 <= args.timeout_ms <= 5000:
        parser.error("--timeout-ms must be between 1 and 5000")

    oracle_root = Path(args.oracle_root).resolve(strict=True)
    sys.path.insert(0, str(oracle_root))
    from official_vici_runtime import RecordingSocket, run_recorded

    python_root = Path(args.python_root).resolve(strict=True)
    sys.path.insert(0, str(python_root))
    from vici import Session
    from vici import protocol

    protocol_file = Path(protocol.__file__).resolve(strict=True)
    if python_root not in protocol_file.parents:
        raise RuntimeError("official_python_module_path_mismatch")

    raw_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    raw_socket.settimeout(args.timeout_ms / 1000.0)
    raw_socket.connect(args.socket)
    recording = RecordingSocket(raw_socket)
    session = Session(recording)
    try:
        version, version_trace = run_recorded(
            recording, "version", session.version, single_frame=True
        )
        stats, stats_trace = run_recorded(
            recording, "stats", session.stats, single_frame=True
        )
        sas, sas_trace = run_recorded(
            recording, "list-sas", lambda: list(session.list_sas())
        )
        policies, policies_trace = run_recorded(
            recording, "list-policies", lambda: list(session.list_policies())
        )
        connections, connections_trace = run_recorded(
            recording, "list-conns", lambda: list(session.list_conns())
        )
    finally:
        recording.close()

    report = OrderedDict([
        ("schemaVersion", 1),
        ("implementation", "official_strongswan_python_vici"),
        ("evidenceClass", "cp7b_value_free_read_only_inventory"),
        ("success", True),
        ("versionResponseKeyNames", list(version.keys())),
        ("statsResponsePresent", isinstance(stats, dict) and bool(stats)),
        ("counts", OrderedDict([
            ("connections", len(connections)),
            ("sas", len(sas)),
            ("policies", len(policies)),
        ])),
        ("traces", OrderedDict([
            ("version", version_trace),
            ("stats", stats_trace),
            ("listSAs", sas_trace),
            ("listPolicies", policies_trace),
            ("listConnections", connections_trace),
        ])),
        ("credentialRead", False),
        ("credentialSerialized", False),
        ("initiateCalled", False),
        ("installCalled", False),
        ("containsSecrets", False),
        ("containsRawState", False),
    ])
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        json.dump({
            "schemaVersion": 1,
            "success": False,
            "errorClass": type(error).__name__,
            "errorCode": "cp7b_read_only_probe_failed",
            "containsSecrets": False,
            "containsRawState": False,
        }, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        raise SystemExit(1)
