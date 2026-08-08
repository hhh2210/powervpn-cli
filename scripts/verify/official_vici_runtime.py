#!/usr/bin/env python3
"""Value-free CP7A oracle using strongSwan 6.0.7's official Python VICI client."""

import argparse
import hashlib
import json
import socket
import struct
import sys
import time
from collections import OrderedDict
from pathlib import Path


CONNECTION_NAME = "cp7a.synthetic.invalid"


class SafeProbeError(Exception):
    def __init__(self, code, details=None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


class RecordingSocket:
    def __init__(self, raw_socket):
        self.raw_socket = raw_socket
        self.sent = bytearray()
        self.received = bytearray()

    def sendall(self, data):
        self.sent.extend(data)
        return self.raw_socket.sendall(data)

    def recv(self, count):
        data = self.raw_socket.recv(count)
        self.received.extend(data)
        return data

    def gettimeout(self):
        return self.raw_socket.gettimeout()

    def settimeout(self, timeout):
        return self.raw_socket.settimeout(timeout)

    def shutdown(self, how):
        return self.raw_socket.shutdown(how)

    def close(self):
        return self.raw_socket.close()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def one_frame_trace(name, sent, received, elapsed_ms):
    if len(sent) < 5 or len(received) < 5:
        raise SafeProbeError("incomplete_vici_frame")
    request_length = struct.unpack("!I", sent[:4])[0]
    response_length = struct.unpack("!I", received[:4])[0]
    if request_length + 4 != len(sent) or response_length + 4 != len(received):
        raise SafeProbeError("unexpected_multi_frame_operation")
    request_payload = sent[4:]
    response_payload = received[4:]
    return OrderedDict([
        ("command", name),
        ("requestPayloadBytes", len(request_payload)),
        ("requestWireBytes", len(sent)),
        ("requestPayloadSHA256", sha256(request_payload)),
        ("responsePayloadBytes", len(response_payload)),
        ("responseWireBytes", len(received)),
        ("responsePayloadSHA256", sha256(response_payload)),
        ("responseOperation", response_payload[0]),
        ("latencyMilliseconds", elapsed_ms),
    ])


def aggregate_trace(name, sent, received, elapsed_ms):
    return OrderedDict([
        ("command", name),
        ("requestWireBytes", len(sent)),
        ("requestWireSHA256", sha256(sent)),
        ("responseWireBytes", len(received)),
        ("responseWireSHA256", sha256(received)),
        ("latencyMilliseconds", elapsed_ms),
    ])


def run_recorded(recording, name, operation, single_frame=False):
    sent_offset = len(recording.sent)
    received_offset = len(recording.received)
    started = time.monotonic_ns()
    result = operation()
    elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
    sent = bytes(recording.sent[sent_offset:])
    received = bytes(recording.received[received_offset:])
    trace = (
        one_frame_trace(name, sent, received, elapsed_ms)
        if single_frame
        else aggregate_trace(name, sent, received, elapsed_ms)
    )
    return result, trace


def synthetic_connection():
    return OrderedDict([
        (CONNECTION_NAME, OrderedDict([
            ("version", "1"),
            ("aggressive", "no"),
            ("remote_addrs", ["198.51.100.1"]),
            ("proposals", ["aes128-sha1-modp1024"]),
            ("local", OrderedDict([
                ("auth", "psk"),
                ("id", "client.cp7a.invalid"),
            ])),
            ("remote", OrderedDict([
                ("auth", "psk"),
                ("id", "gateway.cp7a.invalid"),
            ])),
            ("children", OrderedDict([
                ("resource.cp7a.invalid", OrderedDict([
                    ("local_ts", ["dynamic"]),
                    ("remote_ts", ["203.0.113.0/24"]),
                    ("esp_proposals", ["aes128-sha1"]),
                    ("start_action", "none"),
                ])),
            ])),
        ])),
    ])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--python-root", required=True)
    parser.add_argument("--mode", choices=("version", "cp7a-smoke"), required=True)
    parser.add_argument("--timeout-ms", type=int, default=2000)
    args = parser.parse_args()
    if not 1 <= args.timeout_ms <= 60000:
        parser.error("--timeout-ms must be between 1 and 60000")

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

    version, version_trace = run_recorded(
        recording, "version", session.version, single_frame=True
    )
    report = OrderedDict([
        ("schemaVersion", 1),
        ("implementation", "official_strongswan_python_vici"),
        ("mode", args.mode),
        ("success", True),
        ("officialModule", OrderedDict([
            ("relativePath", str(protocol_file.relative_to(python_root))),
            ("sha256", sha256(protocol_file.read_bytes())),
        ])),
        ("version", OrderedDict([
            ("responseKeyNames", list(version.keys())),
            ("trace", version_trace),
        ])),
        ("syntheticProfile", "rfc5737_no_start_action_no_credential"),
        ("credentialRead", False),
        ("credentialSerialized", False),
        ("initiateCalled", False),
        ("installCalled", False),
        ("secretValuesRetained", False),
    ])

    loaded = False
    try:
        if args.mode == "cp7a-smoke":
            baseline_connections, baseline_trace = run_recorded(
                recording, "list-conns", lambda: list(session.list_conns())
            )
            baseline_matches = sum(
                CONNECTION_NAME in item for item in baseline_connections
            )
            if baseline_matches:
                raise SafeProbeError(
                    "synthetic_connection_present_before_load",
                    {"matches": baseline_matches, "events": len(baseline_connections)},
                )
            _, load_trace = run_recorded(
                recording,
                "load-conn",
                lambda: session.load_conn(synthetic_connection()),
            )
            loaded = True
            connections, list_loaded_trace = run_recorded(
                recording, "list-conns", lambda: list(session.list_conns())
            )
            matches = sum(CONNECTION_NAME in item for item in connections)
            if len(connections) != len(baseline_connections) + 1 or matches != 1:
                raise SafeProbeError(
                    "synthetic_connection_not_observed_exactly_once",
                    {
                        "baselineEvents": len(baseline_connections),
                        "events": len(connections),
                        "matches": matches,
                    },
                )

            _, unload_trace = run_recorded(
                recording,
                "unload-conn",
                lambda: session.unload_conn({"name": CONNECTION_NAME}),
            )
            loaded = False
            final_connections, list_final_trace = run_recorded(
                recording, "list-conns", lambda: list(session.list_conns())
            )
            final_matches = sum(CONNECTION_NAME in item for item in final_connections)
            if len(final_connections) != len(baseline_connections) or final_matches:
                raise SafeProbeError(
                    "synthetic_connection_remained_after_unload",
                    {
                        "baselineEvents": len(baseline_connections),
                        "events": len(final_connections),
                        "matches": final_matches,
                    },
                )

            report["listBeforeLoad"] = OrderedDict([
                ("eventCount", len(baseline_connections)),
                ("syntheticConnectionMatches", baseline_matches),
                ("trace", baseline_trace),
            ])
            report["loadConnection"] = load_trace
            report["listAfterLoad"] = OrderedDict([
                ("eventCount", len(connections)),
                ("syntheticConnectionMatches", matches),
                ("trace", list_loaded_trace),
            ])
            report["unloadConnection"] = unload_trace
            report["listAfterUnload"] = OrderedDict([
                ("eventCount", len(final_connections)),
                ("syntheticConnectionMatches", final_matches),
                ("trace", list_final_trace),
            ])
    finally:
        if loaded:
            try:
                session.unload_conn({"name": CONNECTION_NAME})
            except Exception:
                pass
        recording.close()

    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        failure = {
            "schemaVersion": 1,
            "success": False,
            "errorClass": type(error).__name__,
            "errorCode": (
                error.code if isinstance(error, SafeProbeError) else "external_exception"
            ),
            "secretValuesRetained": False,
        }
        if isinstance(error, SafeProbeError):
            failure["errorDetails"] = error.details
        json.dump(
            failure,
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        raise SystemExit(1)
