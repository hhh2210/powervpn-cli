#!/usr/bin/env python3
import json
import os
import socket
import ssl
import sys

MAX_HTTP_BYTES = 16 * 1024


def write_exclusive(path, payload):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    if len(sys.argv) != 5:
        return 2
    certificate, private_key, port_path, result_path = sys.argv[1:]
    os.umask(0o077)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    observation = {
        "tlsHandshakeCompleted": False,
        "decryptedHTTPByteCount": 0,
        "requestHeadersCompleted": False,
        "responseSent": False,
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10.0)
        write_exclusive(port_path, f"{listener.getsockname()[1]}\n")
        connection, _ = listener.accept()
        connection.settimeout(5.0)
        try:
            with context.wrap_socket(connection, server_side=True) as secure:
                observation["tlsHandshakeCompleted"] = True
                captured = bytearray()
                while len(captured) < MAX_HTTP_BYTES:
                    chunk = secure.recv(MAX_HTTP_BYTES - len(captured))
                    if not chunk:
                        break
                    captured.extend(chunk)
                    if b"\r\n\r\n" in captured:
                        observation["requestHeadersCompleted"] = True
                        break
                observation["decryptedHTTPByteCount"] = len(captured)
                if captured:
                    secure.sendall(
                        b"HTTP/1.1 204 No Content\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    observation["responseSent"] = True
        except (ssl.SSLError, ConnectionError, socket.timeout):
            connection.close()

    write_exclusive(
        result_path,
        json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
