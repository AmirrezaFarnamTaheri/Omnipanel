#!/usr/bin/env python3
"""Send deterministic raw TCP bytes through a local SOCKS5 proxy."""

import argparse
import hashlib
import json
import socket
import struct
import time
from pathlib import Path


def receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            raise RuntimeError("proxy connection closed before the expected payload arrived")
        chunks.extend(chunk)
    return bytes(chunks)


def consume_bound_address(connection: socket.socket, address_type: int) -> None:
    if address_type == 1:
        receive_exact(connection, 4 + 2)
    elif address_type == 3:
        length = receive_exact(connection, 1)[0]
        receive_exact(connection, length + 2)
    elif address_type == 4:
        receive_exact(connection, 16 + 2)
    else:
        raise RuntimeError(f"unsupported SOCKS5 bound address type: {address_type}")


def open_tunnel(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> socket.socket:
    connection = socket.create_connection((proxy_host, proxy_port), timeout=10)
    connection.settimeout(10)
    connection.sendall(b"\x05\x01\x00")
    if receive_exact(connection, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 proxy did not select no-authentication mode")

    request = (
        b"\x05\x01\x00\x01"
        + socket.inet_aton(target_host)
        + struct.pack("!H", target_port)
    )
    connection.sendall(request)
    response = receive_exact(connection, 4)
    if response[0] != 5 or response[1] != 0:
        raise RuntimeError(f"SOCKS5 CONNECT rejected with reply code {response[1]}")
    consume_bound_address(connection, response[3])
    return connection


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload-file", required=True)
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=2080)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=19090)
    parser.add_argument("--hold-seconds", type=float, default=0)
    parser.add_argument("--ready-file")
    args = parser.parse_args()

    payload = Path(args.payload_file).read_bytes()
    if not payload:
        raise RuntimeError("payload must not be empty")

    with open_tunnel(args.proxy_host, args.proxy_port, args.target_host, args.target_port) as connection:
        connection.sendall(payload)
        echoed = receive_exact(connection, len(payload))
        if echoed != payload:
            raise RuntimeError("echoed payload differs from the transmitted payload")

        if args.hold_seconds > 0:
            if not args.ready_file:
                raise RuntimeError("--ready-file is required when holding a session")
            Path(args.ready_file).write_text("ready\n", encoding="utf-8")
            time.sleep(args.hold_seconds)
            connection.settimeout(3)
            try:
                connection.sendall(b"\x00")
                terminated = connection.recv(1) == b""
            except socket.timeout as error:
                raise RuntimeError("existing TCP session remained open after the core restart") from error
            except OSError:
                terminated = True
            if not terminated:
                raise RuntimeError("existing TCP session survived the core restart")
            print(json.dumps({"sessionTerminated": True, "mechanism": "core_restart"}))
            return

    print(json.dumps({
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }))


if __name__ == "__main__":
    main()
