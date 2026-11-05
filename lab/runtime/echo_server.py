#!/usr/bin/env python3
"""Small loopback TCP echo target for the isolated Sing-box runtime smoke test."""

import argparse
import socketserver


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            chunk = self.request.recv(65536)
            if not chunk:
                return
            self.request.sendall(chunk)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19090)
    args = parser.parse_args()

    with EchoServer((args.host, args.port), EchoHandler) as server:
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
