#!/usr/bin/env python3
import os
import socket
import subprocess
import tempfile
import time


def read_until_prompt(sock):
    data = b""
    deadline = time.time() + 5
    while time.time() < deadline:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"> "):
            break
    return data.decode(errors="replace")


def send_cmd(sock, cmd):
    sock.sendall((cmd + "\n").encode())
    return read_until_prompt(sock)


def wait_port(host, port, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)


def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    spf_bin = os.path.join(root, "bin", "spf")
    backend_py = os.path.join(root, "fast_backend.py")

    assert_true(os.path.exists(spf_bin), "spf binary missing")

    with tempfile.TemporaryDirectory(prefix="spf-smoke-") as td:
        log_path = os.path.join(td, "spf.log")
        with open(log_path, "w", encoding="utf-8") as logf:
            backend = subprocess.Popen(["python3", backend_py], cwd=root)
            try:
                assert_true(wait_port("127.0.0.1", 9000), "backend did not start")

                spf = subprocess.Popen(
                    [
                        spf_bin,
                        "--token",
                        "secret",
                        "--admin-port",
                        "18081",
                        "--admin-bind",
                        "127.0.0.1",
                    ],
                    cwd=root,
                    stdout=logf,
                    stderr=logf,
                )
                try:
                    assert_true(
                        wait_port("127.0.0.1", 18081), "spf admin did not start"
                    )

                    with socket.create_connection(
                        ("127.0.0.1", 18081), timeout=3
                    ) as admin:
                        banner = read_until_prompt(admin)
                        assert_true(
                            "AUTH required" in banner, "missing auth requirement"
                        )

                        res = send_cmd(admin, "AUTH secret")
                        assert_true("OK authenticated" in res, "auth failed")

                        res = send_cmd(admin, "ADD 18080 127.0.0.1:9000 rr")
                        assert_true("OK rule" in res, "add rule failed")

                        time.sleep(0.3)
                        with socket.create_connection(
                            ("127.0.0.1", 18080), timeout=3
                        ) as cli:
                            cli.sendall(
                                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                            )
                            payload = cli.recv(4096).decode(errors="replace")
                            assert_true(
                                "200 OK" in payload and "Hello" in payload,
                                "forwarded response invalid",
                            )

                        res = send_cmd(admin, "METRICS")
                        assert_true(
                            "spf_connections_total" in res, "metrics output missing"
                        )

                        send_cmd(admin, "QUIT")

                finally:
                    spf.terminate()
                    try:
                        spf.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        spf.kill()

            finally:
                backend.terminate()
                try:
                    backend.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    backend.kill()


if __name__ == "__main__":
    main()
