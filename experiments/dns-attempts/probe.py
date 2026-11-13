"""Compare local DNS recording and host egress with no public DNS traffic."""

import socket
import struct
import subprocess
import sys
import threading


QUERY = bytes.fromhex("123401000001000000000000") + b"\x05probe\x04test\x00\x00\x01\x00\x01"


def receiver(ready):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 15353))
        ready.set()
        packet, peer = sock.recvfrom(512)
        assert packet == QUERY
        print("attempted=probe.test", flush=True)
        sock.sendto(packet[:2] + b"\x81\x83" + packet[4:], peer)


def request(address, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.4)
        sock.connect((address, port))
        sock.send(QUERY)
        return sock.recv(512)


def child(address, port, local):
    listener = None
    if local:
        ready = threading.Event()
        listener = threading.Thread(target=receiver, args=(ready,), daemon=True)
        listener.start()
        assert ready.wait(1)
        response = request("127.0.0.1", 15353)
        assert response[3] & 15 == 3
    try:
        request(address, port)
    except OSError:
        print("host DNS unavailable", flush=True)
        if listener:
            listener.join()
        return
    raise AssertionError("the isolated process received a host DNS response")


def run():
    received = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as host:
        host.bind(("127.0.0.1", 0))
        port = host.getsockname()[1]
        host.settimeout(0.1)

        def serve():
            while not done.is_set():
                try:
                    packet, peer = host.recvfrom(512)
                except TimeoutError:
                    continue
                received.append(packet)
                host.sendto(packet, peer)

        done = threading.Event()
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            assert request("127.0.0.1", port) == QUERY
            assert received == [QUERY]
            command = [sys.executable, __file__, "child", "127.0.0.1", str(port)]
            if sys.platform == "linux":
                command = [
                    "/usr/bin/bwrap", "--unshare-user", "--disable-userns",
                    "--unshare-net", "--unshare-pid", "--cap-drop", "ALL",
                    "--ro-bind", "/", "/", "--proc", "/proc", "--",
                    *command, "local",
                ]
            elif sys.platform == "darwin":
                command = [
                    "/usr/bin/sandbox-exec", "-p",
                    "(version 1)(allow default)(deny network*)(deny mach-lookup mach-register)",
                    *command,
                ]
            else:
                raise AssertionError("unsupported OS")
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            print(result.stdout, end="")
            assert result.returncode == 0, result.stderr
            assert ("attempted=probe.test" in result.stdout) == (sys.platform == "linux")
            assert "host DNS unavailable" in result.stdout
            assert received == [QUERY]
            print(f"{sys.platform}: host DNS control=1 isolated=0")
        finally:
            done.set()
            worker.join()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run()
    else:
        child(sys.argv[2], int(sys.argv[3]), len(sys.argv) > 4)
