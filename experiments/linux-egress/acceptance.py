"""Receiver-side controls for IPv6, UDP/DNS, Unix IPC, and inherited FDs."""

import errno
import fcntl
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

LAB_IPV6 = "fd42:7665:696c::1"
WAIT = 0.15
SOURCE = Path(__file__).resolve()


def dns_query(token):
    header = struct.pack("!6H", 0x564C, 0x0100, 1, 0, 0, 0)
    question = bytes([len(token)]) + token + b"\x04test\x00\x00\x01\x00\x01"
    return header + question


def probe(route, destination, port, token):
    print(f"attempt route={route} token={token}", flush=True)
    try:
        if route == "fd":
            os.write(int(destination), token.encode())
        elif route in ("udp", "dns"):
            data = dns_query(token.encode()) if route == "dns" else token.encode()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(data, (destination, port))
        else:
            family = {"ipc": socket.AF_UNIX, "ipv6": socket.AF_INET6}.get(route, socket.AF_INET)
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(destination if route == "ipc" else (destination, port))
                client.sendall(token.encode())
    except OSError as error:
        print(f"result={errno.errorcode.get(error.errno, error.errno)}")
    else:
        print("result=sent")


def sandbox(bwrap, ipc_path):
    argv = [
        bwrap, "--unshare-user", "--unshare-net", "--unshare-pid", "--die-with-parent",
        "--new-session", "--cap-drop", "ALL", "--clearenv",
        "--dev", "/dev", "--proc", "/proc",
        "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
        "--ro-bind", str(SOURCE), "/acceptance.py",
        "--ro-bind", str(SOURCE.with_name("target.py")), "/target.py",
    ]
    if Path("/lib64").exists():
        argv.extend(["--ro-bind", "/lib64", "/lib64"])
    # Deliberately expose the test socket even under isolation, simulating an
    # endpoint in an allowed mount. The pathname and permissions stay the same.
    if ipc_path:
        argv.extend(["--ro-bind", ipc_path, ipc_path])
    return argv + ["--"]


def receive(listener, datagram):
    packets = []
    listener.settimeout(WAIT)
    while True:
        if datagram:
            try:
                packets.append(listener.recv(4096))
            except TimeoutError:
                return packets
        else:
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                return packets
            with connection:
                connection.settimeout(2)
                with connection.makefile("rb") as stream:
                    packets.append(stream.read(4096))


def trial(command, route, label, condition, listener, result, *, pass_fd=True):
    token = f"{label}-{condition}"
    fd = None
    port = 0
    if route == "fd":
        with socket.create_connection(listener.getsockname(), timeout=2) as connected:
            # The supervisor, outside isolation, establishes the connection.
            fd = fcntl.fcntl(connected, fcntl.F_DUPFD_CLOEXEC, 20)
        destination = str(fd)
    elif route == "ipc":
        destination = listener.getsockname()
    else:
        destination, port, *_ = listener.getsockname()
    try:
        child = subprocess.run(
            [*command, "probe", route, destination, str(port), token],
            close_fds=True,
            pass_fds=(fd,) if fd is not None and pass_fd else (),
            stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=4
        )
    finally:
        if fd is not None:
            os.close(fd)

    print(child.stdout, end="")
    print(child.stderr, end="", file=sys.stderr)
    packets = receive(listener, route in ("udp", "dns"))
    display = [packet.hex() if route == "dns" else packet.decode() for packet in packets]
    print(f"receiver route={label} condition={condition} events={len(packets)} "
          f"payload_bytes={sum(map(len, packets))} records={display}", flush=True)

    expected_payload = dns_query(token.encode()) if route == "dns" else token.encode()
    # For FD tests, the connection itself is always created by the supervisor.
    expected = [expected_payload] if result == "sent" else [b""] if route == "fd" else []
    if (child.returncode != 0 or f"attempt route={route} token={token}\n" not in child.stdout
            or f"result={result}\n" not in child.stdout or packets != expected):
        raise RuntimeError(f"{label}/{condition}: unexpected client or receiver result")


def run(bwrap, ip):
    subprocess.run(
        ["ip", "-6", "addr", "add", f"{LAB_IPV6}/128", "dev", "lab0", "nodad"], check=True
    )
    print(f"receiver IPv4={ip} IPv6={LAB_IPV6} DNS=UDP/53", flush=True)
    root = Path(tempfile.mkdtemp(prefix="veil-accept-"))
    ipc_path = str(root / "host.sock")
    for route, family, kind, address in (
        ("ipv6", socket.AF_INET6, socket.SOCK_STREAM, (LAB_IPV6, 0)),
        ("udp", socket.AF_INET, socket.SOCK_DGRAM, (ip, 0)),
        ("dns", socket.AF_INET, socket.SOCK_DGRAM, (ip, 53)),
        ("ipc", socket.AF_UNIX, socket.SOCK_STREAM, ipc_path),
        ("fd", socket.AF_INET, socket.SOCK_STREAM, (ip, 0)),
    ):
        with socket.socket(family, kind) as listener:
            listener.bind(address)
            if kind == socket.SOCK_STREAM:
                listener.listen()
            conditions = ("open", "namespace-only", "guarded") if route in ("ipc", "fd") else (
                "open", "guarded"
            )
            for condition in conditions:
                result = "sent"
                if condition == "open":
                    command = [sys.executable, str(SOURCE)]
                else:
                    command = sandbox(bwrap, ipc_path if route == "ipc" else None)
                    if condition == "guarded":
                        command.extend(["/usr/bin/python3", "-B", "/target.py"])
                        result = {"ipc": "EPERM", "fd": "EBADF"}.get(route, "ENETUNREACH")
                    command.extend(["/usr/bin/python3", "-B", "/acceptance.py"])
                trial(command, route, route, condition, listener, result)
    print("PASS: 12 receiver trials for IPv6, UDP, DNS, host IPC, and inherited FD", flush=True)


def macos():
    probe_command = [sys.executable, "-B", str(SOURCE)]
    # A short pathname keeps the Unix socket under Darwin's address length limit.
    root = Path(tempfile.mkdtemp(prefix="veil-mac-", dir="/tmp"))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_port_receiver:
        proxy_port_receiver.bind(("127.0.0.1", 0))
        proxy_port_receiver.listen()
        proxy_port = proxy_port_receiver.getsockname()[1]

        def seatbelt(transport):
            profile = ("(version 1)(allow default)(deny network*)"
                       f'(allow network-outbound (remote {transport} "localhost:{proxy_port}"))')
            return ["/usr/bin/sandbox-exec", "-p", profile, *probe_command]

        original = seatbelt("tcp")
        guarded = seatbelt("tcp4")
        print(f"platform=darwin uid={os.getuid()} proxy_port={proxy_port}", flush=True)
        trial(guarded, "tcp4", "proxy-port-ipv4", "guarded", proxy_port_receiver, "sent")
        for route, label, family, kind, address in (
            ("ipv6", "ipv6-other-port", socket.AF_INET6, socket.SOCK_STREAM, ("::1", 0)),
            ("ipv6", "ipv6-proxy-port", socket.AF_INET6, socket.SOCK_STREAM, ("::1", proxy_port)),
            ("udp", "udp-proxy-port", socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", proxy_port)),
            ("dns", "dns", socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", 0)),
            ("ipc", "ipc", socket.AF_UNIX, socket.SOCK_STREAM, str(root / "host.sock")),
            ("fd", "fd", socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 0)),
        ):
            with socket.socket(family, kind) as listener:
                listener.bind(address)
                if kind == socket.SOCK_STREAM:
                    listener.listen()
                print(f"endpoint route={label} address={listener.getsockname()}", flush=True)
                trial(probe_command, route, label, "open", listener, "sent")
                if label == "ipv6-proxy-port" or route == "fd":
                    trial(original, route, label, "original-seatbelt", listener, "sent")
                if route == "fd":
                    trial(guarded, route, label, "fd-retained", listener, "sent")
                trial(guarded, route, label, "guarded", listener,
                      "EBADF" if route == "fd" else "EPERM", pass_fd=False)
    print("PASS: macOS receiver controls, two bypasses reproduced, guarded paths verified", flush=True)


if __name__ == "__main__":
    mode, *args = sys.argv[1:]
    if mode == "run":
        run(*args)
    elif mode == "macos" and sys.platform == "darwin":
        macos()
    elif mode == "probe":
        route, destination, port, token = args
        probe(route, destination, int(port), token)
    else:
        raise SystemExit("expected run, macos, or probe")
