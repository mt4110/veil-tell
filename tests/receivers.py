"""Exercise the CLI and check payloads from the receiver side on macOS and Linux."""

import base64
import errno
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
from urllib.parse import urlsplit

SCRIPT = Path(__file__).resolve()
DIRECT_ERROR = "EPERM" if sys.platform == "darwin" else "ENETUNREACH"


def connect_probe(host, token):
    proxy = urlsplit(os.environ["HTTPS_PROXY"])
    credentials = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
    with socket.create_connection((proxy.hostname, proxy.port), timeout=3) as conn:
        conn.sendall((f"CONNECT {host}:443 HTTP/1.1\r\n"
                      f"Host: {host}:443\r\n"
                      f"Proxy-Authorization: Basic {credentials}\r\n\r\n").encode())
        with conn.makefile("rb") as stream:
            head = stream.readline().decode().strip()
            for line in stream:
                if line == b"\r\n":
                    break
            print(f"CONNECT={head.split()[1]}")
            if " 200 " in head:
                conn.sendall(f"{token}-connect".encode())
                conn.shutdown(socket.SHUT_WR)
                assert stream.read() == b"ACK"


def probe(address, token):
    connect_probe("allowed.test", token)
    try:
        host, port = address.split(":")
        with socket.create_connection((host, int(port)), timeout=3) as conn:
            conn.sendall(f"{token}-direct".encode())
        print("direct=sent")
    except OSError as error:
        print(f"direct={errno.errorcode.get(error.errno)}")


def receive(listener, count):
    tokens = []
    listener.settimeout(0.25)
    while True:
        try:
            conn, _ = listener.accept()
        except TimeoutError:
            break
        with conn:
            conn.settimeout(3)
            with conn.makefile("rb") as stream:
                tokens.append(stream.read())
    assert len(tokens) == count, tokens
    return tokens


def emit_policy_test(cli, fixture, receiver, project, evidence, env):
    draft = evidence / "observed.toml"
    observation = [fixture, "observe", "--emit-policy", draft]
    received = []

    def acknowledge():
        receiver.settimeout(4)
        for _ in range(2):
            conn, _ = receiver.accept()
            with conn, conn.makefile("rb") as stream:
                conn.settimeout(3)
                received.append(stream.read())
                conn.sendall(b"ACK")

    thread = threading.Thread(target=acknowledge)
    thread.start()
    try:
        result = subprocess.run(
            [*observation, "--", sys.executable, "-B", "probe.py", "observe-candidates"],
            cwd=project, env=env, capture_output=True, text=True, timeout=12,
        )
    finally:
        thread.join()
    assert result.returncode == 0, result.stderr
    assert received == [b"first-connect", b"second-connect"]
    content = draft.read_text()
    assert content.count('# host = "allowed.test"') == 1, content
    assert all(line.startswith("#") for line in content.splitlines() if "allow" in line or "[[rule]]" in line)
    assert draft.stat().st_mode & 0o077 == 0

    result = subprocess.run(
        [*observation, "--", sys.executable, "-c", "print('started')"],
        cwd=project, capture_output=True, text=True, timeout=8,
    )
    assert result.returncode == 125 and "already exists" in result.stderr and not result.stdout, result
    assert draft.read_text() == content

    report_path = evidence / "draft-restrict.json"
    result = subprocess.run(
        [cli, "restrict", "--backend", "isolated", "--policy", draft, "--fail-on-unknown",
         "--report", report_path, "--", sys.executable, "-B", "probe.py", "observe-candidates"],
        cwd=project, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 20 and result.stdout.count("CONNECT=403") == 2, result
    assert receive(receiver, 0) == []
    report = json.loads(report_path.read_text())
    assert report["child_status"]["exit_code"] == 0
    assert report["run_status"] == {"exit_code": 20, "reason": "unknown_destination"}
    event, = report["destinations"]
    assert (event["host"], event["reason"], event["attempts"]) == ("allowed.test", "unknown_destination", 2)
    print("receiver case=policy-draft candidates=1 control_payloads=2 restricted_payloads=0 child_exit=0 exit=20")


def run(cli, fixture, node_root=None):
    cli, fixture = Path(cli).resolve(), Path(fixture).resolve()
    ip = os.environ.get("VEIL_TELL_TEST_IP", "127.0.0.1")
    with tempfile.TemporaryDirectory(prefix="veil-cli-test-", dir="/tmp") as tmp:
        root = Path(tmp).resolve()
        project = root / "project"
        project.mkdir()
        evidence = root / "evidence"
        evidence.mkdir()
        shutil.copyfile(SCRIPT, project / "probe.py")
        policies = {}
        for action in ("unknown", "allow", "deny"):
            path = evidence / f"{action}.toml"
            rule = "" if action == "unknown" else f'\n[[rule]]\naction="{action}"\nhost="allowed.test"\nport=443\n'
            path.write_text('version=1\nprofile="receiver-test"\n' + rule)
            policies[action] = path
        with socket.socket() as receiver:
            receiver.bind((ip, 0))
            receiver.listen()
            host, port = receiver.getsockname()
            address = f"{host}:{port}"
            env = dict(os.environ, VEIL_TELL_FIXTURE_RECEIVER=address)
            emit_policy_test(cli, fixture, receiver, project, evidence, env)
            for name, binary, backend, action, ci, exit_code, proxy_code, direct, tokens in (
                ("proxy-control", fixture, "proxy", "unknown", False, 0, 403, "sent", [b"proxy-control-direct"]),
                ("isolated-allow", fixture, "isolated", "allow", True, 0, 200, DIRECT_ERROR, [b"isolated-allow-connect"]),
                ("isolated-unknown", cli, "isolated", "unknown", True, 20, 403, DIRECT_ERROR, []),
                ("isolated-deny", cli, "isolated", "deny", True, 0, 403, DIRECT_ERROR, []),
            ):
                report_path = evidence / f"{name}.json"
                argv = [binary, "restrict", "--backend", backend, "--policy", policies[action], "--report", report_path]
                if ci:
                    argv.append("--fail-on-unknown")
                argv.extend(["--", sys.executable, "-B", "probe.py", "probe", address, name])
                # The allowed tunnel waits for receiver ACK while the CLI is running.
                collected = []
                if proxy_code == 200:
                    def acknowledge():
                        receiver.settimeout(4)
                        conn, _ = receiver.accept()
                        with conn:
                            conn.settimeout(3)
                            with conn.makefile("rb") as stream:
                                collected.append(stream.read())
                            conn.sendall(b"ACK")
                    thread = threading.Thread(target=acknowledge)
                    thread.start()
                try:
                    child = subprocess.run(argv, cwd=project, env=env, capture_output=True, text=True, timeout=18)
                finally:
                    if proxy_code == 200:
                        thread.join(timeout=8)
                print(child.stdout, end="")
                print(child.stderr, end="")
                assert child.returncode == exit_code, (name, child.returncode, child.stderr)
                assert f"CONNECT={proxy_code}\n" in child.stdout and f"direct={direct}\n" in child.stdout
                collected.extend(receive(receiver, len(tokens) - len(collected)))
                assert collected == tokens, (name, collected)
                report = json.loads(report_path.read_text())
                expected = {"allow": "allow_rule", "unknown": "unknown_destination", "deny": "explicit_deny"}[action]
                assert report["schema_version"] == 1 and report["backend"] == backend
                assert report["child_status"]["exit_code"] == 0
                assert report["run_status"]["exit_code"] == exit_code
                assert report["coverage"]["direct_attempt_destinations"] == "not_observed"
                assert report["coverage"]["proxy"] == "http_connect_requests"
                assert len(report["destinations"]) == 1 and report["destinations"][0]["reason"] == expected
                print(f"receiver case={name} connections={len(collected)} tokens={collected} exit={exit_code}")
                print("json " + json.dumps(report, sort_keys=True))

            with socket.create_connection(receiver.getsockname(), timeout=2) as connected:
                fd = fcntl.fcntl(connected, fcntl.F_DUPFD_CLOEXEC, 20)
            try:
                child = subprocess.run(
                    [cli, "restrict", "--backend", "isolated", "--policy", policies["unknown"],
                     "--", sys.executable, "-B", "probe.py", "fd", str(fd)],
                    pass_fds=(fd,), cwd=project, capture_output=True, text=True, timeout=10,
                )
            finally:
                os.close(fd)
            assert child.returncode == 0 and "EBADF" in child.stdout, (child.stdout, child.stderr)
            assert receive(receiver, 1) == [b""]
            print("receiver case=inherited-fd connections=1 payload_bytes=0 errno=EBADF")
        if node_root:
            npm_test(fixture, Path(node_root).resolve(), project, evidence, policies["allow"], ip)
    print("PASS: CLI receiver, exit status, and JSON checks")


def npm_test(fixture, runtime, project, evidence, policy, ip):
    if sys.platform == "linux":
        shutil.copytree(runtime, project / "runtime", symlinks=True)
        runtime = project / "runtime"
    cert = project / "registry.crt"
    key = evidence / "registry.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=allowed.test", "-addext", "subjectAltName=DNS:allowed.test",
                    "-keyout", key, "-out", cert], check=True, capture_output=True)
    pkg = {"name": "veil-cli-fixture", "version": "1.0.0"}
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        for name, body in [("package.json", json.dumps(pkg)), ("installed.txt", "received")]:
            data = body.encode()
            member = tarfile.TarInfo("package/" + name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    tarball = archive.getvalue()
    path = "/veil-cli-fixture/-/veil-cli-fixture-1.0.0.tgz"
    dist = {"tarball": "https://allowed.test" + path,
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()}
    metadata = json.dumps({**pkg, "dist-tags": {"latest": "1.0.0"},
                           "versions": {"1.0.0": {**pkg, "dist": dist}}}).encode()
    requests = []

    class Registry(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = {"/veil-cli-fixture": metadata, path: tarball}.get(self.path)
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    (project / "package.json").write_text(json.dumps({
        "name": "veil-cli-test-project", "version": "1.0.0", "private": True,
        "dependencies": {"veil-cli-fixture": "1.0.0"},
    }))
    with ThreadingHTTPServer((ip, 0), Registry) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            env = dict(os.environ, VEIL_TELL_FIXTURE_RECEIVER=f"{ip}:{server.server_port}",
                       PATH=f"{runtime / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}")
            result = subprocess.run([
                fixture, "restrict", "--backend", "isolated", "--policy", policy, "--fail-on-unknown",
                "--report", evidence / "npm.json", "--", "npm", "install", "--registry=https://allowed.test",
                "--cafile=registry.crt", "--cache=.npm-cache", "--no-audit", "--no-fund",
                "--no-update-notifier", "--fetch-retries=0",
            ], cwd=project, env=env, capture_output=True, text=True, timeout=25)
        finally:
            server.shutdown()
            thread.join()
    print(result.stdout, end="")
    print(result.stderr, end="")
    assert result.returncode == 0 and requests == ["/veil-cli-fixture", path], (result.stderr, requests)
    assert (project / "node_modules/veil-cli-fixture/installed.txt").read_text() == "received"
    print(f"receiver case=npm requests={requests} exit={result.returncode}")


if __name__ == "__main__":
    if sys.argv[1] == "probe":
        probe(*sys.argv[2:])
    elif sys.argv[1] == "observe-candidates":
        connect_probe("ALLOWED.test.", "first")
        connect_probe("allowed.test", "second")
    elif sys.argv[1] == "fd":
        try:
            os.write(int(sys.argv[2]), b"inherited-fd")
            raise AssertionError("inherited descriptor could be written")
        except OSError as error:
            assert error.errno == errno.EBADF
            print("EBADF")
    else:
        run(*sys.argv[1:])
