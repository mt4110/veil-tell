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


def connect_probe(host, token, auth_override=None):
    proxy = urlsplit(os.environ["HTTPS_PROXY"])
    credentials = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
    if auth_override is not None:
        credentials = auth_override
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


def destination_diff_test(cli, fixture, project, evidence, node_root=None):
    baseline = evidence / "baseline.json"
    changed = evidence / "changed.json"
    report = evidence / "diff.json"
    command = [sys.executable, "-B", "probe.py", "observe-candidates"]
    baseline_cmd = [fixture, "observe", "--backend", "isolated", "--baseline-out", baseline]
    with socket.socket() as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.listen()
        receiver.settimeout(5)
        host, port = receiver.getsockname()
        env = dict(os.environ, VEIL_TELL_FIXTURE_RECEIVER=f"{host}:{port}")

        def run_and_receive(argv, count):
            payloads = []
            def acknowledge():
                for _ in range(count):
                    conn, _ = receiver.accept()
                    with conn:
                        conn.settimeout(5)
                        with conn.makefile("rb") as stream:
                            payloads.append(stream.read())
                        conn.sendall(b"ACK")
            thread = threading.Thread(target=acknowledge)
            thread.start()
            try:
                result = subprocess.run(argv, cwd=project, env=env, capture_output=True,
                                        text=True, timeout=30)
            finally:
                thread.join(timeout=7)
            assert len(payloads) == count, (result.stdout, result.stderr, payloads)
            assert receive(receiver, 0) == []
            return result, payloads

        result, payloads = run_and_receive([*baseline_cmd, "--", *command], 2)
        assert result.returncode == 0 and payloads == [b"first-connect", b"second-connect"]
        before = baseline.read_bytes()
        assert json.loads(before)["destinations"] == [{"host": "allowed.test", "port": 443, "attempts": 2}]

        result, payloads = run_and_receive([
            fixture, "observe", "--backend", "isolated", "--baseline", baseline,
            "--fail-on-new", "--report", report, "--",
            sys.executable, "-B", "probe.py", "new-destination",
        ], 1)
        assert result.returncode == 21 and payloads == [b"new-connect"], result.stderr
        data = json.loads(report.read_text())
        assert data["schema_version"] == 1
        assert data["run_status"] == {"exit_code": 21, "reason": "new_destination"}
        assert [d["host"] for d in data["comparison"]["added"]] == ["new.test"]
        assert [d["host"] for d in data["comparison"]["removed"]] == ["allowed.test"]

        result, _ = run_and_receive([
            cli, "ci", "--baseline", baseline, "--report", changed, "--",
            sys.executable, "-B", "probe.py", "new-destination",
        ], 0)
        assert result.returncode == 21 and "CONNECT=403" in result.stdout, result.stderr
        data = json.loads(changed.read_text())
        assert data["coverage"]["direct_attempt_destinations"] == "not_observed"
        assert data["run_status"] == {"exit_code": 21, "reason": "new_destination"}
        event, = data["destinations"]
        assert (event["reason"], event["result"], event["sent_bytes"], event["received_bytes"]) == (
            "new_destination", "blocked", 0, 0)
        unauthenticated = evidence / "bad-auth.json"
        result, _ = run_and_receive([
            cli, "ci", "--attribute-npm", "--baseline", baseline, "--report", unauthenticated, "--",
            sys.executable, "-B", "probe.py", "invalid-proxy-auth",
        ], 0)
        assert result.returncode == 21 and "CONNECT=407" in result.stdout, result.stderr
        data = json.loads(unauthenticated.read_text())
        event, = data["destinations"]
        assert event["attribution"] == [{"confidence": "unknown"}]
        assert event["reason"] == "new_destination" and event["result"] == "blocked"
        assert data["comparison"]["added"][0]["host"] == "new.test"

        failed = evidence / "failed-child.json"
        result, _ = run_and_receive([
            cli, "ci", "--baseline", baseline, "--report", failed, "--",
            "/bin/sh", "-ec", '"$@"; exit 9', "probe", sys.executable, "-B",
            "probe.py", "new-destination",
        ], 0)
        assert result.returncode == 21, result.stderr
        data = json.loads(failed.read_text())
        assert data["child_status"]["exit_code"] == 9
        assert data["comparison"]["status"] == "new_destinations_only"
        assert data["comparison"]["removed"] == []

        missing = evidence / "missing.json"
        result, _ = run_and_receive([
            cli, "ci", "--baseline", missing, "--", "/bin/echo", "must-not-start",
        ], 0)
        assert result.returncode == 125 and not result.stdout

        result, _ = run_and_receive([
            cli, "observe", "--baseline-out", missing, "--", "/bin/sh", "-c", "exit 9",
        ], 0)
        assert result.returncode == 9 and not missing.exists()
        assert baseline.read_bytes() == before
        print("receiver case=destination-diff observe_payload=1 ci_payload=0 exit=21")

        if node_root:
            npm_destination_diff(cli, project, evidence, Path(node_root).resolve())
            lockfile_destination_diff(cli, project, evidence, Path(node_root).resolve())
            cargo_destination_diff(cli, project, evidence)


def npm_destination_diff(cli, project, evidence, runtime):
    demo = project / "destination-diff"
    shutil.copytree(SCRIPT.parent / "fixtures" / "destination-diff", demo)
    if sys.platform == "linux":
        shutil.copytree(runtime, demo / "runtime", symlinks=True)
        runtime = demo / "runtime"
    env = dict(os.environ, PATH=f"{runtime / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    args = ["npm", "install", "--foreground-scripts", "--no-audit", "--no-fund",
            "--no-update-notifier", "--cache=.npm-cache"]
    baseline = evidence / "npm-baseline.json"
    report = evidence / "npm-diff.json"

    def invoke(argv):
        return subprocess.run(argv, cwd=demo, env=env, capture_output=True, text=True, timeout=35)

    result = invoke([cli, "observe", "--backend", "isolated", "--baseline-out", baseline, "--", *args])
    assert result.returncode == 0, result.stderr
    assert json.loads(baseline.read_text())["destinations"] == []
    automatic = invoke([cli, *args])
    assert automatic.returncode == 0 and "Baseline saved" in automatic.stderr
    for _ in range(5):
        stable = invoke([cli, *args, "--offline"])
        assert stable.returncode == 0 and "No new destinations" in stable.stderr
        assert "veil-tell accept" not in stable.stderr
        assert not (demo / ".veil-tell/pending.json").exists()
    linked = invoke([cli, "ci", "--", "npm", "ci", *args[2:]])
    assert linked.returncode == 0 and "No new destinations" in linked.stderr, linked.stderr
    assert json.loads((demo / ".veil-tell/npm.json").read_text())["backend"] == "isolated"
    print(f"fixture os={sys.platform} install_to_ci=0 offline_repeats=5 approvals=0")
    manifest = demo / "package.json"
    package = json.loads(manifest.read_text())
    package["dependencies"] = {
        "veil-tell-demo-postinstall": "file:./postinstall",
        "veil-tell-demo-quiet": "file:./quiet",
    }
    manifest.write_text(json.dumps(package))
    result = invoke([cli, "observe", "--backend", "isolated", "--baseline", baseline,
                     "--fail-on-new", "--report", report, "--", *args])
    print(result.stdout, end="")
    print(result.stderr, end="")
    assert result.returncode == 21, (result.stdout, result.stderr)
    data = json.loads(report.read_text())
    assert data["child_status"]["exit_code"] == 0
    assert data["run_status"] == {"exit_code": 21, "reason": "new_destination"}
    inferred = {"confidence": "inferred", "package": {
        "name": "veil-tell-demo-postinstall", "version": "1.0.0",
        "script": "postinstall", "path": "postinstall",
    }}
    assert data["comparison"]["added"] == [
        {"host": "postinstall.local", "port": 443, "attempts": 1, "attribution": [inferred]}
    ], data["comparison"]
    assert "quiet postinstall" in result.stdout
    assert "postinstall.local:443 ← veil-tell-demo-postinstall@1.0.0 postinstall (postinstall) [inferred" in result.stderr
    assert data["destinations"][0]["attribution"] == [inferred]
    assert data["destinations"][0]["reason"] == "non_public_destination"
    ci_report = evidence / "npm-ci-diff.json"
    result = invoke([cli, "ci", "--baseline", baseline, "--report", ci_report, "--", *args])
    assert result.returncode == 21, (result.stdout, result.stderr)
    ci_data = json.loads(ci_report.read_text())
    assert ci_data["run_status"] == {"exit_code": 21, "reason": "new_destination"}
    assert ci_data["comparison"]["added"] == data["comparison"]["added"]
    assert ci_data["destinations"][0]["reason"] == "new_destination"
    automatic = invoke([cli, *args])
    assert automatic.returncode == 0 and "+ postinstall.local:443 (1)" in automatic.stderr
    default_baseline = demo / ".veil-tell/npm.json"
    assert json.loads(default_baseline.read_text())["destinations"] == []
    accepted = invoke([cli, "accept"])
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(default_baseline.read_text())["destinations"] == data["comparison"]["added"]
    stable = invoke([cli, *args])
    assert stable.returncode == 0 and "No new destinations" in stable.stderr
    print(f"fixture os={sys.platform} npm_exit=0 veil_tell_exit=21")
    print("fixture comparison " + json.dumps(data["comparison"], sort_keys=True))

    package["dependencies"] = {
        "veil-tell-demo-spoof": "file:./spoof",
        "veil-tell-demo-quiet": "file:./quiet",
    }
    manifest.write_text(json.dumps(package))
    spoof_report = evidence / "npm-spoof.json"
    result = invoke([cli, "ci", "--baseline", baseline, "--report", spoof_report, "--", *args])
    assert result.returncode == 21, (result.stdout, result.stderr)
    spoof = json.loads(spoof_report.read_text())
    assert spoof["child_status"]["exit_code"] == 0
    assert spoof["run_status"]["reason"] == "new_destination"
    assert spoof["comparison"]["added"] == [
        {"host": "spoof.local", "port": 443, "attempts": 1, "attribution": [{"confidence": "unknown"}]}
    ], spoof["comparison"]
    print(result.stderr, end="")
    print(f"fixture os={sys.platform} spoof=unknown veil_tell_exit=21")

    # Use the ordinary client to test shell selection and the opt-out.
    package["dependencies"] = {"veil-tell-demo-postinstall": "file:./postinstall"}
    manifest.write_text(json.dumps(package))
    npmrc = demo / ".npmrc"
    npmrc.write_text("script-shell=/bin/sh\n")
    custom = evidence / "npm-custom.json"
    result = invoke([cli, "ci", "--baseline", baseline, "--report", custom, "--", *args])
    assert result.returncode == 21 and "npm attribution is off" in result.stderr, (result.stdout, result.stderr)
    assert "attribution" not in json.loads(custom.read_text())["destinations"][0]
    npmrc.write_text("script-shell=/no-such-veil-test-shell\n")
    result = invoke([cli, "ci", "--baseline", baseline, "--", *args])
    assert result.returncode != 0 and "npm attribution is off" in result.stderr and "ENOENT" in result.stderr
    npmrc.unlink()

    no_attribute = evidence / "npm-no-attribute.json"
    result = invoke([cli, "ci", "--no-attribute", "--baseline", baseline, "--report", no_attribute, "--", *args])
    assert result.returncode == 21 and "attribution" not in json.loads(no_attribute.read_text())["destinations"][0]
    migration = project / "migration"
    migration.mkdir()
    if sys.platform == "linux":
        shutil.copytree(runtime, migration / "runtime", symlinks=True)
        runtime = migration / "runtime"
    baseline_upgrade_test(cli, migration, runtime)




def lockfile_destination_diff(cli, project, evidence, runtime):
    demo = project / "lockfile-diff"
    shutil.copytree(SCRIPT.parent / "fixtures" / "destination-diff", demo)
    if sys.platform == "linux":
        shutil.copytree(runtime, demo / "runtime", symlinks=True)
        runtime = demo / "runtime"
    env = dict(os.environ, PATH=f"{runtime / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    install = ["npm", "install", "--foreground-scripts", "--no-audit", "--no-fund",
               "--no-update-notifier", "--cache=.npm-cache"]
    main = demo / "package.json"
    manifest = json.loads(main.read_text())
    manifest["dependencies"] = {
        "veil-tell-demo-postinstall": "file:./postinstall",
        "veil-tell-demo-quiet": "file:./quiet",
    }
    main.write_text(json.dumps(manifest))
    original = demo / "postinstall/package.json"
    active = json.loads(original.read_text())
    old = dict(active, version="0.9.0", scripts={})
    original.write_text(json.dumps(old))

    def invoke(args, code=0):
        result = subprocess.run(args, cwd=demo, env=env, capture_output=True, text=True, timeout=35)
        assert result.returncode == code, (result.stdout, result.stderr)
        return result

    def refresh_lock():
        invoke([*install, "--package-lock-only", "--ignore-scripts"])

    refresh_lock()
    baseline = evidence / "locked-npm.json"
    invoke([cli, "observe", "--backend", "isolated", "--baseline-out", baseline, "--", *install])
    assert any(p["version"] == "0.9.0" for p in json.loads(baseline.read_text())["lockfile"]["packages"])
    original.write_text(json.dumps(active))
    refresh_lock()

    def compare(base, name, status):
        report = evidence / f"lock-{name}.json"
        result = invoke([cli, "ci", "--baseline", base, "--report", report, "--", *install], 21)
        data = json.loads(report.read_text())
        assert data["run_status"] == {"exit_code": 21, "reason": "new_destination"}
        assert data["comparison"]["lockfile_evidence"][0]["status"] == status, data["comparison"]
        print(next(line.strip() for line in result.stderr.splitlines() if "←" in line))

    compare(baseline, "updated", "corroborated")
    # Build a second baseline with the updated lock but no script invocation.
    unchanged = evidence / "locked-npm-unchanged.json"
    invoke([cli, "observe", "--backend", "isolated", "--baseline-out", unchanged, "--", *install, "--ignore-scripts"])
    compare(unchanged, "unchanged", "unchanged")

    manifest["dependencies"]["veil-tell-demo-spoof"] = "file:./spoof"
    del manifest["dependencies"]["veil-tell-demo-postinstall"]
    main.write_text(json.dumps(manifest))
    refresh_lock()
    compare(baseline, "spoof", "candidates")
    print(f"fixture os={sys.platform} lockfile=corroborated,unchanged,candidates exit=21")


def cargo_destination_diff(cli, project, evidence):
    demo = project / "cargo-destination"
    shutil.copytree(SCRIPT.parent / "fixtures" / "cargo-destination", demo)
    baseline = evidence / "locked-cargo.json"
    report = evidence / "cargo-diff.json"

    def invoke(args, code=0):
        result = subprocess.run(args, cwd=demo, capture_output=True, text=True, timeout=60)
        assert result.returncode == code, (result.stdout, result.stderr)
        return result

    # First record the same build before the fixture activates its CONNECT.
    script = demo / "build-probe/build.rs"
    original = script.read_text()
    script.write_text("fn main() {}\n")
    invoke([cli, "observe", "--baseline-out", baseline, "--", "cargo", "build"])
    assert json.loads(baseline.read_text())["lockfile"]["ecosystem"] == "cargo"
    script.write_text(original)
    result = invoke([cli, "observe", "--baseline", baseline, "--fail-on-new",
                     "--report", report, "--", "cargo", "build"], 21)
    data = json.loads(report.read_text())
    assert data["comparison"]["added"][0]["attribution"][0]["package"] == {
        "name": "veil-build-probe", "version": "1.2.3", "script": "build.rs", "path": "build-probe",
    }, data
    assert data["comparison"]["lockfile_evidence"][0]["status"] == "unchanged"
    print(next(line.strip() for line in result.stderr.splitlines() if "←" in line))
    warm = evidence / "cargo-warm.json"
    invoke([cli, "observe", "--baseline", baseline, "--report", warm, "--", "cargo", "build"])
    assert json.loads(warm.read_text())["destinations"] == []
    print(f"fixture os={sys.platform} cargo=build.rs exit=21 cached_connects=0")


def baseline_upgrade_test(cli, project, runtime):
    env = dict(os.environ, PATH=f"{runtime / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    state = project / ".veil-tell"
    state.mkdir(exist_ok=True)
    old = state / ("baseline-" + "a" * 64 + ".json")
    data = {"schema_version": 1, "backend": "proxy", "coverage": "http_connect_requests",
            "destinations": [{"host": "allowed.test", "port": 443, "attempts": 1}]}
    old.write_text(json.dumps(data))
    result = subprocess.run([cli, "migrate-baseline", "npm", old], cwd=project, capture_output=True, text=True)
    assert result.returncode == 0 and json.loads((state / "npm.json").read_text()) == data
    assert old.exists()
    # Known hosts that go quiet never become pending. Exercise a known nonempty baseline.
    for _ in range(5):
        result = subprocess.run([cli, "npm", "--version"], cwd=project, env=env, capture_output=True, text=True)
        assert result.returncode == 0 and "今回は未観測: allowed.test:443" in result.stderr, result.stderr
        assert "veil-tell accept" not in result.stderr and not (state / "pending.json").exists()
    if sys.platform == "linux":
        env = dict(env, VEIL_TELL_BWRAP="/nonexistent/veil-bwrap")
        result = subprocess.run([cli, "npm", "--version"], cwd=project, env=env, capture_output=True, text=True)
        assert result.returncode == 0 and "Direct connections are not visible" in result.stderr
        strict = subprocess.run([cli, "ci", "--", "npm", "--version"], cwd=project, env=env, capture_output=True, text=True)
        assert strict.returncode == 125 and not strict.stdout
    print(f"fixture os={sys.platform} known_destination_missing=5 approvals=0 migration=ok")


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
        destination_diff_test(cli, fixture, project, evidence, node_root)
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
    elif sys.argv[1] == "invalid-proxy-auth":
        connect_probe("new.test", "new", "aW52YWxpZA==")
    elif sys.argv[1] == "new-destination":
        connect_probe("new.test", "new")
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
