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
    previous_timeout = listener.gettimeout()
    listener.settimeout(0.25)
    try:
        while True:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                break
            with conn:
                conn.settimeout(3)
                with conn.makefile("rb") as stream:
                    tokens.append(stream.read())
    finally:
        listener.settimeout(previous_timeout)
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
        assert data["coverage"]["direct_attempt_destinations"] == ("ip_port" if sys.platform == "linux" else "not_observed")
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
            dns_attempt_test(cli, project, evidence, Path(node_root).resolve())
            npm_destination_diff(cli, project, evidence, Path(node_root).resolve())
            lockfile_destination_diff(cli, project, evidence, Path(node_root).resolve())
            cargo_destination_diff(cli, project, evidence)


def action_summary(cli, report):
    return subprocess.check_output([str(cli), "summary", str(report)], text=True)


def upstream_connect(stream):
    request = stream.readline()
    for line in stream:
        if line == b"\r\n":
            return request
    raise AssertionError("incomplete upstream CONNECT request")


def volume_test(cli, fixture, project, evidence, node_root):
    policy = evidence / "volume.toml"
    policy.write_text('version = 1\nprofile = "volume"\n[[rule]]\n'
                      'action = "allow"\nhost = "allowed.test"\nport = 443\nmax_sent_bytes = 8192\n')
    baseline = evidence / "volume-baseline.json"
    upstream_baseline = evidence / "upstream-volume-baseline.json"
    refused_baseline = evidence / "upstream-refused-baseline.json"
    with socket.socket() as receiver:
        receiver.bind((os.environ.get("VEIL_TELL_TEST_IP", "127.0.0.1"), 0))
        receiver.listen()
        receiver.settimeout(5)
        address = f"{receiver.getsockname()[0]}:{receiver.getsockname()[1]}"
        env = dict(os.environ, VEIL_TELL_FIXTURE_RECEIVER=address)
        cases = [
            ("train", ["observe", "--baseline-out", baseline], 4096, 4096, 0),
            ("observe", ["observe", "--baseline", baseline], 524288, 524288, 21),
            ("no-baseline", ["observe"], 524288, 524288, 0),
            ("restrict", ["restrict", "--policy", policy], 524288, 8192, 22),
            ("ci", ["ci", "--baseline", baseline], 524288, 131072, 22),
            ("upstream-train", ["observe", "--baseline-out", upstream_baseline], 4096, 4096, 0),
            ("upstream-observe", ["observe", "--baseline", upstream_baseline], 524288, 524288, 21),
            ("upstream-ci", ["ci", "--baseline", upstream_baseline], 524288, 131072, 22),
            ("upstream-refused", ["observe", "--baseline-out", refused_baseline], 0, 0, 0),
        ]
        if node_root:
            demo = project / "volume-demo"
            demo.mkdir()
            runtime = Path(node_root).resolve()
            if sys.platform == "linux":
                shutil.copytree(runtime, demo / "runtime", symlinks=True)
                runtime = demo / "runtime"
            env["PATH"] = f"{runtime / 'bin'}:{env['PATH']}"
            shutil.copyfile(SCRIPT, demo / "probe.py")
            install_baseline = evidence / "install-volume-baseline.json"
            cases.extend([
                ("install-train", ["observe", "--baseline-out", install_baseline], 4096, 4096, 0),
                ("install-observe", ["observe", "--baseline", install_baseline], 524288, 524288, 21),
                ("install-ci", ["ci", "--baseline", install_baseline], 524288, 131072, 22),
                ("install-restrict", ["restrict", "--policy", policy], 524288, 8192, 22),
            ])

        for name, arguments, sent, expected, code in cases:
            via_upstream = name.startswith("upstream-")
            refused = name == "upstream-refused"
            received = []

            def collect():
                conn, _ = receiver.accept()
                with conn, conn.makefile("rb") as data:
                    conn.settimeout(4)
                    if via_upstream:
                        host = "new.test" if refused else "allowed.test"
                        assert upstream_connect(data) == f"CONNECT {host}:443 HTTP/1.1\r\n".encode()
                        if refused:
                            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                            received.append(len(data.read()))
                            return
                        conn.sendall(b"HTTP/1.1 200 Established\r\n\r\n")
                    received.append(len(data.read()))
                    try:
                        conn.sendall(b"ACK")
                    except OSError:
                        pass

            thread = threading.Thread(target=collect)
            thread.start()
            report = evidence / f"volume-{name}.json"
            try:
                install = name.startswith("install-")
                if install:
                    (demo / "package.json").write_text(json.dumps({
                        "name": "veil-volume-fixture", "version": "1.2.3", "private": True,
                        "scripts": {"postinstall": f"{sys.executable} -B probe.py volume {sent}"},
                    }))
                    command = ["npm", "install", "--no-audit", "--no-fund", "--no-update-notifier"]
                elif refused:
                    command = [sys.executable, "-B", "probe.py", "new-destination"]
                else:
                    command = [sys.executable, "-B", "probe.py", "volume", str(sent)]
                child = subprocess.run(
                    [cli if via_upstream else fixture, *arguments,
                     *([] if arguments[0] == "ci" else ["--backend", "isolated"]),
                     "--report", report, "--", *command],
                    cwd=demo if install else project,
                    env=dict(env, HTTPS_PROXY=f"http://{address}", NO_PROXY="") if via_upstream else env,
                    capture_output=True, text=True, timeout=12,
                )
            finally:
                thread.join()
            assert child.returncode == code and received == [expected], (child.stderr, received)
            result = json.loads(report.read_text())
            assert result["child_status"]["exit_code"] == 0, (child.stdout, child.stderr, result)
            destination, = result["destinations"]
            assert destination["sent_bytes"] == expected, destination
            if via_upstream:
                assert destination["via_upstream_proxy"] and destination["connected_ip"] is None, destination
            if name == "upstream-train":
                assert json.loads(upstream_baseline.read_text())["volume"]["allowed.test"] == {
                    "sent_bytes": expected, "max_connection_bytes": expected, "connections": 1,
                }
            if refused:
                assert destination["result"] == "connect_failed", destination
                assert not json.loads(refused_baseline.read_text()).get("volume")
            if code:
                anomaly, = result["volume_anomalies"]
                assert anomaly["blocked"] == (code == 22), result
                assert anomaly["observed"] == {
                    "sent_bytes": expected, "max_connection_bytes": expected, "connections": 1,
                }, anomaly
                assert result["run_status"]["reason"] == (
                    "volume_limit_exceeded" if code == 22 else "volume_anomaly"
                ), result
                if install:
                    source, = anomaly["attribution"]
                    assert source["package"]["name"] == "veil-volume-fixture"
                    assert source["package"]["script"] == "postinstall"
                print(next(line for line in child.stderr.splitlines() if "volume anomaly" in line))
            else:
                assert not result.get("volume_anomalies"), result
            if name == "install-ci":
                summary = action_summary(cli, report)
                assert "Volume limit cut" in summary and "bytes 131072/262144" in summary
                assert "veil-volume-fixture@1.2.3" in summary and "切断" in summary
            print(f"receiver case=volume-{name} os={sys.platform} bytes={expected} child=0 exit={code}")


def dns_attempt_test(cli, project, evidence, runtime):
    demo = project / "dns-attempts"
    demo.mkdir()
    (demo / "package.json").write_text(json.dumps({
        "name": "veil-dns-fixture", "version": "1.2.3", "private": True,
        "scripts": {"postinstall": "node probe.cjs"},
    }))
    (demo / "probe.cjs").write_text(
        'require("node:dns").promises.lookup("postinstall.invalid").then(() => process.exit(2), '
        'error => { if (error.code !== "ENOTFOUND") process.exit(3) });'
    )
    if sys.platform == "linux":
        shutil.copytree(runtime, demo / "runtime", symlinks=True)
        runtime = demo / "runtime"
    env = dict(os.environ, PATH=f"{runtime / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    baseline = evidence / "dns-baseline.json"
    report = evidence / "dns-report.json"
    child = subprocess.run(
        [cli, "observe", "--backend", "isolated", "--baseline-out", baseline, "--", "/usr/bin/true"],
        cwd=demo, env=env, capture_output=True, text=True, timeout=10,
    )
    assert child.returncode == 0, child.stderr
    child = subprocess.run(
        [cli, "ci", "--baseline", baseline, "--report", report, "--", "npm", "--no-update-notifier", "run", "postinstall"],
        cwd=demo, env=env, capture_output=True, text=True, timeout=20,
    )
    data = json.loads(report.read_text())
    assert child.returncode == 21 and data["child_status"]["exit_code"] == 0, child.stderr
    assert data["run_status"] == {"exit_code": 21, "reason": "new_destination"}
    assert data["coverage"]["dns_attempts"] == "node_dns_lookup_hook" and not data["destinations"], data
    attempt, = data["comparison"]["attempted_added"]
    assert data["attempted"] == [attempt] and attempt["host"] == "postinstall.invalid"
    assert attempt["attribution"] == [{"confidence": "inferred", "package": {
        "name": "veil-dns-fixture", "version": "1.2.3", "script": "postinstall", "path": ".",
    }}], child.stderr
    print(next(line for line in child.stderr.splitlines() if "attempted (blocked)" in line))
    summary = action_summary(cli, report)
    assert "<code>Attempted DNS</code>" in summary and "veil-dns-fixture@1.2.3" in summary
    print(f"receiver case=node-dns os={sys.platform} connect=0 child=0 exit=21")

    for ci, expected in (("false", 0), ("true", 21)):
        child = subprocess.run(
            [cli, "--json", "node", "probe.cjs"], cwd=demo, env=dict(env, CI=ci),
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(child.stdout)
        assert child.returncode == expected and data["child_status"]["exit_code"] == 0, child.stderr
        assert [record["host"] for record in data["attempted"]] == ["postinstall.invalid"]
    quiet = subprocess.run([cli, "--json", "/usr/bin/true"], cwd=demo, env=env,
                           capture_output=True, text=True, timeout=10)
    data = json.loads(quiet.stdout)
    assert data["attempted"] == [] and "DNS attempts recorded" not in quiet.stderr

    flood = evidence / "dns-overflow.json"
    child = subprocess.run(
        [cli, "observe", "--backend", "isolated", "--report", flood, "--", "node", "-e",
         'const dns = require("node:dns").promises; (async () => { for (let i = 0; i < 1025; i++)'
         ' await dns.lookup("overflow" + i + ".invalid").catch(() => {}); })()'],
        cwd=demo, env=env, capture_output=True, text=True, timeout=30,
    )
    data = json.loads(flood.read_text())
    assert child.returncode == 125 and data["coverage"]["dns_attempts"] == "incomplete", child.stderr
    assert len(data["attempted"]) == 1024 and not data["destinations"]


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
    clean_report = evidence / "npm-unchanged-summary.json"
    unchanged = invoke([cli, "ci", "--report", clean_report, "--", "npm", "ci", *args[2:]])
    assert unchanged.returncode == 0 and len(action_summary(cli, clean_report).splitlines()) == 1
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
    assert "<code>CONNECT</code>" in action_summary(cli, report)
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
    default_baseline = demo / ".veil-tell/npm.json"
    pending = default_baseline.with_name("pending.json")
    assert not pending.exists()
    original = default_baseline.read_bytes()
    project_ci = invoke([cli, "ci", "--", *args])
    assert project_ci.returncode == 21 and "veil-tell accept" in project_ci.stderr, project_ci.stderr
    assert default_baseline.read_bytes() == original
    accepted = invoke([cli, "accept"])
    assert accepted.returncode == 0 and not pending.exists(), accepted.stderr
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
    (migration / "package.json").write_text('{"name":"migration","version":"1.0.0","private":true}')
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
    preview = subprocess.run([cli, "clean"], cwd=project, capture_output=True, text=True)
    assert preview.returncode == 0 and old.name in preview.stdout and old.exists()
    cleaned = subprocess.run([cli, "clean", "--apply"], cwd=project, capture_output=True, text=True)
    assert cleaned.returncode == 0 and not old.exists() and (state / "npm.json").exists()
    assert "Baseline saved" not in subprocess.run(
        [cli, "/usr/bin/true"], cwd=project, env=env, capture_output=True, text=True
    ).stderr
    # Known hosts that go quiet never become pending. Exercise a known nonempty baseline.
    for _ in range(5):
        result = subprocess.run([cli, "npm", "install", "--offline", "--no-audit", "--no-fund", "--no-update-notifier"], cwd=project, env=env, capture_output=True, text=True)
        assert result.returncode == 0 and "今回は未観測: allowed.test:443" in result.stderr, result.stderr
        assert "veil-tell accept" not in result.stderr and not (state / "pending.json").exists()
    if sys.platform == "linux":
        env = dict(env, VEIL_TELL_BWRAP="/nonexistent/veil-bwrap")
        result = subprocess.run([cli, "npm", "--version"], cwd=project, env=env, capture_output=True, text=True)
        assert result.returncode == 0 and "Direct connections are not visible" in result.stderr
        strict = subprocess.run([cli, "ci", "--", "npm", "--version"], cwd=project, env=env, capture_output=True, text=True)
        assert strict.returncode == 125 and not strict.stdout
    print(f"fixture os={sys.platform} known_destination_missing=5 approvals=0 migration=ok")


def linux_shorthand_startup(cli, project):
    if sys.platform != "linux":
        return
    env = os.environ.copy()
    env.pop("VEIL_TELL_BWRAP", None)
    env.pop("CI", None)

    # A running child owns its exit status, including 125. Cross the startup
    # deadline to check that it applies only before exec and cannot replay it.
    result = subprocess.run(
        [cli, "--json", "/bin/sh", "-c", "echo started >> starts; sleep 6; exit 125"],
        cwd=project, env=env, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 125 and (project / "starts").read_text() == "started\n"
    assert json.loads(result.stdout)["backend"] == "isolated"
    assert "observing via proxy" not in result.stderr

    # A system root is not an isolatable project. Interactive shorthand can
    # fall back after the independent probe fails. CI must stop before exec.
    for strict in (False, True):
        result = subprocess.run(
            [cli, "--json", "/bin/echo", "payload-ran"], cwd="/",
            env=dict(env, CI="1" if strict else "0"), capture_output=True, text=True,
        )
        if strict:
            assert result.returncode == 125 and "payload-ran" not in result.stderr
            assert "CI requires isolation" in result.stderr and not result.stdout
        else:
            assert result.returncode == 0 and json.loads(result.stdout)["backend"] == "proxy"
            assert result.stderr.splitlines().count("payload-ran") == 1
    print("receiver case=linux-shorthand-startup once=1 child_exit=125 fallback=proxy ci=125")


def output_and_upstream_test(cli, project):
    def invoke(args, env=None):
        return subprocess.run([cli, *args], cwd=project, env=env, capture_output=True, text=True, timeout=12)
    missing = invoke(["veil-tell-command-does-not-exist"])
    assert missing.returncode and missing.stderr.count("Next / 次:") == 1, missing.stderr
    denied = invoke(["curl", "-fsS", "https://example.local"])
    assert denied.returncode and "Next / 次: veil-tell denied example.local:443 (non_public_destination)" in denied.stderr
    env = dict(os.environ, NO_PROXY="", no_proxy="")
    with socket.socket() as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.listen()
        receiver.settimeout(6)
        env["HTTPS_PROXY"] = f"http://trial:fixture-secret@127.0.0.1:{receiver.getsockname()[1]}"
        requests = []
        def upstream():
            for _ in range(2):
                conn, _ = receiver.accept()
                with conn, conn.makefile("rb") as stream:
                    request = []
                    for line in stream:
                        if line == b"\r\n": break
                        request.append(line)
                    requests.append(request)
                    conn.sendall(b"HTTP/1.1 200 Established\r\n\r\n")
                    stream.read()
                    conn.sendall(b"ACK")
        thread = threading.Thread(target=upstream)
        thread.start()
        try:
            result=invoke(["observe","--json","--",sys.executable,"-B","probe.py","observe-candidates"],env)
        finally:
            thread.join()
    assert result.returncode==0, result.stderr
    assert len(requests)==2 and all(r[0]==b"CONNECT allowed.test:443 HTTP/1.1\r\n" for r in requests)
    encoded = base64.b64encode(b"trial:fixture-secret")
    assert all(b"Proxy-Authorization: Basic "+encoded+b"\r\n" in r for r in requests)
    assert all(secret not in result.stdout+result.stderr for secret in ("fixture-secret",encoded.decode()))
    assert json.loads(result.stdout)["destinations"][0]["via_upstream_proxy"]
    assert [s for s in result.stderr.splitlines() if s.startswith("veil-tell: allowed.test:")] == [
        "veil-tell: allowed.test:443 allow observe ×2"]
    if sys.platform != "linux":
        print("SKIP direct_attempts: Linux seccomp notification test")
        return
    for cmd in ([sys.executable,"-c","import socket;socket.create_connection(('192.0.2.1',443),1)"],
                ["curl","--noproxy","*","--max-time","2","https://example.invalid"]):
        trial=invoke(["observe","--backend","isolated","--json","--",*cmd])
        data=json.loads(trial.stdout)
        assert data["coverage"]["direct_attempt_destinations"]=="ip_port" and trial.returncode
        assert any(r["attempts"]>=1 and r["port"]==(443 if cmd[0]==sys.executable else 53) for r in data["direct_attempts"])


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
        linux_shorthand_startup(cli, project)
        output_and_upstream_test(cli, project)
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
                assert report["coverage"]["direct_attempt_destinations"] == ("ip_port" if backend == "isolated" and sys.platform == "linux" else "not_observed")
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
        volume_test(cli, fixture, project, evidence, node_root)
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
            command = [
                "npm", "install", "--registry=https://allowed.test", "--cafile=registry.crt",
                "--cache=.npm-cache", "--no-audit", "--no-fund", "--no-update-notifier",
                "--fetch-retries=0",
            ]
            result = subprocess.run([
                fixture, "restrict", "--backend", "isolated", "--policy", policy, "--fail-on-unknown",
                "--report", evidence / "npm.json", "--", *command,
            ], cwd=project, env=env, capture_output=True, text=True, timeout=25)
            for backend in ("proxy", "isolated"):
                for probe in ("fetch('https://allowed.test/veil-cli-fixture').then(r=>r.json()).then(r=>console.log(r.name))",
                              "require('node:https').get('https://allowed.test/veil-cli-fixture',{ca:require('fs').readFileSync('registry.crt')},r=>r.pipe(process.stdout))"):
                    # Supply the fixture CA in the child even when the isolated environment is cleared.
                    child = subprocess.run([fixture, "observe", "--backend", backend, "--json", "--",
                                            runtime / "bin/node", "--use-openssl-ca", "-e",
                                            "const tls=require('node:tls');tls.setDefaultCACertificates([require('fs').readFileSync('registry.crt','utf8')]);"+probe],
                                           cwd=project, env=env, text=True, capture_output=True, timeout=10)
                    assert child.returncode == 0 and "veil-cli-fixture" in child.stderr, child.stderr
                    row, = json.loads(child.stdout)["destinations"]
                    assert (row["host"],row["attempts"],row["result"]) == ("allowed.test",1,"completed"), row
            training_command = ["--cache=.npm-training-cache" if arg.startswith("--cache=") else arg
                                for arg in command]
            training_command[1] = "ci"
            training = subprocess.run(
                [fixture, *training_command], cwd=project, env=env, capture_output=True, text=True, timeout=25,
            )
            assert training.returncode == 0, training.stderr
            for i in range(5):
                args = command.copy()
                args[args.index("install")] = "ci" if i % 2 == 0 else "install"
                repeat = subprocess.run(
                    [fixture, "ci", "--json", "--", *args],
                    cwd=project, env=env, capture_output=True, text=True, timeout=25,
                )
                assert repeat.returncode == 0, repeat.stderr
                assert not json.loads(repeat.stdout).get("volume_anomalies"), repeat.stdout
                assert not (project / ".veil-tell/pending.json").exists()
            print(f"receiver case=npm-volume-repeats os={sys.platform} repeats=5 anomalies=0")
        finally:
            server.shutdown()
            thread.join()
    print(result.stdout, end="")
    print(result.stderr, end="")
    assert result.returncode == 0 and requests[:2] == ["/veil-cli-fixture", path], (result.stderr, requests)
    assert (project / "node_modules/veil-cli-fixture/installed.txt").read_text() == "received"
    print(f"receiver case=npm requests={requests} exit={result.returncode}")


if __name__ == "__main__":
    os.environ.pop("CI", None)
    if sys.argv[1] == "probe":
        probe(*sys.argv[2:])
    elif sys.argv[1] == "invalid-proxy-auth":
        connect_probe("new.test", "new", "aW52YWxpZA==")
    elif sys.argv[1] == "new-destination":
        connect_probe("new.test", "new")
    elif sys.argv[1] == "observe-candidates":
        connect_probe("ALLOWED.test.", "first")
        connect_probe("allowed.test", "second")
    elif sys.argv[1] == "volume":
        proxy = urlsplit(os.environ["HTTPS_PROXY"])
        credentials = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
        with socket.create_connection((proxy.hostname, proxy.port), timeout=5) as conn:
            conn.sendall((f"CONNECT allowed.test:443 HTTP/1.1\r\n"
                          f"Proxy-Authorization: Basic {credentials}\r\n\r\n").encode())
            with conn.makefile("rb") as stream:
                assert b" 200 " in stream.readline()
                for line in stream:
                    if line == b"\r\n":
                        break
                try:
                    conn.sendall(b"X" * int(sys.argv[2]))
                    conn.shutdown(socket.SHUT_WR)
                    stream.read()
                except OSError as error:
                    # The proxy may close before this process calls shutdown.
                    if error.errno not in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN):
                        raise
    elif sys.argv[1] == "fd":
        try:
            os.write(int(sys.argv[2]), b"inherited-fd")
            raise AssertionError("inherited descriptor could be written")
        except OSError as error:
            assert error.errno == errno.EBADF
            print("EBADF")
    else:
        run(*sys.argv[1:])
