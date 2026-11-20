"""Run with the built veil-tell binary and receiver_cli example as arguments."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from receivers import connect_probe, upstream_connect


SCRIPT = Path(__file__).resolve()
POLICY = 'version = 1\nprofile = "verify-test"\n'
TARGET_RULE = '[[rule]]\naction = "{}"\nhost = "allowed.test"\nport = 443\n'


def probe(behavior):
    seed = Path("seed.txt")
    assert seed.read_text() == "original\n"
    assert Path("seed.link").read_text() == "original\n"
    assert not Path("trial-artifact.txt").exists()
    seed.write_text("modified by this trial\n")
    Path("trial-artifact.txt").touch()
    if behavior == "no-contact":
        return

    if behavior.startswith("upstream-"):
        connect_probe("other.test", behavior)

    response = io.StringIO()
    with redirect_stdout(response):
        connect_probe("allowed.test", behavior)
    if response.getvalue() == "CONNECT=200\n":
        return
    assert response.getvalue() == "CONNECT=403\n", response.getvalue()
    if behavior == "required":
        sys.exit(7)
    if behavior == "reserved-exit":
        sys.exit(125)
    if behavior == "timeout":
        time.sleep(30)


def receiver_case(run, behavior, expected_connections, upstream_hosts=()):
    def acknowledge():
        payloads = []
        for index in range(expected_connections):
            conn, _ = receiver.accept()
            with conn, conn.makefile("rb") as stream:
                conn.settimeout(3)
                if upstream_hosts:
                    host = upstream_hosts[index]
                    assert upstream_connect(stream) == f"CONNECT {host}:443 HTTP/1.1\r\n".encode()
                    if behavior == "upstream-refused" and host == "other.test":
                        conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                        continue
                    conn.sendall(b"HTTP/1.1 200 Established\r\n\r\n")
                payloads.append(stream.read())
                conn.sendall(b"ACK")
        return payloads

    with socket.socket() as receiver, ThreadPoolExecutor(max_workers=1) as pool:
        receiver.bind(("127.0.0.1", 0))
        receiver.listen()
        receiver.settimeout(5)
        listener = pool.submit(acknowledge)
        ip, port = receiver.getsockname()
        env = ({"HTTPS_PROXY": f"http://{ip}:{port}", "NO_PROXY": ""} if upstream_hosts
               else {"VEIL_TELL_FIXTURE_RECEIVER": f"{ip}:{port}"})
        result = run(env)
        payloads = listener.result()
        count = expected_connections - (behavior == "upstream-refused")
        assert payloads == [f"{behavior}-connect".encode()] * count, payloads
        assert not select.select([receiver], [], [], 0)[0], "unexpected receiver connection"
        return result


def assert_comparison(result, report, code, verdict, phase, reason):
    assert result.returncode == code, (result.stdout, result.stderr)
    assert verdict in result.stdout, result.stdout
    expected = {
        "schema_version": 1,
        "timeout_seconds": 3,
        "destination": {"host": "allowed.test", "port": 443},
        "verdict": verdict,
        "phase": phase,
        "reason": reason,
        "exit_code": code,
    }
    assert {key: report[key] for key in expected} == expected, report
    return report["trials"]


def assert_trial(trial, child_exit, event_reason):
    assert trial["backend"] == "isolated" and trial["isolation"] == "applied", trial
    assert trial["child_status"] == {"exit_code": child_exit, "signal": None}, trial
    reason = "completed" if child_exit == 0 else "child_failed"
    assert trial["run_status"] == {"exit_code": child_exit, "reason": reason}, trial
    if event_reason is None:
        assert trial["destinations"] == [], trial
        return
    event, = trial["destinations"]
    assert (event["host"], event["port"], event["reason"], event["attempts"]) == (
        "allowed.test", 443, event_reason, 1,
    ), event
    if event_reason == "explicit_deny":
        assert event["result"] == "blocked" and event["received_bytes"] == 0, event
    else:
        assert event["received_bytes"] == len(b"ACK"), event


def run(cli, fixture):
    cli, fixture = Path(cli).resolve(), Path(fixture).resolve()
    with tempfile.TemporaryDirectory(prefix="veil-verify-test-", dir="/tmp") as tmp:
        root = Path(tmp).resolve()
        source, evidence = root / "project", root / "evidence"
        source.mkdir()
        evidence.mkdir()
        shutil.copyfile(SCRIPT, source / "verify_probe.py")
        shutil.copyfile(SCRIPT.with_name("receivers.py"), source / "receivers.py")
        seed = source / "seed.txt"
        seed.write_text("original\n")
        (source / "seed.link").symlink_to(seed.name)
        policy = evidence / "policy.toml"
        policy_text = POLICY + TARGET_RULE.format("allow")
        policy.write_text(policy_text)

        def invoke(binary, report, command, env=None):
            return subprocess.run(
                [binary, "verify", "--source", source, "--policy", policy,
                 "--without", "ALLOWED.test.:443", "--report", report,
                 "--timeout-seconds", "3", "--", *command],
                cwd=root, env=env, capture_output=True, text=True, timeout=15,
            )

        def run_probe(binary, behavior, extra_env=None):
            report = evidence / f"{behavior}.json"
            result = invoke(
                binary, report, [sys.executable, "-B", "verify_probe.py", "--probe", behavior],
                dict(os.environ, **(extra_env or {})),
            )
            assert report.is_file(), (result.stdout, result.stderr)
            return result, json.loads(report.read_text())

        marker = ["/bin/sh", "-c", "printf 'command ran\\n'"]
        existing = evidence / "existing.json"
        existing.write_text("previous report\n")
        result = invoke(cli, existing, marker)
        assert result.returncode == 125 and "already exists" in result.stderr, result
        assert not result.stdout and existing.read_text() == "previous report\n", result

        source_report = source / "report.json"
        result = invoke(cli, source_report, marker)
        assert result.returncode == 125 and "outside --source" in result.stderr, result
        assert not result.stdout and not source_report.exists(), result

        rejected = evidence / "rejected.json"
        for rules in ("", TARGET_RULE.format("deny")):
            policy.write_text(POLICY + rules)
            result = invoke(cli, rejected, marker)
            assert result.returncode == 125 and "explicit allow" in result.stderr, result
            assert not result.stdout and not rejected.exists(), result
        policy.write_text(policy_text)

        result, report = run_probe(cli, "no-contact")
        trials = assert_comparison(result, report, 2, "inconclusive", "allowed",
                                   "allowed_connection_not_observed")
        assert_trial(trials["allowed"], 0, None)
        assert trials["denied"] is None and trials["restored"] is None, trials

        for behavior, connections, code, verdict, phase, reason in (
            ("optional", 1, 0, "passes", "denied", "passed_with_destination_blocked"),
            ("required", 2, 1, "fails", "restored", "failed_with_destination_blocked"),
            ("timeout", 1, 2, "inconclusive", "denied", "timed_out"),
        ):
            result, report = receiver_case(
                lambda env: run_probe(fixture, behavior, env), behavior, connections,
            )
            trials = assert_comparison(result, report, code, verdict, phase, reason)
            assert_trial(trials["allowed"], 0, "allow_rule")
            if behavior == "timeout":
                denied = trials["denied"]
                assert denied["run_status"] == {"exit_code": 124, "reason": "timed_out"}, denied
                assert denied["coverage"]["proxy_capture"] == "until_interrupted", denied
                event, = denied["destinations"]
                assert event["reason"] == "explicit_deny" and event["result"] == "blocked", event
            else:
                assert_trial(trials["denied"], 7 if behavior == "required" else 0, "explicit_deny")
            if behavior == "required":
                assert_trial(trials["restored"], 0, "allow_rule")
            else:
                assert trials["restored"] is None, trials

        if sys.platform == "linux":
            result, report = receiver_case(
                lambda env: run_probe(fixture, "reserved-exit", env), "reserved-exit", 1,
            )
            trials = assert_comparison(result, report, 2, "inconclusive", "denied",
                                       "child_exit_ambiguous")
            assert_trial(trials["denied"], 125, "explicit_deny")
            assert trials["restored"] is None, trials

        assert policy.read_text() == policy_text
        other_rule = TARGET_RULE.format("allow").replace("allowed.test", "other.test")
        policy.write_text(policy_text + other_rule)
        for behavior, hosts, code, verdict, phase, reason in (
            ("upstream-ok", ("other.test", "allowed.test", "other.test"), 0, "passes",
             "denied", "passed_with_destination_blocked"),
            ("upstream-refused", ("other.test", "allowed.test"), 2, "inconclusive",
             "allowed", "other_destination_unavailable"),
        ):
            result, report = receiver_case(
                lambda env: run_probe(cli, behavior, env), behavior, len(hosts), hosts,
            )
            trials = assert_comparison(result, report, code, verdict, phase, reason)
            other, = (row for row in trials["allowed"]["destinations"] if row["host"] == "other.test")
            assert other["connected_ip"] is None and other["via_upstream_proxy"], other

        assert policy.read_text() == policy_text + other_rule
        assert seed.read_text() == "original\n"
        assert not (source / "trial-artifact.txt").exists()

        (source / "escape.link").symlink_to(Path("..") / source.name / seed.name)
        result = invoke(cli, rejected, marker)
        assert result.returncode == 125 and "symlink escapes snapshot" in result.stderr, result
        assert not result.stdout and not rejected.exists(), result
    print("PASS: verify CLI, receiver, snapshot, and report checks")


if __name__ == "__main__":
    if sys.argv[1] == "--probe":
        probe(sys.argv[2])
    else:
        run(*sys.argv[1:])
