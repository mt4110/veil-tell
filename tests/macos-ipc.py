"""Check named Mach and XPC paths against local receivers with the ordinary CLI."""

import json
import os
from pathlib import Path
import plistlib
import secrets
import select
import socket
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).with_suffix(".c").resolve()


def bundle(contents, name, executable, service=False):
    (contents / "MacOS").mkdir(parents=True)
    plist = {"CFBundleIdentifier": name, "CFBundleExecutable": executable,
             "CFBundlePackageType": "XPC!" if service else "APPL"}
    if service:
        plist["XPCService"] = {"ServiceType": "Application"}
    (contents / "Info.plist").write_bytes(plistlib.dumps(plist))
    return contents / "MacOS" / executable


def run(cli):
    assert sys.platform == "darwin" and os.getuid() != 0
    cli = Path(cli).resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="veil-tell-macos-ipc-", dir="/tmp")).resolve()
    print(f"uid={os.getuid()} evidence={root}", flush=True)
    work, reports = root / "work", root / "reports"
    work.mkdir()
    reports.mkdir()
    policy = reports / "empty.toml"
    policy.write_text('version=1\nprofile="macos-ipc"\n')
    mach_log, xpc_log = root / "mach-receiver.log", root / "xpc-receiver.log"
    mach_log.touch()
    xpc_log.touch()
    nonce = secrets.token_hex(8)
    mach_name = f"local.veil.tell.mach.{nonce}"
    xpc_name = f"local.veil.tell.forward.{nonce}"
    app = root / "VeilForward.app" / "Contents"
    sender = bundle(app, xpc_name + ".client", "sender")
    service = bundle(app / "XPCServices/Receiver.xpc/Contents", xpc_name, "receiver", service=True)
    clang = ["/usr/bin/clang", "-Wall", "-Wextra", "-Werror", "-fblocks", SOURCE]
    subprocess.run([*clang, "-framework", "CoreFoundation", "-o", sender], check=True)

    outcomes = {}

    def probe(label, args, isolated=False):
        if isolated:
            args = [cli, "restrict", "--backend", "isolated", "--policy", policy,
                    "--fail-on-unknown", "--report", reports / f"{label}.json", "--", *args]
        child = subprocess.run(args, cwd=work, capture_output=True, text=True, timeout=8)
        outcomes[label] = {"exit_code": child.returncode, "stdout": child.stdout, "stderr": child.stderr}
        print(f"{label} exit={child.returncode}\n{child.stdout}{child.stderr}", end="", flush=True)

    with socket.socket() as tcp:
        tcp.bind(("127.0.0.1", 0))
        tcp.listen()
        subprocess.run([*clang, "-DXPC_RECEIVER", f'-DRECEIVER_LOG="{xpc_log}"',
                        f"-DTCP_PORT={tcp.getsockname()[1]}", "-o", service], check=True)
        with subprocess.Popen([sender, "listen-mach", mach_name, mach_log], cwd=work,
                              stdout=subprocess.PIPE, text=True) as listener:
            try:
                assert select.select([listener.stdout], [], [], 4)[0], "Mach receiver did not start"
                assert listener.stdout.readline().strip() == "mach_receiver=ready"
                for phase in ("control-before", "isolated", "control-after"):
                    for path, name in (("mach", mach_name), ("xpc", xpc_name)):
                        label = f"{path}-{phase}"
                        probe(label, [sender, f"send-{path}", name, label], phase == "isolated")
                probe("mach-register-control", [sender, "register-mach", mach_name + ".control", mach_log])
                probe("mach-register-isolated", [sender, "register-mach", mach_name + ".new", mach_log], True)
            finally:
                if listener.poll() is None:
                    listener.terminate()
                subprocess.run([sender, "send-xpc", xpc_name, "stop-fixture"], cwd=work,
                               capture_output=True, timeout=6)
        tcp_tokens = []
        tcp.settimeout(0.3)
        while True:
            try:
                connection, _ = tcp.accept()
            except TimeoutError:
                break
            with connection, connection.makefile() as stream:
                connection.settimeout(3)
                tcp_tokens.append(stream.readline(128).strip())

    (root / "tcp-receiver.json").write_text(json.dumps(tcp_tokens, indent=2) + "\n")
    (root / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
    mach_tokens = mach_log.read_text().splitlines()
    xpc_tokens = xpc_log.read_text().splitlines()
    assert mach_tokens == ["mach-control-before", "mach-control-after"], mach_tokens
    assert xpc_tokens == tcp_tokens == ["xpc-control-before", "xpc-control-after"], (xpc_tokens, tcp_tokens)
    control = outcomes["mach-register-control"]
    assert control["exit_code"] == 0 and "mach_receiver=registered" in control["stdout"], control
    for path in ("mach", "xpc"):
        for phase in ("control-before", "control-after"):
            control = outcomes[f"{path}-{phase}"]
            assert control["exit_code"] == 0 and f"{path}_reply=ACK" in control["stdout"], control
    for label, code, stdout in (
        ("mach-isolated", 11, "mach_reply=unavailable"),
        ("xpc-isolated", 11, "xpc_reply=connection_invalid"),
        ("mach-register-isolated", 12, "mach_receiver=unavailable"),
    ):
        result = outcomes[label]
        assert result["exit_code"] == code and stdout in result["stdout"], result
        report = json.loads((reports / f"{label}.json").read_text())
        assert report["backend"] == "isolated" and report["isolation"] == "unconfirmed", report
        assert report["child_status"] == {"exit_code": code, "signal": None}, report
        assert report["run_status"] == {"exit_code": code, "reason": "child_failed"}, report
        assert report["coverage"]["proxy"] == "http_connect_requests", report
        assert report["coverage"]["direct_attempt_destinations"] == "not_observed", report
        assert report["destinations"] == [], report
    print("PASS: Mach and XPC receive logs, exit codes, and JSON")


if __name__ == "__main__":
    run(sys.argv[1])
