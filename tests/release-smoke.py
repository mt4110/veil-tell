import base64
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit


def prepare(case):
    baseline = {
        "schema_version": 1,
        "backend": "isolated",
        "coverage": "http_connect_requests",
        "destinations": [],
    }
    if case == "volume":
        baseline["destinations"] = [{"host": "volume.test", "port": 443, "attempts": 1}]
        baseline["volume"] = {
            "volume.test": {"sent_bytes": 4096, "connections": 1, "max_connection_bytes": 4096}
        }
    Path(".veil-tell/npm.json").write_text(json.dumps(baseline))
    Path("probe.py").write_text(Path(__file__).read_text())


def probe(case):
    if case == "unchanged":
        return
    if case == "dns":
        subprocess.run(["node", "-e",
                        'fetch("https://release-smoke-dns.invalid").then(() => process.exit(2), '
                        'error => { if (error.cause?.code !== "ENOTFOUND") process.exit(3) });'],
                       check=True, timeout=10)
        return
    if case == "volume":
        Path("receiver.start").touch()
        for _ in range(80):
            if Path("receiver.ready").is_file():
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("local receiver did not start")
    host = "volume.test" if case == "volume" else "new.test"
    proxy = urlsplit(os.environ["HTTPS_PROXY"])
    auth = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
    with socket.create_connection((proxy.hostname, proxy.port), timeout=5) as conn:
        conn.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
        with conn.makefile("rb") as stream:
            code = stream.readline().split()[1]
            for line in stream:
                if line == b"\r\n":
                    break
            assert code == (b"200" if case == "volume" else b"403"), code
            if case == "volume":
                try:
                    conn.sendall(b"X" * 524288)
                    conn.shutdown(socket.SHUT_WR)
                    stream.read()
                except OSError as error:
                    if error.errno not in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN):
                        raise


def receive():
    with socket.socket() as server:
        server.bind(("192.0.1.2", 443))
        server.listen()
        server.settimeout(0.2)
        print("ready", flush=True)
        connections = received = 0
        deadline = time.monotonic() + 120
        while not Path("receiver.stop").exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("receiver did not get a stop signal")
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            with conn, conn.makefile("rb") as stream:
                conn.settimeout(10)
                connections += 1
                received += len(stream.read())
        print(f"connections={connections} received={received}", flush=True)


def check():
    case = os.environ["CASE"]
    expected = int(os.environ["EXPECTED"])
    temp = Path(os.environ["RUNNER_TEMP"])
    evidence = temp / "evidence"
    assert os.environ["ACTION_OUTCOME"] == os.environ["EXPECTED_OUTCOME"]
    data = json.loads((evidence / "report.json").read_text())
    assert data["backend"] == "isolated" and data["isolation"] == "applied"
    assert data["child_status"]["exit_code"] == 0
    assert data["run_status"]["exit_code"] == expected
    # Read what the actual composite step wrote, rather than rendering JSON again.
    summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
    summaries = sorted(summary_path.parent.glob("step_summary_*"))
    markers = {
        "unchanged": "新しい送り先・試み・送信量の異常はありません",
        "new": "<code>new.test:443</code>",
        "dns": "<code>Attempted DNS</code>",
        "volume": "<code>Volume anomaly</code>",
    }
    if case == "volume":
        receiver = (evidence / "receiver.log").read_text()
        assert "ready" in receiver.splitlines(), receiver
        assert "connections=1 received=131072" in receiver.splitlines(), receiver
    if case == "unchanged":
        assert data["run_status"]["reason"] == "completed"
        assert not data["comparison"]["added"] and not data.get("volume_anomalies")
        assert not data["comparison"].get("attempted_added")
    elif case == "new":
        assert data["run_status"]["reason"] == "new_destination"
        assert data["comparison"]["added"][0]["host"] == "new.test"
        assert data["destinations"][0]["result"] == "blocked"
    elif case == "dns":
        assert data["run_status"]["reason"] == "new_destination"
        assert data["coverage"]["dns_attempts"] == "node_dns_lookup_hook"
        assert not data["comparison"]["added"]
        attempt, = data["comparison"]["attempted_added"]
        assert attempt["host"] == "release-smoke-dns.invalid"
        assert data["attempted"][0]["host"] == attempt["host"]
    else:
        assert data["run_status"]["reason"] == "volume_limit_exceeded"
        anomaly, = data["volume_anomalies"]
        assert anomaly["host"] == "volume.test" and anomaly["blocked"]
        assert anomaly["observed"]["sent_bytes"] == 131072
    if case != "unchanged":
        row = data["attempted"][0] if case == "dns" else data["destinations"][0]
        source, = row["attribution"]
        assert source["package"]["name"] == "veil-release-smoke"
        assert source["package"]["script"] == "postinstall"
    expected_summary = markers[case]
    for path in summaries:
        summary = path.read_text()
        if expected_summary in summary:
            if case != "unchanged":
                assert "<code>veil-release-smoke@1.0.0</code>" in summary, summary
                assert "<code>postinstall</code>" in summary, summary
            if case == "dns":
                assert "<code>release-smoke-dns.invalid</code>" in summary, summary
            if case == "volume":
                assert "bytes 131072/262144" in summary, summary
                assert "max bytes per connection 131072/131072" in summary, summary
            (evidence / "summary.md").write_text(summary)
            break
    else:
        raise AssertionError(f"Action did not write the expected summary: {expected_summary}")
    print(f"case={case} action={os.environ['ACTION_OUTCOME']} child=0 veil-tell={expected}")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        probe(Path("case.txt").read_text().strip())
    elif sys.argv[1] == "prepare":
        prepare(sys.argv[2])
    elif sys.argv[1] == "receive":
        receive()
    elif sys.argv[1] == "check":
        check()
