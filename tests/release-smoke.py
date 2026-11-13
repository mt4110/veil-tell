import base64
import json
import os
from pathlib import Path
import socket
import sys
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
                except (ConnectionResetError, BrokenPipeError):
                    pass


def receive():
    with socket.socket() as server:
        server.bind(("192.0.1.2", 443))
        server.listen(1)
        server.settimeout(120)
        print("ready", flush=True)
        conn, _ = server.accept()
        with conn, conn.makefile("rb") as stream:
            conn.settimeout(10)
            print(f"received={len(stream.read())}", flush=True)


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
        "volume": "<code>Volume anomaly</code>",
    }
    if case == "unchanged":
        assert data["run_status"]["reason"] == "completed"
        assert not data["comparison"]["added"] and not data.get("volume_anomalies")
    elif case == "new":
        assert data["run_status"]["reason"] == "new_destination"
        assert data["comparison"]["added"][0]["host"] == "new.test"
        assert data["destinations"][0]["result"] == "blocked"
    else:
        assert data["run_status"]["reason"] == "volume_limit_exceeded"
        anomaly, = data["volume_anomalies"]
        assert anomaly["host"] == "volume.test" and anomaly["blocked"]
        assert anomaly["observed"]["sent_bytes"] == 131072
        assert "received=131072" in (evidence / "receiver.log").read_text()
    if case != "unchanged":
        source, = data["destinations"][0]["attribution"]
        assert source["package"]["name"] == "veil-release-smoke"
        assert source["package"]["script"] == "postinstall"
    expected_summary = markers[case]
    for path in summaries:
        summary = path.read_text()
        if expected_summary in summary:
            (evidence / "summary.md").write_text(summary)
            break
    else:
        # The runner rotates each step's command files; the uploaded summary
        # remains on the run's Summary page even when the local file is gone.
        print(f"Verify the uploaded summary on the run page: {expected_summary}")
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
