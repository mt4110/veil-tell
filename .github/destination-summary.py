"""Render outbound changes from a veil-tell JSON report."""

import html
import json
from pathlib import Path
import sys


def cell(value):
    text = html.escape(str(value)).replace("|", "&#124;")
    return "<code>" + " ".join(text.splitlines()) + "</code>"


def summary(report):
    comparison = report.get("comparison") or {}
    findings = (
        [("CONNECT", row) for row in comparison.get("added", [])]
        + [("Attempted DNS", row) for row in comparison.get("attempted_added", [])]
        + [("Volume anomaly", row) for row in report.get("volume_anomalies", [])]
    )
    if not findings:
        if comparison.get("status") == "compared":
            print("No new destinations, attempts or volume anomalies / 新しい送り先・試み・送信量の異常はありません")
        else:
            print("Comparison unavailable / 比較できません:", cell(report["run_status"]["reason"]))
        return
    print("### veil-tell outbound changes\n")
    evidence = {
        (item["host"], item["port"], json.dumps(item["source"], sort_keys=True)): item["label"]
        for item in comparison.get("lockfile_evidence", [])
    }
    print("| Kind | Destination | Package | Lifecycle | Path | Attribution |")
    print("| --- | --- | --- | --- | --- | --- |")
    rows = 0
    for kind, endpoint in findings:
        for source in endpoint.get("attribution") or [{"confidence": "unknown"}]:
            if rows >= 100:
                print("\nAdditional entries are available in the JSON report.")
                return
            package = source.get("package") or {}
            host, port = endpoint["host"], endpoint.get("port")
            values = (
                kind, f"{host}:{port}" if port else host,
                f'{package["name"]}@{package["version"]}' if package else "—",
                package.get("script", "—"), package.get("path", "—"),
                " · ".join(filter(None, (source["confidence"], evidence.get((
                    host, port, json.dumps(source, sort_keys=True)
                ))))),
            )
            print("| " + " | ".join(map(cell, values)) + " |")
            rows += 1


if __name__ == "__main__":
    summary(json.loads(Path(sys.argv[1]).read_text()))
