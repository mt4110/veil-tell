"""Render outbound changes from a veil-tell JSON report."""

import html
import json
from pathlib import Path
import sys


def cell(value):
    text = html.escape(str(value)).replace("|", "&#124;")
    return "<code>" + " ".join(text.splitlines()) + "</code>"


def volume_details(endpoint):
    if "observed" not in endpoint:
        return "—"
    observed, limits = endpoint["observed"], endpoint["limits"]
    details = ", ".join(
        f"{label} {observed[key]}/{limits[key]}"
        for key, label in (
            ("sent_bytes", "bytes"), ("connections", "connections"),
            ("max_connection_bytes", "max bytes per connection"),
        )
    )
    return ("cut / 切断 · " if endpoint["blocked"] else "observed / 観測 · ") + details


def matching_lock_change(changes, package):
    if not package:
        return "—"
    identity = package["name"], package["version"]
    for entry in changes.get("updated", []):
        before, after = entry["before"], entry["after"]
        if (after["name"], after["version"]) == identity:
            if before["version"] == after["version"]:
                return f'{after["version"]} integrity changed / integrity 変更'
            return f'{before["version"]}→{after["version"]}'
    for added in changes.get("added", []):
        if (added["name"], added["version"]) == identity:
            return "added / 追加"
    return "—"


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
    changes = comparison.get("lockfile_changes") or {}
    print("| Kind | Destination | Package | Lifecycle | Path | Attribution | Lockfile | Observed / Limit |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
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
                source["confidence"],
                evidence.get((host, port, json.dumps(source, sort_keys=True)))
                or matching_lock_change(changes, package),
                volume_details(endpoint),
            )
            print("| " + " | ".join(map(cell, values)) + " |")
            rows += 1


if __name__ == "__main__":
    summary(json.loads(Path(sys.argv[1]).read_text()))
