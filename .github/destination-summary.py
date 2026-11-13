"""Render the new CONNECT destinations from a veil-tell report as a job summary."""

import html
import json
from pathlib import Path
import sys


def cell(value):
    # Keep report text inside its cell, including data supplied by a child.
    text = html.escape(str(value)).replace("|", "&#124;")
    return "<code>" + " ".join(text.splitlines()) + "</code>"


def summary(report):
    print("### veil-tell: new CONNECT destinations")
    print()
    added = (report.get("comparison") or {}).get("added", [])
    if not added:
        print("No new CONNECT destinations recorded. Result:", cell(report["run_status"]["reason"]))
        return
    print("| Destination | Package | Lifecycle | Path | Attribution |")
    print("| --- | --- | --- | --- | --- |")
    rows = 0
    for endpoint in added:
        for source in endpoint.get("attribution") or [{"confidence": "unknown"}]:
            if rows >= 100:
                print("\nAdditional entries are available in the JSON report.")
                return
            package = source.get("package") or {}
            values = (
                f'{endpoint["host"]}:{endpoint["port"]}',
                f'{package["name"]}@{package["version"]}' if package else "—",
                package.get("script", "—"),
                package.get("path", "—"),
                source["confidence"],
            )
            print("| " + " | ".join(map(cell, values)) + " |")
            rows += 1


if __name__ == "__main__":
    summary(json.loads(Path(sys.argv[1]).read_text()))
