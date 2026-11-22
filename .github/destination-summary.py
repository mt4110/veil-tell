"""Render outbound findings and PR notification flags from a veil-tell JSON report."""

import argparse
import html
import json
import os
from pathlib import Path
import sys


REASON_LABELS = {
    "new": ("New", "新規"),
    "blocked": ("Blocked", "拒否"),
    "volume_cut": ("Volume limit cut", "送信量上限で切断"),
    "volume_anomaly": ("Volume anomaly", "送信量異常"),
}


def cell(value):
    text = html.escape(str(value)).replace("|", "&#124;")
    return "<code>" + " ".join(text.splitlines()) + "</code>"


def format_bytes(num_bytes):
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KiB"
    return f"{num_bytes / (1024 * 1024):.1f} MiB"


def format_attribution_short(sources):
    if not sources:
        return "特定できず (unknown)"
    parts = []
    for source in sources:
        pkg = source.get("package") or {}
        if pkg:
            script = pkg.get("script")
            label = f"{pkg['name']}@{pkg['version']}"
            if script:
                label += f" {script}"
            conf = source.get("confidence", "inferred")
            if conf == "inferred":
                label += "（推定）"
            else:
                label += f"（{conf}）"
            parts.append(label)
        else:
            parts.append("特定できず (unknown)")
    return ", ".join(dict.fromkeys(parts))


def volume_details(anomaly):
    if not anomaly or "observed" not in anomaly:
        return None
    observed, limits = anomaly["observed"], anomaly["limits"]
    details = ", ".join(
        f"{label} {observed[key]}/{limits[key]}"
        for key, label in (
            ("sent_bytes", "bytes"),
            ("connections", "connections"),
            ("max_connection_bytes", "max bytes per connection"),
        )
    )
    prefix = "cut / 切断" if anomaly.get("blocked") else "observed / 観測"
    return f"{prefix} · {details}"


def matching_lock_change(changes, package):
    if not package:
        return "—"
    identity = (package.get("name"), package.get("version"))
    for entry in changes.get("updated", []):
        before, after = entry["before"], entry["after"]
        if (after.get("name"), after.get("version")) == identity:
            if before.get("version") == after.get("version"):
                return f'{after["version"]} integrity changed / integrity 変更'
            return f'{before["version"]}→{after["version"]}'
    for added in changes.get("added", []):
        if (added.get("name"), added.get("version")) == identity:
            return "added / 追加"
    return "—"


def format_reason_pair(reasons):
    en = " + ".join(REASON_LABELS[r][0] for r in reasons)
    ja = "・".join(REASON_LABELS[r][1] for r in reasons)
    return f"{en} / {ja}"


def format_reason_ja(reasons):
    return "・".join(REASON_LABELS[r][1] for r in reasons)


def add_reason(entry, reason):
    if reason not in entry["reasons"]:
        entry["reasons"].append(reason)


def dedup_sources(sources):
    seen = set()
    unique = []
    for source in sources or []:
        key = json.dumps(source, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(source)
    return unique


def build_findings(report):
    comparison = report.get("comparison") or {}
    run_status = report.get("run_status") or {}
    run_reason = run_status.get("reason", "unknown")
    coverage = report.get("coverage") or {}

    entries = {}

    def ensure_entry(key, kind, dest_label):
        if key not in entries:
            entries[key] = {
                "kind": kind,
                "destination": dest_label,
                "reasons": [],
                "decision": None,
                "result": None,
                "deny_reason": None,
                "sent_bytes": 0,
                "attempts": 0,
                "attribution": [],
                "anomaly": None,
                "lock_hint": None,
            }
        return entries[key]

    dest_by_key = {}
    for dest in report.get("destinations") or []:
        key = ("CONNECT", dest["host"], dest.get("port", 443))
        existing = dest_by_key.get(key)
        if existing is None:
            dest_by_key[key] = dict(dest)
        else:
            existing["attempts"] = existing.get("attempts", 0) + dest.get("attempts", 0)
            existing["sent_bytes"] = existing.get("sent_bytes", 0) + dest.get("sent_bytes", 0)
            if dest.get("decision") == "deny":
                existing["decision"] = "deny"
                existing["reason"] = dest.get("reason", existing.get("reason"))
            if dest.get("result") == "blocked":
                existing["result"] = "blocked"
            if dest.get("attribution"):
                existing["attribution"] = dedup_sources(
                    existing.get("attribution", []) + dest["attribution"]
                )

    # 1. New CONNECT destinations from comparison
    for row in comparison.get("added") or []:
        port = row.get("port", 443)
        key = ("CONNECT", row["host"], port)
        entry = ensure_entry(key, "CONNECT", f"{row['host']}:{port}")
        add_reason(entry, "new")
        entry["attempts"] = row.get("attempts", 0)
        entry["attribution"] = row.get("attribution") or []
        matched = dest_by_key.get(key)
        if matched:
            entry["decision"] = matched.get("decision")
            entry["result"] = matched.get("result")
            entry["sent_bytes"] = matched.get("sent_bytes", 0)
            entry["attempts"] = matched.get("attempts", entry["attempts"])
            if not entry["attribution"]:
                entry["attribution"] = matched.get("attribution") or []
            if matched.get("decision") == "deny" or matched.get("result") == "blocked":
                add_reason(entry, "blocked")
                entry["deny_reason"] = matched.get("reason")
        elif comparison.get("status") == "new_destinations_only" or run_reason == "new_destination":
            entry["decision"] = "deny"
            entry["result"] = "blocked"
            add_reason(entry, "blocked")

    # 2. Explicit denials or blocked CONNECT destinations (even if known in baseline)
    for key, dest in dest_by_key.items():
        if dest.get("decision") == "deny" or dest.get("result") == "blocked":
            entry = ensure_entry(key, "CONNECT", f"{dest['host']}:{dest.get('port', 443)}")
            add_reason(entry, "blocked")
            entry["decision"] = dest.get("decision", "deny")
            entry["result"] = dest.get("result", "blocked")
            entry["deny_reason"] = dest.get("reason")
            entry["sent_bytes"] = dest.get("sent_bytes", 0)
            entry["attempts"] = dest.get("attempts", 0)
            if not entry["attribution"]:
                entry["attribution"] = dest.get("attribution") or []

    # 3. Volume anomalies (observed or cut)
    for anomaly in report.get("volume_anomalies") or []:
        port = anomaly.get("port", 443)
        key = ("CONNECT", anomaly["host"], port)
        entry = ensure_entry(key, "CONNECT", f"{anomaly['host']}:{port}")
        add_reason(entry, "volume_cut" if anomaly.get("blocked") else "volume_anomaly")
        entry["anomaly"] = anomaly
        observed = anomaly.get("observed") or {}
        entry["sent_bytes"] = observed.get("sent_bytes", entry["sent_bytes"])
        entry["attempts"] = observed.get("connections", entry["attempts"])
        if not entry["attribution"]:
            entry["attribution"] = anomaly.get("attribution") or []
        if anomaly.get("blocked") and entry["result"] is None:
            entry["result"] = "cut"

    # 4. New DNS lookup attempts (Node hook or future DNS sensors)
    added_dns_hosts = set()
    for row in comparison.get("attempted_added") or []:
        host = row["host"]
        added_dns_hosts.add(host)
        key = ("DNS", host, None)
        entry = ensure_entry(key, "Attempted DNS", host)
        add_reason(entry, "new")
        add_reason(entry, "blocked")
        entry["decision"] = "deny"
        entry["result"] = "blocked"
        entry["attempts"] = row.get("attempts", 0)
        entry["attribution"] = row.get("attribution") or []

    # Shorthand CI without comparison file, or known DNS attempts blocked during run
    for row in report.get("attempted") or []:
        host = row["host"]
        if host in added_dns_hosts:
            continue
        key = ("DNS", host, None)
        entry = ensure_entry(key, "Attempted DNS", host)
        if not comparison and run_reason == "new_destination":
            add_reason(entry, "new")
        add_reason(entry, "blocked")
        entry["decision"] = "deny"
        entry["result"] = "blocked"
        entry["attempts"] = row.get("attempts", 0)
        entry["attribution"] = row.get("attribution") or []

    # 5. Direct IP:port attempts recorded by isolation layer (only when observed)
    direct_cov = coverage.get("direct_attempt_destinations", "not_observed")
    if direct_cov != "not_observed":
        for row in report.get("direct_attempts") or []:
            dest_label = f"{row['ip']}:{row['port']}"
            key = ("DIRECT", row["ip"], row["port"])
            entry = ensure_entry(key, "Direct IP", dest_label)
            add_reason(entry, "blocked")
            entry["decision"] = "deny"
            entry["result"] = "blocked"
            entry["attempts"] = row.get("attempts", 0)

    return list(entries.values())


def detect_incomplete_reasons(report):
    run_status = report.get("run_status") or {}
    run_reason = run_status.get("reason", "unknown")
    coverage = report.get("coverage") or {}
    comparison = report.get("comparison")
    reasons = []

    if run_reason in {
        "incomplete_capture",
        "baseline_failed",
        "proxy_stopped",
        "timed_out",
        "interrupted",
        "policy_output_failed",
    }:
        reasons.append(f"run_status.reason={run_reason}")

    if coverage.get("proxy_capture") in {"incomplete", "until_proxy_stopped", "until_interrupted"}:
        reasons.append(f"coverage.proxy_capture={coverage['proxy_capture']}")
    if coverage.get("direct_attempt_destinations") == "incomplete":
        reasons.append("coverage.direct_attempt_destinations=incomplete")
    if coverage.get("dns_attempts") == "incomplete":
        reasons.append("coverage.dns_attempts=incomplete")

    if report.get("backend") == "isolated" and report.get("isolation") == "unconfirmed":
        reasons.append("isolation=unconfirmed")

    if comparison is None and run_reason not in {"new_destination"}:
        reasons.append("comparison=missing")
    elif comparison and comparison.get("status") in {"skipped", "created"}:
        reasons.append(f"comparison.status={comparison['status']}")

    return reasons


def compute_should_comment(report):
    comparison = report.get("comparison") or {}
    run_reason = (report.get("run_status") or {}).get("reason")
    has_new_from_comparison = bool(comparison.get("added") or comparison.get("attempted_added"))
    has_new_without_comparison = (
        not report.get("comparison")
        and run_reason == "new_destination"
        and bool(report.get("attempted"))
    )
    return bool(has_new_from_comparison or has_new_without_comparison)


def analyze_report(report, metadata=None):
    run_status = report.get("run_status") or {}
    run_reason = run_status.get("reason", "unknown")
    child_status = report.get("child_status") or {}
    child_exit = child_status.get("exit_code")
    child_signal = child_status.get("signal")
    comparison = report.get("comparison") or {}
    comp_status = comparison.get("status")
    coverage = report.get("coverage") or {}

    findings = build_findings(report)
    incomplete_reasons = detect_incomplete_reasons(report)
    should_comment = compute_should_comment(report)

    reason_tags = []
    for entry in findings:
        for r in entry["reasons"]:
            if r not in reason_tags:
                reason_tags.append(r)

    lines = []

    # Quiet success: 1 line only
    if (
        not findings
        and not incomplete_reasons
        and run_reason == "completed"
        and comp_status == "compared"
    ):
        lines.append(
            "OK (quiet): No new destinations, blocked attempts, or volume anomalies "
            "/ 新しい送り先・止めた試み・送信量の異常はありません"
        )
        return {
            "markdown": "\n".join(lines),
            "should_comment": False,
            "has_findings": False,
            "reasons": [],
        }

    # No outbound findings, but run/comparison did not finish cleanly
    if not findings:
        if run_reason == "child_failed":
            child_desc = (
                f"signal {child_signal}"
                if child_exit is None and child_signal is not None
                else f"exit {child_exit}"
            )
            lines.append("### veil-tell check incomplete (child failed)")
            lines.append("")
            lines.append(
                f"- **Status**: Child command failed (`{child_desc}`) with no new destinations "
                f"or blocked attempts observed / 子コマンドが終了しました（`{child_desc}`）。"
                "新しい送り先や遮断は観測されていません。"
            )
            if incomplete_reasons:
                lines.append(
                    "- **Comparison / Capture**: "
                    + ", ".join(cell(r) for r in incomplete_reasons)
                )
            lines.append(
                "- **Next**: Check the child command's own error log. "
                "This failure was not caused by a new outbound destination."
            )
        else:
            lines.append("### veil-tell check incomplete / 比較・観測が完了していません")
            lines.append("")
            lines.append(f"- **Run reason**: {cell(run_reason)} (exit {cell(run_status.get('exit_code', '?'))})")
            if incomplete_reasons:
                lines.append(
                    "- **Details**: " + ", ".join(cell(r) for r in incomplete_reasons)
                )
            lines.append(
                "- **Next**: Check the failing step log, baseline file, and isolation prerequisites "
                "before trusting this run."
            )
        append_metadata(lines, report, metadata)
        return {
            "markdown": "\n".join(lines),
            "should_comment": should_comment,
            "has_findings": False,
            "reasons": reason_tags,
        }

    # Findings exist: 1-line highlights + detailed table + next steps
    lines.append("### veil-tell outbound alert / 通信の変化・遮断を検出しました")
    lines.append("")

    for entry in findings[:20]:
        reasons_ja = format_reason_ja(entry["reasons"])
        attr_short = format_attribution_short(entry["attribution"])
        if entry["kind"] == "Direct IP":
            traffic_short = f"{entry['attempts']} 回"
        elif entry["kind"] == "Attempted DNS":
            traffic_short = f"試行 {entry['attempts']} 回"
        else:
            traffic_short = f"転送 {format_bytes(entry['sent_bytes'])}"
        lines.append(
            f"- **{reasons_ja}** ｜ `{entry['destination']}` ｜ {attr_short} ｜ {traffic_short}"
        )
    if len(findings) > 20:
        lines.append(f"- *({len(findings) - 20} additional items shown in table / report)*")

    notes = []
    if comp_status == "new_destinations_only":
        notes.append(
            "Comparison was restricted to new destinations after failure (`new_destinations_only`); "
            "removed destinations were not evaluated."
        )
    if comparison.get("backend_changed"):
        notes.append("Baseline was recorded under a different backend than this run (`backend_changed=true`).")
    for inc in incomplete_reasons:
        if not (comp_status == "skipped" and inc == "comparison.status=skipped"):
            notes.append(f"Capture/comparison note: `{inc}`.")
    if comp_status == "skipped":
        notes.append("Baseline comparison was skipped (`comparison.status=skipped`).")
    if notes:
        lines.append("")
        for note in notes:
            lines.append(f"> {note}")

    lines.append("")
    lines.append(
        "| Reasons | Kind | Destination | Outcome | Package / Attribution | Lockfile | Traffic / Limit |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")

    evidence = {
        (item["host"], item.get("port"), json.dumps(item["source"], sort_keys=True)): item["label"]
        for item in comparison.get("lockfile_evidence") or []
    }
    changes = comparison.get("lockfile_changes") or {}

    rows = 0
    for entry in findings:
        sources = entry["attribution"] or [{"confidence": "unknown"}]
        for source in sources:
            if rows >= 100:
                lines.append("\nAdditional entries are available in `report.json`.")
                break
            package = source.get("package") or {}
            host_only = entry["destination"].rsplit(":", 1)[0] if ":" in entry["destination"] else entry["destination"]
            port_val = None
            if entry["kind"] == "CONNECT" and ":" in entry["destination"]:
                port_val = int(entry["destination"].rsplit(":", 1)[1])

            if package:
                pkg_str = f"{package['name']}@{package['version']}"
                if package.get("script"):
                    pkg_str += f" ({package['script']})"
                if package.get("path"):
                    pkg_str += f" @ {package['path']}"
                pkg_str += f" [{source.get('confidence', 'inferred')}]"
            else:
                pkg_str = f"unknown ({source.get('confidence', 'unknown')})"

            if entry["kind"] == "CONNECT":
                lock_str = (
                    evidence.get((host_only, port_val, json.dumps(source, sort_keys=True)))
                    or matching_lock_change(changes, package)
                )
            elif entry["kind"] == "Attempted DNS":
                lock_str = (
                    evidence.get((host_only, None, json.dumps(source, sort_keys=True)))
                    or matching_lock_change(changes, package)
                )
            else:
                lock_str = "—"

            outcome_parts = []
            if entry["result"]:
                outcome_parts.append(entry["result"])
            elif entry["decision"]:
                outcome_parts.append(entry["decision"])
            else:
                outcome_parts.append("observed")
            if entry["deny_reason"]:
                outcome_parts.append(f"({entry['deny_reason']})")
            outcome_str = " ".join(outcome_parts)

            vol_str = volume_details(entry["anomaly"])
            if vol_str:
                traffic_str = vol_str
            elif entry["kind"] == "CONNECT":
                traffic_str = f"{format_bytes(entry['sent_bytes'])} ({entry['attempts']} attempts)"
            else:
                traffic_str = f"{entry['attempts']} attempts"

            values = (
                format_reason_pair(entry["reasons"]),
                entry["kind"],
                entry["destination"],
                outcome_str,
                pkg_str,
                lock_str,
                traffic_str,
            )
            lines.append("| " + " | ".join(map(cell, values)) + " |")
            rows += 1
        if rows >= 100:
            break

    lines.append("")
    lines.append("**Next steps / 次の一手**")
    if "new" in reason_tags:
        lines.append(
            "- **New destination / 新規宛先**: Verify why the dependency needs this host and check "
            "the lockfile diff. Do **not** approve by editing the baseline in the PR branch; "
            "if legitimate, re-record and review the baseline on the trusted base branch first."
        )
    if "blocked" in reason_tags and "new" not in reason_tags:
        lines.append(
            "- **Blocked attempt / 止めた試み**: Confirm whether this blocked connection or direct IP/DNS "
            "attempt is an expected policy denial or a bypass attempt."
        )
    if "volume_cut" in reason_tags or "volume_anomaly" in reason_tags:
        lines.append(
            "- **Volume anomaly / 送信量の異常**: Compare `observed` vs `limits` in `report.json` "
            "to confirm there is no unexpected upload or connection burst."
        )

    append_metadata(lines, report, metadata)
    return {
        "markdown": "\n".join(lines),
        "should_comment": should_comment,
        "has_findings": True,
        "reasons": reason_tags,
    }


def append_metadata(lines, report, metadata):
    coverage = report.get("coverage") or {}
    run_status = report.get("run_status") or {}
    meta_items = [
        f"run_status={run_status.get('reason', 'unknown')} (exit {run_status.get('exit_code', '?')})",
        f"backend={report.get('backend', '?')}",
        f"isolation={report.get('isolation', '?')}",
        f"coverage.dns={coverage.get('dns_attempts', '?')}",
        f"coverage.direct={coverage.get('direct_attempt_destinations', '?')}",
    ]
    if metadata:
        for key in ("action_ref", "action_sha", "binary_version", "binary_sha256", "runner_os", "runner_arch"):
            if metadata.get(key):
                meta_items.append(f"{key}={metadata[key]}")
    lines.append("")
    lines.append("<details><summary>Coverage &amp; run metadata</summary>")
    lines.append("")
    lines.append("```text")
    for item in meta_items:
        lines.append(item)
    lines.append("```")
    lines.append("</details>")


def write_github_output(path, result):
    with Path(path).open("a", encoding="utf-8") as fh:
        fh.write(f"should_comment={'true' if result['should_comment'] else 'false'}\n")
        fh.write(f"has_findings={'true' if result['has_findings'] else 'false'}\n")
        fh.write(f"finding_reasons={','.join(result['reasons'])}\n")


def main():
    parser = argparse.ArgumentParser(description="Summarize a veil-tell JSON report.")
    parser.add_argument("report", help="Path to report.json")
    parser.add_argument("--github-output", default=None, help="Path to GITHUB_OUTPUT file")
    parser.add_argument("--missing-reason", default=None, help="Reason shown if report.json is missing")
    parser.add_argument("--action-ref", default=os.environ.get("VEIL_ACTION_REF"))
    parser.add_argument("--action-sha", default=os.environ.get("VEIL_ACTION_SHA"))
    parser.add_argument("--binary-version", default=os.environ.get("VEIL_BINARY_VERSION"))
    parser.add_argument("--binary-sha256", default=os.environ.get("VEIL_BINARY_SHA256"))
    parser.add_argument("--runner-os", default=os.environ.get("RUNNER_OS"))
    parser.add_argument("--runner-arch", default=os.environ.get("RUNNER_ARCH"))
    args = parser.parse_args()

    metadata = {
        "action_ref": args.action_ref,
        "action_sha": args.action_sha,
        "binary_version": args.binary_version,
        "binary_sha256": args.binary_sha256,
        "runner_os": args.runner_os,
        "runner_arch": args.runner_arch,
    }

    report_path = Path(args.report)
    if not report_path.is_file():
        detail = args.missing_reason or f"Report file not found (`{report_path}`)."
        result = {
            "markdown": (
                "### veil-tell check incomplete / レポートが生成されませんでした\n\n"
                f"- **Error**: {html.escape(detail)}\n"
                "- **Next**: Open the failing step log to check baseline resolution, isolation prerequisites, and release verification."
            ),
            "should_comment": False,
            "has_findings": False,
            "reasons": [],
        }
    else:
        try:
            report_data = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result = {
                "markdown": (
                    "### veil-tell check incomplete / レポートを読み取れませんでした\n\n"
                    f"- **Error**: Could not parse report JSON ({html.escape(str(exc))}).\n"
                    "- **Next**: Check the failing step log and verify disk/output state."
                ),
                "should_comment": False,
                "has_findings": False,
                "reasons": [],
            }
        else:
            result = analyze_report(report_data, metadata=metadata)

    print(result["markdown"])
    if args.github_output:
        write_github_output(args.github_output, result)


if __name__ == "__main__":
    main()
