"""Monthly operations rollup tool (M01) for veil-tell.

Aggregates 30-day UTC dependency update PR observations according to
docs/roadmap-to-1.0.md section 5 without leaking sensitive fields (argv, cwd,
raw logs, or private hostnames).
"""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


ALERT_KINDS = ("new", "blocked", "volume")
REVIEW_CLASSES = (
    "actionable_true_positive",
    "noise_valid_observation",
    "false_positive",
    "unreviewed",
)
EVALUATABLE_STATUSES = {"evaluated"}


def parse_utc(value):
    if value is None:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def empty_review_counts():
    return {name: 0 for name in REVIEW_CLASSES}


def empty_kind_counts():
    return {kind: 0 for kind in ALERT_KINDS}


def _run_matches_entry(run, entry, default_mgr):
    mgr = entry.get("manager", default_mgr)
    run_mgr = run.get("manager", default_mgr)
    if run_mgr != mgr:
        return False

    explicit_revs = entry.get("target_revisions")
    if explicit_revs:
        matched_rev = False
        for rev in explicit_revs:
            head = rev.get("pr_head_sha") or rev.get("head_sha")
            if head and run.get("pr_head_sha") != head:
                continue
            base = rev.get("base_sha")
            if base is not None and run.get("base_sha", "") != base:
                continue
            checkout = rev.get("checkout_sha")
            if checkout is not None and run.get("checkout_sha", "") != checkout:
                continue
            matched_rev = True
            break
        if not matched_rev:
            return False

    target_heads = entry.get("target_heads")
    if target_heads and run.get("pr_head_sha") not in target_heads:
        return False
    if entry.get("base_sha") is not None and run.get("base_sha", "") != entry.get("base_sha"):
        return False
    if entry.get("checkout_sha") is not None and run.get("checkout_sha", "") != entry.get("checkout_sha"):
        return False
    return True


def rollup_group(repo_key, manager_key, prs, runs, window_start, window_end, required_jobs, config_intervals, outages):
    default_mgr = "npm" if manager_key == "all" else manager_key
    natural_entries = [p for p in prs if p.get("kind", "natural") == "natural"]
    non_natural_entries = [p for p in prs if p.get("kind", "natural") != "natural"]

    natural_entries_by_pr = defaultdict(list)
    for entry in natural_entries:
        natural_entries_by_pr[(entry["repo"], entry["pr"])].append(entry)
    natural_pr_ids = set(natural_entries_by_pr.keys())

    seen_non_natural_prs = set()
    non_natural_counts = defaultdict(int)
    for p in non_natural_entries:
        kind = p.get("kind", "synthetic")
        unique_key = (p["repo"], p["pr"], kind)
        if unique_key not in seen_non_natural_prs:
            seen_non_natural_prs.add(unique_key)
            non_natural_counts[kind] += 1

    # Filter runs into natural vs non-natural, enforce registered target heads/revisions,
    # and enforce half-open [window_start, window_end)
    in_window_natural_runs = []
    pre_window_runs = []
    post_deadline_runs = []
    unregistered_target_runs = []
    non_natural_runs_count = 0

    for run in runs:
        pr_id = (run["repo"], run["pr"])
        if pr_id not in natural_pr_ids:
            non_natural_runs_count += 1
            continue
        if not any(_run_matches_entry(run, entry, default_mgr) for entry in natural_entries_by_pr[pr_id]):
            unregistered_target_runs.append(
                {
                    "repo": run["repo"],
                    "pr": run["pr"],
                    "manager": run.get("manager", default_mgr),
                    "base_sha": run.get("base_sha"),
                    "pr_head_sha": run.get("pr_head_sha"),
                    "checkout_sha": run.get("checkout_sha"),
                    "job_matrix": run.get("job_matrix"),
                    "run_id": run.get("run_id"),
                    "run_attempt": run.get("run_attempt"),
                    "completed_at": run.get("completed_at"),
                }
            )
            continue
        completed = parse_utc(run.get("completed_at"))
        if window_start is not None and completed is not None and completed < window_start:
            pre_window_runs.append(
                {
                    "repo": run["repo"],
                    "pr": run["pr"],
                    "pr_head_sha": run.get("pr_head_sha"),
                    "job_matrix": run.get("job_matrix"),
                    "run_id": run.get("run_id"),
                    "run_attempt": run.get("run_attempt"),
                    "completed_at": run.get("completed_at"),
                }
            )
            continue
        if window_end is not None and completed is not None and completed >= window_end:
            post_deadline_runs.append(
                {
                    "repo": run["repo"],
                    "pr": run["pr"],
                    "pr_head_sha": run.get("pr_head_sha"),
                    "job_matrix": run.get("job_matrix"),
                    "run_id": run.get("run_id"),
                    "run_attempt": run.get("run_attempt"),
                    "completed_at": run.get("completed_at"),
                }
            )
            continue
        in_window_natural_runs.append(run)

    # Sort deterministically so reruns are detected consistently
    in_window_natural_runs.sort(
        key=lambda r: (
            r["repo"],
            r["pr"],
            r.get("manager", ""),
            r.get("base_sha", ""),
            r.get("pr_head_sha", ""),
            r.get("checkout_sha", ""),
            r.get("job_matrix", ""),
            str(r.get("completed_at") or ""),
            int(r.get("run_id") or 0),
            int(r.get("run_attempt") or 0),
        )
    )

    seen_exam_keys = set()
    runs_by_pr = defaultdict(list)

    runs_with_execution = 0
    quiet_evaluatable_runs = 0
    recorded_finding_runs = 0
    actual_notification_runs = 0
    actual_notification_reruns = 0
    display_failed_runs = 0
    display_unverified_runs = 0

    recorded_reason_counts = empty_kind_counts()
    displayed_reason_review = empty_review_counts()
    recorded_reason_review = empty_review_counts()
    runs_with_unreviewed = 0
    runs_with_false_positive = 0
    runs_with_missed_confirmed = 0

    for run in in_window_natural_runs:
        pr_id = (run["repo"], run["pr"])
        runs_by_pr[pr_id].append(run)

        status = run.get("status", "evaluated")
        if status != "not_run":
            runs_with_execution += 1

        exam_key = (
            run["repo"],
            run["pr"],
            run.get("manager", "npm"),
            run.get("base_sha", ""),
            run.get("pr_head_sha", ""),
            run.get("checkout_sha", ""),
            run.get("job_matrix", ""),
        )
        is_rerun = exam_key in seen_exam_keys
        seen_exam_keys.add(exam_key)

        reasons = run.get("reasons") or []
        summary_displayed = run.get("summary_displayed", "none")

        if status in EVALUATABLE_STATUSES and not reasons:
            quiet_evaluatable_runs += 1

        if run.get("missed_confirmed"):
            runs_with_missed_confirmed += 1

        if reasons:
            recorded_finding_runs += 1
            for item in reasons:
                kind = item.get("kind")
                if kind in recorded_reason_counts:
                    recorded_reason_counts[kind] += 1
                review = item.get("review", "unreviewed")
                if review not in recorded_reason_review:
                    review = "unreviewed"
                recorded_reason_review[review] += 1

            if summary_displayed == "shown":
                actual_notification_runs += 1
                if is_rerun:
                    actual_notification_reruns += 1
                has_unrev = False
                has_fp = False
                for item in reasons:
                    review = item.get("review", "unreviewed")
                    if review not in displayed_reason_review:
                        review = "unreviewed"
                    displayed_reason_review[review] += 1
                    if review == "unreviewed":
                        has_unrev = True
                    if review == "false_positive":
                        has_fp = True
                if has_unrev:
                    runs_with_unreviewed += 1
                if has_fp:
                    runs_with_false_positive += 1
            elif summary_displayed == "failed":
                display_failed_runs += 1
            elif summary_displayed == "unverified":
                display_unverified_runs += 1

    # PR-level aggregation
    prs_with_runs = 0
    prs_fully_evaluated = 0
    prs_partially_evaluated = 0
    prs_completely_missing = 0
    prs_alerted = 0
    prs_by_reason = empty_kind_counts()
    prs_with_false_positive = 0
    prs_with_noise = 0
    prs_with_unreviewed = 0
    prs_with_missed_confirmed = 0

    for pr_id in sorted(natural_entries_by_pr.keys()):
        pr_entries = natural_entries_by_pr[pr_id]
        pr_runs = runs_by_pr.get(pr_id, [])
        executed_runs = [r for r in pr_runs if r.get("status", "evaluated") != "not_run"]
        if executed_runs:
            prs_with_runs += 1

        default_mgr = "npm" if manager_key == "all" else manager_key
        expected_targets = set()
        evaluated_targets = set()

        for entry in pr_entries:
            mgr = entry.get("manager", default_mgr)
            entry_runs = [r for r in pr_runs if _run_matches_entry(r, entry, default_mgr)]
            target_heads = entry.get("target_heads")
            if not target_heads:
                heads = {r.get("pr_head_sha") for r in entry_runs if r.get("pr_head_sha")}
                target_heads = sorted(heads) if heads else ["(unknown-head)"]

            jobs = entry.get("required_jobs") or required_jobs or sorted(
                {r.get("job_matrix", "default") for r in entry_runs} or {"default"}
            )

            expected_revisions = set()
            explicit_revs = entry.get("target_revisions")
            if explicit_revs:
                for rev in explicit_revs:
                    expected_revisions.add(
                        (
                            rev.get("base_sha", ""),
                            rev.get("pr_head_sha") or rev.get("head_sha") or target_heads[0],
                            rev.get("checkout_sha", ""),
                        )
                    )
            for h in target_heads:
                head_runs = [
                    r for r in entry_runs if (r.get("pr_head_sha") or target_heads[0]) == h
                ]
                for r in head_runs:
                    expected_revisions.add(
                        (
                            r.get("base_sha", ""),
                            h,
                            r.get("checkout_sha", ""),
                        )
                    )
                if not head_runs and not any(rev[1] == h for rev in expected_revisions):
                    expected_revisions.add(
                        (
                            entry.get("base_sha", ""),
                            h,
                            entry.get("checkout_sha", ""),
                        )
                    )

            for base_sha, head_sha, checkout_sha in expected_revisions:
                for j in jobs:
                    expected_targets.add((mgr, base_sha, head_sha, checkout_sha, j))

            for r in entry_runs:
                if r.get("status", "evaluated") in EVALUATABLE_STATUSES:
                    evaluated_targets.add(
                        (
                            mgr,
                            r.get("base_sha", ""),
                            r.get("pr_head_sha") or target_heads[0],
                            r.get("checkout_sha", ""),
                            r.get("job_matrix", "default"),
                        )
                    )

        if expected_targets and expected_targets <= evaluated_targets:
            prs_fully_evaluated += 1
        elif evaluated_targets:
            prs_partially_evaluated += 1
        else:
            prs_completely_missing += 1

        # Alerted PR: had at least one actual notification run (displayed)
        notified_runs = [
            r for r in pr_runs if (r.get("reasons") and r.get("summary_displayed", "none") == "shown")
        ]
        if notified_runs:
            prs_alerted += 1

        pr_kinds = set()
        pr_has_fp = False
        pr_has_noise = False
        pr_has_unrev = False
        pr_missed = False

        for r in pr_runs:
            if r.get("missed_confirmed"):
                pr_missed = True
            if r.get("summary_displayed", "none") == "shown":
                for item in r.get("reasons") or []:
                    kind = item.get("kind")
                    if kind in ALERT_KINDS:
                        pr_kinds.add(kind)
                    review = item.get("review", "unreviewed")
                    if review == "false_positive":
                        pr_has_fp = True
                    elif review == "noise_valid_observation":
                        pr_has_noise = True
                    elif review == "unreviewed":
                        pr_has_unrev = True

        for kind in pr_kinds:
            prs_by_reason[kind] += 1
        if pr_has_fp:
            prs_with_false_positive += 1
        if pr_has_noise:
            prs_with_noise += 1
        if pr_has_unrev:
            prs_with_unreviewed += 1
        if pr_missed:
            prs_with_missed_confirmed += 1

    reviewed_reasons_total = (
        displayed_reason_review["actionable_true_positive"]
        + displayed_reason_review["noise_valid_observation"]
        + displayed_reason_review["false_positive"]
    )
    if reviewed_reasons_total > 0:
        fp_rate = displayed_reason_review["false_positive"] / reviewed_reasons_total
    else:
        fp_rate = None

    if len(natural_pr_ids) == 0:
        effectiveness_status = "pending_zero_updates"
    elif (
        prs_with_unreviewed > 0
        or prs_completely_missing > 0
        or prs_partially_evaluated > 0
    ):
        effectiveness_status = "partial_or_pending_review"
    else:
        effectiveness_status = "ready"

    return {
        "repo": repo_key,
        "manager": manager_key,
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
        "target_prs": len(natural_pr_ids),
        "prs_with_runs": prs_with_runs,
        "prs_fully_evaluated": prs_fully_evaluated,
        "prs_partially_evaluated": prs_partially_evaluated,
        "prs_completely_missing": prs_completely_missing,
        "prs_alerted": prs_alerted,
        "runs_with_execution": runs_with_execution,
        "quiet_evaluatable_runs": quiet_evaluatable_runs,
        "recorded_finding_runs": recorded_finding_runs,
        "actual_notification_runs": actual_notification_runs,
        "actual_notification_reruns": actual_notification_reruns,
        "display_failed_runs": display_failed_runs,
        "display_unverified_runs": display_unverified_runs,
        "prs_by_reason": prs_by_reason,
        "recorded_reason_counts": recorded_reason_counts,
        "displayed_reason_review": displayed_reason_review,
        "recorded_reason_review": recorded_reason_review,
        "reviewed_alert_reasons": reviewed_reasons_total,
        "technical_false_positive_rate": fp_rate,
        "runs_with_false_positive": runs_with_false_positive,
        "runs_with_unreviewed": runs_with_unreviewed,
        "prs_with_false_positive": prs_with_false_positive,
        "prs_with_noise": prs_with_noise,
        "prs_with_unreviewed": prs_with_unreviewed,
        "runs_with_missed_confirmed": runs_with_missed_confirmed,
        "prs_with_missed_confirmed": prs_with_missed_confirmed,
        "non_natural_prs": dict(non_natural_counts),
        "non_natural_runs": non_natural_runs_count,
        "pre_window_runs": pre_window_runs,
        "post_deadline_runs": post_deadline_runs,
        "unregistered_target_runs": unregistered_target_runs,
        "config_intervals": config_intervals,
        "outages": outages,
        "effectiveness_status": effectiveness_status,
    }


def rollup_ledger(ledger):
    window_start = parse_utc(ledger.get("window_start"))
    window_end = parse_utc(ledger.get("window_end"))
    repos_meta = {
        (item["repo"], item.get("manager", "npm")): item
        for item in ledger.get("repositories") or []
    }

    prs_by_group = defaultdict(list)
    for pr in ledger.get("target_prs") or []:
        key = (pr["repo"], pr.get("manager", "npm"))
        prs_by_group[key].append(pr)

    runs_by_group = defaultdict(list)
    for run in ledger.get("runs") or []:
        key = (run["repo"], run.get("manager", "npm"))
        runs_by_group[key].append(run)

    all_keys = sorted(set(repos_meta) | set(prs_by_group) | set(runs_by_group))
    groups = []
    for key in all_keys:
        meta = repos_meta.get(key, {})
        groups.append(
            rollup_group(
                key[0],
                key[1],
                prs_by_group.get(key, []),
                runs_by_group.get(key, []),
                window_start,
                window_end,
                meta.get("required_jobs") or [],
                meta.get("config_intervals") or [],
                meta.get("outages") or [],
            )
        )

    enriched_prs = []
    for pr in ledger.get("target_prs") or []:
        key = (pr["repo"], pr.get("manager", "npm"))
        meta = repos_meta.get(key, {})
        pr_copy = dict(pr)
        if not pr_copy.get("required_jobs") and meta.get("required_jobs"):
            pr_copy["required_jobs"] = meta["required_jobs"]
        enriched_prs.append(pr_copy)

    total = rollup_group(
        "ALL",
        "all",
        enriched_prs,
        ledger.get("runs") or [],
        window_start,
        window_end,
        [],
        [],
        [],
    )
    return {
        "window_start": ledger.get("window_start"),
        "window_end": ledger.get("window_end"),
        "groups": groups,
        "total": total,
    }


def format_rate(rate):
    if rate is None:
        return "算出不可"
    return f"{rate * 100:.1f}%"


def render_markdown(summary):
    lines = ["### veil-tell Monthly Operations Summary", ""]
    if summary.get("window_start") or summary.get("window_end"):
        lines.append(
            f"- Window (UTC): `{summary.get('window_start') or '?'}` .. `{summary.get('window_end') or '?'}`"
        )
        lines.append("")

    lines.append(
        "| Repo | Manager | Target PRs | With Runs | Fully Eval | Partial Eval | Missing | "
        "Alerted PRs | Notif Runs (Reruns) | Display Failed | New PRs | Blocked PRs | Vol PRs | "
        "FP Reasons | Noise Reasons | Unreviewed Reasons | Tech FP Rate | Status |"
    )
    lines.append(
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | "
        "---: | ---: | ---: | ---: | ---: | ---: | "
        "---: | ---: | ---: | ---: | --- |"
    )

    rows = list(summary["groups"])
    if len(rows) > 1:
        rows.append(summary["total"])

    for row in rows:
        rev = row["displayed_reason_review"]
        by_reason = row["prs_by_reason"]
        lines.append(
            "| "
            + " | ".join(
                [
                    row["repo"],
                    row["manager"],
                    str(row["target_prs"]),
                    str(row["prs_with_runs"]),
                    str(row["prs_fully_evaluated"]),
                    str(row["prs_partially_evaluated"]),
                    str(row["prs_completely_missing"]),
                    str(row["prs_alerted"]),
                    f"{row['actual_notification_runs']} ({row['actual_notification_reruns']})",
                    str(row["display_failed_runs"]),
                    str(by_reason["new"]),
                    str(by_reason["blocked"]),
                    str(by_reason["volume"]),
                    str(rev["false_positive"]),
                    str(rev["noise_valid_observation"]),
                    str(rev["unreviewed"]),
                    format_rate(row["technical_false_positive_rate"]),
                    row["effectiveness_status"],
                ]
            )
            + " |"
        )

    total = summary["total"]
    if total["non_natural_prs"] or total["post_deadline_runs"]:
        lines.append("")
        lines.append("Separate tracking (excluded from primary natural PR counts):")
        if total["non_natural_prs"]:
            lines.append(f"- Non-natural PRs: `{json.dumps(total['non_natural_prs'], sort_keys=True)}`")
        if total["post_deadline_runs"]:
            lines.append(f"- Post-deadline runs: `{len(total['post_deadline_runs'])}`")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Roll up monthly veil-tell PR operations ledger.")
    parser.add_argument("ledger", help="Path to ledger JSON file")
    parser.add_argument("--format", choices=("markdown", "json", "both"), default="markdown")
    parser.add_argument("--out-json", default=None)
    parser.add_argument("--out-md", default=None)
    args = parser.parse_args()

    ledger = json.loads(Path(args.ledger).read_text(encoding="utf-8"))
    summary = rollup_ledger(ledger)
    md = render_markdown(summary)

    if args.out_json:
        Path(args.out_json).write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.out_md:
        Path(args.out_md).write_text(md + "\n", encoding="utf-8")

    if args.format == "markdown":
        print(md)
    elif args.format == "json":
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        print(md)
        print()
        print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
