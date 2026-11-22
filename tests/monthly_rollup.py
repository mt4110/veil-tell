"""M01 acceptance tests for scripts/monthly_rollup.py (docs/roadmap-to-1.0.md section 5)."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
ROLLUP_SCRIPT = ROOT / "scripts" / "monthly_rollup.py"


def load_rollup():
    spec = importlib.util.spec_from_file_location("monthly_rollup", ROLLUP_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MonthlyRollupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_rollup()

    def test_roadmap_acceptance_example_and_controls(self):
        # Section 5.2 canonical acceptance example:
        # 3 natural PRs: A (new + blocked, plus 1 rerun on same head, all 4 reasons unreviewed),
        # B (compared, quiet), C (not run, then rerun after deadline), plus 1 synthetic PR.
        ledger = {
            "window_start": "2026-12-01T00:00:00Z",
            "window_end": "2026-12-31T00:00:00Z",
            "repositories": [
                {
                    "repo": "mt4110/image-drop-input",
                    "manager": "npm",
                    "required_jobs": ["npm-destinations"],
                }
            ],
            "target_prs": [
                {"repo": "mt4110/image-drop-input", "pr": 101, "manager": "npm", "kind": "natural", "target_heads": ["hA"]},
                {"repo": "mt4110/image-drop-input", "pr": 102, "manager": "npm", "kind": "natural", "target_heads": ["hB"]},
                {"repo": "mt4110/image-drop-input", "pr": 103, "manager": "npm", "kind": "natural", "target_heads": ["hC"]},
                {"repo": "mt4110/image-drop-input", "pr": 104, "manager": "npm", "kind": "synthetic", "target_heads": ["hS"]},
            ],
            "runs": [
                {
                    "repo": "mt4110/image-drop-input", "pr": 101, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "hA", "checkout_sha": "m1",
                    "job_matrix": "npm-destinations", "run_id": 1, "run_attempt": 1,
                    "completed_at": "2026-12-02T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "shown",
                    "reasons": [{"kind": "new", "review": "unreviewed"}, {"kind": "blocked", "review": "unreviewed"}],
                },
                {
                    "repo": "mt4110/image-drop-input", "pr": 101, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "hA", "checkout_sha": "m1",
                    "job_matrix": "npm-destinations", "run_id": 1, "run_attempt": 2,
                    "completed_at": "2026-12-02T01:00:00Z",
                    "status": "evaluated", "summary_displayed": "shown",
                    "reasons": [{"kind": "new", "review": "unreviewed"}, {"kind": "blocked", "review": "unreviewed"}],
                },
                {
                    "repo": "mt4110/image-drop-input", "pr": 102, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "hB", "checkout_sha": "m2",
                    "job_matrix": "npm-destinations", "run_id": 2, "run_attempt": 1,
                    "completed_at": "2026-12-03T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "none",
                    "reasons": [],
                },
                {
                    "repo": "mt4110/image-drop-input", "pr": 104, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "hS", "checkout_sha": "mS",
                    "job_matrix": "npm-destinations", "run_id": 3, "run_attempt": 1,
                    "completed_at": "2026-12-04T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "shown",
                    "reasons": [{"kind": "new", "review": "actionable_true_positive"}],
                },
                # Post-deadline rerun for PR 103 must not change primary completely_missing count
                {
                    "repo": "mt4110/image-drop-input", "pr": 103, "manager": "npm",
                    "base_sha": "b2", "pr_head_sha": "hC", "checkout_sha": "m3",
                    "job_matrix": "npm-destinations", "run_id": 4, "run_attempt": 1,
                    "completed_at": "2027-01-01T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "none",
                    "reasons": [],
                },
            ],
        }
        res = self.mod.rollup_ledger(ledger)
        row = res["groups"][0]
        self.assertEqual(row["target_prs"], 3)
        self.assertEqual(row["prs_with_runs"], 2)
        self.assertEqual(row["prs_fully_evaluated"], 2)
        self.assertEqual(row["prs_completely_missing"], 1)
        self.assertEqual(row["prs_alerted"], 1)
        self.assertEqual(row["actual_notification_runs"], 2)
        self.assertEqual(row["actual_notification_reruns"], 1)
        self.assertEqual(row["prs_by_reason"]["new"], 1)
        self.assertEqual(row["prs_by_reason"]["blocked"], 1)
        self.assertEqual(row["prs_with_unreviewed"], 1)
        self.assertEqual(row["runs_with_unreviewed"], 2)
        self.assertEqual(row["displayed_reason_review"]["unreviewed"], 4)
        self.assertIsNone(row["technical_false_positive_rate"])
        self.assertEqual(row["non_natural_prs"], {"synthetic": 1})
        self.assertEqual(len(row["post_deadline_runs"]), 1)

    def test_display_failure_and_interrupted_run_and_base_change(self):
        ledger = {
            "window_start": "2026-12-01T00:00:00Z",
            "window_end": "2026-12-31T00:00:00Z",
            "repositories": [{"repo": "mt4110/prompt-recipe", "manager": "npm", "required_jobs": ["check"]}],
            "target_prs": [
                {"repo": "mt4110/prompt-recipe", "pr": 10, "manager": "npm", "kind": "natural", "target_heads": ["h10"]},
                {"repo": "mt4110/prompt-recipe", "pr": 11, "manager": "npm", "kind": "natural", "target_heads": ["h11"]},
            ],
            "runs": [
                # Control 1: JSON has blocked=1, summary failed, interrupted -> recorded=1, display_failed=1, actual_notification=0, quiet=0
                {
                    "repo": "mt4110/prompt-recipe", "pr": 10, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "h10", "checkout_sha": "m1",
                    "job_matrix": "check", "run_id": 10, "run_attempt": 1,
                    "completed_at": "2026-12-05T00:00:00Z",
                    "status": "interrupted_with_findings", "summary_displayed": "failed",
                    "reasons": [{"kind": "blocked", "review": "actionable_true_positive"}],
                },
                # Control 2: Same pr_head_sha h11, different base_sha (b1 vs b2) -> NOT a rerun!
                {
                    "repo": "mt4110/prompt-recipe", "pr": 11, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "h11", "checkout_sha": "m2",
                    "job_matrix": "check", "run_id": 11, "run_attempt": 1,
                    "completed_at": "2026-12-06T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "shown",
                    "reasons": [{"kind": "new", "review": "actionable_true_positive"}],
                },
                {
                    "repo": "mt4110/prompt-recipe", "pr": 11, "manager": "npm",
                    "base_sha": "b2", "pr_head_sha": "h11", "checkout_sha": "m3",
                    "job_matrix": "check", "run_id": 12, "run_attempt": 1,
                    "completed_at": "2026-12-06T01:00:00Z",
                    "status": "evaluated", "summary_displayed": "shown",
                    "reasons": [{"kind": "new", "review": "false_positive"}],
                },
            ],
        }
        row = self.mod.rollup_ledger(ledger)["groups"][0]
        self.assertEqual(row["recorded_finding_runs"], 3)
        self.assertEqual(row["display_failed_runs"], 1)
        self.assertEqual(row["actual_notification_runs"], 2)
        self.assertEqual(row["actual_notification_reruns"], 0)
        self.assertEqual(row["quiet_evaluatable_runs"], 0)
        self.assertEqual(row["prs_fully_evaluated"], 1)
        self.assertEqual(row["prs_completely_missing"], 1)
        self.assertEqual(row["prs_with_false_positive"], 1)
        self.assertAlmostEqual(row["technical_false_positive_rate"], 0.5)

    def test_noise_separate_from_fp_and_zero_updates_and_cli(self):
        ledger = {
            "window_start": "2026-12-01T00:00:00Z",
            "window_end": "2026-12-31T00:00:00Z",
            "repositories": [
                {"repo": "mt4110/quiet-repo", "manager": "cargo", "required_jobs": ["check"]},
                {"repo": "mt4110/noise-repo", "manager": "npm", "required_jobs": ["a", "b"]},
            ],
            "target_prs": [
                {"repo": "mt4110/noise-repo", "pr": 1, "manager": "npm", "kind": "natural", "target_heads": ["h1"]},
            ],
            "runs": [
                {
                    "repo": "mt4110/noise-repo", "pr": 1, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "h1", "checkout_sha": "m1",
                    "job_matrix": "a", "run_id": 20, "run_attempt": 1,
                    "completed_at": "2026-12-10T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "shown",
                    "reasons": [
                        {"kind": "new", "review": "noise_valid_observation"},
                        {"kind": "volume", "review": "actionable_true_positive"},
                    ],
                    "raw_log": "SECRET_PRIVATE_HOSTNAME",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            ledger_file = td / "ledger.json"
            out_json = td / "out.json"
            out_md = td / "out.md"
            ledger_file.write_text(json.dumps(ledger), encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    str(ROLLUP_SCRIPT),
                    str(ledger_file),
                    "--format",
                    "both",
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            summary = json.loads(out_json.read_text(encoding="utf-8"))
            md_text = out_md.read_text(encoding="utf-8")
            self.assertNotIn("SECRET_PRIVATE_HOSTNAME", out_json.read_text(encoding="utf-8"))
            self.assertNotIn("SECRET_PRIVATE_HOSTNAME", md_text)
            cargo_row = next(g for g in summary["groups"] if g["repo"] == "mt4110/quiet-repo")
            npm_row = next(g for g in summary["groups"] if g["repo"] == "mt4110/noise-repo")
            self.assertEqual(cargo_row["effectiveness_status"], "pending_zero_updates")
            self.assertEqual(npm_row["prs_partially_evaluated"], 1)
            self.assertEqual(npm_row["effectiveness_status"], "partial_or_pending_review")
            self.assertEqual(npm_row["prs_with_noise"], 1)
            self.assertEqual(npm_row["displayed_reason_review"]["false_positive"], 0)
            self.assertEqual(npm_row["technical_false_positive_rate"], 0.0)

    def test_half_open_window_boundaries_partial_status_and_multi_manager_pr(self):
        # 1. Half-open window [window_start, window_end):
        #    runs < window_start -> pre_window_runs
        #    runs == window_end -> post_deadline_runs
        # 2. Same PR (#50) updates both npm and cargo:
        #    npm runs & alerts, cargo does not run -> total.target_prs=1, total.prs_alerted=1,
        #    total.prs_partially_evaluated=1, effectiveness_status="partial_or_pending_review"
        ledger = {
            "window_start": "2026-12-01T00:00:00Z",
            "window_end": "2026-12-31T00:00:00Z",
            "repositories": [
                {"repo": "mt4110/veil-tell", "manager": "npm", "required_jobs": ["npm-check"]},
                {"repo": "mt4110/veil-tell", "manager": "cargo", "required_jobs": ["cargo-check"]},
            ],
            "target_prs": [
                {"repo": "mt4110/veil-tell", "pr": 50, "manager": "npm", "kind": "natural", "target_heads": ["h50"]},
                {"repo": "mt4110/veil-tell", "pr": 50, "manager": "cargo", "kind": "natural", "target_heads": ["h50"]},
            ],
            "runs": [
                # Before window_start -> excluded from primary counts
                {
                    "repo": "mt4110/veil-tell", "pr": 50, "manager": "cargo",
                    "base_sha": "b0", "pr_head_sha": "h50", "checkout_sha": "m0",
                    "job_matrix": "cargo-check", "run_id": 1, "run_attempt": 1,
                    "completed_at": "2026-11-30T23:59:59Z",
                    "status": "evaluated", "summary_displayed": "none",
                    "reasons": [],
                },
                # Exactly at window_start -> included
                {
                    "repo": "mt4110/veil-tell", "pr": 50, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "h50", "checkout_sha": "m1",
                    "job_matrix": "npm-check", "run_id": 2, "run_attempt": 1,
                    "completed_at": "2026-12-01T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "shown",
                    "reasons": [{"kind": "new", "review": "actionable_true_positive"}],
                },
                # Exactly at window_end -> excluded (half-open interval)
                {
                    "repo": "mt4110/veil-tell", "pr": 50, "manager": "cargo",
                    "base_sha": "b1", "pr_head_sha": "h50", "checkout_sha": "m1",
                    "job_matrix": "cargo-check", "run_id": 3, "run_attempt": 1,
                    "completed_at": "2026-12-31T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "none",
                    "reasons": [],
                },
            ],
        }
        res = self.mod.rollup_ledger(ledger)
        cargo_grp = next(g for g in res["groups"] if g["manager"] == "cargo")
        npm_grp = next(g for g in res["groups"] if g["manager"] == "npm")
        total = res["total"]

        self.assertEqual(len(cargo_grp["pre_window_runs"]), 1)
        self.assertEqual(len(cargo_grp["post_deadline_runs"]), 1)
        self.assertEqual(cargo_grp["prs_completely_missing"], 1)
        self.assertEqual(npm_grp["prs_fully_evaluated"], 1)
        self.assertEqual(npm_grp["effectiveness_status"], "ready")

        self.assertEqual(total["target_prs"], 1)
        self.assertEqual(total["prs_alerted"], 1)
        self.assertEqual(total["prs_fully_evaluated"], 0)
        self.assertEqual(total["prs_partially_evaluated"], 1)
        self.assertEqual(total["prs_completely_missing"], 0)
        self.assertEqual(total["effectiveness_status"], "partial_or_pending_review")

    def test_unregistered_target_heads_excluded_and_base_checkout_preserved_in_coverage(self):
        # 1. PR 70 registers target_heads=["h2"] only, while runs only contain head "h1"
        #    with an evaluated, notifying run -> must be excluded from primary aggregation:
        #    prs_with_runs=0, prs_alerted=0, prs_completely_missing=1, unregistered_target_runs=1.
        # 2. PR 71 registers target_heads=["h1"] and runs against two bases:
        #    (b1, h1, checkout1) is evaluated, while (b2, h1, checkout2) is cancelled ->
        #    coverage must preserve base/checkout identity and report prs_partially_evaluated=1,
        #    effectiveness_status="partial_or_pending_review" (not ready).
        ledger = {
            "window_start": "2026-12-01T00:00:00Z",
            "window_end": "2026-12-31T00:00:00Z",
            "repositories": [
                {"repo": "mt4110/veil-tell", "manager": "npm", "required_jobs": ["check"]},
            ],
            "target_prs": [
                {"repo": "mt4110/veil-tell", "pr": 70, "manager": "npm", "kind": "natural", "target_heads": ["h2"]},
                {"repo": "mt4110/veil-tell", "pr": 71, "manager": "npm", "kind": "natural", "target_heads": ["h1"]},
            ],
            "runs": [
                # Unregistered head h1 for PR 70 (target_heads=["h2"])
                {
                    "repo": "mt4110/veil-tell", "pr": 70, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "h1", "checkout_sha": "c1",
                    "job_matrix": "check", "run_id": 700, "run_attempt": 1,
                    "completed_at": "2026-12-05T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "shown",
                    "reasons": [{"kind": "new", "review": "actionable_true_positive"}],
                },
                # Registered head h1 for PR 71 on (b1, h1, c1) -> evaluated
                {
                    "repo": "mt4110/veil-tell", "pr": 71, "manager": "npm",
                    "base_sha": "b1", "pr_head_sha": "h1", "checkout_sha": "c1",
                    "job_matrix": "check", "run_id": 710, "run_attempt": 1,
                    "completed_at": "2026-12-06T00:00:00Z",
                    "status": "evaluated", "summary_displayed": "none",
                    "reasons": [],
                },
                # Same head h1 for PR 71 on updated base (b2, h1, c2) -> cancelled (incomplete)
                {
                    "repo": "mt4110/veil-tell", "pr": 71, "manager": "npm",
                    "base_sha": "b2", "pr_head_sha": "h1", "checkout_sha": "c2",
                    "job_matrix": "check", "run_id": 711, "run_attempt": 1,
                    "completed_at": "2026-12-07T00:00:00Z",
                    "status": "cancelled", "summary_displayed": "none",
                    "reasons": [],
                },
            ],
        }
        row = self.mod.rollup_ledger(ledger)["groups"][0]
        self.assertEqual(row["target_prs"], 2)
        self.assertEqual(row["prs_with_runs"], 1)
        self.assertEqual(row["prs_alerted"], 0)
        self.assertEqual(row["actual_notification_runs"], 0)
        self.assertEqual(row["prs_fully_evaluated"], 0)
        self.assertEqual(row["prs_partially_evaluated"], 1)
        self.assertEqual(row["prs_completely_missing"], 1)
        self.assertEqual(len(row["unregistered_target_runs"]), 1)
        self.assertEqual(row["effectiveness_status"], "partial_or_pending_review")


if __name__ == "__main__":
    unittest.main()
