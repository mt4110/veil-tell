use super::*;
use serde_json::json;

#[test]
fn roadmap_acceptance_example_and_controls() {
    let ledger: Ledger = serde_json::from_value(json!({
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
            {
                "repo": "mt4110/image-drop-input", "pr": 103, "manager": "npm",
                "base_sha": "b2", "pr_head_sha": "hC", "checkout_sha": "m3",
                "job_matrix": "npm-destinations", "run_id": 4, "run_attempt": 1,
                "completed_at": "2027-01-01T00:00:00Z",
                "status": "evaluated", "summary_displayed": "none",
                "reasons": [],
            },
        ]
    }))
    .unwrap();

    let res = rollup_ledger(&ledger);
    let row = &res.groups[0];
    assert_eq!(row.target_prs, 3);
    assert_eq!(row.prs_with_runs, 2);
    assert_eq!(row.prs_fully_evaluated, 2);
    assert_eq!(row.prs_completely_missing, 1);
    assert_eq!(row.prs_alerted, 1);
    assert_eq!(row.actual_notification_runs, 2);
    assert_eq!(row.actual_notification_reruns, 1);
    assert_eq!(row.prs_by_reason["new"], 1);
    assert_eq!(row.prs_by_reason["blocked"], 1);
    assert_eq!(row.prs_with_unreviewed, 1);
    assert_eq!(row.runs_with_unreviewed, 2);
    assert_eq!(row.displayed_reason_review["unreviewed"], 4);
    assert!(row.technical_false_positive_rate.is_none());
    assert_eq!(row.non_natural_prs.get("synthetic"), Some(&1));
    assert_eq!(row.post_deadline_runs.len(), 1);
}

#[test]
fn display_failure_and_interrupted_run_and_base_change() {
    let ledger: Ledger = serde_json::from_value(json!({
        "window_start": "2026-12-01T00:00:00Z",
        "window_end": "2026-12-31T00:00:00Z",
        "repositories": [{"repo": "mt4110/prompt-recipe", "manager": "npm", "required_jobs": ["check"]}],
        "target_prs": [
            {"repo": "mt4110/prompt-recipe", "pr": 10, "manager": "npm", "kind": "natural", "target_heads": ["h10"]},
            {"repo": "mt4110/prompt-recipe", "pr": 11, "manager": "npm", "kind": "natural", "target_heads": ["h11"]},
        ],
        "runs": [
            {
                "repo": "mt4110/prompt-recipe", "pr": 10, "manager": "npm",
                "base_sha": "b1", "pr_head_sha": "h10", "checkout_sha": "m1",
                "job_matrix": "check", "run_id": 10, "run_attempt": 1,
                "completed_at": "2026-12-05T00:00:00Z",
                "status": "interrupted_with_findings", "summary_displayed": "failed",
                "reasons": [{"kind": "blocked", "review": "actionable_true_positive"}],
            },
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
        ]
    }))
    .unwrap();

    let row = &rollup_ledger(&ledger).groups[0];
    assert_eq!(row.recorded_finding_runs, 3);
    assert_eq!(row.display_failed_runs, 1);
    assert_eq!(row.actual_notification_runs, 2);
    assert_eq!(row.actual_notification_reruns, 0);
    assert_eq!(row.quiet_evaluatable_runs, 0);
    assert_eq!(row.prs_fully_evaluated, 1);
    assert_eq!(row.prs_completely_missing, 1);
    assert_eq!(row.prs_with_false_positive, 1);
    assert_eq!(row.technical_false_positive_rate, Some(0.5));
}

#[test]
fn noise_separate_from_fp_and_zero_updates_and_no_leak() {
    let raw = json!({
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
        ]
    });
    let ledger: Ledger = serde_json::from_value(raw).unwrap();
    let summary = rollup_ledger(&ledger);
    let md_text = render_markdown(&summary);
    let json_text = serde_json::to_string(&summary).unwrap();
    assert!(!json_text.contains("SECRET_PRIVATE_HOSTNAME"));
    assert!(!md_text.contains("SECRET_PRIVATE_HOSTNAME"));

    let cargo_row = summary
        .groups
        .iter()
        .find(|g| g.repo == "mt4110/quiet-repo")
        .unwrap();
    let npm_row = summary
        .groups
        .iter()
        .find(|g| g.repo == "mt4110/noise-repo")
        .unwrap();
    assert_eq!(cargo_row.effectiveness_status, "pending_zero_updates");
    assert_eq!(npm_row.prs_partially_evaluated, 1);
    assert_eq!(npm_row.effectiveness_status, "partial_or_pending_review");
    assert_eq!(npm_row.prs_with_noise, 1);
    assert_eq!(npm_row.displayed_reason_review["false_positive"], 0);
    assert_eq!(npm_row.technical_false_positive_rate, Some(0.0));
}

#[test]
fn half_open_window_boundaries_partial_status_and_multi_manager_pr() {
    let ledger: Ledger = serde_json::from_value(json!({
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
            {
                "repo": "mt4110/veil-tell", "pr": 50, "manager": "cargo",
                "base_sha": "b0", "pr_head_sha": "h50", "checkout_sha": "m0",
                "job_matrix": "cargo-check", "run_id": 1, "run_attempt": 1,
                "completed_at": "2026-11-30T23:59:59Z",
                "status": "evaluated", "summary_displayed": "none",
                "reasons": [],
            },
            {
                "repo": "mt4110/veil-tell", "pr": 50, "manager": "npm",
                "base_sha": "b1", "pr_head_sha": "h50", "checkout_sha": "m1",
                "job_matrix": "npm-check", "run_id": 2, "run_attempt": 1,
                "completed_at": "2026-12-01T00:00:00Z",
                "status": "evaluated", "summary_displayed": "shown",
                "reasons": [{"kind": "new", "review": "actionable_true_positive"}],
            },
            {
                "repo": "mt4110/veil-tell", "pr": 50, "manager": "cargo",
                "base_sha": "b1", "pr_head_sha": "h50", "checkout_sha": "m1",
                "job_matrix": "cargo-check", "run_id": 3, "run_attempt": 1,
                "completed_at": "2026-12-31T00:00:00Z",
                "status": "evaluated", "summary_displayed": "none",
                "reasons": [],
            },
        ]
    }))
    .unwrap();

    let res = rollup_ledger(&ledger);
    let cargo_grp = res.groups.iter().find(|g| g.manager == "cargo").unwrap();
    let npm_grp = res.groups.iter().find(|g| g.manager == "npm").unwrap();
    let total = &res.total;

    assert_eq!(cargo_grp.pre_window_runs.len(), 1);
    assert_eq!(cargo_grp.post_deadline_runs.len(), 1);
    assert_eq!(cargo_grp.prs_completely_missing, 1);
    assert_eq!(npm_grp.prs_fully_evaluated, 1);
    assert_eq!(npm_grp.effectiveness_status, "ready");

    assert_eq!(total.target_prs, 1);
    assert_eq!(total.prs_alerted, 1);
    assert_eq!(total.prs_fully_evaluated, 0);
    assert_eq!(total.prs_partially_evaluated, 1);
    assert_eq!(total.prs_completely_missing, 0);
    assert_eq!(total.effectiveness_status, "partial_or_pending_review");
}

#[test]
fn unregistered_target_heads_excluded_and_base_checkout_preserved_in_coverage() {
    let ledger: Ledger = serde_json::from_value(json!({
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
            {
                "repo": "mt4110/veil-tell", "pr": 70, "manager": "npm",
                "base_sha": "b1", "pr_head_sha": "h1", "checkout_sha": "c1",
                "job_matrix": "check", "run_id": 700, "run_attempt": 1,
                "completed_at": "2026-12-05T00:00:00Z",
                "status": "evaluated", "summary_displayed": "shown",
                "reasons": [{"kind": "new", "review": "actionable_true_positive"}],
            },
            {
                "repo": "mt4110/veil-tell", "pr": 71, "manager": "npm",
                "base_sha": "b1", "pr_head_sha": "h1", "checkout_sha": "c1",
                "job_matrix": "check", "run_id": 710, "run_attempt": 1,
                "completed_at": "2026-12-06T00:00:00Z",
                "status": "evaluated", "summary_displayed": "none",
                "reasons": [],
            },
            {
                "repo": "mt4110/veil-tell", "pr": 71, "manager": "npm",
                "base_sha": "b2", "pr_head_sha": "h1", "checkout_sha": "c2",
                "job_matrix": "check", "run_id": 711, "run_attempt": 1,
                "completed_at": "2026-12-07T00:00:00Z",
                "status": "cancelled", "summary_displayed": "none",
                "reasons": [],
            },
        ]
    }))
    .unwrap();

    let row = &rollup_ledger(&ledger).groups[0];
    assert_eq!(row.target_prs, 2);
    assert_eq!(row.prs_with_runs, 1);
    assert_eq!(row.prs_alerted, 0);
    assert_eq!(row.actual_notification_runs, 0);
    assert_eq!(row.prs_fully_evaluated, 0);
    assert_eq!(row.prs_partially_evaluated, 1);
    assert_eq!(row.prs_completely_missing, 1);
    assert_eq!(row.unregistered_target_runs.len(), 1);
    assert_eq!(row.effectiveness_status, "partial_or_pending_review");
}
