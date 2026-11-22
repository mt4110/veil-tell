//! Monthly operations rollup tool (M01) for veil-tell.
//!
//! Aggregates 30-day UTC dependency update PR observations according to
//! docs/roadmap-to-1.0.md section 5 without leaking sensitive fields (argv, cwd,
//! raw logs, or private hostnames).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[path = "rollup_types.rs"]
mod types;
pub use types::{
    ALERT_KINDS, ExcludedRunRef, GroupRollup, Ledger, LedgerRun, REVIEW_CLASSES, ReasonReview,
    RepositoryMeta, RollupSummary, TargetPrEntry, TargetRevision, empty_kind_counts,
    empty_review_counts, parse_utc, run_matches_entry,
};

#[path = "rollup_view.rs"]
mod view;
pub use view::{render_markdown, run};

#[allow(clippy::too_many_arguments)]
pub fn rollup_group(
    repo_key: &str,
    manager_key: &str,
    prs: &[TargetPrEntry],
    runs: &[LedgerRun],
    window_start_raw: Option<&str>,
    window_end_raw: Option<&str>,
    required_jobs: &[String],
    config_intervals: Vec<Value>,
    outages: Vec<Value>,
) -> GroupRollup {
    let default_mgr = if manager_key == "all" {
        "npm"
    } else {
        manager_key
    };
    let window_start = parse_utc(window_start_raw);
    let window_end = parse_utc(window_end_raw);

    let mut natural_entries_by_pr: BTreeMap<(String, u64), Vec<TargetPrEntry>> = BTreeMap::new();
    let mut seen_non_natural_prs: BTreeSet<(String, u64, String)> = BTreeSet::new();
    let mut non_natural_counts: BTreeMap<String, usize> = BTreeMap::new();

    for entry in prs {
        let kind = if entry.kind.is_empty() {
            "natural"
        } else {
            entry.kind.as_str()
        };
        if kind == "natural" {
            natural_entries_by_pr
                .entry((entry.repo.clone(), entry.pr))
                .or_default()
                .push(entry.clone());
        } else {
            let unique_key = (entry.repo.clone(), entry.pr, kind.to_string());
            if seen_non_natural_prs.insert(unique_key) {
                *non_natural_counts.entry(kind.to_string()).or_insert(0) += 1;
            }
        }
    }

    let mut in_window_natural_runs: Vec<LedgerRun> = Vec::new();
    let mut pre_window_runs: Vec<ExcludedRunRef> = Vec::new();
    let mut post_deadline_runs: Vec<ExcludedRunRef> = Vec::new();
    let mut unregistered_target_runs: Vec<ExcludedRunRef> = Vec::new();
    let mut non_natural_runs_count = 0usize;

    for run in runs {
        let pr_id = (run.repo.clone(), run.pr);
        let Some(entries_for_pr) = natural_entries_by_pr.get(&pr_id) else {
            non_natural_runs_count += 1;
            continue;
        };
        if !entries_for_pr
            .iter()
            .any(|entry| run_matches_entry(run, entry, default_mgr))
        {
            unregistered_target_runs.push(ExcludedRunRef {
                repo: run.repo.clone(),
                pr: run.pr,
                manager: Some(if run.manager.is_empty() {
                    default_mgr.to_string()
                } else {
                    run.manager.clone()
                }),
                base_sha: run.base_sha.clone(),
                pr_head_sha: run.pr_head_sha.clone(),
                checkout_sha: run.checkout_sha.clone(),
                job_matrix: run.job_matrix.clone(),
                run_id: run.run_id,
                run_attempt: run.run_attempt,
                completed_at: run.completed_at.clone(),
            });
            continue;
        }
        let completed = parse_utc(run.completed_at.as_deref());
        if let (Some(ws), Some(comp)) = (window_start, completed)
            && comp < ws
        {
            pre_window_runs.push(ExcludedRunRef {
                repo: run.repo.clone(),
                pr: run.pr,
                manager: None,
                base_sha: None,
                pr_head_sha: run.pr_head_sha.clone(),
                checkout_sha: None,
                job_matrix: run.job_matrix.clone(),
                run_id: run.run_id,
                run_attempt: run.run_attempt,
                completed_at: run.completed_at.clone(),
            });
            continue;
        }
        if let (Some(we), Some(comp)) = (window_end, completed)
            && comp >= we
        {
            post_deadline_runs.push(ExcludedRunRef {
                repo: run.repo.clone(),
                pr: run.pr,
                manager: None,
                base_sha: None,
                pr_head_sha: run.pr_head_sha.clone(),
                checkout_sha: None,
                job_matrix: run.job_matrix.clone(),
                run_id: run.run_id,
                run_attempt: run.run_attempt,
                completed_at: run.completed_at.clone(),
            });
            continue;
        }
        let mut accepted_run = run.clone();
        if (window_start.is_some() || window_end.is_some())
            && completed.is_none()
            && matches!(accepted_run.status.as_str(), "" | "evaluated")
        {
            // When an observation window is active, a run without a valid completion
            // timestamp has no proof of in-window completion and cannot establish
            // completed evaluation coverage.
            accepted_run.status = "undated".to_string();
        }
        in_window_natural_runs.push(accepted_run);
    }

    in_window_natural_runs.sort_by(|a, b| {
        (
            &a.repo,
            a.pr,
            &a.manager,
            a.base_sha.as_deref().unwrap_or(""),
            a.pr_head_sha.as_deref().unwrap_or(""),
            a.checkout_sha.as_deref().unwrap_or(""),
            a.job_matrix.as_deref().unwrap_or(""),
            a.completed_at.as_deref().unwrap_or(""),
            a.run_id.unwrap_or(0),
            a.run_attempt.unwrap_or(0),
        )
            .cmp(&(
                &b.repo,
                b.pr,
                &b.manager,
                b.base_sha.as_deref().unwrap_or(""),
                b.pr_head_sha.as_deref().unwrap_or(""),
                b.checkout_sha.as_deref().unwrap_or(""),
                b.job_matrix.as_deref().unwrap_or(""),
                b.completed_at.as_deref().unwrap_or(""),
                b.run_id.unwrap_or(0),
                b.run_attempt.unwrap_or(0),
            ))
    });

    let mut seen_exam_keys = BTreeSet::new();
    let mut runs_by_pr: BTreeMap<(String, u64), Vec<LedgerRun>> = BTreeMap::new();

    let mut runs_with_execution = 0usize;
    let mut quiet_evaluatable_runs = 0usize;
    let mut recorded_finding_runs = 0usize;
    let mut actual_notification_runs = 0usize;
    let mut actual_notification_reruns = 0usize;
    let mut display_failed_runs = 0usize;
    let mut display_unverified_runs = 0usize;

    let mut recorded_reason_counts = empty_kind_counts();
    let mut displayed_reason_review = empty_review_counts();
    let mut recorded_reason_review = empty_review_counts();
    let mut runs_with_unreviewed = 0usize;
    let mut runs_with_false_positive = 0usize;
    let mut runs_with_missed_confirmed = 0usize;

    for run in &in_window_natural_runs {
        let pr_id = (run.repo.clone(), run.pr);
        runs_by_pr.entry(pr_id).or_default().push(run.clone());

        let status = if run.status.is_empty() {
            "evaluated"
        } else {
            run.status.as_str()
        };
        let is_rerun = if status != "not_run" {
            runs_with_execution += 1;
            let exam_key = (
                run.repo.clone(),
                run.pr,
                if run.manager.is_empty() {
                    default_mgr.to_string()
                } else {
                    run.manager.clone()
                },
                run.base_sha.clone().unwrap_or_default(),
                run.pr_head_sha.clone().unwrap_or_default(),
                run.checkout_sha.clone().unwrap_or_default(),
                run.job_matrix.clone().unwrap_or_default(),
            );
            !seen_exam_keys.insert(exam_key)
        } else {
            false
        };

        let summary_displayed = if run.summary_displayed.is_empty() {
            "none"
        } else {
            run.summary_displayed.as_str()
        };

        if status == "evaluated" && run.reasons.is_empty() {
            quiet_evaluatable_runs += 1;
        }
        if run.missed_confirmed {
            runs_with_missed_confirmed += 1;
        }

        if !run.reasons.is_empty() {
            recorded_finding_runs += 1;
            for item in &run.reasons {
                if let Some(slot) = recorded_reason_counts.get_mut(&item.kind) {
                    *slot += 1;
                }
                let review_key = if recorded_reason_review.contains_key(&item.review) {
                    item.review.as_str()
                } else {
                    "unreviewed"
                };
                *recorded_reason_review.get_mut(review_key).unwrap() += 1;
            }

            if summary_displayed == "shown" {
                actual_notification_runs += 1;
                if is_rerun {
                    actual_notification_reruns += 1;
                }
                let mut has_unrev = false;
                let mut has_fp = false;
                for item in &run.reasons {
                    let review_key = if displayed_reason_review.contains_key(&item.review) {
                        item.review.as_str()
                    } else {
                        "unreviewed"
                    };
                    *displayed_reason_review.get_mut(review_key).unwrap() += 1;
                    if review_key == "unreviewed" {
                        has_unrev = true;
                    }
                    if review_key == "false_positive" {
                        has_fp = true;
                    }
                }
                if has_unrev {
                    runs_with_unreviewed += 1;
                }
                if has_fp {
                    runs_with_false_positive += 1;
                }
            } else if summary_displayed == "failed" {
                display_failed_runs += 1;
            } else if summary_displayed == "unverified" {
                display_unverified_runs += 1;
            }
        }
    }

    let mut prs_with_runs = 0usize;
    let mut prs_fully_evaluated = 0usize;
    let mut prs_partially_evaluated = 0usize;
    let mut prs_completely_missing = 0usize;
    let mut prs_alerted = 0usize;
    let mut prs_by_reason = empty_kind_counts();
    let mut prs_with_false_positive = 0usize;
    let mut prs_with_noise = 0usize;
    let mut prs_with_unreviewed = 0usize;
    let mut prs_with_missed_confirmed = 0usize;

    for (pr_id, pr_entries) in &natural_entries_by_pr {
        let empty_runs = Vec::new();
        let pr_runs = runs_by_pr.get(pr_id).unwrap_or(&empty_runs);
        let has_executed = pr_runs.iter().any(|r| {
            let st = if r.status.is_empty() {
                "evaluated"
            } else {
                r.status.as_str()
            };
            st != "not_run"
        });
        if has_executed {
            prs_with_runs += 1;
        }

        let mut expected_targets: BTreeSet<(
            String,
            Option<String>,
            String,
            Option<String>,
            String,
        )> = BTreeSet::new();
        let mut evaluated_targets: BTreeSet<(String, String, String, String, String)> =
            BTreeSet::new();

        for entry in pr_entries {
            let mgr = if entry.manager.is_empty() {
                default_mgr.to_string()
            } else {
                entry.manager.clone()
            };
            let entry_runs: Vec<&LedgerRun> = pr_runs
                .iter()
                .filter(|r| run_matches_entry(r, entry, default_mgr))
                .collect();

            let target_heads: Vec<String> = if !entry.target_heads.is_empty() {
                entry.target_heads.clone()
            } else {
                let heads: BTreeSet<String> = entry_runs
                    .iter()
                    .filter_map(|r| r.pr_head_sha.clone())
                    .filter(|h| !h.is_empty())
                    .collect();
                if heads.is_empty() {
                    vec!["(unknown-head)".to_string()]
                } else {
                    heads.into_iter().collect()
                }
            };

            let jobs: Vec<String> = if !entry.required_jobs.is_empty() {
                entry.required_jobs.clone()
            } else if !required_jobs.is_empty() {
                required_jobs.to_vec()
            } else {
                let observed_jobs: BTreeSet<String> = entry_runs
                    .iter()
                    .map(|r| {
                        r.job_matrix
                            .clone()
                            .unwrap_or_else(|| "default".to_string())
                    })
                    .collect();
                if observed_jobs.is_empty() {
                    vec!["default".to_string()]
                } else {
                    observed_jobs.into_iter().collect()
                }
            };

            let mut expected_revisions: BTreeSet<(Option<String>, String, Option<String>)> =
                BTreeSet::new();
            for rev in &entry.target_revisions {
                let head = rev.pr_head_sha.as_ref().or(rev.head_sha.as_ref());
                let base = rev.base_sha.as_ref().or(entry.base_sha.as_ref());
                let checkout = rev.checkout_sha.as_ref().or(entry.checkout_sha.as_ref());
                for head in head.map(std::slice::from_ref).unwrap_or(&target_heads) {
                    expected_revisions.insert((base.cloned(), head.clone(), checkout.cloned()));
                }
            }

            for h in &target_heads {
                let head_runs: Vec<&&LedgerRun> = entry_runs
                    .iter()
                    .filter(|r| {
                        r.status != "not_run"
                            && r.pr_head_sha.as_deref().unwrap_or(target_heads[0].as_str())
                                == h.as_str()
                    })
                    .collect();
                for r in &head_runs {
                    expected_revisions.insert((
                        Some(r.base_sha.clone().unwrap_or_default()),
                        h.clone(),
                        Some(r.checkout_sha.clone().unwrap_or_default()),
                    ));
                }
                if head_runs.is_empty() && !expected_revisions.iter().any(|rev| &rev.1 == h) {
                    expected_revisions.insert((
                        entry.base_sha.clone(),
                        h.clone(),
                        entry.checkout_sha.clone(),
                    ));
                }
            }

            for (base_pat, head_sha, checkout_pat) in expected_revisions {
                for j in &jobs {
                    expected_targets.insert((
                        mgr.clone(),
                        base_pat.clone(),
                        head_sha.clone(),
                        checkout_pat.clone(),
                        j.clone(),
                    ));
                }
            }

            for r in entry_runs {
                let st = if r.status.is_empty() {
                    "evaluated"
                } else {
                    r.status.as_str()
                };
                if st == "evaluated" {
                    evaluated_targets.insert((
                        mgr.clone(),
                        r.base_sha.clone().unwrap_or_default(),
                        r.pr_head_sha
                            .clone()
                            .unwrap_or_else(|| target_heads[0].clone()),
                        r.checkout_sha.clone().unwrap_or_default(),
                        r.job_matrix
                            .clone()
                            .unwrap_or_else(|| "default".to_string()),
                    ));
                }
            }
        }

        let all_expected_satisfied = !expected_targets.is_empty()
            && expected_targets
                .iter()
                .all(|(mgr, base_pat, head_sha, checkout_pat, job)| {
                    evaluated_targets.iter().any(|(em, eb, eh, ec, ej)| {
                        em == mgr
                            && eh == head_sha
                            && ej == job
                            && base_pat.as_deref().is_none_or(|b| b == eb)
                            && checkout_pat.as_deref().is_none_or(|c| c == ec)
                    })
                });

        if all_expected_satisfied {
            prs_fully_evaluated += 1;
        } else if !evaluated_targets.is_empty() {
            prs_partially_evaluated += 1;
        } else {
            prs_completely_missing += 1;
        }

        let notified = pr_runs
            .iter()
            .any(|r| !r.reasons.is_empty() && r.summary_displayed == "shown");
        if notified {
            prs_alerted += 1;
        }

        let mut pr_kinds = BTreeSet::new();
        let mut pr_has_fp = false;
        let mut pr_has_noise = false;
        let mut pr_has_unrev = false;
        let mut pr_missed = false;

        for r in pr_runs {
            if r.missed_confirmed {
                pr_missed = true;
            }
            if r.summary_displayed == "shown" {
                for item in &r.reasons {
                    if ALERT_KINDS.contains(&item.kind.as_str()) {
                        pr_kinds.insert(item.kind.clone());
                    }
                    match item.review.as_str() {
                        "false_positive" => pr_has_fp = true,
                        "noise_valid_observation" => pr_has_noise = true,
                        "actionable_true_positive" => {}
                        _ => pr_has_unrev = true,
                    }
                }
            }
        }

        for kind in pr_kinds {
            if let Some(slot) = prs_by_reason.get_mut(&kind) {
                *slot += 1;
            }
        }
        if pr_has_fp {
            prs_with_false_positive += 1;
        }
        if pr_has_noise {
            prs_with_noise += 1;
        }
        if pr_has_unrev {
            prs_with_unreviewed += 1;
        }
        if pr_missed {
            prs_with_missed_confirmed += 1;
        }
    }

    let reviewed_reasons_total = displayed_reason_review["actionable_true_positive"]
        + displayed_reason_review["noise_valid_observation"]
        + displayed_reason_review["false_positive"];
    let fp_rate = if reviewed_reasons_total > 0 {
        Some(displayed_reason_review["false_positive"] as f64 / reviewed_reasons_total as f64)
    } else {
        None
    };

    let target_prs_count = natural_entries_by_pr.len();
    let effectiveness_status = if target_prs_count == 0 {
        "pending_zero_updates".to_string()
    } else if prs_with_unreviewed > 0 || prs_completely_missing > 0 || prs_partially_evaluated > 0 {
        "partial_or_pending_review".to_string()
    } else {
        "ready".to_string()
    };

    GroupRollup {
        repo: repo_key.to_string(),
        manager: manager_key.to_string(),
        window_start: window_start_raw.map(str::to_string),
        window_end: window_end_raw.map(str::to_string),
        target_prs: target_prs_count,
        prs_with_runs,
        prs_fully_evaluated,
        prs_partially_evaluated,
        prs_completely_missing,
        prs_alerted,
        runs_with_execution,
        quiet_evaluatable_runs,
        recorded_finding_runs,
        actual_notification_runs,
        actual_notification_reruns,
        display_failed_runs,
        display_unverified_runs,
        prs_by_reason,
        recorded_reason_counts,
        displayed_reason_review,
        recorded_reason_review,
        reviewed_alert_reasons: reviewed_reasons_total,
        technical_false_positive_rate: fp_rate,
        runs_with_false_positive,
        runs_with_unreviewed,
        prs_with_false_positive,
        prs_with_noise,
        prs_with_unreviewed,
        runs_with_missed_confirmed,
        prs_with_missed_confirmed,
        non_natural_prs: non_natural_counts,
        non_natural_runs: non_natural_runs_count,
        pre_window_runs,
        post_deadline_runs,
        unregistered_target_runs,
        config_intervals,
        outages,
        effectiveness_status,
    }
}

pub fn rollup_ledger(ledger: &Ledger) -> RollupSummary {
    let mut repos_meta: BTreeMap<(String, String), RepositoryMeta> = BTreeMap::new();
    for item in &ledger.repositories {
        let mgr = if item.manager.is_empty() {
            "npm".to_string()
        } else {
            item.manager.clone()
        };
        repos_meta.insert((item.repo.clone(), mgr), item.clone());
    }

    let mut prs_by_group: BTreeMap<(String, String), Vec<TargetPrEntry>> = BTreeMap::new();
    for pr in &ledger.target_prs {
        let mgr = if pr.manager.is_empty() {
            "npm".to_string()
        } else {
            pr.manager.clone()
        };
        prs_by_group
            .entry((pr.repo.clone(), mgr))
            .or_default()
            .push(pr.clone());
    }

    let mut runs_by_group: BTreeMap<(String, String), Vec<LedgerRun>> = BTreeMap::new();
    for run in &ledger.runs {
        let mgr = if run.manager.is_empty() {
            "npm".to_string()
        } else {
            run.manager.clone()
        };
        runs_by_group
            .entry((run.repo.clone(), mgr))
            .or_default()
            .push(run.clone());
    }

    let mut all_keys: BTreeSet<(String, String)> = BTreeSet::new();
    all_keys.extend(repos_meta.keys().cloned());
    all_keys.extend(prs_by_group.keys().cloned());
    all_keys.extend(runs_by_group.keys().cloned());

    let mut groups = Vec::new();
    for key in all_keys {
        let meta = repos_meta.get(&key);
        let prs = prs_by_group.get(&key).map_or(&[][..], Vec::as_slice);
        let runs = runs_by_group.get(&key).map_or(&[][..], Vec::as_slice);
        let req_jobs = meta.map_or(&[][..], |m| m.required_jobs.as_slice());
        let intervals = meta.map_or_else(Vec::new, |m| m.config_intervals.clone());
        let outages = meta.map_or_else(Vec::new, |m| m.outages.clone());
        groups.push(rollup_group(
            &key.0,
            &key.1,
            prs,
            runs,
            ledger.window_start.as_deref(),
            ledger.window_end.as_deref(),
            req_jobs,
            intervals,
            outages,
        ));
    }

    let mut enriched_prs = Vec::with_capacity(ledger.target_prs.len());
    for pr in &ledger.target_prs {
        let mgr = if pr.manager.is_empty() {
            "npm".to_string()
        } else {
            pr.manager.clone()
        };
        let key = (pr.repo.clone(), mgr);
        let mut pr_copy = pr.clone();
        if pr_copy.required_jobs.is_empty()
            && let Some(meta) = repos_meta.get(&key)
            && !meta.required_jobs.is_empty()
        {
            pr_copy.required_jobs = meta.required_jobs.clone();
        }
        enriched_prs.push(pr_copy);
    }

    let total = rollup_group(
        "ALL",
        "all",
        &enriched_prs,
        &ledger.runs,
        ledger.window_start.as_deref(),
        ledger.window_end.as_deref(),
        &[],
        Vec::new(),
        Vec::new(),
    );

    RollupSummary {
        window_start: ledger.window_start.clone(),
        window_end: ledger.window_end.clone(),
        groups,
        total,
    }
}

#[cfg(test)]
#[path = "rollup_tests.rs"]
mod tests;
