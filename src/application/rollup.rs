//! Monthly operations rollup tool (M01) for veil-tell.
//!
//! Aggregates 30-day UTC dependency update PR observations according to
//! docs/roadmap-to-1.0.md section 5 without leaking sensitive fields (argv, cwd,
//! raw logs, or private hostnames).

use crate::{Result, error};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;

const ALERT_KINDS: &[&str] = &["new", "blocked", "volume"];
const REVIEW_CLASSES: &[&str] = &[
    "actionable_true_positive",
    "noise_valid_observation",
    "false_positive",
    "unreviewed",
];

fn default_npm() -> String {
    "npm".to_string()
}

fn default_natural() -> String {
    "natural".to_string()
}

fn default_evaluated() -> String {
    "evaluated".to_string()
}

fn default_none() -> String {
    "none".to_string()
}

fn default_unreviewed() -> String {
    "unreviewed".to_string()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Ledger {
    pub window_start: Option<String>,
    pub window_end: Option<String>,
    #[serde(default)]
    pub repositories: Vec<RepositoryMeta>,
    #[serde(default)]
    pub target_prs: Vec<TargetPrEntry>,
    #[serde(default)]
    pub runs: Vec<LedgerRun>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RepositoryMeta {
    pub repo: String,
    #[serde(default = "default_npm")]
    pub manager: String,
    #[serde(default)]
    pub required_jobs: Vec<String>,
    #[serde(default)]
    pub config_intervals: Vec<Value>,
    #[serde(default)]
    pub outages: Vec<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetRevision {
    pub base_sha: Option<String>,
    pub pr_head_sha: Option<String>,
    pub head_sha: Option<String>,
    pub checkout_sha: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetPrEntry {
    pub repo: String,
    pub pr: u64,
    #[serde(default = "default_npm")]
    pub manager: String,
    #[serde(default = "default_natural")]
    pub kind: String,
    #[serde(default)]
    pub target_heads: Vec<String>,
    #[serde(default)]
    pub target_revisions: Vec<TargetRevision>,
    pub base_sha: Option<String>,
    pub checkout_sha: Option<String>,
    #[serde(default)]
    pub required_jobs: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReasonReview {
    pub kind: String,
    #[serde(default = "default_unreviewed")]
    pub review: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LedgerRun {
    pub repo: String,
    pub pr: u64,
    #[serde(default = "default_npm")]
    pub manager: String,
    pub base_sha: Option<String>,
    pub pr_head_sha: Option<String>,
    pub checkout_sha: Option<String>,
    pub job_matrix: Option<String>,
    pub run_id: Option<u64>,
    pub run_attempt: Option<u64>,
    pub completed_at: Option<String>,
    #[serde(default = "default_evaluated")]
    pub status: String,
    #[serde(default = "default_none")]
    pub summary_displayed: String,
    #[serde(default)]
    pub reasons: Vec<ReasonReview>,
    #[serde(default)]
    pub missed_confirmed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcludedRunRef {
    pub repo: String,
    pub pr: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_sha: Option<String>,
    pub pr_head_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout_sha: Option<String>,
    pub job_matrix: Option<String>,
    pub run_id: Option<u64>,
    pub run_attempt: Option<u64>,
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRollup {
    pub repo: String,
    pub manager: String,
    pub window_start: Option<String>,
    pub window_end: Option<String>,
    pub target_prs: usize,
    pub prs_with_runs: usize,
    pub prs_fully_evaluated: usize,
    pub prs_partially_evaluated: usize,
    pub prs_completely_missing: usize,
    pub prs_alerted: usize,
    pub runs_with_execution: usize,
    pub quiet_evaluatable_runs: usize,
    pub recorded_finding_runs: usize,
    pub actual_notification_runs: usize,
    pub actual_notification_reruns: usize,
    pub display_failed_runs: usize,
    pub display_unverified_runs: usize,
    pub prs_by_reason: BTreeMap<String, usize>,
    pub recorded_reason_counts: BTreeMap<String, usize>,
    pub displayed_reason_review: BTreeMap<String, usize>,
    pub recorded_reason_review: BTreeMap<String, usize>,
    pub reviewed_alert_reasons: usize,
    pub technical_false_positive_rate: Option<f64>,
    pub runs_with_false_positive: usize,
    pub runs_with_unreviewed: usize,
    pub prs_with_false_positive: usize,
    pub prs_with_noise: usize,
    pub prs_with_unreviewed: usize,
    pub runs_with_missed_confirmed: usize,
    pub prs_with_missed_confirmed: usize,
    pub non_natural_prs: BTreeMap<String, usize>,
    pub non_natural_runs: usize,
    pub pre_window_runs: Vec<ExcludedRunRef>,
    pub post_deadline_runs: Vec<ExcludedRunRef>,
    pub unregistered_target_runs: Vec<ExcludedRunRef>,
    pub config_intervals: Vec<Value>,
    pub outages: Vec<Value>,
    pub effectiveness_status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollupSummary {
    pub window_start: Option<String>,
    pub window_end: Option<String>,
    pub groups: Vec<GroupRollup>,
    pub total: GroupRollup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct UtcTimestamp(i64);

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parses an ISO-8601 / RFC-3339 timestamp into UTC epoch seconds.
fn parse_utc(value: Option<&str>) -> Option<UtcTimestamp> {
    let text = value?.trim();
    if text.len() < 19 {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    if text.as_bytes().get(4) != Some(&b'-') {
        return None;
    }
    let month: i64 = text.get(5..7)?.parse().ok()?;
    if text.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    let day: i64 = text.get(8..10)?.parse().ok()?;
    if !matches!(text.as_bytes().get(10), Some(b'T' | b't' | b' ')) {
        return None;
    }
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    if text.as_bytes().get(13) != Some(&b':') {
        return None;
    }
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    if text.as_bytes().get(16) != Some(&b':') {
        return None;
    }
    let second: i64 = text.get(17..19)?.parse().ok()?;

    let mut rest = &text[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits = after_dot
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .count();
        rest = &after_dot[digits..];
    }

    let offset_seconds: i64 = if rest.is_empty() || rest.eq_ignore_ascii_case("Z") {
        0
    } else if rest.starts_with('+') || rest.starts_with('-') {
        let sign = if rest.starts_with('-') { -1 } else { 1 };
        let tz = &rest[1..];
        let (oh, om) = if let Some((h, m)) = tz.split_once(':') {
            (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?)
        } else if tz.len() == 4 {
            (tz[0..2].parse::<i64>().ok()?, tz[2..4].parse::<i64>().ok()?)
        } else {
            return None;
        };
        sign * (oh * 3600 + om * 60)
    } else {
        return None;
    };

    let days = days_from_civil(year, month, day);
    let secs = days * 86400 + hour * 3600 + minute * 60 + second - offset_seconds;
    Some(UtcTimestamp(secs))
}

fn empty_review_counts() -> BTreeMap<String, usize> {
    REVIEW_CLASSES
        .iter()
        .map(|name| ((*name).to_string(), 0))
        .collect()
}

fn empty_kind_counts() -> BTreeMap<String, usize> {
    ALERT_KINDS
        .iter()
        .map(|kind| ((*kind).to_string(), 0))
        .collect()
}

fn run_matches_entry(run: &LedgerRun, entry: &TargetPrEntry, default_mgr: &str) -> bool {
    let mgr = if entry.manager.is_empty() {
        default_mgr
    } else {
        entry.manager.as_str()
    };
    let run_mgr = if run.manager.is_empty() {
        default_mgr
    } else {
        run.manager.as_str()
    };
    if run_mgr != mgr {
        return false;
    }

    if !entry.target_revisions.is_empty() {
        let mut matched_rev = false;
        for rev in &entry.target_revisions {
            let head = rev.pr_head_sha.as_deref().or(rev.head_sha.as_deref());
            if let Some(head) = head
                && run.pr_head_sha.as_deref() != Some(head)
            {
                continue;
            }
            if let Some(base) = rev.base_sha.as_deref()
                && run.base_sha.as_deref().unwrap_or("") != base
            {
                continue;
            }
            if let Some(checkout) = rev.checkout_sha.as_deref()
                && run.checkout_sha.as_deref().unwrap_or("") != checkout
            {
                continue;
            }
            matched_rev = true;
            break;
        }
        if !matched_rev {
            return false;
        }
    }

    if !entry.target_heads.is_empty() {
        let Some(run_head) = run.pr_head_sha.as_deref() else {
            return false;
        };
        if !entry.target_heads.iter().any(|h| h == run_head) {
            return false;
        }
    }
    if let Some(base) = entry.base_sha.as_deref()
        && run.base_sha.as_deref().unwrap_or("") != base
    {
        return false;
    }
    if let Some(checkout) = entry.checkout_sha.as_deref()
        && run.checkout_sha.as_deref().unwrap_or("") != checkout
    {
        return false;
    }
    true
}

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
        in_window_natural_runs.push(run.clone());
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
        if status != "not_run" {
            runs_with_execution += 1;
        }

        let exam_key = (
            run.repo.clone(),
            run.pr,
            if run.manager.is_empty() {
                "npm".to_string()
            } else {
                run.manager.clone()
            },
            run.base_sha.clone().unwrap_or_default(),
            run.pr_head_sha.clone().unwrap_or_default(),
            run.checkout_sha.clone().unwrap_or_default(),
            run.job_matrix.clone().unwrap_or_default(),
        );
        let is_rerun = !seen_exam_keys.insert(exam_key);

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

        let mut expected_targets: BTreeSet<(String, String, String, String, String)> =
            BTreeSet::new();
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

            let mut expected_revisions: BTreeSet<(String, String, String)> = BTreeSet::new();
            for rev in &entry.target_revisions {
                let head = rev
                    .pr_head_sha
                    .clone()
                    .or_else(|| rev.head_sha.clone())
                    .unwrap_or_else(|| target_heads[0].clone());
                expected_revisions.insert((
                    rev.base_sha.clone().unwrap_or_default(),
                    head,
                    rev.checkout_sha.clone().unwrap_or_default(),
                ));
            }

            for h in &target_heads {
                let head_runs: Vec<&&LedgerRun> = entry_runs
                    .iter()
                    .filter(|r| {
                        r.pr_head_sha
                            .as_deref()
                            .unwrap_or(target_heads[0].as_str())
                            == h.as_str()
                    })
                    .collect();
                for r in &head_runs {
                    expected_revisions.insert((
                        r.base_sha.clone().unwrap_or_default(),
                        h.clone(),
                        r.checkout_sha.clone().unwrap_or_default(),
                    ));
                }
                if head_runs.is_empty()
                    && !expected_revisions.iter().any(|rev| &rev.1 == h)
                {
                    expected_revisions.insert((
                        entry.base_sha.clone().unwrap_or_default(),
                        h.clone(),
                        entry.checkout_sha.clone().unwrap_or_default(),
                    ));
                }
            }

            for (base_sha, head_sha, checkout_sha) in expected_revisions {
                for j in &jobs {
                    expected_targets.insert((
                        mgr.clone(),
                        base_sha.clone(),
                        head_sha.clone(),
                        checkout_sha.clone(),
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

        if !expected_targets.is_empty() && expected_targets.is_subset(&evaluated_targets) {
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

fn format_rate(rate: Option<f64>) -> String {
    match rate {
        None => "算出不可".to_string(),
        Some(r) => format!("{:.1}%", r * 100.0),
    }
}

pub fn render_markdown(summary: &RollupSummary) -> String {
    let mut lines = vec![
        "### veil-tell Monthly Operations Summary".to_string(),
        String::new(),
    ];
    if summary.window_start.is_some() || summary.window_end.is_some() {
        lines.push(format!(
            "- Window (UTC): `{}` .. `{}`",
            summary.window_start.as_deref().unwrap_or("?"),
            summary.window_end.as_deref().unwrap_or("?")
        ));
        lines.push(String::new());
    }

    lines.push(
        "| Repo | Manager | Target PRs | With Runs | Fully Eval | Partial Eval | Missing | Alerted PRs | Notif Runs (Reruns) | Display Failed | New PRs | Blocked PRs | Vol PRs | FP Reasons | Noise Reasons | Unreviewed Reasons | Tech FP Rate | Status |"
            .to_string(),
    );
    lines.push(
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |"
            .to_string(),
    );

    let mut rows: Vec<&GroupRollup> = summary.groups.iter().collect();
    if rows.len() > 1 {
        rows.push(&summary.total);
    }

    for row in rows {
        let rev = &row.displayed_reason_review;
        let by_reason = &row.prs_by_reason;
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} ({}) | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            row.repo,
            row.manager,
            row.target_prs,
            row.prs_with_runs,
            row.prs_fully_evaluated,
            row.prs_partially_evaluated,
            row.prs_completely_missing,
            row.prs_alerted,
            row.actual_notification_runs,
            row.actual_notification_reruns,
            row.display_failed_runs,
            by_reason.get("new").copied().unwrap_or(0),
            by_reason.get("blocked").copied().unwrap_or(0),
            by_reason.get("volume").copied().unwrap_or(0),
            rev.get("false_positive").copied().unwrap_or(0),
            rev.get("noise_valid_observation").copied().unwrap_or(0),
            rev.get("unreviewed").copied().unwrap_or(0),
            format_rate(row.technical_false_positive_rate),
            row.effectiveness_status,
        ));
    }

    let total = &summary.total;
    if !total.non_natural_prs.is_empty() || !total.post_deadline_runs.is_empty() {
        lines.push(String::new());
        lines.push("Separate tracking (excluded from primary natural PR counts):".to_string());
        if !total.non_natural_prs.is_empty() {
            let json_str = serde_json::to_string(&total.non_natural_prs).unwrap_or_default();
            lines.push(format!("- Non-natural PRs: `{json_str}`"));
        }
        if !total.post_deadline_runs.is_empty() {
            lines.push(format!(
                "- Post-deadline runs: `{}`",
                total.post_deadline_runs.len()
            ));
        }
    }

    lines.join("\n")
}

pub fn run(args: &[OsString]) -> Result<u8> {
    let mut ledger_path: Option<PathBuf> = None;
    let mut format = "markdown".to_string();
    let mut out_json: Option<PathBuf> = None;
    let mut out_md: Option<PathBuf> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("-h" | "--help") => {
                println!(
                    "usage: veil-tell rollup LEDGER.JSON [--format markdown|json|both] [--out-json FILE] [--out-md FILE]"
                );
                return Ok(0);
            }
            Some("--format") => {
                let val = iter
                    .next()
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| error("--format requires markdown, json, or both"))?;
                if !matches!(val, "markdown" | "json" | "both") {
                    return Err(error("--format requires markdown, json, or both"));
                }
                format = val.to_string();
            }
            Some("--out-json") => {
                out_json = Some(
                    iter.next()
                        .ok_or_else(|| error("--out-json requires a file path"))?
                        .into(),
                );
            }
            Some("--out-md") => {
                out_md = Some(
                    iter.next()
                        .ok_or_else(|| error("--out-md requires a file path"))?
                        .into(),
                );
            }
            Some(flag) if flag.starts_with('-') => {
                return Err(error(format!("unexpected option for rollup: {flag}")));
            }
            _ if ledger_path.is_none() => {
                ledger_path = Some(arg.into());
            }
            _ => return Err(error("usage: veil-tell rollup LEDGER.JSON [OPTIONS]")),
        }
    }

    let ledger_path =
        ledger_path.ok_or_else(|| error("usage: veil-tell rollup LEDGER.JSON [OPTIONS]"))?;
    let raw = std::fs::read_to_string(&ledger_path)?;
    let ledger: Ledger = serde_json::from_str(&raw)?;
    let summary = rollup_ledger(&ledger);
    let md = render_markdown(&summary);
    let json_text = serde_json::to_string_pretty(&summary)?;

    if let Some(path) = out_json {
        std::fs::write(path, format!("{json_text}\n"))?;
    }
    if let Some(path) = out_md {
        std::fs::write(path, format!("{md}\n"))?;
    }

    match format.as_str() {
        "markdown" => println!("{md}"),
        "json" => println!("{json_text}"),
        "both" => {
            println!("{md}\n\n{json_text}");
        }
        _ => unreachable!(),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
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
}
