//! Domain types, UTC window parsing, and target revision matching for monthly rollup (M01).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const ALERT_KINDS: &[&str] = &["new", "blocked", "volume"];
pub const REVIEW_CLASSES: &[&str] = &[
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

fn deserialize_review<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_else(default_unreviewed))
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReasonReview {
    pub kind: String,
    #[serde(
        default = "default_unreviewed",
        deserialize_with = "deserialize_review"
    )]
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
pub struct UtcTimestamp(i64);

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
pub fn parse_utc(value: Option<&str>) -> Option<UtcTimestamp> {
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

    let month_days = match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        1..=12 => 31,
        _ => return None,
    };
    if !(1..=month_days).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    let mut rest = &text[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits = after_dot.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        rest = &after_dot[digits..];
    }

    let offset_seconds: i64 = if rest.is_empty() || rest.eq_ignore_ascii_case("Z") {
        0
    } else if rest.starts_with('+') || rest.starts_with('-') {
        let sign = if rest.starts_with('-') { -1 } else { 1 };
        let tz = &rest[1..];
        let (h, m) = tz.split_once(':').or_else(|| tz.split_at_checked(2))?;
        if h.len() != 2 || m.len() != 2 || !h.bytes().chain(m.bytes()).all(|b| b.is_ascii_digit()) {
            return None;
        }
        let (hours, minutes) = (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?);
        if hours >= 24 || minutes >= 60 {
            return None;
        }
        sign * (hours * 3600 + minutes * 60)
    } else {
        return None;
    };

    let days = days_from_civil(year, month, day);
    let secs = days * 86400 + hour * 3600 + minute * 60 + second - offset_seconds;
    Some(UtcTimestamp(secs))
}

pub fn empty_review_counts() -> BTreeMap<String, usize> {
    REVIEW_CLASSES
        .iter()
        .map(|name| ((*name).to_string(), 0))
        .collect()
}

pub fn empty_kind_counts() -> BTreeMap<String, usize> {
    ALERT_KINDS
        .iter()
        .map(|kind| ((*kind).to_string(), 0))
        .collect()
}

pub fn run_matches_entry(run: &LedgerRun, entry: &TargetPrEntry, default_mgr: &str) -> bool {
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
