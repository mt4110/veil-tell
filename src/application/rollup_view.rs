//! Markdown and CLI presentation for monthly operations rollup (M01).

use super::{GroupRollup, Ledger, RollupSummary, rollup_ledger};
use crate::{Result, error};
use std::ffi::OsString;
use std::path::PathBuf;

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
