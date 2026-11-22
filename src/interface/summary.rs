//! Render outbound findings and PR notification flags from a veil-tell JSON report (A01).

use crate::{Result, error};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

#[path = "summary_findings.rs"]
mod findings;
use findings::{
    build_findings, canonical_json_key, compute_should_comment, detect_incomplete_reasons,
};

const REASON_ORDER: &[(&str, (&str, &str))] = &[
    ("new", ("New", "新規")),
    ("blocked", ("Blocked", "拒否")),
    ("volume_cut", ("Volume limit cut", "送信量上限で切断")),
    ("volume_anomaly", ("Volume anomaly", "送信量異常")),
];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryMetadata {
    pub action_ref: Option<String>,
    pub action_sha: Option<String>,
    pub binary_version: Option<String>,
    pub binary_sha256: Option<String>,
    pub runner_os: Option<String>,
    pub runner_arch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryResult {
    pub markdown: String,
    pub should_comment: bool,
    pub has_findings: bool,
    pub reasons: Vec<String>,
}

fn reason_label(key: &str) -> (&'static str, &'static str) {
    REASON_ORDER
        .iter()
        .find_map(|(k, pair)| (*k == key).then_some(*pair))
        .unwrap_or(("Unknown", "不明"))
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn cell(value: &str) -> String {
    let escaped = html_escape(value).replace('|', "&#124;");
    let joined = escaped.lines().collect::<Vec<_>>().join(" ");
    format!("<code>{joined}</code>")
}

fn format_bytes(num_bytes: u64) -> String {
    if num_bytes < 1024 {
        format!("{num_bytes} B")
    } else if num_bytes < 1024 * 1024 {
        format!("{:.1} KiB", num_bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", num_bytes as f64 / (1024.0 * 1024.0))
    }
}

fn format_attribution_short(sources: &[Value]) -> String {
    if sources.is_empty() {
        return "特定できず (unknown)".to_string();
    }
    let mut parts = Vec::new();
    let mut seen = BTreeSet::new();
    for source in sources {
        let pkg = source.get("package").and_then(Value::as_object);
        let label = if let Some(pkg) = pkg
            && let (Some(name), Some(version)) = (
                pkg.get("name").and_then(Value::as_str),
                pkg.get("version").and_then(Value::as_str),
            ) {
            let mut s = format!("{name}@{version}");
            if let Some(script) = pkg.get("script").and_then(Value::as_str)
                && !script.is_empty()
            {
                s.push(' ');
                s.push_str(script);
            }
            let conf = source
                .get("confidence")
                .and_then(Value::as_str)
                .unwrap_or("inferred");
            if conf == "inferred" {
                s.push_str("（推定）");
            } else {
                s.push_str(&format!("（{conf}）"));
            }
            s
        } else {
            "特定できず (unknown)".to_string()
        };
        if seen.insert(label.clone()) {
            parts.push(label);
        }
    }
    parts.join(", ")
}

fn volume_details(anomaly: Option<&Value>) -> Option<String> {
    let anomaly = anomaly?;
    let observed = anomaly.get("observed")?.as_object()?;
    let limits = anomaly.get("limits")?.as_object()?;
    let mut details = Vec::new();
    for (key, label) in [
        ("sent_bytes", "bytes"),
        ("connections", "connections"),
        ("max_connection_bytes", "max bytes per connection"),
    ] {
        let obs = observed.get(key).and_then(Value::as_u64).unwrap_or(0);
        let lim = limits.get(key).and_then(Value::as_u64).unwrap_or(0);
        details.push(format!("{label} {obs}/{lim}"));
    }
    let blocked = anomaly
        .get("blocked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let prefix = if blocked {
        "cut / 切断"
    } else {
        "observed / 観測"
    };
    Some(format!("{prefix} · {}", details.join(", ")))
}

fn matching_lock_change(changes: Option<&Value>, package: Option<&Value>) -> String {
    let Some(pkg) = package.and_then(Value::as_object) else {
        return "—".to_string();
    };
    let name = pkg.get("name").and_then(Value::as_str);
    let version = pkg.get("version").and_then(Value::as_str);
    let Some((name, version)) = name.zip(version) else {
        return "—".to_string();
    };
    let Some(changes) = changes.and_then(Value::as_object) else {
        return "—".to_string();
    };
    if let Some(updated) = changes.get("updated").and_then(Value::as_array) {
        for entry in updated {
            let before = entry.get("before").and_then(Value::as_object);
            let after = entry.get("after").and_then(Value::as_object);
            if let (Some(before), Some(after)) = (before, after)
                && after.get("name").and_then(Value::as_str) == Some(name)
                && after.get("version").and_then(Value::as_str) == Some(version)
            {
                let before_ver = before.get("version").and_then(Value::as_str).unwrap_or("");
                if before_ver == version {
                    return format!("{version} integrity changed / integrity 変更");
                }
                return format!("{before_ver}→{version}");
            }
        }
    }
    if let Some(added) = changes.get("added").and_then(Value::as_array) {
        for item in added {
            if item.get("name").and_then(Value::as_str) == Some(name)
                && item.get("version").and_then(Value::as_str) == Some(version)
            {
                return "added / 追加".to_string();
            }
        }
    }
    "—".to_string()
}

fn format_reason_pair(reasons: &[String]) -> String {
    let en = reasons
        .iter()
        .map(|r| reason_label(r).0)
        .collect::<Vec<_>>()
        .join(" + ");
    let ja = reasons
        .iter()
        .map(|r| reason_label(r).1)
        .collect::<Vec<_>>()
        .join("・");
    format!("{en} / {ja}")
}

fn format_reason_ja(reasons: &[String]) -> String {
    reasons
        .iter()
        .map(|r| reason_label(r).1)
        .collect::<Vec<_>>()
        .join("・")
}

fn append_metadata(lines: &mut Vec<String>, report: &Value, metadata: &SummaryMetadata) {
    let coverage = report.get("coverage").and_then(Value::as_object);
    let run_status = report.get("run_status").and_then(Value::as_object);
    let reason = run_status
        .and_then(|s| s.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let exit_str = run_status
        .and_then(|s| s.get("exit_code"))
        .and_then(Value::as_i64)
        .map_or_else(|| "?".to_string(), |c| c.to_string());
    let backend = report
        .get("backend")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let isolation = report
        .get("isolation")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let cov_dns = coverage
        .and_then(|c| c.get("dns_attempts"))
        .and_then(Value::as_str)
        .unwrap_or("?");
    let cov_direct = coverage
        .and_then(|c| c.get("direct_attempt_destinations"))
        .and_then(Value::as_str)
        .unwrap_or("?");

    let mut meta_items = vec![
        format!("run_status={reason} (exit {exit_str})"),
        format!("backend={backend}"),
        format!("isolation={isolation}"),
        format!("coverage.dns={cov_dns}"),
        format!("coverage.direct={cov_direct}"),
    ];
    for (key, val) in [
        ("action_ref", &metadata.action_ref),
        ("action_sha", &metadata.action_sha),
        ("binary_version", &metadata.binary_version),
        ("binary_sha256", &metadata.binary_sha256),
        ("runner_os", &metadata.runner_os),
        ("runner_arch", &metadata.runner_arch),
    ] {
        if let Some(v) = val
            && !v.is_empty()
        {
            meta_items.push(format!("{key}={v}"));
        }
    }
    lines.push(String::new());
    lines.push("<details><summary>Coverage &amp; run metadata</summary>".to_string());
    lines.push(String::new());
    lines.push("```text".to_string());
    lines.extend(meta_items);
    lines.push("```".to_string());
    lines.push("</details>".to_string());
}

pub fn analyze_report(report: &Value, metadata: &SummaryMetadata) -> SummaryResult {
    let run_status = report.get("run_status").and_then(Value::as_object);
    let run_reason = run_status
        .and_then(|s| s.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let child_status = report.get("child_status").and_then(Value::as_object);
    let child_exit = child_status
        .and_then(|s| s.get("exit_code"))
        .and_then(Value::as_i64);
    let child_signal = child_status
        .and_then(|s| s.get("signal"))
        .and_then(Value::as_i64);
    let comparison = report.get("comparison").and_then(Value::as_object);
    let comp_status = comparison
        .and_then(|c| c.get("status"))
        .and_then(Value::as_str);

    let findings = build_findings(report);
    let incomplete_reasons = detect_incomplete_reasons(report);
    let should_comment = compute_should_comment(report);

    let mut reason_tags = Vec::new();
    for entry in &findings {
        for r in &entry.reasons {
            if !reason_tags.contains(r) {
                reason_tags.push(r.clone());
            }
        }
    }

    let mut lines = Vec::new();

    if findings.is_empty()
        && incomplete_reasons.is_empty()
        && run_reason == "completed"
        && comp_status == Some("compared")
    {
        lines.push(
            "OK (quiet): No new destinations, blocked attempts, or volume anomalies / 新しい送り先・止めた試み・送信量の異常はありません"
                .to_string(),
        );
        return SummaryResult {
            markdown: lines.join("\n"),
            should_comment: false,
            has_findings: false,
            reasons: Vec::new(),
        };
    }

    if findings.is_empty() {
        if run_reason == "child_failed" {
            let child_desc = match (child_exit, child_signal) {
                (None, Some(sig)) => format!("signal {sig}"),
                (Some(code), _) => format!("exit {code}"),
                (None, None) => "exit None".to_string(),
            };
            lines.push("### veil-tell check incomplete (child failed)".to_string());
            lines.push(String::new());
            lines.push(format!(
                "- **Status**: Child command failed (`{child_desc}`) with no new destinations or blocked attempts observed / 子コマンドが終了しました（`{child_desc}`）。新しい送り先や遮断は観測されていません。"
            ));
            if !incomplete_reasons.is_empty() {
                let formatted = incomplete_reasons
                    .iter()
                    .map(|r| cell(r))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!("- **Comparison / Capture**: {formatted}"));
            }
            lines.push(
                "- **Next**: Check the child command's own error log. This failure was not caused by a new outbound destination."
                    .to_string(),
            );
        } else {
            let exit_val = run_status
                .and_then(|s| s.get("exit_code"))
                .and_then(Value::as_i64)
                .map_or_else(|| "?".to_string(), |c| c.to_string());
            lines.push(
                "### veil-tell check incomplete / 比較・観測が完了していません".to_string(),
            );
            lines.push(String::new());
            lines.push(format!(
                "- **Run reason**: {} (exit {})",
                cell(run_reason),
                cell(&exit_val)
            ));
            if !incomplete_reasons.is_empty() {
                let formatted = incomplete_reasons
                    .iter()
                    .map(|r| cell(r))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!("- **Details**: {formatted}"));
            }
            lines.push(
                "- **Next**: Check the failing step log, baseline file, and isolation prerequisites before trusting this run."
                    .to_string(),
            );
        }
        append_metadata(&mut lines, report, metadata);
        return SummaryResult {
            markdown: lines.join("\n"),
            should_comment,
            has_findings: false,
            reasons: reason_tags,
        };
    }

    lines.push("### veil-tell outbound alert / 通信の変化・遮断を検出しました".to_string());
    lines.push(String::new());

    for entry in findings.iter().take(20) {
        let reasons_ja = format_reason_ja(&entry.reasons);
        let attr_short = format_attribution_short(&entry.attribution);
        let traffic_short = if entry.kind == "Direct IP" {
            format!("{} 回", entry.attempts)
        } else if entry.kind == "Attempted DNS" {
            format!("試行 {} 回", entry.attempts)
        } else {
            format!("転送 {}", format_bytes(entry.sent_bytes))
        };
        lines.push(format!(
            "- **{reasons_ja}** ｜ `{}` ｜ {attr_short} ｜ {traffic_short}",
            entry.destination
        ));
    }
    if findings.len() > 20 {
        lines.push(format!(
            "- *({} additional items shown in table / report)*",
            findings.len() - 20
        ));
    }

    let mut notes = Vec::new();
    if comp_status == Some("new_destinations_only") {
        notes.push(
            "Comparison was restricted to new destinations after failure (`new_destinations_only`); removed destinations were not evaluated."
                .to_string(),
        );
    }
    if comparison
        .and_then(|c| c.get("backend_changed"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        notes.push(
            "Baseline was recorded under a different backend than this run (`backend_changed=true`)."
                .to_string(),
        );
    }
    for inc in &incomplete_reasons {
        if !(comp_status == Some("skipped") && inc == "comparison.status=skipped") {
            notes.push(format!("Capture/comparison note: `{inc}`."));
        }
    }
    if comp_status == Some("skipped") {
        notes.push("Baseline comparison was skipped (`comparison.status=skipped`).".to_string());
    }
    if !notes.is_empty() {
        lines.push(String::new());
        for note in notes {
            lines.push(format!("> {note}"));
        }
    }

    lines.push(String::new());
    lines.push(
        "| Reasons | Kind | Destination | Outcome | Package / Attribution | Lockfile | Traffic / Limit |"
            .to_string(),
    );
    lines.push("| --- | --- | --- | --- | --- | --- | --- |".to_string());

    let mut evidence: BTreeMap<(String, Option<u64>, String), String> = BTreeMap::new();
    if let Some(comp) = comparison
        && let Some(ev_list) = comp.get("lockfile_evidence").and_then(Value::as_array)
    {
        for item in ev_list {
            let host = item
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let port = item.get("port").and_then(Value::as_u64);
            let source_key = item
                .get("source")
                .map(canonical_json_key)
                .unwrap_or_default();
            if let Some(label) = item.get("label").and_then(Value::as_str) {
                evidence.insert((host, port, source_key), label.to_string());
            }
        }
    }
    let changes = comparison.and_then(|c| c.get("lockfile_changes"));

    let mut rows = 0usize;
    let fallback_unknown = vec![serde_json::json!({"confidence": "unknown"})];
    for entry in &findings {
        let sources = if entry.attribution.is_empty() {
            &fallback_unknown
        } else {
            &entry.attribution
        };
        for source in sources {
            if rows >= 100 {
                lines.push("\nAdditional entries are available in `report.json`.".to_string());
                break;
            }
            let package = source.get("package");
            let (host_only, port_val) = if entry.kind == "CONNECT"
                && let Some((h, p)) = entry.destination.rsplit_once(':')
            {
                (h.to_string(), p.parse::<u64>().ok())
            } else if let Some((h, _)) = entry.destination.rsplit_once(':') {
                (h.to_string(), None)
            } else {
                (entry.destination.clone(), None)
            };

            let pkg_str = if let Some(pkg) = package.and_then(Value::as_object)
                && let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(Value::as_str),
                    pkg.get("version").and_then(Value::as_str),
                ) {
                let mut s = format!("{name}@{version}");
                if let Some(script) = pkg.get("script").and_then(Value::as_str)
                    && !script.is_empty()
                {
                    s.push_str(&format!(" ({script})"));
                }
                if let Some(path) = pkg.get("path").and_then(Value::as_str)
                    && !path.is_empty()
                {
                    s.push_str(&format!(" @ {path}"));
                }
                let conf = source
                    .get("confidence")
                    .and_then(Value::as_str)
                    .unwrap_or("inferred");
                s.push_str(&format!(" [{conf}]"));
                s
            } else {
                let conf = source
                    .get("confidence")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                format!("unknown ({conf})")
            };

            let lock_str = if entry.kind == "CONNECT" {
                evidence
                    .get(&(host_only, port_val, canonical_json_key(source)))
                    .cloned()
                    .unwrap_or_else(|| matching_lock_change(changes, package))
            } else if entry.kind == "Attempted DNS" {
                evidence
                    .get(&(host_only, None, canonical_json_key(source)))
                    .cloned()
                    .unwrap_or_else(|| matching_lock_change(changes, package))
            } else {
                "—".to_string()
            };

            let mut outcome_parts = Vec::new();
            if let Some(res) = &entry.result {
                outcome_parts.push(res.clone());
            } else if let Some(dec) = &entry.decision {
                outcome_parts.push(dec.clone());
            } else {
                outcome_parts.push("observed".to_string());
            }
            if let Some(deny) = &entry.deny_reason {
                outcome_parts.push(format!("({deny})"));
            }
            let outcome_str = outcome_parts.join(" ");

            let traffic_str = if let Some(vol) = volume_details(entry.anomaly.as_ref()) {
                vol
            } else if entry.kind == "CONNECT" {
                format!(
                    "{} ({} attempts)",
                    format_bytes(entry.sent_bytes),
                    entry.attempts
                )
            } else {
                format!("{} attempts", entry.attempts)
            };

            let values = [
                format_reason_pair(&entry.reasons),
                entry.kind.clone(),
                entry.destination.clone(),
                outcome_str,
                pkg_str,
                lock_str,
                traffic_str,
            ];
            let rendered_cells = values.iter().map(|v| cell(v)).collect::<Vec<_>>().join(" | ");
            lines.push(format!("| {rendered_cells} |"));
            rows += 1;
        }
        if rows >= 100 {
            break;
        }
    }

    lines.push(String::new());
    lines.push("**Next steps / 次の一手**".to_string());
    if reason_tags.iter().any(|r| r == "new") {
        lines.push(
            "- **New destination / 新規宛先**: Verify why the dependency needs this host and check the lockfile diff. Do **not** approve by editing the baseline in the PR branch; if legitimate, re-record and review the baseline on the trusted base branch first."
                .to_string(),
        );
    }
    if reason_tags.iter().any(|r| r == "blocked") && !reason_tags.iter().any(|r| r == "new") {
        lines.push(
            "- **Blocked attempt / 止めた試み**: Confirm whether this blocked connection or direct IP/DNS attempt is an expected policy denial or a bypass attempt."
                .to_string(),
        );
    }
    if reason_tags
        .iter()
        .any(|r| r == "volume_cut" || r == "volume_anomaly")
    {
        lines.push(
            "- **Volume anomaly / 送信量の異常**: Compare `observed` vs `limits` in `report.json` to confirm there is no unexpected upload or connection burst."
                .to_string(),
        );
    }

    append_metadata(&mut lines, report, metadata);
    SummaryResult {
        markdown: lines.join("\n"),
        should_comment,
        has_findings: true,
        reasons: reason_tags,
    }
}

pub fn summarize_report_file(
    report_path: &Path,
    missing_reason: Option<&str>,
    metadata: &SummaryMetadata,
) -> SummaryResult {
    if !report_path.is_file() {
        let detail = missing_reason
            .map(str::to_string)
            .unwrap_or_else(|| format!("Report file not found (`{}`).", report_path.display()));
        return SummaryResult {
            markdown: format!(
                "### veil-tell check incomplete / レポートが生成されませんでした\n\n- **Error**: {}\n- **Next**: Open the failing step log to check baseline resolution, isolation prerequisites, and release verification.",
                html_escape(&detail)
            ),
            should_comment: false,
            has_findings: false,
            reasons: Vec::new(),
        };
    }

    match std::fs::read_to_string(report_path)
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str::<Value>(&text).map_err(|e| e.to_string()))
    {
        Ok(report_data) => analyze_report(&report_data, metadata),
        Err(err) => SummaryResult {
            markdown: format!(
                "### veil-tell check incomplete / レポートを読み取れませんでした\n\n- **Error**: Could not parse report JSON ({}).\n- **Next**: Check the failing step log and verify disk/output state.",
                html_escape(&err)
            ),
            should_comment: false,
            has_findings: false,
            reasons: Vec::new(),
        },
    }
}

fn write_github_output(path: &Path, result: &SummaryResult) -> Result<()> {
    let mut fh = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(
        fh,
        "should_comment={}",
        if result.should_comment { "true" } else { "false" }
    )?;
    writeln!(
        fh,
        "has_findings={}",
        if result.has_findings { "true" } else { "false" }
    )?;
    writeln!(fh, "finding_reasons={}", result.reasons.join(","))?;
    Ok(())
}

pub fn run(args: &[OsString]) -> Result<u8> {
    let mut report_path: Option<PathBuf> = None;
    let mut github_output: Option<PathBuf> = None;
    let mut missing_reason: Option<String> = None;
    let mut metadata = SummaryMetadata {
        action_ref: std::env::var("VEIL_ACTION_REF").ok(),
        action_sha: std::env::var("VEIL_ACTION_SHA").ok(),
        binary_version: std::env::var("VEIL_BINARY_VERSION").ok(),
        binary_sha256: std::env::var("VEIL_BINARY_SHA256").ok(),
        runner_os: std::env::var("RUNNER_OS").ok(),
        runner_arch: std::env::var("RUNNER_ARCH").ok(),
    };

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("-h" | "--help") => {
                println!(
                    "usage: veil-tell summary REPORT.JSON [--github-output FILE] [--missing-reason TEXT]"
                );
                return Ok(0);
            }
            Some("--github-output") => {
                github_output = Some(
                    iter.next()
                        .ok_or_else(|| error("--github-output requires a path"))?
                        .into(),
                );
            }
            Some("--missing-reason") => {
                missing_reason = Some(
                    iter.next()
                        .ok_or_else(|| error("--missing-reason requires text"))?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            Some("--action-ref") => {
                metadata.action_ref = Some(
                    iter.next()
                        .ok_or_else(|| error("--action-ref requires value"))?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            Some("--action-sha") => {
                metadata.action_sha = Some(
                    iter.next()
                        .ok_or_else(|| error("--action-sha requires value"))?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            Some("--binary-version") => {
                metadata.binary_version = Some(
                    iter.next()
                        .ok_or_else(|| error("--binary-version requires value"))?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            Some("--binary-sha256") => {
                metadata.binary_sha256 = Some(
                    iter.next()
                        .ok_or_else(|| error("--binary-sha256 requires value"))?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            Some("--runner-os") => {
                metadata.runner_os = Some(
                    iter.next()
                        .ok_or_else(|| error("--runner-os requires value"))?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            Some("--runner-arch") => {
                metadata.runner_arch = Some(
                    iter.next()
                        .ok_or_else(|| error("--runner-arch requires value"))?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            Some(flag) if flag.starts_with('-') => {
                return Err(error(format!("unexpected option for summary: {flag}")));
            }
            _ if report_path.is_none() => {
                report_path = Some(arg.into());
            }
            _ => return Err(error("usage: veil-tell summary REPORT.JSON [OPTIONS]")),
        }
    }

    let report_path =
        report_path.ok_or_else(|| error("usage: veil-tell summary REPORT.JSON [OPTIONS]"))?;
    let result = summarize_report_file(&report_path, missing_reason.as_deref(), &metadata);
    println!("{}", result.markdown);
    if let Some(out_path) = github_output {
        write_github_output(&out_path, &result)?;
    }
    Ok(0)
}

#[cfg(test)]
#[path = "summary_tests.rs"]
mod tests;
