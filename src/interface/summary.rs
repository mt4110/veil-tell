//! Render outbound findings and PR notification flags from a veil-tell JSON report (A01),
//! plus compatibility contract tests (C01).

use crate::{Result, error};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

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

fn canonical_json_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn dedup_sources(sources: &[Value]) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for src in sources {
        let key = canonical_json_key(src);
        if seen.insert(key) {
            out.push(src.clone());
        }
    }
    out
}

#[derive(Clone, Debug)]
struct FindingEntry {
    kind: String,
    destination: String,
    reasons: Vec<String>,
    decision: Option<String>,
    result: Option<String>,
    deny_reason: Option<String>,
    sent_bytes: u64,
    attempts: u64,
    attribution: Vec<Value>,
    anomaly: Option<Value>,
}

impl FindingEntry {
    fn add_reason(&mut self, reason: &str) {
        if !self.reasons.iter().any(|r| r == reason) {
            self.reasons.push(reason.to_string());
        }
    }
}

#[derive(Clone, Debug, Default)]
struct MergedDest {
    host: String,
    port: u64,
    decision: Option<String>,
    reason: Option<String>,
    result: Option<String>,
    attempts: u64,
    sent_bytes: u64,
    attribution: Vec<Value>,
}

fn ensure_entry<'a>(
    order: &mut Vec<(String, String, Option<u64>)>,
    entries: &'a mut BTreeMap<(String, String, Option<u64>), FindingEntry>,
    key: (String, String, Option<u64>),
    kind: &str,
    dest_label: String,
) -> &'a mut FindingEntry {
    if !entries.contains_key(&key) {
        order.push(key.clone());
        entries.insert(
            key.clone(),
            FindingEntry {
                kind: kind.to_string(),
                destination: dest_label,
                reasons: Vec::new(),
                decision: None,
                result: None,
                deny_reason: None,
                sent_bytes: 0,
                attempts: 0,
                attribution: Vec::new(),
                anomaly: None,
            },
        );
    }
    entries.get_mut(&key).unwrap()
}

fn build_findings(report: &Value) -> Vec<FindingEntry> {
    let comparison = report.get("comparison").and_then(Value::as_object);
    let run_reason = report
        .get("run_status")
        .and_then(|s| s.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let coverage = report.get("coverage").and_then(Value::as_object);

    let mut order: Vec<(String, String, Option<u64>)> = Vec::new();
    let mut entries: BTreeMap<(String, String, Option<u64>), FindingEntry> = BTreeMap::new();

    let mut dest_order: Vec<(String, String, Option<u64>)> = Vec::new();
    let mut dest_by_key: BTreeMap<(String, String, Option<u64>), MergedDest> = BTreeMap::new();
    if let Some(dests) = report.get("destinations").and_then(Value::as_array) {
        for dest in dests {
            let host = dest
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let port = dest.get("port").and_then(Value::as_u64).unwrap_or(443);
            let key = ("CONNECT".to_string(), host.clone(), Some(port));
            let attempts = dest.get("attempts").and_then(Value::as_u64).unwrap_or(0);
            let sent_bytes = dest.get("sent_bytes").and_then(Value::as_u64).unwrap_or(0);
            let decision = dest
                .get("decision")
                .and_then(Value::as_str)
                .map(str::to_string);
            let reason = dest
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_string);
            let result = dest
                .get("result")
                .and_then(Value::as_str)
                .map(str::to_string);
            let attr = dest
                .get("attribution")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            if let Some(existing) = dest_by_key.get_mut(&key) {
                existing.attempts += attempts;
                existing.sent_bytes += sent_bytes;
                if decision.as_deref() == Some("deny") {
                    existing.decision = Some("deny".to_string());
                    if reason.is_some() {
                        existing.reason = reason;
                    }
                }
                if result.as_deref() == Some("blocked") {
                    existing.result = Some("blocked".to_string());
                }
                if !attr.is_empty() {
                    let mut combined = existing.attribution.clone();
                    combined.extend(attr);
                    existing.attribution = dedup_sources(&combined);
                }
            } else {
                dest_order.push(key.clone());
                dest_by_key.insert(
                    key,
                    MergedDest {
                        host,
                        port,
                        decision,
                        reason,
                        result,
                        attempts,
                        sent_bytes,
                        attribution: dedup_sources(&attr),
                    },
                );
            }
        }
    }

    // 1. New CONNECT destinations from comparison
    if let Some(comp) = comparison
        && let Some(added) = comp.get("added").and_then(Value::as_array)
    {
        let comp_status = comp.get("status").and_then(Value::as_str);
        for row in added {
            let host = row
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let port = row.get("port").and_then(Value::as_u64).unwrap_or(443);
            let key = ("CONNECT".to_string(), host.clone(), Some(port));
            let entry = ensure_entry(
                &mut order,
                &mut entries,
                key.clone(),
                "CONNECT",
                format!("{host}:{port}"),
            );
            entry.add_reason("new");
            entry.attempts = row.get("attempts").and_then(Value::as_u64).unwrap_or(0);
            entry.attribution = row
                .get("attribution")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(matched) = dest_by_key.get(&key) {
                entry.decision = matched.decision.clone();
                entry.result = matched.result.clone();
                entry.sent_bytes = matched.sent_bytes;
                entry.attempts = matched.attempts;
                if entry.attribution.is_empty() {
                    entry.attribution = matched.attribution.clone();
                }
                if matched.decision.as_deref() == Some("deny")
                    || matched.result.as_deref() == Some("blocked")
                {
                    entry.add_reason("blocked");
                    entry.deny_reason = matched.reason.clone();
                }
            } else if comp_status == Some("new_destinations_only")
                || run_reason == "new_destination"
            {
                entry.decision = Some("deny".to_string());
                entry.result = Some("blocked".to_string());
                entry.add_reason("blocked");
            }
        }
    }

    // 2. Explicit denials or blocked CONNECT destinations
    for key in &dest_order {
        let dest = &dest_by_key[key];
        if dest.decision.as_deref() == Some("deny") || dest.result.as_deref() == Some("blocked") {
            let entry = ensure_entry(
                &mut order,
                &mut entries,
                key.clone(),
                "CONNECT",
                format!("{}:{}", dest.host, dest.port),
            );
            entry.add_reason("blocked");
            entry.decision = Some(dest.decision.clone().unwrap_or_else(|| "deny".to_string()));
            entry.result = Some(dest.result.clone().unwrap_or_else(|| "blocked".to_string()));
            entry.deny_reason = dest.reason.clone();
            entry.sent_bytes = dest.sent_bytes;
            entry.attempts = dest.attempts;
            if entry.attribution.is_empty() {
                entry.attribution = dest.attribution.clone();
            }
        }
    }

    // 3. Volume anomalies (observed or cut)
    if let Some(anomalies) = report.get("volume_anomalies").and_then(Value::as_array) {
        for anomaly in anomalies {
            let host = anomaly
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let port = anomaly.get("port").and_then(Value::as_u64).unwrap_or(443);
            let key = ("CONNECT".to_string(), host.clone(), Some(port));
            let blocked = anomaly
                .get("blocked")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let entry = ensure_entry(
                &mut order,
                &mut entries,
                key,
                "CONNECT",
                format!("{host}:{port}"),
            );
            entry.add_reason(if blocked {
                "volume_cut"
            } else {
                "volume_anomaly"
            });
            entry.anomaly = Some(anomaly.clone());
            if let Some(obs) = anomaly.get("observed").and_then(Value::as_object) {
                if let Some(sb) = obs.get("sent_bytes").and_then(Value::as_u64) {
                    entry.sent_bytes = sb;
                }
                if let Some(c) = obs.get("connections").and_then(Value::as_u64) {
                    entry.attempts = c;
                }
            }
            if entry.attribution.is_empty() {
                entry.attribution = anomaly
                    .get("attribution")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
            }
            if blocked && entry.result.is_none() {
                entry.result = Some("cut".to_string());
            }
        }
    }

    // 4. New DNS lookup attempts
    let mut added_dns_hosts = BTreeSet::new();
    if let Some(comp) = comparison
        && let Some(attempted_added) = comp.get("attempted_added").and_then(Value::as_array)
    {
        for row in attempted_added {
            let host = row
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            added_dns_hosts.insert(host.clone());
            let key = ("DNS".to_string(), host.clone(), None);
            let entry = ensure_entry(&mut order, &mut entries, key, "Attempted DNS", host);
            entry.add_reason("new");
            entry.add_reason("blocked");
            entry.decision = Some("deny".to_string());
            entry.result = Some("blocked".to_string());
            entry.attempts = row.get("attempts").and_then(Value::as_u64).unwrap_or(0);
            entry.attribution = row
                .get("attribution")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
        }
    }

    if let Some(attempted) = report.get("attempted").and_then(Value::as_array) {
        let has_comp = comparison.is_some_and(|c| !c.is_empty());
        for row in attempted {
            let host = row
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if added_dns_hosts.contains(&host) {
                continue;
            }
            let key = ("DNS".to_string(), host.clone(), None);
            let entry = ensure_entry(&mut order, &mut entries, key, "Attempted DNS", host);
            if !has_comp && run_reason == "new_destination" {
                entry.add_reason("new");
            }
            entry.add_reason("blocked");
            entry.decision = Some("deny".to_string());
            entry.result = Some("blocked".to_string());
            entry.attempts = row.get("attempts").and_then(Value::as_u64).unwrap_or(0);
            entry.attribution = row
                .get("attribution")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
        }
    }

    // 5. Direct IP:port attempts recorded by isolation layer (only when observed)
    let direct_cov = coverage
        .and_then(|c| c.get("direct_attempt_destinations"))
        .and_then(Value::as_str)
        .unwrap_or("not_observed");
    if direct_cov != "not_observed"
        && let Some(direct_attempts) = report.get("direct_attempts").and_then(Value::as_array)
    {
        for row in direct_attempts {
            let ip = row
                .get("ip")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let port = row.get("port").and_then(Value::as_u64).unwrap_or(0);
            let key = ("DIRECT".to_string(), ip.clone(), Some(port));
            let entry = ensure_entry(
                &mut order,
                &mut entries,
                key,
                "Direct IP",
                format!("{ip}:{port}"),
            );
            entry.add_reason("blocked");
            entry.decision = Some("deny".to_string());
            entry.result = Some("blocked".to_string());
            entry.attempts = row.get("attempts").and_then(Value::as_u64).unwrap_or(0);
        }
    }

    order
        .into_iter()
        .filter_map(|k| entries.remove(&k))
        .collect()
}

fn detect_incomplete_reasons(report: &Value) -> Vec<String> {
    let run_reason = report
        .get("run_status")
        .and_then(|s| s.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let coverage = report.get("coverage").and_then(Value::as_object);
    let comparison = report.get("comparison").filter(|v| !v.is_null());
    let mut reasons = Vec::new();

    if matches!(
        run_reason,
        "incomplete_capture"
            | "baseline_failed"
            | "proxy_stopped"
            | "timed_out"
            | "interrupted"
            | "policy_output_failed"
    ) {
        reasons.push(format!("run_status.reason={run_reason}"));
    }

    if let Some(cov) = coverage {
        if let Some(pc) = cov.get("proxy_capture").and_then(Value::as_str)
            && matches!(pc, "incomplete" | "until_proxy_stopped" | "until_interrupted")
        {
            reasons.push(format!("coverage.proxy_capture={pc}"));
        }
        if cov
            .get("direct_attempt_destinations")
            .and_then(Value::as_str)
            == Some("incomplete")
        {
            reasons.push("coverage.direct_attempt_destinations=incomplete".to_string());
        }
        if cov.get("dns_attempts").and_then(Value::as_str) == Some("incomplete") {
            reasons.push("coverage.dns_attempts=incomplete".to_string());
        }
    }

    if report.get("backend").and_then(Value::as_str) == Some("isolated")
        && report.get("isolation").and_then(Value::as_str) == Some("unconfirmed")
    {
        reasons.push("isolation=unconfirmed".to_string());
    }

    if comparison.is_none() && run_reason != "new_destination" {
        reasons.push("comparison=missing".to_string());
    } else if let Some(comp) = comparison.and_then(Value::as_object)
        && let Some(status) = comp.get("status").and_then(Value::as_str)
        && matches!(status, "skipped" | "created")
    {
        reasons.push(format!("comparison.status={status}"));
    }

    reasons
}

fn compute_should_comment(report: &Value) -> bool {
    let comparison = report.get("comparison").filter(|v| !v.is_null());
    let run_reason = report
        .get("run_status")
        .and_then(|s| s.get("reason"))
        .and_then(Value::as_str);

    let has_new_from_comparison = comparison.is_some_and(|comp| {
        let added = comp
            .get("added")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        let att_added = comp
            .get("attempted_added")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        added || att_added
    });
    let has_new_without_comparison = comparison.is_none()
        && run_reason == Some("new_destination")
        && report
            .get("attempted")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
    has_new_from_comparison || has_new_without_comparison
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

    // Quiet success: 1 line only
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

    // No outbound findings, but run/comparison did not finish cleanly
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

    // Findings exist: 1-line highlights + detailed table + next steps
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
mod tests {
    use super::*;
    use serde_json::json;

    fn base_report() -> Value {
        json!({
            "schema_version": 1,
            "backend": "isolated",
            "mode": "observe",
            "isolation": "applied",
            "coverage": {
                "proxy": "http_connect_requests",
                "direct_attempt_destinations": "ip_port",
                "dns_attempts": "node_dns_lookup_hook",
                "proxy_capture": "while_running",
            },
            "direct_attempts": [],
            "child_status": {"exit_code": 0, "signal": null},
            "run_status": {"exit_code": 0, "reason": "completed"},
            "destinations": [
                {
                    "host": "registry.npmjs.org",
                    "port": 443,
                    "decision": "allow",
                    "reason": "baseline",
                    "result": "connected",
                    "connected_ip": "104.16.0.1",
                    "attempts": 3,
                    "sent_bytes": 1200,
                    "max_connection_bytes": 600,
                    "received_bytes": 8000,
                }
            ],
            "volume_anomalies": [],
            "attempted": [],
            "comparison": {
                "status": "compared",
                "backend_changed": false,
                "added": [],
                "removed": [],
                "attempted_added": [],
                "count_changes": [],
            }
        })
    }

    #[test]
    fn quiet_success_single_line_even_with_removed() {
        let mut report = base_report();
        report["comparison"]["removed"] = json!([
            {"host": "old-mirror.example.test", "port": 443, "attempts": 1}
        ]);
        let res = analyze_report(&report, &SummaryMetadata::default());
        assert!(!res.should_comment);
        assert!(!res.has_findings);
        assert_eq!(res.markdown.lines().count(), 1);
        assert!(res.markdown.contains("OK (quiet)"));
    }

    #[test]
    fn new_connect_and_dns_attempt_trigger_alert_and_comment() {
        let mut report = base_report();
        report["run_status"] = json!({"exit_code": 21, "reason": "new_destination"});
        report["child_status"] = json!({"exit_code": 1, "signal": null});
        let attr = json!([
            {
                "confidence": "inferred",
                "package": {
                    "name": "puppeteer",
                    "version": "24.0.0",
                    "script": "postinstall",
                    "path": "node_modules/puppeteer",
                }
            }
        ]);
        report["destinations"].as_array_mut().unwrap().push(json!({
            "host": "storage.googleapis.com",
            "port": 443,
            "decision": "deny",
            "reason": "new_destination",
            "result": "blocked",
            "connected_ip": null,
            "attempts": 1,
            "sent_bytes": 0,
            "max_connection_bytes": 0,
            "received_bytes": 0,
            "attribution": attr,
        }));
        report["comparison"]["status"] = json!("new_destinations_only");
        report["comparison"]["added"] = json!([
            {
                "host": "storage.googleapis.com",
                "port": 443,
                "attempts": 1,
                "attribution": attr,
            }
        ]);
        report["comparison"]["attempted_added"] = json!([
            {"host": "telemetry.example.test", "attempts": 2, "attribution": []}
        ]);

        let res = analyze_report(&report, &SummaryMetadata::default());
        assert!(res.should_comment);
        assert!(res.has_findings);
        assert!(res.markdown.contains("新規・拒否"));
        assert!(res.markdown.contains("storage.googleapis.com:443"));
        assert!(res.markdown.contains("puppeteer@24.0.0"));
        assert!(res.markdown.contains("telemetry.example.test"));
        assert!(res.markdown.contains("特定できず (unknown)"));
    }

    #[test]
    fn known_destination_explicit_deny_and_direct_attempts() {
        let mut report = base_report();
        report["direct_attempts"] = json!([{"ip": "203.0.113.10", "port": 443, "attempts": 5}]);
        report["destinations"].as_array_mut().unwrap().push(json!({
            "host": "telemetry.npmjs.org",
            "port": 443,
            "decision": "deny",
            "reason": "policy_deny",
            "result": "blocked",
            "connected_ip": null,
            "attempts": 2,
            "sent_bytes": 0,
            "max_connection_bytes": 0,
            "received_bytes": 0,
        }));
        let res = analyze_report(&report, &SummaryMetadata::default());
        assert!(!res.should_comment);
        assert!(res.has_findings);
        assert!(res.markdown.contains("telemetry.npmjs.org:443"));
        assert!(res.markdown.contains("policy_deny"));
        assert!(res.markdown.contains("203.0.113.10:443"));
        assert!(res.markdown.contains("5 回"));
    }

    #[test]
    fn direct_attempts_hidden_when_not_observed() {
        let mut report = base_report();
        report["direct_attempts"] = json!([{"ip": "203.0.113.10", "port": 443, "attempts": 5}]);
        report["coverage"]["direct_attempt_destinations"] = json!("not_observed");
        let res = analyze_report(&report, &SummaryMetadata::default());
        assert!(!res.has_findings);
    }

    #[test]
    fn volume_anomaly_observed_and_cut() {
        for (blocked, expected_text) in [(false, "observed / 観測"), (true, "cut / 切断")] {
            let mut report = base_report();
            report["run_status"] = json!({
                "exit_code": if blocked { 22 } else { 21 },
                "reason": if blocked { "volume_limit_exceeded" } else { "volume_anomaly" },
            });
            report["volume_anomalies"] = json!([
                {
                    "host": "registry.npmjs.org",
                    "port": 443,
                    "observed": {"sent_bytes": 300000, "connections": 4, "max_connection_bytes": 150000},
                    "limits": {"sent_bytes": 262144, "connections": 64, "max_connection_bytes": 131072},
                    "blocked": blocked,
                    "attribution": [],
                }
            ]);
            let res = analyze_report(&report, &SummaryMetadata::default());
            assert!(!res.should_comment);
            assert!(res.has_findings);
            assert!(res.markdown.contains(expected_text));
            assert!(res.markdown.contains("300000/262144"));
        }
    }

    #[test]
    fn new_destination_and_volume_anomaly_together() {
        let mut report = base_report();
        report["run_status"] = json!({"exit_code": 21, "reason": "new_destination"});
        report["volume_anomalies"] = json!([
            {
                "host": "registry.npmjs.org",
                "port": 443,
                "observed": {"sent_bytes": 300000, "connections": 4, "max_connection_bytes": 150000},
                "limits": {"sent_bytes": 262144, "connections": 64, "max_connection_bytes": 131072},
                "blocked": true,
                "attribution": [],
            }
        ]);
        report["comparison"]["added"] = json!([
            {"host": "new.example.test", "port": 443, "attempts": 1, "attribution": []}
        ]);
        let res = analyze_report(&report, &SummaryMetadata::default());
        assert!(res.should_comment);
        assert!(res.has_findings);
        assert!(res.markdown.contains("new.example.test:443"));
        assert!(res.markdown.contains("registry.npmjs.org:443"));
        assert!(res.markdown.contains("送信量上限で切断"));
    }

    #[test]
    fn child_own_exit_21_does_not_fabricate_destination_or_comment() {
        for code in [20, 21, 22, 125] {
            let mut report = base_report();
            report["child_status"] = json!({"exit_code": code, "signal": null});
            report["run_status"] = json!({"exit_code": code, "reason": "child_failed"});
            report["comparison"] =
                json!({"status": "skipped", "added": [], "removed": [], "count_changes": []});
            let res = analyze_report(&report, &SummaryMetadata::default());
            assert!(!res.should_comment);
            assert!(!res.has_findings);
            assert!(res.markdown.contains("child failed"));
            assert!(res.markdown.contains(&format!("exit {code}")));
            assert!(!res.markdown.contains("New destination"));
        }
    }

    #[test]
    fn incomplete_capture_with_blocked_destination() {
        let mut report = base_report();
        report["run_status"] = json!({"exit_code": 125, "reason": "incomplete_capture"});
        report["coverage"]["proxy_capture"] = json!("incomplete");
        report["destinations"].as_array_mut().unwrap().push(json!({
            "host": "blocked.example.test",
            "port": 443,
            "decision": "deny",
            "reason": "policy_deny",
            "result": "blocked",
            "connected_ip": null,
            "attempts": 1,
            "sent_bytes": 0,
            "max_connection_bytes": 0,
            "received_bytes": 0,
        }));
        let res = analyze_report(&report, &SummaryMetadata::default());
        assert!(!res.should_comment);
        assert!(res.has_findings);
        assert!(res.markdown.contains("blocked.example.test:443"));
        assert!(res.markdown.contains("run_status.reason=incomplete_capture"));
    }

    #[test]
    fn missing_and_malformed_report_outputs() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("absent.json");
        let res_missing = summarize_report_file(
            &missing,
            Some("Missing baseline in PR base"),
            &SummaryMetadata::default(),
        );
        assert!(res_missing.markdown.contains("Missing baseline in PR base"));
        assert!(!res_missing.should_comment);
        assert!(!res_missing.has_findings);

        let bad_json = tmp.path().join("bad.json");
        std::fs::write(&bad_json, "{not json").unwrap();
        let res_bad = summarize_report_file(&bad_json, None, &SummaryMetadata::default());
        assert!(res_bad.markdown.contains("Could not parse report JSON"));
    }

    #[test]
    fn yaml_action_and_template_contracts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let action_text = std::fs::read_to_string(root.join("action.yml")).unwrap();
        let template_text = std::fs::read_to_string(
            root.join("examples")
                .join("github-actions")
                .join("veil-tell-npm.yml"),
        )
        .unwrap();

        let action_data: Value = serde_yaml_ng::from_str(&action_text).unwrap();
        let template_data: Value = serde_yaml_ng::from_str(&template_text).unwrap();

        assert_eq!(action_data["runs"]["using"], "composite");
        let steps = action_data["runs"]["steps"].as_array().unwrap();
        let comment_step = steps
            .iter()
            .find(|s| s.get("name").and_then(Value::as_str) == Some("Comment on new destinations"))
            .unwrap();
        let comment_if = comment_step["if"].as_str().unwrap();
        assert!(comment_if.contains("steps.check.outputs.should_comment == 'true'"));
        assert!(!comment_if.contains("steps.check.outputs.status == '21'"));

        // Verify action.yml uses the veil-tell binary itself (`summary`) instead of python3
        assert!(!action_text.contains("destination-summary.py"));

        assert_eq!(template_data["env"]["VEIL_TELL_VERSION"], "0.6.0");
        assert!(action_text.contains("version=0.6.0"));

        let job_steps = template_data["jobs"]["npm-destinations"]["steps"]
            .as_array()
            .unwrap();
        for step in job_steps {
            if let Some(run_body) = step.get("run").and_then(Value::as_str) {
                assert!(!run_body.contains("sudo apt-get"));
            }
        }
        let prereq_step = job_steps
            .iter()
            .find(|s| {
                s.get("name").and_then(Value::as_str) == Some("Check isolation prerequisites")
            })
            .unwrap();
        assert!(
            prereq_step["run"]
                .as_str()
                .unwrap()
                .contains("/usr/bin/bwrap --unshare-user --unshare-net")
        );
    }

    #[test]
    fn compat_v060_fixtures_contract() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixtures_dir = root.join("tests").join("fixtures").join("compat-v0.6.0");
        let manifest_text = std::fs::read_to_string(fixtures_dir.join("manifest.json")).unwrap();
        let manifest: Value = serde_json::from_str(&manifest_text).unwrap();
        let fixtures = manifest["fixtures"].as_object().unwrap();

        for (name, expected) in fixtures {
            let path = fixtures_dir.join(name);
            assert!(path.is_file(), "missing fixture {name}");

            if name.starts_with("report-") {
                let data: Value =
                    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                assert_eq!(data["schema_version"], 1);
                let res = analyze_report(&data, &SummaryMetadata::default());
                assert_eq!(
                    res.should_comment,
                    expected["should_comment"].as_bool().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    res.has_findings,
                    expected["has_findings"].as_bool().unwrap(),
                    "{name}"
                );
                let exp_reasons: Vec<String> = expected["reasons"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                assert_eq!(res.reasons, exp_reasons, "{name}");
            } else if name.starts_with("verify-") {
                let data: Value =
                    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                assert_eq!(data["schema_version"], 1);
                assert_eq!(data["verdict"], expected["verdict"], "{name}");
                assert_eq!(data["exit_code"], expected["exit_code"], "{name}");
                assert!(data.get("trials").is_some(), "{name}");
            } else if name == "policy-v1.toml" {
                let pol = crate::policy::Policy::read(&path).unwrap();
                assert!(!pol.limits().is_empty());
            } else if name == "baseline-minimal.json" || name == "baseline-full.json" {
                let opts = crate::baseline::Options {
                    input: Some(path.clone()),
                    output: None,
                    fail_on_new: false,
                    ci: false,
                    automatic: false,
                    no_attribute: false,
                };
                let session = crate::baseline::Session::prepare(&opts, root, &[]).unwrap();
                let diff = session
                    .finish(crate::cli::Backend::Proxy, &[], &[])
                    .unwrap();
                let serialized = serde_json::to_value(&diff).unwrap();
                assert_eq!(
                    serialized["status"], expected["expected_comparison_status"],
                    "{name}"
                );
            } else if name.starts_with("baseline-invalid-") {
                let opts = crate::baseline::Options {
                    input: Some(path.clone()),
                    output: None,
                    fail_on_new: false,
                    ci: false,
                    automatic: false,
                    no_attribute: false,
                };
                assert!(
                    crate::baseline::Session::prepare(&opts, root, &[]).is_err(),
                    "{name} must be rejected"
                );
            } else if name == "agent-log-v0.6.0.jsonl" {
                let mut rows = Vec::new();
                for line in std::fs::read_to_string(&path).unwrap().lines() {
                    if !line.trim().is_empty() {
                        let obj: Value = serde_json::from_str(line).unwrap();
                        assert!(obj.get("time").is_some());
                        assert!(obj.get("run_status").is_some());
                        rows.push(obj);
                    }
                }
                assert_eq!(
                    rows.len(),
                    expected["expected_records"].as_u64().unwrap() as usize
                );
                assert_eq!(rows[0]["scope"], "agent_session");
                assert_eq!(rows[1]["agent"]["name"], "codex");
            }
        }
    }
}
