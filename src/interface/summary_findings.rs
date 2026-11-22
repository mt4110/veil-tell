//!Finding extraction and completeness analysis from a veil-tell report JSON (A01).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct FindingEntry {
    pub kind: String,
    pub destination: String,
    pub reasons: Vec<String>,
    pub decision: Option<String>,
    pub result: Option<String>,
    pub deny_reason: Option<String>,
    pub sent_bytes: u64,
    pub attempts: u64,
    pub attribution: Vec<Value>,
    pub anomaly: Option<Value>,
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

pub fn canonical_json_key(value: &Value) -> String {
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

pub fn build_findings(report: &Value) -> Vec<FindingEntry> {
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

pub fn detect_incomplete_reasons(report: &Value) -> Vec<String> {
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

pub fn compute_should_comment(report: &Value) -> bool {
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
