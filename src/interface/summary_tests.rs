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
