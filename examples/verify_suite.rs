//! Run `veil-tell verify` checks against local receivers in Rust (no Python).

use base64::Engine;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

const POLICY_HEAD: &str = "version = 1\nprofile = \"verify-test\"\n";

fn target_rule(action: &str, host: &str) -> String {
    format!("[[rule]]\naction = \"{action}\"\nhost = \"{host}\"\nport = 443\n")
}

fn parse_proxy_url(url: &str) -> (String, u16, String) {
    let trimmed = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let (userinfo, hostport) = trimmed.rsplit_once('@').unwrap_or(("", trimmed));
    let hostport = hostport.split('/').next().unwrap_or(hostport);
    let (host, port_str) = hostport.rsplit_once(':').unwrap();
    let creds = base64::engine::general_purpose::STANDARD.encode(userinfo.as_bytes());
    (host.to_string(), port_str.parse().unwrap(), creds)
}

fn connect_probe_quiet(host: &str, token: &str) -> String {
    let proxy_env = env::var("HTTPS_PROXY").unwrap();
    let (phost, pport, creds) = parse_proxy_url(&proxy_env);
    let mut conn = TcpStream::connect((phost.as_str(), pport)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let req = format!(
        "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
    );
    conn.write_all(req.as_bytes()).unwrap();

    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut head = String::new();
    reader.read_line(&mut head).unwrap();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }
    let code = head.split_whitespace().nth(1).unwrap_or("").to_string();
    if head.contains(" 200 ") {
        conn.write_all(format!("{token}-connect").as_bytes())
            .unwrap();
        let _ = conn.shutdown(Shutdown::Write);
        let mut ack = Vec::new();
        reader.read_to_end(&mut ack).unwrap();
        assert_eq!(ack, b"ACK");
    }
    format!("CONNECT={code}\n")
}

fn probe(behavior: &str) {
    let seed = Path::new("seed.txt");
    assert_eq!(fs::read_to_string(seed).unwrap(), "original\n");
    assert_eq!(fs::read_to_string("seed.link").unwrap(), "original\n");
    assert!(!Path::new("trial-artifact.txt").exists());
    fs::write(seed, "modified by this trial\n").unwrap();
    fs::write("trial-artifact.txt", "").unwrap();
    if behavior == "no-contact" {
        return;
    }
    if behavior.starts_with("upstream-") {
        let _ = connect_probe_quiet("other.test", behavior);
    }
    let resp = connect_probe_quiet("allowed.test", behavior);
    if resp == "CONNECT=200\n" {
        return;
    }
    assert_eq!(resp, "CONNECT=403\n", "{resp}");
    match behavior {
        "required" => std::process::exit(7),
        "reserved-exit" => std::process::exit(125),
        "timeout" => thread::sleep(Duration::from_secs(30)),
        _ => {}
    }
}

fn upstream_connect(reader: &mut BufReader<TcpStream>) -> String {
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "incomplete upstream CONNECT request");
        if line == "\r\n" {
            return first;
        }
    }
}

fn receiver_case<F>(
    run_fn: F,
    behavior: &str,
    expected_connections: usize,
    upstream_hosts: &[&str],
) -> (std::process::Output, Value)
where
    F: FnOnce(BTreeMap<String, String>) -> (std::process::Output, Value),
{
    let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = receiver.local_addr().unwrap();
    let behavior_owned = behavior.to_string();
    let hosts_owned: Vec<String> = upstream_hosts.iter().map(|s| (*s).to_string()).collect();

    let handle = thread::spawn(move || {
        let mut payloads = Vec::new();
        for index in 0..expected_connections {
            let (mut conn, _) = receiver.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            if !hosts_owned.is_empty() {
                let host = &hosts_owned[index];
                let req = upstream_connect(&mut reader);
                assert_eq!(req, format!("CONNECT {host}:443 HTTP/1.1\r\n"));
                if behavior_owned == "upstream-refused" && host == "other.test" {
                    conn.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap();
                    continue;
                }
                conn.write_all(b"HTTP/1.1 200 Established\r\n\r\n").unwrap();
            }
            let mut body = Vec::new();
            reader.read_to_end(&mut body).unwrap();
            payloads.push(body);
            conn.write_all(b"ACK").unwrap();
        }
        payloads
    });

    let mut env_map = BTreeMap::new();
    if !upstream_hosts.is_empty() {
        env_map.insert("HTTPS_PROXY".to_string(), format!("http://{addr}"));
        env_map.insert("NO_PROXY".to_string(), String::new());
    } else {
        env_map.insert("VEIL_TELL_FIXTURE_RECEIVER".to_string(), addr.to_string());
    }

    let (output, report) = run_fn(env_map);
    let payloads = handle.join().unwrap();
    let count = expected_connections - usize::from(behavior == "upstream-refused");
    let expected_payload = format!("{behavior}-connect").into_bytes();
    assert_eq!(payloads, vec![expected_payload; count]);
    (output, report)
}

fn assert_comparison<'a>(
    result: &std::process::Output,
    report: &'a Value,
    code: i32,
    verdict: &str,
    phase: &str,
    reason: &str,
) -> &'a Value {
    assert_eq!(
        result.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains(verdict),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["timeout_seconds"], 3);
    assert_eq!(
        report["destination"],
        json!({"host": "allowed.test", "port": 443})
    );
    assert_eq!(report["verdict"], verdict);
    assert_eq!(report["phase"], phase);
    assert_eq!(report["reason"], reason);
    assert_eq!(report["exit_code"], code);
    &report["trials"]
}

fn assert_trial(trial: &Value, child_exit: i32, event_reason: Option<&str>) {
    assert_eq!(trial["backend"], "isolated");
    assert_eq!(trial["isolation"], "applied");
    assert_eq!(
        trial["child_status"],
        json!({"exit_code": child_exit, "signal": null})
    );
    let reason = if child_exit == 0 {
        "completed"
    } else {
        "child_failed"
    };
    assert_eq!(
        trial["run_status"],
        json!({"exit_code": child_exit, "reason": reason})
    );
    let Some(ev_reason) = event_reason else {
        assert_eq!(trial["destinations"], json!([]));
        return;
    };
    let dests = trial["destinations"].as_array().unwrap();
    assert_eq!(dests.len(), 1);
    let event = &dests[0];
    assert_eq!(event["host"], "allowed.test");
    assert_eq!(event["port"], 443);
    assert_eq!(event["reason"], ev_reason);
    assert_eq!(event["attempts"], 1);
    if ev_reason == "explicit_deny" {
        assert_eq!(event["result"], "blocked");
        assert_eq!(event["received_bytes"], 0);
    } else {
        assert_eq!(event["received_bytes"], 3);
    }
}

fn run(cli: &Path, fixture: &Path) {
    let cli = cli.canonicalize().unwrap();
    let fixture = fixture.canonicalize().unwrap();
    let self_exe = env::current_exe().unwrap().canonicalize().unwrap();

    let tmp = tempfile::Builder::new()
        .prefix("veil-verify-test-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let source = root.join("project");
    let evidence = root.join("evidence");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&evidence).unwrap();

    let probe_bin = source.join("verify_probe");
    fs::copy(&self_exe, &probe_bin).unwrap();
    let seed = source.join("seed.txt");
    fs::write(&seed, "original\n").unwrap();
    symlink("seed.txt", source.join("seed.link")).unwrap();

    let policy = evidence.join("policy.toml");
    let policy_text = format!("{POLICY_HEAD}{}", target_rule("allow", "allowed.test"));
    fs::write(&policy, &policy_text).unwrap();

    let invoke = |binary: &Path,
                  report: &Path,
                  command: &[&str],
                  extra_env: Option<&BTreeMap<String, String>>| {
        let mut cmd = Command::new(binary);
        cmd.arg("verify")
            .arg("--source")
            .arg(&source)
            .arg("--policy")
            .arg(&policy)
            .args(["--without", "ALLOWED.test.:443", "--report"])
            .arg(report)
            .args(["--timeout-seconds", "3", "--"])
            .args(command)
            .current_dir(&root);
        if let Some(map) = extra_env {
            for (k, v) in map {
                cmd.env(k, v);
            }
        }
        cmd.output().unwrap()
    };

    let run_probe = |binary: &Path,
                     behavior: &str,
                     extra_env: Option<&BTreeMap<String, String>>|
     -> (std::process::Output, Value) {
        let report = evidence.join(format!("{behavior}.json"));
        let out = invoke(binary, &report, &["./verify_probe", "--probe", behavior], extra_env);
        assert!(
            report.is_file(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let data: Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
        (out, data)
    };

    let marker = ["/bin/sh", "-c", "printf 'command ran\\n'"];
    let existing = evidence.join("existing.json");
    fs::write(&existing, "previous report\n").unwrap();
    let result = invoke(&cli, &existing, &marker, None);
    assert_eq!(result.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&result.stderr).contains("already exists"));
    assert!(result.stdout.is_empty());
    assert_eq!(fs::read_to_string(&existing).unwrap(), "previous report\n");

    let source_report = source.join("report.json");
    let result = invoke(&cli, &source_report, &marker, None);
    assert_eq!(result.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&result.stderr).contains("outside --source"));
    assert!(result.stdout.is_empty());
    assert!(!source_report.exists());

    let rejected = evidence.join("rejected.json");
    for rules in ["", &target_rule("deny", "allowed.test")] {
        fs::write(&policy, format!("{POLICY_HEAD}{rules}")).unwrap();
        let result = invoke(&cli, &rejected, &marker, None);
        assert_eq!(result.status.code(), Some(125));
        assert!(String::from_utf8_lossy(&result.stderr).contains("explicit allow"));
        assert!(result.stdout.is_empty());
        assert!(!rejected.exists());
    }
    fs::write(&policy, &policy_text).unwrap();

    let (result, report) = run_probe(&cli, "no-contact", None);
    let trials = assert_comparison(
        &result,
        &report,
        2,
        "inconclusive",
        "allowed",
        "allowed_connection_not_observed",
    );
    assert_trial(&trials["allowed"], 0, None);
    assert!(trials["denied"].is_null() && trials["restored"].is_null());

    for (behavior, connections, code, verdict, phase, reason) in [
        (
            "optional",
            1,
            0,
            "passes",
            "denied",
            "passed_with_destination_blocked",
        ),
        (
            "required",
            2,
            1,
            "fails",
            "restored",
            "failed_with_destination_blocked",
        ),
        ("timeout", 1, 2, "inconclusive", "denied", "timed_out"),
    ] {
        let (result, report) = receiver_case(
            |env_map| run_probe(&fixture, behavior, Some(&env_map)),
            behavior,
            connections,
            &[],
        );
        let trials = assert_comparison(&result, &report, code, verdict, phase, reason);
        assert_trial(&trials["allowed"], 0, Some("allow_rule"));
        if behavior == "timeout" {
            let denied = &trials["denied"];
            assert_eq!(
                denied["run_status"],
                json!({"exit_code": 124, "reason": "timed_out"})
            );
            assert_eq!(denied["coverage"]["proxy_capture"], "until_interrupted");
            let ev = &denied["destinations"][0];
            assert_eq!(ev["reason"], "explicit_deny");
            assert_eq!(ev["result"], "blocked");
        } else {
            assert_trial(
                &trials["denied"],
                if behavior == "required" { 7 } else { 0 },
                Some("explicit_deny"),
            );
        }
        if behavior == "required" {
            assert_trial(&trials["restored"], 0, Some("allow_rule"));
        } else {
            assert!(trials["restored"].is_null());
        }
    }

    if cfg!(target_os = "linux") {
        let (result, report) = receiver_case(
            |env_map| run_probe(&fixture, "reserved-exit", Some(&env_map)),
            "reserved-exit",
            1,
            &[],
        );
        let trials = assert_comparison(
            &result,
            &report,
            2,
            "inconclusive",
            "denied",
            "child_exit_ambiguous",
        );
        assert_trial(&trials["denied"], 125, Some("explicit_deny"));
        assert!(trials["restored"].is_null());
    }

    assert_eq!(fs::read_to_string(&policy).unwrap(), policy_text);
    let other_rule = target_rule("allow", "other.test");
    fs::write(&policy, format!("{policy_text}{other_rule}")).unwrap();

    for (behavior, hosts, code, verdict, phase, reason) in [
        (
            "upstream-ok",
            &["other.test", "allowed.test", "other.test"][..],
            0,
            "passes",
            "denied",
            "passed_with_destination_blocked",
        ),
        (
            "upstream-refused",
            &["other.test", "allowed.test"][..],
            2,
            "inconclusive",
            "allowed",
            "other_destination_unavailable",
        ),
    ] {
        let (result, report) = receiver_case(
            |env_map| run_probe(&cli, behavior, Some(&env_map)),
            behavior,
            hosts.len(),
            hosts,
        );
        let trials = assert_comparison(&result, &report, code, verdict, phase, reason);
        let other = trials["allowed"]["destinations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["host"] == "other.test")
            .unwrap();
        assert!(other["connected_ip"].is_null());
        assert_eq!(other["via_upstream_proxy"], true);
    }

    assert_eq!(
        fs::read_to_string(&policy).unwrap(),
        format!("{policy_text}{other_rule}")
    );
    assert_eq!(fs::read_to_string(&seed).unwrap(), "original\n");
    assert!(!source.join("trial-artifact.txt").exists());

    symlink(
        Path::new("..")
            .join(source.file_name().unwrap())
            .join(seed.file_name().unwrap()),
        source.join("escape.link"),
    )
    .unwrap();
    let result = invoke(&cli, &rejected, &marker, None);
    assert_eq!(result.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&result.stderr).contains("symlink escapes snapshot"));
    assert!(result.stdout.is_empty());
    assert!(!rejected.exists());

    println!("PASS: verify CLI, receiver, snapshot, and report checks");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("--probe") {
        probe(&args[2]);
    } else {
        run(Path::new(&args[1]), Path::new(&args[2]));
    }
}
