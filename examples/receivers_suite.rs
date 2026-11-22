//! Exercise the CLI and check payloads from the receiver side on macOS and Linux in Rust
//! (replaces tests/receivers.py).

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn os_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

fn direct_error_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "EPERM"
    } else {
        "ENETUNREACH"
    }
}

fn errno_name(code: i32) -> String {
    match code {
        libc::EPERM => "EPERM".to_string(),
        libc::ENETUNREACH => "ENETUNREACH".to_string(),
        libc::EACCES => "EACCES".to_string(),
        libc::ECONNREFUSED => "ECONNREFUSED".to_string(),
        libc::EBADF => "EBADF".to_string(),
        other => format!("ERRNO_{other}"),
    }
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

fn connect_probe(host: &str, token: &str, auth_override: Option<&str>) {
    let proxy_env = env::var("HTTPS_PROXY").unwrap();
    let (phost, pport, mut creds) = parse_proxy_url(&proxy_env);
    if let Some(ov) = auth_override {
        creds = ov.to_string();
    }
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
    let code = head.split_whitespace().nth(1).unwrap_or("");
    println!("CONNECT={code}");
    if head.contains(" 200 ") {
        conn.write_all(format!("{token}-connect").as_bytes())
            .unwrap();
        let _ = conn.shutdown(Shutdown::Write);
        let mut ack = Vec::new();
        reader.read_to_end(&mut ack).unwrap();
        assert_eq!(ack, b"ACK");
    }
}

fn probe(address: &str, token: &str) {
    connect_probe("allowed.test", token, None);
    let (host, port_s) = address.rsplit_once(':').unwrap();
    let port: u16 = port_s.parse().unwrap();
    match TcpStream::connect((host, port)) {
        Ok(mut conn) => {
            let _ = conn.write_all(format!("{token}-direct").as_bytes());
            println!("direct=sent");
        }
        Err(err) => {
            let code = err.raw_os_error().unwrap_or(0);
            println!("direct={}", errno_name(code));
        }
    }
}

fn volume_probe(size: usize) {
    let proxy_env = env::var("HTTPS_PROXY").unwrap();
    let (phost, pport, creds) = parse_proxy_url(&proxy_env);
    let mut conn = TcpStream::connect((phost.as_str(), pport)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let req = format!(
        "CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
    );
    conn.write_all(req.as_bytes()).unwrap();
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut head = String::new();
    reader.read_line(&mut head).unwrap();
    assert!(head.contains(" 200 "), "{head}");
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }
    let payload = vec![b'X'; size];
    let _ = conn.write_all(&payload);
    let _ = conn.shutdown(Shutdown::Write);
    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
}

fn fd_probe(fd: i32) {
    let data = b"inherited-fd";
    let res = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if res >= 0 {
        panic!("inherited descriptor could be written");
    }
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    assert_eq!(err, libc::EBADF);
    println!("EBADF");
}

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let dest_path = dst.join(entry.file_name());
        if ty.is_symlink() {
            let target = fs::read_link(entry.path()).unwrap();
            symlink(target, dest_path).unwrap();
        } else if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_path);
        } else {
            fs::copy(entry.path(), dest_path).unwrap();
        }
    }
}

fn receive(listener: &TcpListener, count: usize) -> Vec<Vec<u8>> {
    let mut tokens = Vec::new();
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_millis(250);
    loop {
        match listener.accept() {
            Ok((conn, _)) => {
                conn.set_nonblocking(false).unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut buf = Vec::new();
                let mut br = BufReader::new(conn);
                let _ = br.read_to_end(&mut buf);
                tokens.push(buf);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(_) => break,
        }
    }
    listener.set_nonblocking(false).unwrap();
    assert_eq!(tokens.len(), count, "{tokens:?}");
    tokens
}

fn action_summary(cli: &Path, report: &Path) -> String {
    let out = Command::new(cli)
        .arg("summary")
        .arg(report)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn upstream_connect(reader: &mut BufReader<TcpStream>) -> String {
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "incomplete upstream CONNECT request");
        if line == "\r\n" {
            return request;
        }
    }
}

fn run_with_env(
    cwd: &Path,
    args: &[&str],
    env_map: &BTreeMap<String, String>,
    expected: Option<i32>,
) -> std::process::Output {
    let mut cmd = Command::new(args[0]);
    cmd.args(&args[1..]).current_dir(cwd).env_clear();
    for (k, v) in env_map {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    if let Some(code) = expected {
        assert_eq!(
            out.status.code(),
            Some(code),
            "args={args:?}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out
}

fn emit_policy_test(
    cli: &Path,
    fixture: &Path,
    receiver: &TcpListener,
    project: &Path,
    evidence: &Path,
    env_map: &BTreeMap<String, String>,
) {
    let draft = evidence.join("observed.toml");
    let recv_clone = receiver.try_clone().unwrap();
    let handle = thread::spawn(move || {
        let mut received = Vec::new();
        for _ in 0..2 {
            let (mut conn, _) = recv_clone.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut body = Vec::new();
            let mut br = BufReader::new(conn.try_clone().unwrap());
            br.read_to_end(&mut body).unwrap();
            received.push(body);
            conn.write_all(b"ACK").unwrap();
        }
        received
    });

    let fix_s = fixture.to_str().unwrap();
    let draft_s = draft.to_str().unwrap();
    let result = run_with_env(
        project,
        &[
            fix_s,
            "observe",
            "--emit-policy",
            draft_s,
            "--",
            "./probe",
            "observe-candidates",
        ],
        env_map,
        Some(0),
    );
    let received = handle.join().unwrap();
    assert!(result.status.success());
    assert_eq!(
        received,
        vec![b"first-connect".to_vec(), b"second-connect".to_vec()]
    );
    let content = fs::read_to_string(&draft).unwrap();
    assert_eq!(content.matches("# host = \"allowed.test\"").count(), 1);
    assert!(
        content
            .lines()
            .filter(|l| l.contains("allow") || l.contains("[[rule]]"))
            .all(|l| l.starts_with('#'))
    );
    assert_eq!(fs::metadata(&draft).unwrap().permissions().mode() & 0o077, 0);

    let dup = run_with_env(
        project,
        &[
            fix_s,
            "observe",
            "--emit-policy",
            draft_s,
            "--",
            "/bin/echo",
            "started",
        ],
        env_map,
        Some(125),
    );
    assert!(String::from_utf8_lossy(&dup.stderr).contains("already exists"));
    assert!(dup.stdout.is_empty());
    assert_eq!(fs::read_to_string(&draft).unwrap(), content);

    let report_path = evidence.join("draft-restrict.json");
    let cli_s = cli.to_str().unwrap();
    let rep_s = report_path.to_str().unwrap();
    let res = run_with_env(
        project,
        &[
            cli_s,
            "restrict",
            "--backend",
            "isolated",
            "--policy",
            draft_s,
            "--fail-on-unknown",
            "--report",
            rep_s,
            "--",
            "./probe",
            "observe-candidates",
        ],
        env_map,
        Some(20),
    );
    assert_eq!(
        String::from_utf8_lossy(&res.stdout)
            .matches("CONNECT=403")
            .count(),
        2
    );
    assert!(receive(receiver, 0).is_empty());
    let report: Value = serde_json::from_str(&fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(report["child_status"]["exit_code"], 0);
    assert_eq!(
        report["run_status"],
        json!({"exit_code": 20, "reason": "unknown_destination"})
    );
    let event = &report["destinations"][0];
    assert_eq!(event["host"], "allowed.test");
    assert_eq!(event["reason"], "unknown_destination");
    assert_eq!(event["attempts"], 2);
    println!(
        "receiver case=policy-draft candidates=1 control_payloads=2 restricted_payloads=0 child_exit=0 exit=20"
    );
}

fn dns_attempt_test(cli: &Path, project: &Path, evidence: &Path, mut runtime: PathBuf) {
    let demo = project.join("dns-attempts");
    fs::create_dir_all(&demo).unwrap();
    fs::write(
        demo.join("package.json"),
        json!({
            "name": "veil-dns-fixture",
            "version": "1.2.3",
            "private": true,
            "scripts": {"postinstall": "node probe.cjs"}
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        demo.join("probe.cjs"),
        "require(\"node:dns\").promises.lookup(\"postinstall.invalid\").then(() => process.exit(2), error => { if (error.code !== \"ENOTFOUND\") process.exit(3) });",
    )
    .unwrap();
    if cfg!(target_os = "linux") {
        let local_rt = demo.join("runtime");
        copy_dir_all(&runtime, &local_rt);
        runtime = local_rt;
    }
    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    let sys_path = env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    env_map.insert(
        "PATH".to_string(),
        format!("{}:{sys_path}", runtime.join("bin").display()),
    );

    let baseline = evidence.join("dns-baseline.json");
    let report = evidence.join("dns-report.json");
    let cli_s = cli.to_str().unwrap();
    let base_s = baseline.to_str().unwrap();
    let rep_s = report.to_str().unwrap();

    run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--backend",
            "isolated",
            "--baseline-out",
            base_s,
            "--",
            "/usr/bin/true",
        ],
        &env_map,
        Some(0),
    );
    let child = run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--baseline",
            base_s,
            "--report",
            rep_s,
            "--",
            "npm",
            "--no-update-notifier",
            "run",
            "postinstall",
        ],
        &env_map,
        Some(21),
    );
    let data: Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(data["child_status"]["exit_code"], 0);
    assert_eq!(
        data["run_status"],
        json!({"exit_code": 21, "reason": "new_destination"})
    );
    assert_eq!(data["coverage"]["dns_attempts"], "node_dns_lookup_hook");
    assert_eq!(data["destinations"], json!([]));
    let attempt = &data["comparison"]["attempted_added"][0];
    assert_eq!(data["attempted"], json!([attempt]));
    assert_eq!(attempt["host"], "postinstall.invalid");
    assert_eq!(
        attempt["attribution"],
        json!([{
            "confidence": "inferred",
            "package": {
                "name": "veil-dns-fixture",
                "version": "1.2.3",
                "script": "postinstall",
                "path": "."
            }
        }])
    );
    let stderr_s = String::from_utf8_lossy(&child.stderr);
    println!(
        "{}",
        stderr_s
            .lines()
            .find(|l| l.contains("attempted (blocked)"))
            .unwrap()
    );
    let summary = action_summary(cli, &report);
    assert!(
        summary.contains("<code>Attempted DNS</code>")
            && summary.contains("veil-dns-fixture@1.2.3")
    );
    println!(
        "receiver case=node-dns os={} connect=0 child=0 exit=21",
        os_label()
    );

    for (ci_val, expected) in [("false", 0), ("true", 21)] {
        let mut e = env_map.clone();
        e.insert("CI".to_string(), ci_val.to_string());
        let c = run_with_env(&demo, &[cli_s, "--json", "node", "probe.cjs"], &e, Some(expected));
        let d: Value = serde_json::from_slice(&c.stdout).unwrap();
        assert_eq!(d["child_status"]["exit_code"], 0);
        assert_eq!(d["attempted"][0]["host"], "postinstall.invalid");
    }

    let quiet = run_with_env(&demo, &[cli_s, "--json", "/usr/bin/true"], &env_map, Some(0));
    let qd: Value = serde_json::from_slice(&quiet.stdout).unwrap();
    assert_eq!(qd["attempted"], json!([]));
    assert!(!String::from_utf8_lossy(&quiet.stderr).contains("DNS attempts recorded"));

    let flood = evidence.join("dns-overflow.json");
    let flood_s = flood.to_str().unwrap();
    run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--backend",
            "isolated",
            "--report",
            flood_s,
            "--",
            "node",
            "-e",
            "const dns = require(\"node:dns\").promises; (async () => { for (let i = 0; i < 1025; i++) await dns.lookup(\"overflow\" + i + \".invalid\").catch(() => {}); })()",
        ],
        &env_map,
        Some(125),
    );
    let fd: Value = serde_json::from_str(&fs::read_to_string(&flood).unwrap()).unwrap();
    assert_eq!(fd["coverage"]["dns_attempts"], "incomplete");
    assert_eq!(fd["attempted"].as_array().unwrap().len(), 1024);
    assert_eq!(fd["destinations"], json!([]));
}

fn baseline_upgrade_test(cli: &Path, project: &Path, runtime: &Path) {
    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    let sys_path = env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    env_map.insert(
        "PATH".to_string(),
        format!("{}:{sys_path}", runtime.join("bin").display()),
    );
    let state = project.join(".veil-tell");
    fs::create_dir_all(&state).unwrap();
    let old = state.join(format!("baseline-{}.json", "a".repeat(64)));
    let data = json!({
        "schema_version": 1,
        "backend": "proxy",
        "coverage": "http_connect_requests",
        "destinations": [{"host": "allowed.test", "port": 443, "attempts": 1}]
    });
    fs::write(&old, data.to_string()).unwrap();

    let cli_s = cli.to_str().unwrap();
    let old_s = old.to_str().unwrap();
    run_with_env(
        project,
        &[cli_s, "migrate-baseline", "npm", old_s],
        &env_map,
        Some(0),
    );
    let migrated: Value =
        serde_json::from_str(&fs::read_to_string(state.join("npm.json")).unwrap()).unwrap();
    assert_eq!(migrated, data);
    assert!(old.exists());

    let preview = run_with_env(project, &[cli_s, "clean"], &env_map, Some(0));
    assert!(
        String::from_utf8_lossy(&preview.stdout)
            .contains(old.file_name().unwrap().to_str().unwrap())
    );
    assert!(old.exists());

    run_with_env(project, &[cli_s, "clean", "--apply"], &env_map, Some(0));
    assert!(!old.exists() && state.join("npm.json").exists());

    let tr = run_with_env(project, &[cli_s, "/usr/bin/true"], &env_map, Some(0));
    assert!(!String::from_utf8_lossy(&tr.stderr).contains("Baseline saved"));

    for _ in 0..5 {
        let res = run_with_env(
            project,
            &[
                cli_s,
                "npm",
                "install",
                "--offline",
                "--no-audit",
                "--no-fund",
                "--no-update-notifier",
            ],
            &env_map,
            Some(0),
        );
        let err = String::from_utf8_lossy(&res.stderr);
        assert!(err.contains("今回は未観測: allowed.test:443"));
        assert!(!err.contains("veil-tell accept") && !state.join("pending.json").exists());
    }
    if cfg!(target_os = "linux") {
        let mut e = env_map.clone();
        e.insert(
            "VEIL_TELL_BWRAP".to_string(),
            "/nonexistent/veil-bwrap".to_string(),
        );
        let res = run_with_env(project, &[cli_s, "npm", "--version"], &e, Some(0));
        assert!(
            String::from_utf8_lossy(&res.stderr).contains("Direct connections are not visible")
        );
        let strict = run_with_env(project, &[cli_s, "ci", "--", "npm", "--version"], &e, Some(125));
        assert!(strict.stdout.is_empty());
    }
    println!(
        "fixture os={} known_destination_missing=5 approvals=0 migration=ok",
        os_label()
    );
}

fn npm_destination_diff(cli: &Path, project: &Path, evidence: &Path, mut runtime: PathBuf) {
    let demo = project.join("destination-diff");
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    copy_dir_all(&fixtures_root.join("destination-diff"), &demo);
    if cfg!(target_os = "linux") {
        let local_rt = demo.join("runtime");
        copy_dir_all(&runtime, &local_rt);
        runtime = local_rt;
    }
    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    let sys_path = env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    env_map.insert(
        "PATH".to_string(),
        format!("{}:{sys_path}", runtime.join("bin").display()),
    );

    let baseline = evidence.join("npm-baseline.json");
    let report = evidence.join("npm-diff.json");
    let cli_s = cli.to_str().unwrap();
    let base_s = baseline.to_str().unwrap();
    let rep_s = report.to_str().unwrap();

    run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--backend",
            "isolated",
            "--baseline-out",
            base_s,
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(0),
    );
    let bl_data: Value = serde_json::from_str(&fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(bl_data["destinations"], json!([]));

    let automatic = run_with_env(
        &demo,
        &[
            cli_s,
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(0),
    );
    assert!(String::from_utf8_lossy(&automatic.stderr).contains("Baseline saved"));

    for _ in 0..5 {
        let stable = run_with_env(
            &demo,
            &[
                cli_s,
                "npm",
                "install",
                "--foreground-scripts",
                "--no-audit",
                "--no-fund",
                "--no-update-notifier",
                "--cache=.npm-cache",
                "--offline",
            ],
            &env_map,
            Some(0),
        );
        let err = String::from_utf8_lossy(&stable.stderr);
        assert!(err.contains("No new destinations") && !err.contains("veil-tell accept"));
        assert!(!demo.join(".veil-tell/pending.json").exists());
    }

    let linked = run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--",
            "npm",
            "ci",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(0),
    );
    assert!(String::from_utf8_lossy(&linked.stderr).contains("No new destinations"));

    let clean_report = evidence.join("npm-unchanged-summary.json");
    run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--report",
            clean_report.to_str().unwrap(),
            "--",
            "npm",
            "ci",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(0),
    );
    assert_eq!(action_summary(cli, &clean_report).lines().count(), 1);
    let npm_bl: Value =
        serde_json::from_str(&fs::read_to_string(demo.join(".veil-tell/npm.json")).unwrap())
            .unwrap();
    assert_eq!(npm_bl["backend"], "isolated");
    println!(
        "fixture os={} install_to_ci=0 offline_repeats=5 approvals=0",
        os_label()
    );

    let manifest = demo.join("package.json");
    let mut package: Value =
        serde_json::from_str(&fs::read_to_string(&manifest).unwrap()).unwrap();
    package["dependencies"] = json!({
        "veil-tell-demo-postinstall": "file:./postinstall",
        "veil-tell-demo-quiet": "file:./quiet",
    });
    fs::write(&manifest, package.to_string()).unwrap();

    let result = run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--backend",
            "isolated",
            "--baseline",
            base_s,
            "--fail-on-new",
            "--report",
            rep_s,
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(21),
    );
    assert!(action_summary(cli, &report).contains("<code>CONNECT</code>"));
    let data: Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(data["child_status"]["exit_code"], 0);
    assert_eq!(
        data["run_status"],
        json!({"exit_code": 21, "reason": "new_destination"})
    );
    let inferred = json!({
        "confidence": "inferred",
        "package": {
            "name": "veil-tell-demo-postinstall",
            "version": "1.0.0",
            "script": "postinstall",
            "path": "postinstall"
        }
    });
    assert_eq!(
        data["comparison"]["added"],
        json!([{
            "host": "postinstall.local",
            "port": 443,
            "attempts": 1,
            "attribution": [inferred]
        }])
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("quiet postinstall"));
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("postinstall.local:443 ← veil-tell-demo-postinstall@1.0.0 postinstall (postinstall) [inferred")
    );
    assert_eq!(data["destinations"][0]["attribution"], json!([inferred]));
    assert_eq!(data["destinations"][0]["reason"], "non_public_destination");

    let ci_report = evidence.join("npm-ci-diff.json");
    run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--baseline",
            base_s,
            "--report",
            ci_report.to_str().unwrap(),
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(21),
    );
    let ci_data: Value = serde_json::from_str(&fs::read_to_string(&ci_report).unwrap()).unwrap();
    assert_eq!(
        ci_data["run_status"],
        json!({"exit_code": 21, "reason": "new_destination"})
    );
    assert_eq!(ci_data["comparison"]["added"], data["comparison"]["added"]);
    assert_eq!(ci_data["destinations"][0]["reason"], "new_destination");

    let default_baseline = demo.join(".veil-tell/npm.json");
    let pending = default_baseline.with_file_name("pending.json");
    assert!(!pending.exists());
    let original = fs::read(&default_baseline).unwrap();
    let project_ci = run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(21),
    );
    assert!(String::from_utf8_lossy(&project_ci.stderr).contains("veil-tell accept"));
    assert_eq!(fs::read(&default_baseline).unwrap(), original);

    run_with_env(&demo, &[cli_s, "accept"], &env_map, Some(0));
    assert!(!pending.exists());
    let updated_bl: Value =
        serde_json::from_str(&fs::read_to_string(&default_baseline).unwrap()).unwrap();
    assert_eq!(updated_bl["destinations"], data["comparison"]["added"]);

    let stable = run_with_env(
        &demo,
        &[
            cli_s,
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(0),
    );
    assert!(String::from_utf8_lossy(&stable.stderr).contains("No new destinations"));
    println!("fixture os={} npm_exit=0 veil_tell_exit=21", os_label());

    package["dependencies"] = json!({
        "veil-tell-demo-spoof": "file:./spoof",
        "veil-tell-demo-quiet": "file:./quiet",
    });
    fs::write(&manifest, package.to_string()).unwrap();
    let spoof_report = evidence.join("npm-spoof.json");
    run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--baseline",
            base_s,
            "--report",
            spoof_report.to_str().unwrap(),
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(21),
    );
    let spoof: Value = serde_json::from_str(&fs::read_to_string(&spoof_report).unwrap()).unwrap();
    assert_eq!(spoof["child_status"]["exit_code"], 0);
    assert_eq!(spoof["run_status"]["reason"], "new_destination");
    assert_eq!(
        spoof["comparison"]["added"],
        json!([{
            "host": "spoof.local",
            "port": 443,
            "attempts": 1,
            "attribution": [{"confidence": "unknown"}]
        }])
    );
    println!("fixture os={} spoof=unknown veil_tell_exit=21", os_label());

    package["dependencies"] = json!({"veil-tell-demo-postinstall": "file:./postinstall"});
    fs::write(&manifest, package.to_string()).unwrap();
    let npmrc = demo.join(".npmrc");
    fs::write(&npmrc, "script-shell=/bin/sh\n").unwrap();
    let custom = evidence.join("npm-custom.json");
    let res = run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--baseline",
            base_s,
            "--report",
            custom.to_str().unwrap(),
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(21),
    );
    assert!(String::from_utf8_lossy(&res.stderr).contains("npm attribution is off"));
    let cust_data: Value = serde_json::from_str(&fs::read_to_string(&custom).unwrap()).unwrap();
    assert!(cust_data["destinations"][0].get("attribution").is_none());

    fs::write(&npmrc, "script-shell=/no-such-veil-test-shell\n").unwrap();
    let res_bad = run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--baseline",
            base_s,
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        None,
    );
    assert!(!res_bad.status.success());
    let err_bad = String::from_utf8_lossy(&res_bad.stderr);
    assert!(err_bad.contains("npm attribution is off") && err_bad.contains("ENOENT"));
    fs::remove_file(&npmrc).unwrap();

    let no_attr = evidence.join("npm-no-attribute.json");
    run_with_env(
        &demo,
        &[
            cli_s,
            "ci",
            "--no-attribute",
            "--baseline",
            base_s,
            "--report",
            no_attr.to_str().unwrap(),
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(21),
    );
    let na_data: Value = serde_json::from_str(&fs::read_to_string(&no_attr).unwrap()).unwrap();
    assert!(na_data["destinations"][0].get("attribution").is_none());

    let migration = project.join("migration");
    fs::create_dir_all(&migration).unwrap();
    fs::write(
        migration.join("package.json"),
        "{\"name\":\"migration\",\"version\":\"1.0.0\",\"private\":true}",
    )
    .unwrap();
    let mig_rt = if cfg!(target_os = "linux") {
        let r = migration.join("runtime");
        copy_dir_all(&runtime, &r);
        r
    } else {
        runtime
    };
    baseline_upgrade_test(cli, &migration, &mig_rt);
}

fn lockfile_destination_diff(cli: &Path, project: &Path, evidence: &Path, mut runtime: PathBuf) {
    let demo = project.join("lockfile-diff");
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    copy_dir_all(&fixtures_root.join("destination-diff"), &demo);
    if cfg!(target_os = "linux") {
        let local_rt = demo.join("runtime");
        copy_dir_all(&runtime, &local_rt);
        runtime = local_rt;
    }
    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    let sys_path = env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    env_map.insert(
        "PATH".to_string(),
        format!("{}:{sys_path}", runtime.join("bin").display()),
    );

    let main_pkg = demo.join("package.json");
    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&main_pkg).unwrap()).unwrap();
    manifest["dependencies"] = json!({
        "veil-tell-demo-postinstall": "file:./postinstall",
        "veil-tell-demo-quiet": "file:./quiet",
    });
    fs::write(&main_pkg, manifest.to_string()).unwrap();

    let original_post = demo.join("postinstall/package.json");
    let active: Value =
        serde_json::from_str(&fs::read_to_string(&original_post).unwrap()).unwrap();
    let mut old = active.clone();
    old["version"] = json!("0.9.0");
    old["scripts"] = json!({});
    fs::write(&original_post, old.to_string()).unwrap();

    let refresh_lock = || {
        run_with_env(
            &demo,
            &[
                "npm",
                "install",
                "--foreground-scripts",
                "--no-audit",
                "--no-fund",
                "--no-update-notifier",
                "--cache=.npm-cache",
                "--package-lock-only",
                "--ignore-scripts",
            ],
            &env_map,
            Some(0),
        );
    };
    refresh_lock();

    let cli_s = cli.to_str().unwrap();
    let baseline = evidence.join("locked-npm.json");
    let base_s = baseline.to_str().unwrap();
    run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--backend",
            "isolated",
            "--baseline-out",
            base_s,
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
        ],
        &env_map,
        Some(0),
    );
    let bl_data: Value = serde_json::from_str(&fs::read_to_string(&baseline).unwrap()).unwrap();
    assert!(
        bl_data["lockfile"]["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["version"] == "0.9.0")
    );
    fs::write(&original_post, active.to_string()).unwrap();
    refresh_lock();

    let compare = |base: &Path, name: &str, status: &str| {
        let rep = evidence.join(format!("lock-{name}.json"));
        let res = run_with_env(
            &demo,
            &[
                cli_s,
                "ci",
                "--baseline",
                base.to_str().unwrap(),
                "--report",
                rep.to_str().unwrap(),
                "--",
                "npm",
                "install",
                "--foreground-scripts",
                "--no-audit",
                "--no-fund",
                "--no-update-notifier",
                "--cache=.npm-cache",
            ],
            &env_map,
            Some(21),
        );
        let d: Value = serde_json::from_str(&fs::read_to_string(&rep).unwrap()).unwrap();
        assert_eq!(
            d["run_status"],
            json!({"exit_code": 21, "reason": "new_destination"})
        );
        assert_eq!(d["comparison"]["lockfile_evidence"][0]["status"], status);
        let err = String::from_utf8_lossy(&res.stderr);
        println!(
            "{}",
            err.lines().find(|l| l.contains("←")).unwrap().trim()
        );
    };

    compare(&baseline, "updated", "corroborated");
    let unchanged = evidence.join("locked-npm-unchanged.json");
    run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--backend",
            "isolated",
            "--baseline-out",
            unchanged.to_str().unwrap(),
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--cache=.npm-cache",
            "--ignore-scripts",
        ],
        &env_map,
        Some(0),
    );
    compare(&unchanged, "unchanged", "unchanged");

    manifest["dependencies"] = json!({
        "veil-tell-demo-spoof": "file:./spoof",
        "veil-tell-demo-quiet": "file:./quiet",
    });
    fs::write(&main_pkg, manifest.to_string()).unwrap();
    refresh_lock();
    compare(&baseline, "spoof", "candidates");
    println!(
        "fixture os={} lockfile=corroborated,unchanged,candidates exit=21",
        os_label()
    );
}

fn cargo_destination_diff(cli: &Path, project: &Path, evidence: &Path) {
    let demo = project.join("cargo-destination");
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    copy_dir_all(&fixtures_root.join("cargo-destination"), &demo);
    let baseline = evidence.join("locked-cargo.json");
    let report = evidence.join("cargo-diff.json");
    let env_map: BTreeMap<String, String> = env::vars().collect();

    let script = demo.join("build-probe/build.rs");
    let original = fs::read_to_string(&script).unwrap();
    fs::write(&script, "fn main() {}\n").unwrap();
    let cli_s = cli.to_str().unwrap();
    let base_s = baseline.to_str().unwrap();
    let rep_s = report.to_str().unwrap();

    run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--baseline-out",
            base_s,
            "--",
            "cargo",
            "build",
        ],
        &env_map,
        Some(0),
    );
    let bl_data: Value = serde_json::from_str(&fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(bl_data["lockfile"]["ecosystem"], "cargo");

    fs::write(&script, &original).unwrap();
    let result = run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--baseline",
            base_s,
            "--fail-on-new",
            "--report",
            rep_s,
            "--",
            "cargo",
            "build",
        ],
        &env_map,
        Some(21),
    );
    let data: Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(
        data["comparison"]["added"][0]["attribution"][0]["package"],
        json!({
            "name": "veil-build-probe",
            "version": "1.2.3",
            "script": "build.rs",
            "path": "build-probe"
        })
    );
    assert_eq!(
        data["comparison"]["lockfile_evidence"][0]["status"],
        "unchanged"
    );
    let err = String::from_utf8_lossy(&result.stderr);
    println!(
        "{}",
        err.lines().find(|l| l.contains("←")).unwrap().trim()
    );

    let warm = evidence.join("cargo-warm.json");
    run_with_env(
        &demo,
        &[
            cli_s,
            "observe",
            "--baseline",
            base_s,
            "--report",
            warm.to_str().unwrap(),
            "--",
            "cargo",
            "build",
        ],
        &env_map,
        Some(0),
    );
    let warm_data: Value = serde_json::from_str(&fs::read_to_string(&warm).unwrap()).unwrap();
    assert_eq!(warm_data["destinations"], json!([]));
    println!(
        "fixture os={} cargo=build.rs exit=21 cached_connects=0",
        os_label()
    );
}

fn destination_diff_test(
    cli: &Path,
    fixture: &Path,
    project: &Path,
    evidence: &Path,
    node_root: Option<&Path>,
) {
    let baseline = evidence.join("baseline.json");
    let changed = evidence.join("changed.json");
    let report = evidence.join("diff.json");
    let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = receiver.local_addr().unwrap();
    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    env_map.insert("VEIL_TELL_FIXTURE_RECEIVER".to_string(), addr.to_string());

    let run_and_receive = |argv: &[&str], count: usize, expected_code: i32| {
        let recv_clone = receiver.try_clone().unwrap();
        let handle = thread::spawn(move || {
            let mut payloads = Vec::new();
            for _ in 0..count {
                let (mut conn, _) = recv_clone.accept().unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut body = Vec::new();
                let mut br = BufReader::new(conn.try_clone().unwrap());
                br.read_to_end(&mut body).unwrap();
                payloads.push(body);
                conn.write_all(b"ACK").unwrap();
            }
            payloads
        });
        let res = run_with_env(project, argv, &env_map, Some(expected_code));
        let payloads = handle.join().unwrap();
        assert_eq!(payloads.len(), count);
        assert!(receive(&receiver, 0).is_empty());
        (res, payloads)
    };

    let cli_s = cli.to_str().unwrap();
    let fix_s = fixture.to_str().unwrap();
    let base_s = baseline.to_str().unwrap();
    let rep_s = report.to_str().unwrap();
    let chg_s = changed.to_str().unwrap();

    let (_, payloads) = run_and_receive(
        &[
            fix_s,
            "observe",
            "--backend",
            "isolated",
            "--baseline-out",
            base_s,
            "--",
            "./probe",
            "observe-candidates",
        ],
        2,
        0,
    );
    assert_eq!(
        payloads,
        vec![b"first-connect".to_vec(), b"second-connect".to_vec()]
    );
    let before = fs::read(&baseline).unwrap();
    let bl_val: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(
        bl_val["destinations"],
        json!([{"host": "allowed.test", "port": 443, "attempts": 2}])
    );

    let (_, payloads) = run_and_receive(
        &[
            fix_s,
            "observe",
            "--backend",
            "isolated",
            "--baseline",
            base_s,
            "--fail-on-new",
            "--report",
            rep_s,
            "--",
            "./probe",
            "new-destination",
        ],
        1,
        21,
    );
    assert_eq!(payloads, vec![b"new-connect".to_vec()]);
    let data: Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(data["schema_version"], 1);
    assert_eq!(
        data["run_status"],
        json!({"exit_code": 21, "reason": "new_destination"})
    );
    assert_eq!(data["comparison"]["added"][0]["host"], "new.test");
    assert_eq!(data["comparison"]["removed"][0]["host"], "allowed.test");

    let (res, _) = run_and_receive(
        &[
            cli_s,
            "ci",
            "--baseline",
            base_s,
            "--report",
            chg_s,
            "--",
            "./probe",
            "new-destination",
        ],
        0,
        21,
    );
    assert!(String::from_utf8_lossy(&res.stdout).contains("CONNECT=403"));
    let data: Value = serde_json::from_str(&fs::read_to_string(&changed).unwrap()).unwrap();
    assert_eq!(
        data["coverage"]["direct_attempt_destinations"],
        if cfg!(target_os = "linux") {
            "ip_port"
        } else {
            "not_observed"
        }
    );
    assert_eq!(
        data["run_status"],
        json!({"exit_code": 21, "reason": "new_destination"})
    );
    let ev = &data["destinations"][0];
    assert_eq!(ev["reason"], "new_destination");
    assert_eq!(ev["result"], "blocked");
    assert_eq!(ev["sent_bytes"], 0);
    assert_eq!(ev["received_bytes"], 0);

    let unauth = evidence.join("bad-auth.json");
    let (res, _) = run_and_receive(
        &[
            cli_s,
            "ci",
            "--attribute-npm",
            "--baseline",
            base_s,
            "--report",
            unauth.to_str().unwrap(),
            "--",
            "./probe",
            "invalid-proxy-auth",
        ],
        0,
        21,
    );
    assert!(String::from_utf8_lossy(&res.stdout).contains("CONNECT=407"));
    let data: Value = serde_json::from_str(&fs::read_to_string(&unauth).unwrap()).unwrap();
    let ev = &data["destinations"][0];
    assert_eq!(ev["attribution"], json!([{"confidence": "unknown"}]));
    assert_eq!(ev["reason"], "new_destination");
    assert_eq!(ev["result"], "blocked");
    assert_eq!(data["comparison"]["added"][0]["host"], "new.test");

    let failed = evidence.join("failed-child.json");
    run_and_receive(
        &[
            cli_s,
            "ci",
            "--baseline",
            base_s,
            "--report",
            failed.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-ec",
            "\"$@\"; exit 9",
            "probe",
            "./probe",
            "new-destination",
        ],
        0,
        21,
    );
    let data: Value = serde_json::from_str(&fs::read_to_string(&failed).unwrap()).unwrap();
    assert_eq!(data["child_status"]["exit_code"], 9);
    assert_eq!(data["comparison"]["status"], "new_destinations_only");
    assert_eq!(data["comparison"]["removed"], json!([]));

    let missing = evidence.join("missing.json");
    let (res_miss, _) = run_and_receive(
        &[
            cli_s,
            "ci",
            "--baseline",
            missing.to_str().unwrap(),
            "--",
            "/bin/echo",
            "must-not-start",
        ],
        0,
        125,
    );
    assert!(res_miss.stdout.is_empty());

    run_and_receive(
        &[
            cli_s,
            "observe",
            "--baseline-out",
            missing.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "exit 9",
        ],
        0,
        9,
    );
    assert!(!missing.exists());
    assert_eq!(fs::read(&baseline).unwrap(), before);
    println!("receiver case=destination-diff observe_payload=1 ci_payload=0 exit=21");

    if let Some(nr) = node_root {
        let nr_abs = nr.canonicalize().unwrap();
        dns_attempt_test(cli, project, evidence, nr_abs.clone());
        npm_destination_diff(cli, project, evidence, nr_abs.clone());
        lockfile_destination_diff(cli, project, evidence, nr_abs);
        cargo_destination_diff(cli, project, evidence);
    }
}

fn volume_test(
    cli: &Path,
    fixture: &Path,
    project: &Path,
    evidence: &Path,
    node_root: Option<&Path>,
) {
    let policy = evidence.join("volume.toml");
    fs::write(
        &policy,
        "version = 1\nprofile = \"volume\"\n[[rule]]\naction = \"allow\"\nhost = \"allowed.test\"\nport = 443\nmax_sent_bytes = 8192\n",
    )
    .unwrap();
    let baseline = evidence.join("volume-baseline.json");
    let upstream_baseline = evidence.join("upstream-volume-baseline.json");
    let refused_baseline = evidence.join("upstream-refused-baseline.json");

    let test_ip = env::var("VEIL_TELL_TEST_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let receiver = TcpListener::bind((test_ip.as_str(), 0)).unwrap();
    let address = receiver.local_addr().unwrap().to_string();
    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    env_map.insert("VEIL_TELL_FIXTURE_RECEIVER".to_string(), address.clone());

    let pol_s = policy.display().to_string();
    let base_s = baseline.display().to_string();
    let up_base_s = upstream_baseline.display().to_string();
    let ref_base_s = refused_baseline.display().to_string();

    let mut cases: Vec<(&str, Vec<String>, usize, usize, i32)> = vec![
        (
            "train",
            vec!["observe".into(), "--baseline-out".into(), base_s.clone()],
            4096,
            4096,
            0,
        ),
        (
            "observe",
            vec!["observe".into(), "--baseline".into(), base_s.clone()],
            524288,
            524288,
            21,
        ),
        ("no-baseline", vec!["observe".into()], 524288, 524288, 0),
        (
            "restrict",
            vec!["restrict".into(), "--policy".into(), pol_s.clone()],
            524288,
            8192,
            22,
        ),
        (
            "ci",
            vec!["ci".into(), "--baseline".into(), base_s],
            524288,
            131072,
            22,
        ),
        (
            "upstream-train",
            vec![
                "observe".into(),
                "--baseline-out".into(),
                up_base_s.clone(),
            ],
            4096,
            4096,
            0,
        ),
        (
            "upstream-observe",
            vec!["observe".into(), "--baseline".into(), up_base_s.clone()],
            524288,
            524288,
            21,
        ),
        (
            "upstream-ci",
            vec!["ci".into(), "--baseline".into(), up_base_s],
            524288,
            131072,
            22,
        ),
        (
            "upstream-refused",
            vec!["observe".into(), "--baseline-out".into(), ref_base_s],
            0,
            0,
            0,
        ),
    ];

    let demo = project.join("volume-demo");
    if let Some(nr) = node_root {
        fs::create_dir_all(&demo).unwrap();
        let mut runtime = nr.canonicalize().unwrap();
        if cfg!(target_os = "linux") {
            let local_rt = demo.join("runtime");
            copy_dir_all(&runtime, &local_rt);
            runtime = local_rt;
        }
        let old_path = env_map.get("PATH").cloned().unwrap_or_default();
        env_map.insert(
            "PATH".to_string(),
            format!("{}:{old_path}", runtime.join("bin").display()),
        );
        fs::copy(project.join("probe"), demo.join("probe")).unwrap();
        let inst_base = evidence
            .join("install-volume-baseline.json")
            .display()
            .to_string();
        cases.extend([
            (
                "install-train",
                vec![
                    "observe".into(),
                    "--baseline-out".into(),
                    inst_base.clone(),
                ],
                4096,
                4096,
                0,
            ),
            (
                "install-observe",
                vec!["observe".into(), "--baseline".into(), inst_base.clone()],
                524288,
                524288,
                21,
            ),
            (
                "install-ci",
                vec!["ci".into(), "--baseline".into(), inst_base],
                524288,
                131072,
                22,
            ),
            (
                "install-restrict",
                vec!["restrict".into(), "--policy".into(), pol_s],
                524288,
                8192,
                22,
            ),
        ]);
    }

    for (name, arguments, sent, expected, code) in cases {
        let via_upstream = name.starts_with("upstream-");
        let refused = name == "upstream-refused";
        let recv_clone = receiver.try_clone().unwrap();
        let handle = thread::spawn(move || {
            let (mut conn, _) = recv_clone.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            if via_upstream {
                let host = if refused { "new.test" } else { "allowed.test" };
                assert_eq!(
                    upstream_connect(&mut reader),
                    format!("CONNECT {host}:443 HTTP/1.1\r\n")
                );
                if refused {
                    let _ = conn.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
                    let mut rest = Vec::new();
                    let _ = reader.read_to_end(&mut rest);
                    return rest.len();
                }
                conn.write_all(b"HTTP/1.1 200 Established\r\n\r\n").unwrap();
            }
            let mut body = Vec::new();
            let _ = reader.read_to_end(&mut body);
            let _ = conn.write_all(b"ACK");
            body.len()
        });

        let report = evidence.join(format!("volume-{name}.json"));
        let install = name.starts_with("install-");
        let cmd_tail: Vec<String> = if install {
            fs::write(
                demo.join("package.json"),
                json!({
                    "name": "veil-volume-fixture",
                    "version": "1.2.3",
                    "private": true,
                    "scripts": {"postinstall": format!("./probe volume {sent}")}
                })
                .to_string(),
            )
            .unwrap();
            vec![
                "npm".into(),
                "install".into(),
                "--no-audit".into(),
                "--no-fund".into(),
                "--no-update-notifier".into(),
            ]
        } else if refused {
            vec!["./probe".into(), "new-destination".into()]
        } else {
            vec!["./probe".into(), "volume".into(), sent.to_string()]
        };

        let bin_path = if via_upstream { cli } else { fixture };
        let mut full_args = vec![bin_path.display().to_string()];
        full_args.extend(arguments.clone());
        if arguments[0] != "ci" {
            full_args.extend(["--backend".into(), "isolated".into()]);
        }
        full_args.extend([
            "--report".into(),
            report.display().to_string(),
            "--".into(),
        ]);
        full_args.extend(cmd_tail);

        let mut run_env = env_map.clone();
        if via_upstream {
            run_env.insert("HTTPS_PROXY".to_string(), format!("http://{address}"));
            run_env.insert("NO_PROXY".to_string(), String::new());
        }
        let full_refs: Vec<&str> = full_args.iter().map(String::as_str).collect();
        let child = run_with_env(
            if install { &demo } else { project },
            &full_refs,
            &run_env,
            Some(code),
        );
        let received_len = handle.join().unwrap();
        assert_eq!(received_len, expected);

        let result: Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
        assert_eq!(result["child_status"]["exit_code"], 0);
        let destination = &result["destinations"][0];
        assert_eq!(destination["sent_bytes"], expected);
        if via_upstream {
            assert_eq!(destination["via_upstream_proxy"], true);
            assert!(destination["connected_ip"].is_null());
        }
        if name == "upstream-train" {
            let ub: Value =
                serde_json::from_str(&fs::read_to_string(&upstream_baseline).unwrap()).unwrap();
            assert_eq!(
                ub["volume"]["allowed.test"],
                json!({
                    "sent_bytes": expected,
                    "max_connection_bytes": expected,
                    "connections": 1
                })
            );
        }
        if refused {
            assert_eq!(destination["result"], "connect_failed");
            let rb: Value =
                serde_json::from_str(&fs::read_to_string(&refused_baseline).unwrap()).unwrap();
            assert!(rb.get("volume").is_none());
        }
        if code != 0 {
            let anomaly = &result["volume_anomalies"][0];
            assert_eq!(anomaly["blocked"], code == 22);
            assert_eq!(
                anomaly["observed"],
                json!({
                    "sent_bytes": expected,
                    "max_connection_bytes": expected,
                    "connections": 1
                })
            );
            assert_eq!(
                result["run_status"]["reason"],
                if code == 22 {
                    "volume_limit_exceeded"
                } else {
                    "volume_anomaly"
                }
            );
            if install {
                let source = &anomaly["attribution"][0];
                assert_eq!(source["package"]["name"], "veil-volume-fixture");
                assert_eq!(source["package"]["script"], "postinstall");
            }
            let err = String::from_utf8_lossy(&child.stderr);
            println!(
                "{}",
                err.lines().find(|l| l.contains("volume anomaly")).unwrap()
            );
        } else {
            assert!(
                result
                    .get("volume_anomalies")
                    .and_then(Value::as_array)
                    .is_none_or(|a| a.is_empty())
            );
        }
        if name == "install-ci" {
            let summary = action_summary(cli, &report);
            assert!(
                summary.contains("Volume limit cut") && summary.contains("bytes 131072/262144")
            );
            assert!(
                summary.contains("veil-volume-fixture@1.2.3") && summary.contains("切断")
            );
        }
        println!(
            "receiver case=volume-{name} os={} bytes={expected} child=0 exit={code}",
            os_label()
        );
    }
}

fn linux_shorthand_startup(cli: &Path, project: &Path) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("VEIL_TELL_BWRAP");
    env_map.remove("CI");

    let cli_s = cli.to_str().unwrap();
    let result = run_with_env(
        project,
        &[
            cli_s,
            "--json",
            "/bin/sh",
            "-c",
            "echo started >> starts; sleep 6; exit 125",
        ],
        &env_map,
        Some(125),
    );
    assert_eq!(
        fs::read_to_string(project.join("starts")).unwrap(),
        "started\n"
    );
    let rep: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(rep["backend"], "isolated");
    assert!(!String::from_utf8_lossy(&result.stderr).contains("observing via proxy"));

    for strict in [false, true] {
        let mut e = env_map.clone();
        e.insert(
            "CI".to_string(),
            if strict { "1" } else { "0" }.to_string(),
        );
        let res = run_with_env(
            Path::new("/"),
            &[cli_s, "--json", "/bin/echo", "payload-ran"],
            &e,
            Some(if strict { 125 } else { 0 }),
        );
        let err = String::from_utf8_lossy(&res.stderr);
        if strict {
            assert!(!err.contains("payload-ran") && err.contains("CI requires isolation"));
            assert!(res.stdout.is_empty());
        } else {
            let d: Value = serde_json::from_slice(&res.stdout).unwrap();
            assert_eq!(d["backend"], "proxy");
            assert_eq!(err.lines().filter(|l| *l == "payload-ran").count(), 1);
        }
    }
    println!(
        "receiver case=linux-shorthand-startup once=1 child_exit=125 fallback=proxy ci=125"
    );
}

fn output_and_upstream_test(cli: &Path, project: &Path) {
    let env_map: BTreeMap<String, String> = env::vars().collect();
    let cli_s = cli.to_str().unwrap();

    let missing = run_with_env(
        project,
        &[cli_s, "veil-tell-command-does-not-exist"],
        &env_map,
        None,
    );
    assert!(!missing.status.success());
    assert_eq!(
        String::from_utf8_lossy(&missing.stderr)
            .matches("Next / 次:")
            .count(),
        1
    );

    let denied = run_with_env(
        project,
        &[cli_s, "curl", "-fsS", "https://example.local"],
        &env_map,
        None,
    );
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr)
            .contains("Next / 次: veil-tell denied example.local:443 (non_public_destination)")
    );

    let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = receiver.local_addr().unwrap().port();
    let mut up_env = env_map.clone();
    up_env.insert("NO_PROXY".to_string(), String::new());
    up_env.insert("no_proxy".to_string(), String::new());
    up_env.insert(
        "HTTPS_PROXY".to_string(),
        format!("http://trial:fixture-secret@127.0.0.1:{port}"),
    );

    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut conn, _) = receiver.accept().unwrap();
            let mut br = BufReader::new(conn.try_clone().unwrap());
            let mut req_lines = Vec::new();
            loop {
                let mut line = String::new();
                br.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                req_lines.push(line);
            }
            requests.push(req_lines);
            conn.write_all(b"HTTP/1.1 200 Established\r\n\r\n").unwrap();
            let mut body = Vec::new();
            br.read_to_end(&mut body).unwrap();
            conn.write_all(b"ACK").unwrap();
        }
        requests
    });

    let result = run_with_env(
        project,
        &[
            cli_s,
            "observe",
            "--json",
            "--",
            "./probe",
            "observe-candidates",
        ],
        &up_env,
        Some(0),
    );
    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 2);
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"trial:fixture-secret");
    for r in &requests {
        assert_eq!(r[0], "CONNECT allowed.test:443 HTTP/1.1\r\n");
        assert!(
            r.iter()
                .any(|l| l == &format!("Proxy-Authorization: Basic {encoded}\r\n"))
        );
    }
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!combined.contains("fixture-secret") && !combined.contains(&encoded));
    let rep: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(rep["destinations"][0]["via_upstream_proxy"], true);
    let stderr_str = String::from_utf8_lossy(&result.stderr);
    let err_lines: Vec<&str> = stderr_str
        .lines()
        .filter(|l| l.starts_with("veil-tell: allowed.test:"))
        .collect();
    assert_eq!(
        err_lines,
        vec!["veil-tell: allowed.test:443 allow observe ×2"]
    );

    if !cfg!(target_os = "linux") {
        println!("SKIP direct_attempts: Linux seccomp notification test");
        return;
    }

    for (cmd, exp_port) in [
        (vec!["./probe", "probe", "192.0.2.1:443", "direct-ip"], 443u64),
        (
            vec![
                "curl",
                "--noproxy",
                "*",
                "--max-time",
                "2",
                "https://example.invalid",
            ],
            53u64,
        ),
    ] {
        let mut args = vec![cli_s, "observe", "--backend", "isolated", "--json", "--"];
        args.extend(cmd);
        let trial = run_with_env(project, &args, &env_map, None);
        let data: Value = serde_json::from_slice(&trial.stdout).unwrap();
        assert_eq!(data["coverage"]["direct_attempt_destinations"], "ip_port");
        assert!(
            data["direct_attempts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["attempts"].as_u64().unwrap() >= 1 && r["port"] == exp_port)
        );
    }
}

const NPM_REGISTRY_SERVER_CJS: &str = r#"
const https = require('node:https');
const fs = require('node:fs');

const [portStr, ip, certPath, keyPath, metaPath, tgzPath, tgzUrlPath, logPath] = process.argv.slice(2);
const cert = fs.readFileSync(certPath);
const key = fs.readFileSync(keyPath);
const metadata = fs.readFileSync(metaPath);
const tarball = fs.readFileSync(tgzPath);

const server = https.createServer({cert, key}, (req, res) => {
  fs.appendFileSync(logPath, req.url + '\n');
  let body = null;
  if (req.url === '/veil-cli-fixture') body = metadata;
  else if (req.url === tgzUrlPath) body = tarball;
  if (!body) {
    res.writeHead(404);
    res.end();
    return;
  }
  res.writeHead(200, {'Content-Length': body.length});
  res.end(body);
});

server.listen(Number(portStr), ip, () => {
  console.log('READY');
});
"#;

fn npm_test(
    fixture: &Path,
    mut runtime: PathBuf,
    project: &Path,
    evidence: &Path,
    policy: &Path,
    ip: &str,
) {
    if cfg!(target_os = "linux") {
        let local_rt = project.join("runtime");
        copy_dir_all(&runtime, &local_rt);
        runtime = local_rt;
    }
    let cert = project.join("registry.crt");
    let key = evidence.join("registry.key");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=allowed.test",
            "-addext",
            "subjectAltName=DNS:allowed.test",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    let pkg_dir = evidence.join("tar-pkg/package");
    fs::create_dir_all(&pkg_dir).unwrap();
    let pkg = json!({"name": "veil-cli-fixture", "version": "1.0.0"});
    fs::write(pkg_dir.join("package.json"), pkg.to_string()).unwrap();
    fs::write(pkg_dir.join("installed.txt"), "received").unwrap();
    let tgz_file = evidence.join("veil-cli-fixture-1.0.0.tgz");
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&tgz_file)
        .arg("-C")
        .arg(evidence.join("tar-pkg"))
        .arg("package")
        .status()
        .unwrap();
    assert!(status.success());

    let tarball = fs::read(&tgz_file).unwrap();
    let tgz_url_path = "/veil-cli-fixture/-/veil-cli-fixture-1.0.0.tgz";
    let digest = Sha512::digest(&tarball);
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    );
    let metadata = json!({
        "name": "veil-cli-fixture",
        "version": "1.0.0",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "veil-cli-fixture",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("https://allowed.test{tgz_url_path}"),
                    "integrity": integrity
                }
            }
        }
    });
    let meta_file = evidence.join("npm-meta.json");
    fs::write(&meta_file, metadata.to_string()).unwrap();

    fs::write(
        project.join("package.json"),
        json!({
            "name": "veil-cli-test-project",
            "version": "1.0.0",
            "private": true,
            "dependencies": {"veil-cli-fixture": "1.0.0"}
        })
        .to_string(),
    )
    .unwrap();

    let server_port = {
        let l = TcpListener::bind((ip, 0)).unwrap();
        l.local_addr().unwrap().port()
    };
    let srv_script = evidence.join("npm_server.cjs");
    fs::write(&srv_script, NPM_REGISTRY_SERVER_CJS).unwrap();
    let req_log = evidence.join("npm_requests.log");
    fs::write(&req_log, "").unwrap();

    let node_bin = runtime.join("bin/node");
    let mut server = Command::new(&node_bin)
        .arg(&srv_script)
        .args([&server_port.to_string(), ip])
        .arg(&cert)
        .arg(&key)
        .arg(&meta_file)
        .arg(&tgz_file)
        .arg(tgz_url_path)
        .arg(&req_log)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut line = String::new();
        let mut br = BufReader::new(server.stdout.take().unwrap());
        br.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "READY");
    }

    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    let sys_path = env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    env_map.insert(
        "VEIL_TELL_FIXTURE_RECEIVER".to_string(),
        format!("{ip}:{server_port}"),
    );
    env_map.insert(
        "PATH".to_string(),
        format!("{}:{sys_path}", runtime.join("bin").display()),
    );

    let fix_s = fixture.to_str().unwrap();
    let pol_s = policy.to_str().unwrap();
    let npm_rep = evidence.join("npm.json");
    let result = run_with_env(
        project,
        &[
            fix_s,
            "restrict",
            "--backend",
            "isolated",
            "--policy",
            pol_s,
            "--fail-on-unknown",
            "--report",
            npm_rep.to_str().unwrap(),
            "--",
            "npm",
            "install",
            "--registry=https://allowed.test",
            "--cafile=registry.crt",
            "--cache=.npm-cache",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--fetch-retries=0",
        ],
        &env_map,
        Some(0),
    );

    let node_s = node_bin.to_str().unwrap();
    for backend in ["proxy", "isolated"] {
        for probe_js in [
            "fetch('https://allowed.test/veil-cli-fixture').then(r=>r.json()).then(r=>console.log(r.name))",
            "require('node:https').get('https://allowed.test/veil-cli-fixture',{ca:require('fs').readFileSync('registry.crt')},r=>r.pipe(process.stdout))",
        ] {
            let code = format!(
                "const tls=require('node:tls');tls.setDefaultCACertificates([require('fs').readFileSync('registry.crt','utf8')]);{probe_js}"
            );
            let child = run_with_env(
                project,
                &[
                    fix_s,
                    "observe",
                    "--backend",
                    backend,
                    "--json",
                    "--",
                    node_s,
                    "--use-openssl-ca",
                    "-e",
                    &code,
                ],
                &env_map,
                Some(0),
            );
            assert!(String::from_utf8_lossy(&child.stderr).contains("veil-cli-fixture"));
            let d: Value = serde_json::from_slice(&child.stdout).unwrap();
            let row = &d["destinations"][0];
            assert_eq!(row["host"], "allowed.test");
            assert_eq!(row["attempts"], 1);
            assert_eq!(row["result"], "completed");
        }
    }

    run_with_env(
        project,
        &[
            fix_s,
            "npm",
            "ci",
            "--registry=https://allowed.test",
            "--cafile=registry.crt",
            "--cache=.npm-training-cache",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--fetch-retries=0",
        ],
        &env_map,
        Some(0),
    );

    for i in 0..5 {
        let sub = if i % 2 == 0 { "ci" } else { "install" };
        let rep = run_with_env(
            project,
            &[
                fix_s,
                "ci",
                "--json",
                "--",
                "npm",
                sub,
                "--registry=https://allowed.test",
                "--cafile=registry.crt",
                "--cache=.npm-cache",
                "--no-audit",
                "--no-fund",
                "--no-update-notifier",
                "--fetch-retries=0",
            ],
            &env_map,
            Some(0),
        );
        let d: Value = serde_json::from_slice(&rep.stdout).unwrap();
        assert!(
            d.get("volume_anomalies")
                .and_then(Value::as_array)
                .is_none_or(|a| a.is_empty())
        );
        assert!(!project.join(".veil-tell/pending.json").exists());
    }
    println!(
        "receiver case=npm-volume-repeats os={} repeats=5 anomalies=0",
        os_label()
    );

    let _ = server.kill();
    let _ = server.wait();

    let reqs: Vec<String> = fs::read_to_string(&req_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(&reqs[..2], &["/veil-cli-fixture", tgz_url_path]);
    assert_eq!(
        fs::read_to_string(project.join("node_modules/veil-cli-fixture/installed.txt")).unwrap(),
        "received"
    );
    println!(
        "receiver case=npm requests={reqs:?} exit={}",
        result.status.code().unwrap()
    );
}

fn run_suite(cli: &Path, fixture: &Path, node_root: Option<&Path>) {
    let cli = cli.canonicalize().unwrap();
    let fixture = fixture.canonicalize().unwrap();
    let self_exe = env::current_exe().unwrap().canonicalize().unwrap();
    let ip = env::var("VEIL_TELL_TEST_IP").unwrap_or_else(|_| "127.0.0.1".to_string());

    let tmp = tempfile::Builder::new()
        .prefix("veil-cli-test-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let project = root.join("project");
    let evidence = root.join("evidence");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&evidence).unwrap();
    fs::copy(&self_exe, project.join("probe")).unwrap();

    linux_shorthand_startup(&cli, &project);
    output_and_upstream_test(&cli, &project);

    let mut policies = BTreeMap::new();
    for action in ["unknown", "allow", "deny"] {
        let path = evidence.join(format!("{action}.toml"));
        let rule = if action == "unknown" {
            String::new()
        } else {
            format!("\n[[rule]]\naction=\"{action}\"\nhost=\"allowed.test\"\nport=443\n")
        };
        fs::write(&path, format!("version=1\nprofile=\"receiver-test\"\n{rule}")).unwrap();
        policies.insert(action, path);
    }

    {
        let receiver = TcpListener::bind((ip.as_str(), 0)).unwrap();
        let address = receiver.local_addr().unwrap().to_string();
        let mut env_map: BTreeMap<String, String> = env::vars().collect();
        env_map.remove("CI");
        env_map.insert("VEIL_TELL_FIXTURE_RECEIVER".to_string(), address.clone());

        emit_policy_test(&cli, &fixture, &receiver, &project, &evidence, &env_map);

        let direct_err = direct_error_name();
        let cases: Vec<(
            &str,
            &Path,
            &str,
            &str,
            bool,
            i32,
            u16,
            &str,
            Vec<&[u8]>,
        )> = vec![
            (
                "proxy-control",
                &fixture,
                "proxy",
                "unknown",
                false,
                0,
                403,
                "sent",
                vec![b"proxy-control-direct"],
            ),
            (
                "isolated-allow",
                &fixture,
                "isolated",
                "allow",
                true,
                0,
                200,
                direct_err,
                vec![b"isolated-allow-connect"],
            ),
            (
                "isolated-unknown",
                &cli,
                "isolated",
                "unknown",
                true,
                20,
                403,
                direct_err,
                vec![],
            ),
            (
                "isolated-deny",
                &cli,
                "isolated",
                "deny",
                true,
                0,
                403,
                direct_err,
                vec![],
            ),
        ];

        for (name, binary, backend, action, ci, exit_code, proxy_code, direct, tokens) in cases {
            let report_path = evidence.join(format!("{name}.json"));
            let mut argv = vec![
                binary.to_str().unwrap().to_string(),
                "restrict".into(),
                "--backend".into(),
                backend.into(),
                "--policy".into(),
                policies[action].display().to_string(),
                "--report".into(),
                report_path.display().to_string(),
            ];
            if ci {
                argv.push("--fail-on-unknown".into());
            }
            argv.extend([
                "--".into(),
                "./probe".into(),
                "probe".into(),
                address.clone(),
                name.into(),
            ]);

            let handle = if proxy_code == 200 {
                let recv_clone = receiver.try_clone().unwrap();
                Some(thread::spawn(move || {
                    let (mut conn, _) = recv_clone.accept().unwrap();
                    conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let mut body = Vec::new();
                    let mut br = BufReader::new(conn.try_clone().unwrap());
                    br.read_to_end(&mut body).unwrap();
                    conn.write_all(b"ACK").unwrap();
                    body
                }))
            } else {
                None
            };

            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            let child = run_with_env(&project, &argv_refs, &env_map, Some(exit_code));
            let stdout_s = String::from_utf8_lossy(&child.stdout);
            assert!(stdout_s.contains(&format!("CONNECT={proxy_code}\n")));
            assert!(stdout_s.contains(&format!("direct={direct}\n")));

            let mut collected = Vec::new();
            if let Some(h) = handle {
                collected.push(h.join().unwrap());
            }
            collected.extend(receive(&receiver, tokens.len() - collected.len()));
            let exp_tokens: Vec<Vec<u8>> = tokens.iter().map(|t| t.to_vec()).collect();
            assert_eq!(collected, exp_tokens);

            let report: Value =
                serde_json::from_str(&fs::read_to_string(&report_path).unwrap()).unwrap();
            let expected_reason = match action {
                "allow" => "allow_rule",
                "unknown" => "unknown_destination",
                "deny" => "explicit_deny",
                _ => unreachable!(),
            };
            assert_eq!(report["schema_version"], 1);
            assert_eq!(report["backend"], backend);
            assert_eq!(report["child_status"]["exit_code"], 0);
            assert_eq!(report["run_status"]["exit_code"], exit_code);
            assert_eq!(
                report["coverage"]["direct_attempt_destinations"],
                if backend == "isolated" && cfg!(target_os = "linux") {
                    "ip_port"
                } else {
                    "not_observed"
                }
            );
            assert_eq!(report["coverage"]["proxy"], "http_connect_requests");
            assert_eq!(report["destinations"].as_array().unwrap().len(), 1);
            assert_eq!(report["destinations"][0]["reason"], expected_reason);
            println!(
                "receiver case={name} connections={} exit={exit_code}",
                collected.len()
            );
        }

        let connected = TcpStream::connect(receiver.local_addr().unwrap()).unwrap();
        let dup_fd = unsafe { libc::fcntl(connected.as_raw_fd(), libc::F_DUPFD, 20) };
        assert!(dup_fd >= 20);
        drop(connected);

        let mut cmd = Command::new(&cli);
        cmd.args(["restrict", "--backend", "isolated", "--policy"])
            .arg(&policies["unknown"])
            .args(["--", "./probe", "fd", &dup_fd.to_string()])
            .current_dir(&project);
        unsafe {
            cmd.pre_exec(move || {
                let flags = libc::fcntl(dup_fd, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(dup_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                }
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        unsafe {
            libc::close(dup_fd);
        }
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("EBADF"));
        assert_eq!(receive(&receiver, 1), vec![Vec::<u8>::new()]);
        println!("receiver case=inherited-fd connections=1 payload_bytes=0 errno=EBADF");
    }

    volume_test(&cli, &fixture, &project, &evidence, node_root);
    destination_diff_test(&cli, &fixture, &project, &evidence, node_root);
    if let Some(nr) = node_root {
        npm_test(
            &fixture,
            nr.canonicalize().unwrap(),
            &project,
            &evidence,
            &policies["allow"],
            &ip,
        );
    }
    println!("PASS: CLI receiver, exit status, and JSON checks");
}

fn main() {
    unsafe {
        env::remove_var("CI");
    }
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("probe") => probe(&args[2], &args[3]),
        Some("invalid-proxy-auth") => connect_probe("new.test", "new", Some("aW52YWxpZA==")),
        Some("new-destination") => connect_probe("new.test", "new", None),
        Some("observe-candidates") => {
            connect_probe("ALLOWED.test.", "first", None);
            connect_probe("allowed.test", "second", None);
        }
        Some("volume") => volume_probe(args[2].parse().unwrap()),
        Some("fd") => fd_probe(args[2].parse().unwrap()),
        _ => {
            let cli = Path::new(&args[1]);
            let fixture = Path::new(&args[2]);
            let node_root = args.get(3).map(Path::new);
            run_suite(cli, fixture, node_root);
        }
    }
}
