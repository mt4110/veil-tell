//! Exercise the CLI and check payloads from the receiver side on macOS and Linux in Rust
//! (replaces tests/receivers.py).

#[path = "support/receivers_diff.rs"]
mod receivers_diff;
#[path = "support/receivers_lock_and_volume.rs"]
mod receivers_lock_and_volume;
#[path = "support/receivers_npm.rs"]
mod receivers_npm;

use base64::Engine;
use receivers_lock_and_volume::{destination_diff_test, volume_test};
use receivers_npm::npm_test;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub(crate) fn os_label() -> &'static str {
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

pub(crate) fn copy_dir_all(src: &Path, dst: &Path) {
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

pub(crate) fn receive(listener: &TcpListener, count: usize) -> Vec<Vec<u8>> {
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

pub(crate) fn action_summary(cli: &Path, report: &Path) -> String {
    let out = Command::new(cli)
        .arg("summary")
        .arg(report)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub(crate) fn upstream_connect(reader: &mut BufReader<TcpStream>) -> String {
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

pub(crate) fn run_with_env(
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
