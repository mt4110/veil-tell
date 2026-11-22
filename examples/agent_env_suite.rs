//! Exercise the generated shell environment with local curl and npm TLS clients in Rust.

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpListener;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let dest_path = dst.join(entry.file_name());
        if ty.is_symlink() {
            let target = fs::read_link(entry.path()).unwrap();
            std::os::unix::fs::symlink(target, dest_path).unwrap();
        } else if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_path);
        } else {
            fs::copy(entry.path(), dest_path).unwrap();
        }
    }
}

fn free_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn open_pty_pair() -> (std::fs::File, std::fs::File) {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
        let name_ptr = libc::ptsname(master);
        assert!(!name_ptr.is_null(), "ptsname failed");
        let slave = libc::open(name_ptr, libc::O_RDWR | libc::O_NOCTTY);
        assert!(slave >= 0, "open slave pty failed");
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    }
}

const REGISTRY_AND_UPSTREAM_CJS: &str = r#"
const https = require('node:https');
const http = require('node:http');
const tls = require('node:tls');
const fs = require('node:fs');

const [mode, portStr, certPath, keyPath, metaPath, tgzPath, logPath, upstreamAuth, targetPortStr] = process.argv.slice(2);
const port = Number(portStr);
const cert = fs.readFileSync(certPath);
const key = fs.readFileSync(keyPath);
const metadata = fs.readFileSync(metaPath);
const tarball = fs.readFileSync(tgzPath);

function handleRegistry(req, res) {
  fs.appendFileSync(logPath, req.url + '\n');
  const body = req.url === '/sample.tgz' ? tarball : metadata;
  res.writeHead(200, {'Content-Length': body.length});
  res.end(body);
}

if (mode === 'registry') {
  const server = https.createServer({cert, key}, handleRegistry);
  server.listen(port, '127.0.0.1', () => {
    console.log('READY');
  });
} else if (mode === 'upstream') {
  const server = http.createServer((req, res) => {
    res.writeHead(405);
    res.end();
  });
  server.on('connect', (req, clientSocket, head) => {
    const allowed = (req.url === 'new.test:443' || req.url === 'allowed.test:443');
    const authOk = req.headers['proxy-authorization'] === 'Basic ' + upstreamAuth;
    if (!allowed || !authOk) {
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    fs.appendFileSync(logPath, 'TUNNEL:' + req.url + '\n');
    clientSocket.write('HTTP/1.1 200 Established\r\n\r\n');
    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      cert,
      key,
    });
    const fakeServer = new https.Server({cert, key}, handleRegistry);
    fakeServer.emit('secureConnection', tlsSocket);
    if (head && head.length > 0) {
      tlsSocket.unshift(head);
    }
  });
  server.listen(port, '127.0.0.1', () => {
    console.log('READY');
  });
}
"#;

pub fn trial(fixture: &Path, node_root: &Path, cache: bool) {
    let fixture = fixture.canonicalize().unwrap();
    let self_exe = env::current_exe().unwrap().canonicalize().unwrap();
    let tmp = tempfile::Builder::new()
        .prefix("veil-agent-env-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let project = root.join("project");
    let home = root.join("home");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&home).unwrap();

    let ca = project.join("registry.crt");
    let key = root.join("key.pem");
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
            "subjectAltName=DNS:allowed.test,DNS:new.test,IP:127.0.0.1",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&ca)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    let pkg_dir = root.join("tar-build/package");
    fs::create_dir_all(&pkg_dir).unwrap();
    let pkg_json = json!({"name": "sample", "version": "1.0.0"});
    fs::write(pkg_dir.join("package.json"), pkg_json.to_string()).unwrap();
    let tgz_path = root.join("sample.tgz");
    let status = Command::new("tar")
        .args(["-czf"])
        .arg(&tgz_path)
        .args(["-C"])
        .arg(root.join("tar-build"))
        .arg("package")
        .status()
        .unwrap();
    assert!(status.success());
    let tarball = fs::read(&tgz_path).unwrap();
    let digest = Sha512::digest(&tarball);
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    );
    let metadata = json!({
        "name": "sample",
        "versions": {
            "1.0.0": {
                "name": "sample",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://allowed.test/sample.tgz",
                    "integrity": integrity
                }
            }
        },
        "dist-tags": {"latest": "1.0.0"}
    });
    let meta_path = root.join("metadata.json");
    fs::write(&meta_path, metadata.to_string()).unwrap();

    let mut runtime = node_root.canonicalize().unwrap();
    if cfg!(target_os = "linux") {
        let local_rt = project.join("runtime");
        copy_dir_all(&runtime, &local_rt);
        runtime = local_rt;
    }
    let node_bin = runtime.join("bin/node");
    let server_script = root.join("server.cjs");
    fs::write(&server_script, REGISTRY_AND_UPSTREAM_CJS).unwrap();
    let requests_log = root.join("requests.log");
    fs::write(&requests_log, "").unwrap();

    let reg_port = free_local_port();
    let mut reg_server = Command::new(&node_bin)
        .arg(&server_script)
        .args(["registry", &reg_port.to_string()])
        .arg(&ca)
        .arg(&key)
        .arg(&meta_path)
        .arg(&tgz_path)
        .arg(&requests_log)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut line = String::new();
        let mut br = std::io::BufReader::new(reg_server.stdout.take().unwrap());
        std::io::BufRead::read_line(&mut br, &mut line).unwrap();
        assert_eq!(line.trim(), "READY");
    }

    let path_env = format!(
        "{}:{}",
        runtime.join("bin").display(),
        env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string())
    );
    let mut base_env: BTreeMap<String, String> = env::vars().collect();
    base_env.remove("CI");
    base_env.remove("VEIL_TELL_LOG");
    base_env.insert("HOME".to_string(), home.display().to_string());
    base_env.insert(
        "XDG_STATE_HOME".to_string(),
        root.join("state").display().to_string(),
    );
    base_env.insert(
        "VEIL_TELL_FIXTURE_RECEIVER".to_string(),
        format!("127.0.0.1:{reg_port}"),
    );
    base_env.insert("NO_PROXY".to_string(), "*".to_string());
    base_env.insert("PATH".to_string(), path_env);

    let run_cmd = |cmd: &[&str],
                   expected: Option<i32>,
                   extra: Option<&BTreeMap<String, String>>,
                   stdin_data: Option<&[u8]>|
     -> std::process::Output {
        let mut c = Command::new(cmd[0]);
        c.args(&cmd[1..]).current_dir(&project).env_clear();
        for (k, v) in &base_env {
            c.env(k, v);
        }
        if let Some(ext) = extra {
            for (k, v) in ext {
                c.env(k, v);
            }
        }
        if stdin_data.is_some() {
            c.stdin(Stdio::piped());
        }
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        if let Some(input) = stdin_data {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        if let Some(code) = expected {
            assert_eq!(
                out.status.code(),
                Some(code),
                "cmd={cmd:?}\nstdout={}\nstderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        out
    };

    let fixture_str = fixture.to_str().unwrap();
    let setup = String::from_utf8(
        run_cmd(&[fixture_str, "agent-env"], Some(0), None, None).stdout,
    )
    .unwrap();

    let shell = |args: &[&str],
                 expected: Option<i32>,
                 extra: Option<&BTreeMap<String, String>>,
                 stdin_data: Option<&[u8]>|
     -> std::process::Output {
        let script = format!("{setup}\nexec \"$@\"");
        let mut full = vec!["/bin/sh", "-c", &script, "test"];
        full.extend_from_slice(args);
        run_cmd(&full, expected, extra, stdin_data)
    };

    let ca_flag = format!("--cafile={}", ca.display());
    let npm_args = [
        "npm",
        "install",
        "sample@1.0.0",
        "--registry=https://allowed.test",
        &ca_flag,
        "--no-audit",
        "--no-fund",
        "--fetch-retries=0",
    ];

    if cache {
        let mut opts = BTreeMap::new();
        opts.insert("VEIL_TELL_CACHE".to_string(), "persistent".to_string());
        let mut times = Vec::new();
        for attempt in 0..2 {
            let fresh = project.join(attempt.to_string());
            fs::create_dir_all(&fresh).unwrap();
            fs::write(
                fresh.join("package.json"),
                "{\"name\":\"cache-trial\",\"version\":\"1.0.0\"}",
            )
            .unwrap();
            let started = Instant::now();
            let fresh_str = fresh.to_str().unwrap();
            let mut cmd_vec = npm_args.to_vec();
            cmd_vec.extend_from_slice(&["--prefix", fresh_str]);
            if attempt > 0 {
                cmd_vec.push("--offline");
            }
            shell(&cmd_vec, Some(0), Some(&opts), None);
            times.push(started.elapsed().as_secs_f64());
            assert!(fresh.join("node_modules/sample/package.json").is_file());
        }
        assert!(!home.join(".npm").exists());
        assert!(home.join(".cache/veil-tell/npm/_cacache").is_dir());
        println!(
            "persistent npm cold={:.3}s offline={:.3}s",
            times[0], times[1]
        );
        let _ = reg_server.kill();
        let _ = reg_server.wait();
        return;
    }

    fs::write(
        project.join("package.json"),
        "{\"name\":\"session-test\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    shell(&npm_args, Some(0), None, None);

    let secret = "Q".repeat(45);
    let ca_str = ca.to_str().unwrap();
    let curl_args = [
        "curl",
        "-fsS",
        "--cacert",
        ca_str,
        "-H",
        "Authorization: Bearer shortsecret",
        "https://allowed.test/private?token=othersecret",
    ];
    shell(&curl_args, Some(0), None, None);

    let log_dir = root.join("state/veil-tell/log");
    let mut logs: Vec<PathBuf> = fs::read_dir(&log_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("jsonl"))
        .collect();
    assert_eq!(logs.len(), 1);
    let log_path = logs.pop().unwrap();

    let entries: Vec<Value> = fs::read_to_string(&log_path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        entries
            .iter()
            .map(|r| r["argv"][0].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["npm", "curl"]
    );
    assert!(
        entries
            .iter()
            .all(|r| r["destinations"][0]["host"] == "allowed.test")
    );
    assert!(!project.join(".veil-tell/npm.json").exists());

    let mut log_off = BTreeMap::new();
    log_off.insert("VEIL_TELL_LOG".to_string(), "off".to_string());
    shell(&curl_args, Some(0), Some(&log_off), None);
    assert_eq!(fs::read_to_string(&log_path).unwrap().lines().count(), 2);

    let count_from_stdin = || {
        fs::read_to_string(&requests_log)
            .unwrap()
            .lines()
            .filter(|l| *l == "/from-stdin")
            .count()
    };
    let config = b"url = \"https://allowed.test/from-stdin\"\n";
    let from_stdin = ["curl", "-fsS", "--cacert", ca_str, "--config", "-"];
    let start_cnt = count_from_stdin();
    shell(&from_stdin, Some(0), None, Some(config));
    run_cmd(
        &[
            fixture_str,
            "agent",
            "--",
            "curl",
            "-fsS",
            "--cacert",
            ca_str,
            "--config",
            "-",
        ],
        Some(0),
        None,
        Some(config),
    );
    assert_eq!(count_from_stdin(), start_cnt + 2);
    let direct = run_cmd(
        &[
            fixture_str,
            "--log",
            "--",
            "curl",
            "-fsS",
            "--cacert",
            ca_str,
            "--config",
            "-",
        ],
        None,
        None,
        Some(config),
    );
    assert!(!direct.status.success());
    assert_eq!(count_from_stdin(), start_cnt + 2);

    let source_input = root.join("input.txt");
    fs::write(&source_input, b"prefix:remaining input\n").unwrap();
    {
        let mut stream = fs::File::open(&source_input).unwrap();
        stream.seek(SeekFrom::Start(7)).unwrap();
        let mut c = Command::new("/bin/sh");
        c.args(["-c", &format!("{setup}\ncurl --version >/dev/null && cat")])
            .current_dir(&project)
            .env_clear();
        for (k, v) in &base_env {
            c.env(k, v);
        }
        c.env("XDG_STATE_HOME", root.join("file-stdin-state"));
        c.stdin(Stdio::from(stream));
        let out = c.output().unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"remaining input\n");
    }

    if cfg!(target_os = "linux") {
        let self_str = self_exe.to_str().unwrap();
        let mut stream = fs::File::open(&source_input).unwrap();
        stream.seek(SeekFrom::Start(7)).unwrap();
        let stream_check = stream.try_clone().unwrap();
        let script = format!("{setup}\nexec \"$@\"");
        let alias = format!("alias.checkinput=!{self_str} --check-stdin");
        let mut c = Command::new("/bin/sh");
        c.args(["-c", &script, "test", "git", "-c", &alias, "checkinput"])
            .current_dir(&project)
            .env_clear();
        for (k, v) in &base_env {
            c.env(k, v);
        }
        c.env("XDG_STATE_HOME", root.join("file-stdin-state"));
        c.stdin(Stdio::from(stream));
        let out = c.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(17),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let mut rem = Vec::new();
         (&stream_check).read_to_end(&mut rem).unwrap();
        assert_eq!(rem, b"aining input\n");
        assert_eq!(fs::read(&source_input).unwrap(), b"prefix:remaining input\n");
    }

    {
        let (mut master, slave) = open_pty_pair();
        let mut pty_bytes = config.to_vec();
        pty_bytes.push(0x04);
        master.write_all(&pty_bytes).unwrap();
        let script = format!("{setup}\nexec \"$@\"");
        let mut c = Command::new("/bin/sh");
        c.args(["-c", &script, "test"])
            .args(&from_stdin)
            .current_dir(&project)
            .env_clear();
        for (k, v) in &base_env {
            c.env(k, v);
        }
        c.stdin(Stdio::from(slave));
        let out = c.output().unwrap();
        assert!(
            out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(count_from_stdin(), start_cnt + 3);
    assert!(!fs::read_to_string(&log_path).unwrap().contains("/from-stdin"));

    run_cmd(
        &[
            fixture_str,
            "--log",
            "true",
            "--password",
            "briefsecret",
            &secret,
        ],
        Some(0),
        None,
        None,
    );
    let log_contents = fs::read_to_string(&log_path).unwrap();
    for s in [
        "private?",
        "othersecret",
        "shortsecret",
        "briefsecret",
        secret.as_str(),
    ] {
        assert!(!log_contents.contains(s), "leaked {s}");
    }

    let blocked = shell(&["curl", "-fsS", "https://fixture.local"], None, None, None);
    assert!(!blocked.status.success());
    let blocked_code = blocked.status.code().unwrap();
    let log_text = fs::read_to_string(&log_path).unwrap();
    let last: Value = serde_json::from_str(log_text.lines().last().unwrap()).unwrap();
    let golden = format!(
        "{}  curl -fsS https://fixture.local  exit {blocked_code}\n          ✗ fixture.local:443  ×1  0 B  non_public_destination\n",
        last["clock"].as_str().unwrap()
    );
    let blocked_log = String::from_utf8(
        run_cmd(
            &[fixture_str, "log", "--today", "--only-blocked"],
            Some(0),
            None,
            None,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(blocked_log, golden);

    let expired = log_path.with_file_name("2000-01-01.jsonl");
    let unrelated = log_path.with_file_name("notes.txt");
    fs::write(&expired, "{}\n").unwrap();
    fs::write(&unrelated, "keep").unwrap();
    run_cmd(
        &[fixture_str, "--log", "observe", "--report", ca_str, "--", "true"],
        Some(125),
        None,
        None,
    );
    assert!(!expired.exists());
    assert_eq!(fs::read_to_string(&unrelated).unwrap(), "keep");
    let failed: Value = serde_json::from_str(
        fs::read_to_string(&log_path)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(failed["run_status"]["reason"], "setup_failed");
    assert!(failed["coverage"].is_null());

    let project_agent = project.join("agent-install");
    fs::create_dir_all(&project_agent).unwrap();
    fs::write(
        project_agent.join("package.json"),
        "{\"name\":\"agent-install\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    let agent_cjs = project.join("fixture-agent.cjs");
    fs::write(
        &agent_cjs,
        r#"
const {readFileSync} = require('node:fs');
const {execFileSync} = require('node:child_process');
(async () => {
  if (readFileSync(0, 'utf8') !== 'interactive input' || process.argv[2] !== 'private prompt') process.exit(2);
  for (const url of [process.env.LOCAL_URL, 'https://new.test/api?key=private-query']) {
    const response = await fetch(url, {headers: {Authorization: 'Bearer private-api-key'}});
    if (!response.ok) process.exit(3);
    await response.text();
  }
  execFileSync('npm', process.argv.slice(3), {stdio:'inherit'});
  console.log('agent output');
})().catch(e => {console.error(e);process.exit(4)});
"#,
    )
    .unwrap();

    let upstream_port = free_local_port();
    let upstream_auth =
        base64::engine::general_purpose::STANDARD.encode(b"fixture:private-upstream");
    let mut upstream_server = Command::new(&node_bin)
        .arg(&server_script)
        .args(["upstream", &upstream_port.to_string()])
        .arg(&ca)
        .arg(&key)
        .arg(&meta_path)
        .arg(&tgz_path)
        .arg(&requests_log)
        .arg(&upstream_auth)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut line = String::new();
        let mut br = std::io::BufReader::new(upstream_server.stdout.take().unwrap());
        std::io::BufRead::read_line(&mut br, &mut line).unwrap();
        assert_eq!(line.trim(), "READY");
    }

    let endpoint = format!("http://fixture:private-upstream@127.0.0.1:{upstream_port}");
    let bypass = "127.0.0.1,private-exclusion.test";
    let local_url = format!("https://127.0.0.1:{reg_port}/bypassed");
    let mut agent_extra = BTreeMap::new();
    agent_extra.insert("HTTPS_PROXY".to_string(), endpoint.clone());
    agent_extra.insert("https_proxy".to_string(), endpoint);
    agent_extra.insert("NO_PROXY".to_string(), bypass.to_string());
    agent_extra.insert("no_proxy".to_string(), bypass.to_string());
    agent_extra.insert("NODE_EXTRA_CA_CERTS".to_string(), ca_str.to_string());
    agent_extra.insert("LOCAL_URL".to_string(), local_url);

    let before_lines = fs::read_to_string(&log_path).unwrap().lines().count();
    let agent_cjs_str = agent_cjs.to_str().unwrap();
    let proj_agent_str = project_agent.to_str().unwrap();
    let mut agent_cmd = vec![
        fixture_str,
        "agent",
        "--",
        "node",
        agent_cjs_str,
        "private prompt",
    ];
    agent_cmd.extend_from_slice(&npm_args[1..]);
    agent_cmd.extend_from_slice(&["--prefix", proj_agent_str]);

    let result = run_cmd(
        &agent_cmd,
        Some(0),
        Some(&agent_extra),
        Some(b"interactive input"),
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("agent output"));
    assert!(
        project_agent
            .join("node_modules/sample/package.json")
            .is_file()
    );

    let after_text = fs::read_to_string(&log_path).unwrap();
    let new_rows: Vec<Value> = after_text
        .lines()
        .skip(before_lines)
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(new_rows.len(), 2);
    let child_row = &new_rows[0];
    let parent_row = &new_rows[1];
    assert_eq!(child_row["argv"][0], "npm");
    assert_eq!(parent_row["argv"], json!(["node"]));
    assert_eq!(parent_row["scope"], "agent_session");

    let req_lines: Vec<String> = fs::read_to_string(&requests_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    for (row, host) in [(child_row, "allowed.test"), (parent_row, "new.test")] {
        let dest = &row["destinations"][0];
        assert_eq!(dest["host"], host);
        assert_eq!(dest["decision"], "allow");
        assert_eq!(dest["reason"], "observe");
        assert!(dest["sent_bytes"].as_u64().unwrap() > 0);
        let tunnel_tag = format!("TUNNEL:{host}:443");
        let tunnel_cnt = req_lines.iter().filter(|l| *l == &tunnel_tag).count() as u64;
        assert_eq!(dest["attempts"].as_u64().unwrap(), tunnel_cnt);
    }
    assert!(req_lines.iter().any(|l| l == "/bypassed"));
    assert!(req_lines.iter().any(|l| l == "/api?key=private-query"));
    assert_eq!(
        parent_row["coverage"]["direct_attempt_destinations"],
        "not_observed"
    );
    for secret_str in [
        "private prompt",
        "private-query",
        "private-api-key",
        "private-upstream",
        "private-exclusion",
    ] {
        assert!(!after_text.contains(secret_str));
    }
    let _ = upstream_server.kill();
    let _ = upstream_server.wait();

    {
        let (_master, slave) = open_pty_pair();
        let slave_out = slave.try_clone().unwrap();
        let slave_err = slave.try_clone().unwrap();
        let mut c = Command::new(&fixture);
        c.args([
            "agent",
            "--",
            "/bin/sh",
            "-c",
            "test -t 0 && test -t 1 && test -t 2 && exit 17",
        ])
        .current_dir(&project)
        .env_clear();
        for (k, v) in &base_env {
            c.env(k, v);
        }
        c.stdin(Stdio::from(slave))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::from(slave_err));
        let status = c.status().unwrap();
        assert_eq!(status.code(), Some(17));
    }

    {
        let mut c = Command::new(&fixture);
        c.args([
            "agent",
            "--",
            "/bin/sh",
            "-c",
            "trap 'exit 42' TERM; echo ready; while :; do sleep 0.1; done",
        ])
        .current_dir(&project)
        .env_clear();
        for (k, v) in &base_env {
            c.env(k, v);
        }
        c.stdout(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let mut line = String::new();
        let mut br = std::io::BufReader::new(child.stdout.take().unwrap());
        std::io::BufRead::read_line(&mut br, &mut line).unwrap();
        assert_eq!(line, "ready\n");
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(42));
    }

    let before_bytes = fs::read(&log_path).unwrap();
    run_cmd(
        &[fixture_str, "agent", "--", "true"],
        Some(0),
        Some(&log_off),
        None,
    );
    assert_eq!(fs::read(&log_path).unwrap(), before_bytes);

    let _ = reg_server.kill();
    let _ = reg_server.wait();
    println!(
        "PASS: shell shims, TLS receiver, private local log, blocked timeline and interactive agent/child TLS observation"
    );
}

#[cfg(target_os = "linux")]
fn check_linux_stdin() -> ! {
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        assert_eq!(libc::fstat(0, &mut st), 0);
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFREG);
        let mut vfs: libc::statvfs = std::mem::zeroed();
        assert_eq!(libc::fstatvfs(0, &mut vfs), 0);
        assert_ne!(vfs.f_flag & (libc::ST_RDONLY as u64), 0);
        assert_eq!(libc::lseek(0, 0, libc::SEEK_CUR), 7);
        let mut buf = [0u8; 3];
        assert_eq!(libc::read(0, buf.as_mut_ptr().cast(), 3), 3);
        assert_eq!(&buf, b"rem");
    }
    std::process::exit(17);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("--check-stdin") {
        check_linux_stdin();
    }
    let cache = args.get(3).map(String::as_str) == Some("--persistent");
    trial(Path::new(&args[1]), Path::new(&args[2]), cache);
}
