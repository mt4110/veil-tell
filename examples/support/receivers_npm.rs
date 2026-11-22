use crate::{copy_dir_all, os_label, run_with_env};
use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

pub(crate) fn npm_test(
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
