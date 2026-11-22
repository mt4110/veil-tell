use crate::receivers_diff::{dns_attempt_test, npm_destination_diff};
use crate::{action_summary, copy_dir_all, os_label, receive, run_with_env, upstream_connect};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

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

pub(crate) fn destination_diff_test(
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

pub(crate) fn volume_test(
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
