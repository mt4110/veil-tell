use crate::{action_summary, copy_dir_all, os_label, run_with_env};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn dns_attempt_test(cli: &Path, project: &Path, evidence: &Path, mut runtime: PathBuf) {
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

pub(crate) fn baseline_upgrade_test(cli: &Path, project: &Path, runtime: &Path) {
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

pub(crate) fn npm_destination_diff(cli: &Path, project: &Path, evidence: &Path, mut runtime: PathBuf) {
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
