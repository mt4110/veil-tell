//! Local dependency lifecycle fixtures in Rust (replaces tests/package_managers.py).

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

fn os_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, format!("{}\n", serde_json::to_string(value).unwrap())).unwrap();
}

fn copy_dir_all(src: &Path, dst: &Path, ignore_name: Option<&str>) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if ignore_name.is_some_and(|ig| name.to_str() == Some(ig)) {
            continue;
        }
        let ty = entry.file_type().unwrap();
        let dest_path = dst.join(&name);
        if ty.is_symlink() {
            let target = fs::read_link(entry.path()).unwrap();
            symlink(target, dest_path).unwrap();
        } else if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_path, ignore_name);
        } else {
            fs::copy(entry.path(), dest_path).unwrap();
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
    if let Some(exp) = expected {
        assert_eq!(
            out.status.code(),
            Some(exp),
            "args={args:?}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out
}

#[derive(PartialEq, Eq, Debug)]
struct EntrySnap {
    mode: u32,
    mtime_nsec: i64,
    link: Option<PathBuf>,
    bytes: Option<Vec<u8>>,
}

fn collect_snapshot(root: &Path, current: &Path, out: &mut BTreeMap<PathBuf, EntrySnap>) {
    let meta = fs::symlink_metadata(current).unwrap();
    let rel = current.strip_prefix(root).unwrap_or(Path::new("")).to_path_buf();
    let ft = meta.file_type();
    let link = if ft.is_symlink() {
        Some(fs::read_link(current).unwrap())
    } else {
        None
    };
    let bytes = if ft.is_file() {
        Some(fs::read(current).unwrap())
    } else {
        None
    };
    out.insert(
        rel,
        EntrySnap {
            mode: meta.mode(),
            mtime_nsec: meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
            link,
            bytes,
        },
    );
    if ft.is_dir() && !ft.is_symlink() {
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            collect_snapshot(root, &entry.path(), out);
        }
    }
}

fn snapshot_modules(root: &Path) -> BTreeMap<PathBuf, EntrySnap> {
    let mut out = BTreeMap::new();
    collect_snapshot(root, root, &mut out);
    out
}

fn tar_octal(buf: &mut [u8], mut val: u64) {
    let len = buf.len();
    buf[len - 1] = 0;
    for i in (0..len - 1).rev() {
        buf[i] = b'0' + ((val & 7) as u8);
        val >>= 3;
    }
}

fn build_deterministic_tar(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, data, mode) in files {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        tar_octal(&mut header[100..108], u64::from(mode));
        tar_octal(&mut header[108..116], 0);
        tar_octal(&mut header[116..124], 0);
        tar_octal(&mut header[124..136], data.len() as u64);
        tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let chksum: u64 = header.iter().map(|&b| u64::from(b)).sum();
        tar_octal(&mut header[148..155], chksum);
        header[155] = b' ';

        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        let rem = data.len() % 512;
        if rem != 0 {
            out.resize(out.len() + (512 - rem), 0);
        }
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn write_tarball_package(target_tgz: &Path) {
    let pkg_json = format!(
        "{}\n",
        serde_json::to_string(&json!({
            "name": "roundtrip-dep",
            "version": "1.0.0",
            "main": "index.js",
            "bin": {"roundtrip-cli": "bin.js"},
        }))
        .unwrap()
    );
    let index_js = b"module.exports = { ok: true, version: '1.0.0' };\n";
    let bin_js = b"#!/usr/bin/env node\nconsole.log('roundtrip-ok');\n";
    let tar_bytes = build_deterministic_tar(&[
        ("package/package.json", pkg_json.as_bytes(), 0o644),
        ("package/index.js", index_js, 0o644),
        ("package/bin.js", bin_js, 0o755),
    ]);

    let mut child = Command::new("gzip")
        .args(["-n", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&tar_bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let mut gz_bytes = out.stdout;
    if gz_bytes.len() >= 10 {
        // Zero OS byte (offset 9) and mtime (4..8) for 100% cross-run determinism
        gz_bytes[4..8].fill(0);
        gz_bytes[9] = 255;
    }
    fs::write(target_tgz, gz_bytes).unwrap();
}

fn test_pnpm_store(
    cli: &Path,
    mut tool: PathBuf,
    workspace: &Path,
    base_env: &BTreeMap<String, String>,
    version: &str,
) {
    let project = workspace.join("store-interoperability");
    let home = workspace.join("native-home");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&home).unwrap();
    let mut env_map = base_env.clone();
    env_map.insert("HOME".to_string(), home.display().to_string());
    env_map.insert(
        "XDG_DATA_HOME".to_string(),
        home.join("data").display().to_string(),
    );
    if cfg!(target_os = "linux") {
        let runtime = project.join("runtime");
        let parent2 = tool.parent().unwrap().parent().unwrap();
        let parent_name = tool.parent().unwrap().file_name().unwrap();
        let tool_name = tool.file_name().unwrap();
        copy_dir_all(parent2, &runtime, None);
        tool = runtime.join(parent_name).join(tool_name);
        let old_path = env_map.get("PATH").cloned().unwrap_or_default();
        env_map.insert(
            "PATH".to_string(),
            format!("{}:{old_path}", tool.parent().unwrap().display()),
        );
    }

    let dependency = project.join("fixture");
    fs::create_dir_all(&dependency).unwrap();
    write_json(
        &dependency.join("package.json"),
        &json!({
            "name": "test-store-dependency",
            "version": "1.0.0",
            "main": "index.js",
            "bin": {"test-store-bin": "bin.js"},
        }),
    );
    fs::write(dependency.join("index.js"), "module.exports = 'store-dep-ok';\n").unwrap();
    fs::write(
        dependency.join("bin.js"),
        "#!/usr/bin/env node\nconsole.log('store-bin-ok');\n",
    )
    .unwrap();
    fs::set_permissions(
        dependency.join("bin.js"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    let marker_file = project.join("precheck-ran.marker");
    let precheck_dep = project.join("precheck-marker-dep");
    fs::create_dir_all(&precheck_dep).unwrap();
    write_json(
        &precheck_dep.join("package.json"),
        &json!({
            "name": "precheck-marker-dep",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node -e \"require('fs').writeFileSync(process.env.PRECHECK_MARKER, 'ran')\""
            }
        }),
    );
    env_map.insert(
        "PRECHECK_MARKER".to_string(),
        marker_file.display().to_string(),
    );

    for name in ["plain-extra", "wrapped-extra"] {
        let extra = project.join(name);
        fs::create_dir_all(&extra).unwrap();
        write_json(
            &extra.join("package.json"),
            &json!({"name": name, "version": "1.0.0"}),
        );
    }
    write_json(
        &project.join("package.json"),
        &json!({
            "name": "test-store-project",
            "version": "1.0.0",
            "private": true,
            "dependencies": {"test-store-dependency": "file:./fixture"},
        }),
    );

    let cli_s = cli.to_str().unwrap();
    let tool_s = tool.to_str().unwrap();

    let guarded = run_with_env(
        &project,
        &[cli_s, tool_s, "install", "--offline"],
        &env_map,
        Some(125),
    );
    assert!(String::from_utf8_lossy(&guarded.stderr).contains("storeDir: .pnpm-store"));
    let modules_dir = project.join("node_modules");
    assert!(!modules_dir.exists());

    run_with_env(&project, &[tool_s, "install", "--offline"], &env_map, Some(0));
    let modules = modules_dir.join(".modules.yaml");
    assert!(modules.is_file());
    let native_modules = snapshot_modules(&modules_dir);

    run_with_env(
        &project,
        &[
            "node",
            "-e",
            "if (require('test-store-dependency') !== 'store-dep-ok') process.exit(1)",
        ],
        &env_map,
        Some(0),
    );
    let bin_path = modules_dir.join(".bin/test-store-bin");
    let bin_out = run_with_env(&project, &[bin_path.to_str().unwrap()], &env_map, Some(0));
    assert_eq!(String::from_utf8_lossy(&bin_out.stdout).trim(), "store-bin-ok");

    let guarded = run_with_env(
        &project,
        &[cli_s, tool_s, "install", "--offline"],
        &env_map,
        Some(125),
    );
    assert!(String::from_utf8_lossy(&guarded.stderr).contains("storeDir: .pnpm-store"));
    assert!(!marker_file.exists());
    assert_eq!(snapshot_modules(&modules_dir), native_modules);
    run_with_env(
        &project,
        &[
            "node",
            "-e",
            "if (require('test-store-dependency') !== 'store-dep-ok') process.exit(1)",
        ],
        &env_map,
        Some(0),
    );
    let bin_out = run_with_env(&project, &[bin_path.to_str().unwrap()], &env_map, Some(0));
    assert_eq!(String::from_utf8_lossy(&bin_out.stdout).trim(), "store-bin-ok");

    let denied_add = run_with_env(
        &project,
        &[
            cli_s,
            tool_s,
            "add",
            "-w",
            "--offline",
            "file:./precheck-marker-dep",
        ],
        &env_map,
        Some(125),
    );
    assert!(String::from_utf8_lossy(&denied_add.stderr).contains("storeDir: .pnpm-store"));
    assert!(!marker_file.exists());
    assert_eq!(snapshot_modules(&modules_dir), native_modules);

    let config = project.join("pnpm-workspace.yaml");
    let install_settings = "packages: ['.']\nstoreDir: .pnpm-store\n";
    fs::write(&config, install_settings).unwrap();
    if version.starts_with("9.") {
        let wrong_store = run_with_env(
            &project,
            &[cli_s, tool_s, "install", "--offline"],
            &env_map,
            Some(125),
        );
        assert!(String::from_utf8_lossy(&wrong_store.stderr).contains("pnpm store path"));
        fs::write(project.join(".npmrc"), "store-dir=.pnpm-store\n").unwrap();
    }
    fs::rename(&modules_dir, project.join("native-modules")).unwrap();
    let override_out = run_with_env(
        &project,
        &[
            cli_s,
            tool_s,
            "--store-dir",
            ".other-store",
            "install",
            "--offline",
        ],
        &env_map,
        Some(125),
    );
    assert!(
        String::from_utf8_lossy(&override_out.stderr)
            .contains("workspace configured in the current directory")
    );
    assert!(!modules.exists());

    run_with_env(
        &project,
        &[cli_s, tool_s, "install", "--offline"],
        &env_map,
        Some(0),
    );
    let store_out = run_with_env(&project, &[tool_s, "store", "path"], &env_map, Some(0));
    let store = PathBuf::from(String::from_utf8_lossy(&store_out.stdout).trim())
        .canonicalize()
        .unwrap();
    assert_eq!(store.parent(), Some(project.join(".pnpm-store").as_path()));
    assert!(
        fs::read_to_string(&modules)
            .unwrap()
            .contains(&store.display().to_string())
    );
    let config_state = fs::read(&config).unwrap();
    assert_eq!(String::from_utf8_lossy(&config_state), install_settings);

    run_with_env(
        &project,
        &[tool_s, "add", "-w", "--offline", "file:./plain-extra"],
        &env_map,
        Some(0),
    );
    run_with_env(
        &project,
        &[
            cli_s,
            tool_s,
            "add",
            "-w",
            "--offline",
            "file:./wrapped-extra",
        ],
        &env_map,
        Some(0),
    );
    let pkg_data: Value =
        serde_json::from_str(&fs::read_to_string(project.join("package.json")).unwrap()).unwrap();
    let deps = pkg_data["dependencies"].as_object().unwrap();
    assert!(deps.contains_key("plain-extra") && deps.contains_key("wrapped-extra"));

    let report_out = run_with_env(
        &project,
        &[cli_s, "--json", tool_s, "install", "--offline"],
        &env_map,
        Some(0),
    );
    let rep_val: Value = serde_json::from_slice(&report_out.stdout).unwrap();
    assert_eq!(rep_val["run_status"]["exit_code"], 0);
    assert!(
        fs::read_to_string(&modules)
            .unwrap()
            .contains(&store.display().to_string())
    );
    assert_eq!(fs::read(&config).unwrap(), config_state);

    println!(
        "{} pnpm {version} store_missing=125 existing_node_modules=unchanged isolated_install=0 native_add=0 isolated_add=0",
        os_label()
    );
}

fn test_native_isolated_native_roundtrip(
    cli: &Path,
    tool: &Path,
    manager: &str,
    workspace: &Path,
    base_env: &BTreeMap<String, String>,
    version: &str,
    yarn_pnp: bool,
) {
    let variant_tag = if yarn_pnp {
        format!("{manager}-pnp")
    } else {
        manager.to_string()
    };
    let roundtrip_root = workspace.join(format!("roundtrip-interoperability-{variant_tag}"));
    let home = workspace.join(format!("roundtrip-home-{variant_tag}"));
    fs::create_dir_all(&roundtrip_root).unwrap();
    fs::create_dir_all(&home).unwrap();

    let mut env_map = base_env.clone();
    env_map.remove("CI");
    env_map.insert("HOME".to_string(), home.display().to_string());
    env_map.insert(
        "XDG_DATA_HOME".to_string(),
        home.join("data").display().to_string(),
    );
    env_map.insert(
        "XDG_CACHE_HOME".to_string(),
        home.join("cache").display().to_string(),
    );

    let prepare_project = |name: &str| {
        let proj = roundtrip_root.join(name);
        let vendor = proj.join("vendor");
        fs::create_dir_all(&vendor).unwrap();
        write_tarball_package(&vendor.join("roundtrip-dep-1.0.0.tgz"));
        write_json(
            &proj.join("package.json"),
            &json!({
                "name": "roundtrip-app",
                "version": "1.0.0",
                "private": true,
                "dependencies": {"roundtrip-dep": "file:./vendor/roundtrip-dep-1.0.0.tgz"},
            }),
        );
        let mut local_tool = tool.to_path_buf();
        let mut local_env = env_map.clone();
        if cfg!(target_os = "linux") {
            let runtime = proj.join("runtime");
            let parent2 = tool.parent().unwrap().parent().unwrap();
            let parent_name = tool.parent().unwrap().file_name().unwrap();
            let tool_name = tool.file_name().unwrap();
            copy_dir_all(parent2, &runtime, None);
            local_tool = runtime.join(parent_name).join(tool_name);
            let sys_path = env::var("PATH").unwrap_or_default();
            local_env.insert(
                "PATH".to_string(),
                format!("{}:{sys_path}", local_tool.parent().unwrap().display()),
            );
        }
        let lt = local_tool.display().to_string();
        let (lock_name, lock_cmd, frozen_cmd, tracked): (
            &'static str,
            Vec<String>,
            Vec<String>,
            Vec<&'static str>,
        ) = if manager == "npm" {
            fs::write(proj.join(".npmrc"), "audit=false\nfund=false\n").unwrap();
            (
                "package-lock.json",
                vec![
                    lt.clone(),
                    "install".into(),
                    "--package-lock-only".into(),
                    "--offline".into(),
                    "--no-audit".into(),
                    "--no-fund".into(),
                ],
                vec![
                    lt,
                    "ci".into(),
                    "--offline".into(),
                    "--no-audit".into(),
                    "--no-fund".into(),
                ],
                vec!["package.json", "package-lock.json", ".npmrc"],
            )
        } else if manager == "pnpm" {
            fs::write(
                proj.join("pnpm-workspace.yaml"),
                "packages:\n  - '.'\nstoreDir: .pnpm-store\nupdateNotifier: false\n",
            )
            .unwrap();
            let mut npmrc = "update-notifier=false\n".to_string();
            if version.starts_with("9.") {
                npmrc.push_str("store-dir=.pnpm-store\n");
            }
            fs::write(proj.join(".npmrc"), npmrc).unwrap();
            (
                "pnpm-lock.yaml",
                vec![
                    lt.clone(),
                    "install".into(),
                    "--lockfile-only".into(),
                    "--offline".into(),
                ],
                vec![
                    lt,
                    "install".into(),
                    "--frozen-lockfile".into(),
                    "--offline".into(),
                ],
                vec![
                    "package.json",
                    "pnpm-lock.yaml",
                    "pnpm-workspace.yaml",
                    ".npmrc",
                ],
            )
        } else if manager == "yarn" && version.starts_with("1.") {
            (
                "yarn.lock",
                vec![lt.clone(), "install".into(), "--offline".into()],
                vec![
                    lt,
                    "install".into(),
                    "--frozen-lockfile".into(),
                    "--offline".into(),
                ],
                vec!["package.json", "yarn.lock"],
            )
        } else if manager == "yarn" {
            let linker = if yarn_pnp { "pnp" } else { "node-modules" };
            fs::write(
                proj.join(".yarnrc.yml"),
                format!(
                    "enableNetwork: false\nenableScripts: true\nenableGlobalCache: false\nenableImmutableInstalls: false\nnodeLinker: {linker}\n"
                ),
            )
            .unwrap();
            (
                "yarn.lock",
                vec![lt.clone(), "install".into()],
                vec![lt, "install".into(), "--immutable".into()],
                vec!["package.json", "yarn.lock", ".yarnrc.yml"],
            )
        } else if manager == "bun" {
            (
                "bun.lock",
                vec![lt.clone(), "install".into()],
                vec![lt, "install".into(), "--frozen-lockfile".into()],
                vec!["package.json", "bun.lock"],
            )
        } else {
            panic!("unsupported manager: {manager}");
        };
        (
            proj,
            local_tool,
            local_env,
            lock_name,
            lock_cmd,
            frozen_cmd,
            tracked,
        )
    };

    let run_vec = |proj: &Path, args: &[String], run_env: &BTreeMap<String, String>| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_with_env(proj, &refs, run_env, Some(0))
    };

    let verify_installed =
        |proj: &Path, local_tool: &Path, run_env: &BTreeMap<String, String>| {
            let lt_s = local_tool.to_str().unwrap();
            if yarn_pnp {
                run_with_env(
                    proj,
                    &[
                        lt_s,
                        "node",
                        "-e",
                        "const d = require('roundtrip-dep'); if (!d.ok || d.version !== '1.0.0') process.exit(1);",
                    ],
                    run_env,
                    Some(0),
                );
                let out = run_with_env(proj, &[lt_s, "roundtrip-cli"], run_env, Some(0));
                assert!(String::from_utf8_lossy(&out.stdout).contains("roundtrip-ok"));
                return;
            }
            run_with_env(
                proj,
                &[
                    "node",
                    "-e",
                    "const d = require('roundtrip-dep'); if (!d.ok || d.version !== '1.0.0') process.exit(1);",
                ],
                run_env,
                Some(0),
            );
            let cli_bin = proj.join("node_modules/.bin/roundtrip-cli");
            let out = run_with_env(proj, &[cli_bin.to_str().unwrap()], run_env, Some(0));
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "roundtrip-ok");
        };

    let (seed, _, seed_env, lock_name, seed_lock_cmd, _, _) = prepare_project("seed");
    run_vec(&seed, &seed_lock_cmd, &seed_env);

    let (control, control_tool, control_env, _, _, control_cmd, tracked) =
        prepare_project("control");
    let (roundtrip, rt_tool, rt_env, _, _, rt_cmd, _) = prepare_project("roundtrip");
    let lock_bytes = fs::read(seed.join(lock_name)).unwrap();
    fs::write(control.join(lock_name), &lock_bytes).unwrap();
    fs::write(roundtrip.join(lock_name), &lock_bytes).unwrap();
    if manager == "yarn" && !version.starts_with("1.") && seed.join(".yarn").exists() {
        for dst in [control.join(".yarn"), roundtrip.join(".yarn")] {
            copy_dir_all(&seed.join(".yarn"), &dst, None);
        }
    }

    run_vec(&control, &control_cmd, &control_env);
    verify_installed(&control, &control_tool, &control_env);
    let expected_files: BTreeMap<&str, Vec<u8>> = tracked
        .iter()
        .map(|&rel| (rel, fs::read(control.join(rel)).unwrap()))
        .collect();

    run_vec(&roundtrip, &rt_cmd, &rt_env);
    verify_installed(&roundtrip, &rt_tool, &rt_env);

    let cli_s = cli.display().to_string();
    let mut step2 = vec![cli_s.clone()];
    step2.extend_from_slice(&rt_cmd);
    run_vec(&roundtrip, &step2, &rt_env);

    let baseline_path = roundtrip.join(".veil-tell").join(format!("{manager}.json"));
    let baseline_data: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).unwrap()).unwrap();
    assert_eq!(baseline_data["backend"], "isolated");
    assert_eq!(baseline_data["lockfile"]["ecosystem"], manager);

    let mut ci_cmd = vec![cli_s.clone(), "ci".into(), "--json".into(), "--".into()];
    ci_cmd.extend_from_slice(&rt_cmd);
    let warm_ci = run_vec(&roundtrip, &ci_cmd, &rt_env);
    let warm_val: Value = serde_json::from_slice(&warm_ci.stdout).unwrap();
    assert_eq!(warm_val["comparison"]["status"], "compared");

    for cache_rel in [
        "node_modules",
        ".pnpm-store",
        ".pnp.cjs",
        ".pnp.loader.mjs",
        ".yarn/unplugged",
    ] {
        let cp = roundtrip.join(cache_rel);
        if cp.is_dir() {
            let _ = fs::remove_dir_all(&cp);
        } else if cp.exists() {
            let _ = fs::remove_file(&cp);
        }
    }
    let cold_ci = run_vec(&roundtrip, &ci_cmd, &rt_env);
    let cold_val: Value = serde_json::from_slice(&cold_ci.stdout).unwrap();
    assert_eq!(cold_val["comparison"]["status"], "compared");

    run_vec(&roundtrip, &rt_cmd, &rt_env);
    verify_installed(&roundtrip, &rt_tool, &rt_env);

    for &rel in &tracked {
        assert_eq!(
            &fs::read(roundtrip.join(rel)).unwrap(),
            &expected_files[rel],
            "{rel} changed during roundtrip"
        );
    }

    if manager == "pnpm" {
        let rt_s = rt_tool.to_str().unwrap();
        let native_out = run_with_env(&roundtrip, &[rt_s, "store", "path"], &rt_env, Some(0));
        let native_store = PathBuf::from(String::from_utf8_lossy(&native_out.stdout).trim())
            .canonicalize()
            .unwrap();
        let iso_out = run_with_env(
            &roundtrip,
            &[
                cli.to_str().unwrap(),
                "observe",
                "--backend",
                "isolated",
                "--",
                rt_s,
                "store",
                "path",
            ],
            &rt_env,
            Some(0),
        );
        let iso_store = PathBuf::from(String::from_utf8_lossy(&iso_out.stdout).trim())
            .canonicalize()
            .unwrap();
        assert_eq!(iso_store, native_store);
        assert_eq!(
            native_store.parent(),
            Some(roundtrip.join(".pnpm-store").as_path())
        );
        let mod_yaml = fs::read_to_string(roundtrip.join("node_modules/.modules.yaml")).unwrap();
        assert!(mod_yaml.contains(&native_store.display().to_string()));
    }

    println!(
        "{} {variant_tag} {version} roundtrip=native->isolated(warm+cold)->native invariants=matched dependency_exec=ok",
        os_label()
    );
}

fn test_cargo_roundtrip(cli: &Path, cargo_tool: &Path) {
    let tmp = tempfile::Builder::new()
        .prefix("veil-pm-cargo-")
        .tempdir()
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    let sys_path = env::var("PATH").unwrap_or_default();
    env_map.insert(
        "PATH".to_string(),
        format!("{}:{sys_path}", cargo_tool.parent().unwrap().display()),
    );
    let cargo_s = cargo_tool.to_str().unwrap();
    let ver_out = run_with_env(&root, &[cargo_s, "-V"], &env_map, Some(0));
    let version = String::from_utf8_lossy(&ver_out.stdout).trim().to_string();

    let prepare_workspace = |name: &str| {
        let app = root.join(name);
        let dep = app.join("dep");
        fs::create_dir_all(dep.join("src")).unwrap();
        fs::create_dir_all(app.join("src")).unwrap();
        fs::write(
            dep.join("Cargo.toml"),
            "[package]\nname = \"roundtrip-dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            dep.join("src/lib.rs"),
            "pub fn greeting() -> &'static str { \"cargo-roundtrip-ok\" }\n",
        )
        .unwrap();
        fs::write(
            app.join("Cargo.toml"),
            "[package]\nname = \"roundtrip-app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nroundtrip-dep = { path = \"dep\" }\n",
        )
        .unwrap();
        fs::write(
            app.join("build.rs"),
            "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n",
        )
        .unwrap();
        fs::write(
            app.join("src/main.rs"),
            "fn main() { println!(\"{}\", roundtrip_dep::greeting()); }\n",
        )
        .unwrap();
        app
    };

    let seed_app = prepare_workspace("seed");
    run_with_env(
        &seed_app,
        &[cargo_s, "generate-lockfile", "--offline"],
        &env_map,
        Some(0),
    );
    let lock_bytes = fs::read(seed_app.join("Cargo.lock")).unwrap();

    let ctrl_app = prepare_workspace("control");
    fs::write(ctrl_app.join("Cargo.lock"), &lock_bytes).unwrap();
    run_with_env(
        &ctrl_app,
        &[cargo_s, "build", "--locked", "--offline"],
        &env_map,
        Some(0),
    );
    let ctrl_bin = ctrl_app.join("target/debug/roundtrip-app");
    let ctrl_out = run_with_env(&ctrl_app, &[ctrl_bin.to_str().unwrap()], &env_map, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&ctrl_out.stdout).trim(),
        "cargo-roundtrip-ok"
    );
    let tracked = ["Cargo.toml", "Cargo.lock", "build.rs"];
    let expected_files: BTreeMap<&str, Vec<u8>> = tracked
        .iter()
        .map(|&rel| (rel, fs::read(ctrl_app.join(rel)).unwrap()))
        .collect();

    let rt_app = prepare_workspace("roundtrip");
    fs::write(rt_app.join("Cargo.lock"), &lock_bytes).unwrap();
    let cli_s = cli.to_str().unwrap();

    run_with_env(
        &rt_app,
        &["cargo", "build", "--locked", "--offline"],
        &env_map,
        Some(0),
    );
    let rt_bin = rt_app.join("target/debug/roundtrip-app");
    let rt_out = run_with_env(&rt_app, &[rt_bin.to_str().unwrap()], &env_map, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&rt_out.stdout).trim(),
        "cargo-roundtrip-ok"
    );

    run_with_env(
        &rt_app,
        &[cli_s, "cargo", "build", "--locked", "--offline"],
        &env_map,
        Some(0),
    );
    let baseline: Value =
        serde_json::from_str(&fs::read_to_string(rt_app.join(".veil-tell/cargo.json")).unwrap())
            .unwrap();
    assert_eq!(baseline["backend"], "isolated");
    assert_eq!(baseline["lockfile"]["ecosystem"], "cargo");

    let warm_ci = run_with_env(
        &rt_app,
        &[
            cli_s,
            "ci",
            "--json",
            "--",
            "cargo",
            "build",
            "--locked",
            "--offline",
        ],
        &env_map,
        Some(0),
    );
    let warm_val: Value = serde_json::from_slice(&warm_ci.stdout).unwrap();
    assert_eq!(warm_val["comparison"]["status"], "compared");

    fs::remove_dir_all(rt_app.join("target")).unwrap();
    let cold_ci = run_with_env(
        &rt_app,
        &[
            cli_s,
            "ci",
            "--json",
            "--",
            "cargo",
            "build",
            "--locked",
            "--offline",
        ],
        &env_map,
        Some(0),
    );
    let cold_val: Value = serde_json::from_slice(&cold_ci.stdout).unwrap();
    assert_eq!(cold_val["comparison"]["status"], "compared");

    run_with_env(
        &rt_app,
        &["cargo", "build", "--locked", "--offline"],
        &env_map,
        Some(0),
    );
    let rt_out = run_with_env(&rt_app, &[rt_bin.to_str().unwrap()], &env_map, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&rt_out.stdout).trim(),
        "cargo-roundtrip-ok"
    );
    for rel in tracked {
        assert_eq!(&fs::read(rt_app.join(rel)).unwrap(), &expected_files[rel]);
    }

    println!(
        "{} cargo ({version}) roundtrip=native->isolated(warm+cold)->native invariants=matched binary_exec=ok",
        os_label()
    );
}

fn test_manager(cli: &Path, tool: &Path, manager: &str) {
    let tmp = tempfile::Builder::new()
        .prefix(&format!("veil-pm-{manager}-"))
        .tempdir()
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let project = root.join("project");
    fs::create_dir_all(&project).unwrap();

    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    let sys_path = env::var("PATH").unwrap_or_default();
    env_map.insert(
        "PATH".to_string(),
        format!("{}:{sys_path}", tool.parent().unwrap().display()),
    );
    let ver_out = run_with_env(&project, &[tool.to_str().unwrap(), "--version"], &env_map, Some(0));
    let version = String::from_utf8_lossy(&ver_out.stdout).trim().to_string();

    let mut runtime_tool = tool.to_path_buf();
    if cfg!(target_os = "linux") {
        let runtime = project.join("runtime");
        let parent2 = tool.parent().unwrap().parent().unwrap();
        let parent_name = tool.parent().unwrap().file_name().unwrap();
        let tool_name = tool.file_name().unwrap();
        copy_dir_all(parent2, &runtime, None);
        runtime_tool = runtime.join(parent_name).join(tool_name);
        env_map.insert(
            "PATH".to_string(),
            format!("{}:{sys_path}", runtime_tool.parent().unwrap().display()),
        );
    }

    if manager == "pnpm" {
        test_pnpm_store(cli, runtime_tool.clone(), &project, &env_map, &version);
    }
    if matches!(manager, "npm" | "pnpm" | "yarn" | "bun") {
        test_native_isolated_native_roundtrip(cli, tool, manager, &project, &env_map, &version, false);
        if manager == "yarn" && !version.starts_with("1.") {
            test_native_isolated_native_roundtrip(
                cli, tool, manager, &project, &env_map, &version, true,
            );
        }
    }

    let mut package = json!({
        "name": "fixture",
        "private": true,
        "version": "1.0.0",
        "dependencies": {"probe": "file:./before"}
    });
    if manager == "bun" {
        package["trustedDependencies"] = json!(["probe"]);
    }
    let before = project.join("before");
    fs::create_dir_all(&before).unwrap();
    write_json(
        &before.join("package.json"),
        &json!({
            "name": "probe",
            "version": "1.2.2",
            "scripts": {"postinstall": "node -e 'process.exit(0)'"}
        }),
    );
    write_json(&project.join("package.json"), &package);

    let rt_s = runtime_tool.display().to_string();
    let mut command = vec![rt_s, "install".to_string()];
    if manager == "npm" {
        fs::write(
            project.join(".npmrc"),
            "install-links=true\naudit=false\nfund=false\n",
        )
        .unwrap();
    } else if manager == "pnpm" {
        let lifecycle = if !version.starts_with("9.") {
            "allowBuilds:\n  probe: true\n  probe@file:before: true\n  probe@file:dep: true\n"
        } else {
            "onlyBuiltDependencies:\n  - probe\nmanagePackageManagerVersions: false\n"
        };
        fs::write(
            project.join("pnpm-workspace.yaml"),
            format!("packages:\n  - no-workspaces/*\n{lifecycle}updateNotifier: false\nstoreDir: .pnpm-store\n"),
        )
        .unwrap();
        let mut npmrc = "update-notifier=false\n".to_string();
        if version.starts_with("9.") {
            npmrc.push_str("store-dir=.pnpm-store\n");
        }
        fs::write(project.join(".npmrc"), npmrc).unwrap();
        command.push("--offline".to_string());
    } else if manager == "yarn" {
        if version.starts_with("1.") {
            command.push("--offline".to_string());
        } else {
            fs::write(
                project.join(".yarnrc.yml"),
                "enableNetwork: false\nenableScripts: true\nenableGlobalCache: false\nenableImmutableInstalls: false\n",
            )
            .unwrap();
        }
    }

    let control_project = root.join("control");
    copy_dir_all(&project, &control_project, Some("runtime"));
    let start = Instant::now();
    let cmd_refs: Vec<&str> = command.iter().map(String::as_str).collect();
    run_with_env(&control_project, &cmd_refs, &env_map, Some(0));
    let elapsed = start.elapsed().as_secs_f64();

    let cli_s = cli.display().to_string();
    let mut wrapped = vec![cli_s.clone()];
    wrapped.extend_from_slice(&command);
    let wrapped_refs: Vec<&str> = wrapped.iter().map(String::as_str).collect();
    let iso_start = Instant::now();
    run_with_env(&project, &wrapped_refs, &env_map, Some(0));
    let isolated_elapsed = iso_start.elapsed().as_secs_f64();

    let baseline = project.join(".veil-tell").join(format!("{manager}.json"));
    let recorded: Value = serde_json::from_str(&fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(recorded["backend"], "isolated");
    assert_eq!(recorded["lockfile"]["ecosystem"], manager);

    for i in 0..10 {
        if i >= 5 {
            let hold = root.join(format!("cold-cache-{i}"));
            fs::create_dir_all(&hold).unwrap();
            for relative in [
                "node_modules",
                ".pnpm-store",
                ".yarn",
                ".pnp.cjs",
                ".pnp.loader.mjs",
            ] {
                let cache = project.join(relative);
                if cache.exists() {
                    fs::rename(&cache, hold.join(relative)).unwrap();
                }
            }
        }
        let stable = run_with_env(&project, &wrapped_refs, &env_map, Some(0));
        let stderr = String::from_utf8_lossy(&stable.stderr);
        assert!(!stderr.contains("veil-tell accept"));
        assert!(!stderr.contains("volume anomaly"));
        assert!(!baseline.parent().unwrap().join("pending.json").exists());
    }

    let mut ci_vec = vec![cli_s.clone(), "ci".into(), "--json".into(), "--".into()];
    ci_vec.extend_from_slice(&command);
    let ci_refs: Vec<&str> = ci_vec.iter().map(String::as_str).collect();
    let stable_ci = run_with_env(&project, &ci_refs, &env_map, Some(0));
    let ci_json: Value = serde_json::from_slice(&stable_ci.stdout).unwrap();
    assert_eq!(ci_json["comparison"]["status"], "compared");
    assert!(ci_json["comparison"].get("lockfile_changes").is_some());

    let mut short_env = env_map.clone();
    short_env.insert("CI".to_string(), "true".to_string());
    let mut short_vec = vec![cli_s.clone(), "--json".into()];
    short_vec.extend_from_slice(&command);
    let short_refs: Vec<&str> = short_vec.iter().map(String::as_str).collect();
    let short_ci = run_with_env(&project, &short_refs, &short_env, Some(0));
    let short_json: Value = serde_json::from_slice(&short_ci.stdout).unwrap();
    assert_eq!(short_json["comparison"]["status"], "compared");

    println!(
        "{} {manager} {version} warm=5 cold=5 ci=0 control={elapsed:.3}s isolated={isolated_elapsed:.3}s",
        os_label()
    );

    let dep = project.join("dep");
    fs::create_dir_all(&dep).unwrap();
    package["dependencies"] = json!({"probe": "file:./dep"});
    write_json(&project.join("package.json"), &package);
    write_json(
        &dep.join("package.json"),
        &json!({
            "name": "probe",
            "version": "1.2.3",
            "scripts": {"postinstall": "node probe.cjs"}
        }),
    );
    fs::write(
        dep.join("probe.cjs"),
        "require(\"node:dns\").promises.lookup(\"new-package.invalid\").then(() => process.exit(2), error => { if (error.code !== \"ENOTFOUND\") process.exit(3) });\n",
    )
    .unwrap();

    let mut upd_vec = ci_vec.clone();
    if manager == "pnpm" && version.starts_with("9.") {
        upd_vec.push("--force".to_string());
    }
    let upd_refs: Vec<&str> = upd_vec.iter().map(String::as_str).collect();
    let updated = run_with_env(&project, &upd_refs, &env_map, Some(21));
    let report: Value = serde_json::from_slice(&updated.stdout).unwrap();
    let attempt = &report["comparison"]["attempted_added"][0];
    let source = &attempt["attribution"][0];
    assert_eq!(attempt["host"], "new-package.invalid");
    if manager == "bun" {
        assert_eq!(source, &json!({"confidence": "unknown"}));
        println!("{} bun changed=21 attribution=unknown", os_label());
        return;
    }
    assert_eq!(source["confidence"], "inferred");
    assert_eq!(source["package"]["name"], "probe");
    assert_eq!(source["package"]["version"], "1.2.3");
    assert_eq!(source["package"]["script"], "postinstall");
    let stderr_str = String::from_utf8_lossy(&updated.stderr);
    let line = stderr_str
        .lines()
        .find(|l| l.contains("attempted (blocked)"))
        .unwrap();
    println!("{line}");
}

fn collect_rel_paths(root: &Path, current: &Path, out: &mut BTreeSet<PathBuf>) {
    if let Ok(entries) = fs::read_dir(current) {
        for e in entries.flatten() {
            let p = e.path();
            out.insert(p.strip_prefix(root).unwrap().to_path_buf());
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                collect_rel_paths(root, &p, out);
            }
        }
    }
}

fn test_corepack(cli: &Path, corepack: &Path, standalone: &Path, node: &Path) {
    let tmp = tempfile::Builder::new()
        .prefix("veil-corepack-")
        .tempdir()
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let project = root.join("project");
    let home = root.join("home");
    let bin_dir = home.join("bin");
    let cache = home.join(".cache/node/corepack");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();

    symlink(corepack, bin_dir.join("corepack")).unwrap();
    symlink(corepack.with_file_name("pnpm.js"), bin_dir.join("pnpm")).unwrap();
    fs::copy(node, bin_dir.join("node")).unwrap();
    fs::write(home.join("private-sentinel"), "outside the sandbox").unwrap();

    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    let sys_path = env::var("PATH").unwrap_or_default();
    env_map.insert("HOME".to_string(), home.display().to_string());
    env_map.insert("COREPACK_HOME".to_string(), cache.display().to_string());
    env_map.insert("PATH".to_string(), format!("{}:{sys_path}", bin_dir.display()));

    write_json(
        &project.join("package.json"),
        &json!({
            "name": "test-corepack",
            "private": true,
            "packageManager": "pnpm@10.34.9"
        }),
    );
    fs::write(project.join("pnpm-workspace.yaml"), "storeDir: .pnpm-store\n").unwrap();

    let cli_s = cli.to_str().unwrap();
    let cold = run_with_env(
        &project,
        &[cli_s, "pnpm", "install", "--offline"],
        &env_map,
        Some(125),
    );
    let cold_err = String::from_utf8_lossy(&cold.stderr);
    assert!(cold_err.contains("failed during the isolated store probe"));
    assert!(cold_err.contains("corepack install") && !cold_err.contains("storeDir:"));
    assert!(!project.join("node_modules").exists());

    run_with_env(&project, &["corepack", "install"], &env_map, Some(0));
    let mut snapshot = BTreeSet::new();
    collect_rel_paths(&cache, &cache, &mut snapshot);

    env_map.remove("COREPACK_HOME");
    env_map.insert(
        "XDG_CACHE_HOME".to_string(),
        home.join(".cache").display().to_string(),
    );
    run_with_env(
        &project,
        &[cli_s, "pnpm", "install", "--offline"],
        &env_map,
        Some(0),
    );
    run_with_env(
        &project,
        &[cli_s, "corepack", "pnpm", "install", "--offline"],
        &env_map,
        Some(0),
    );
    let bl: Value =
        serde_json::from_str(&fs::read_to_string(project.join(".veil-tell/pnpm.json")).unwrap())
            .unwrap();
    assert_eq!(bl["backend"], "isolated");
    run_with_env(
        &project,
        &[
            cli_s,
            "corepack",
            "pnpm",
            "exec",
            "/bin/sh",
            "-c",
            "test -d \"$COREPACK_HOME/v1/pnpm\" && ! touch \"$COREPACK_HOME/v1/pnpm/probe\"",
        ],
        &env_map,
        Some(0),
    );
    let mut after_snap = BTreeSet::new();
    collect_rel_paths(&cache, &cache, &mut after_snap);
    assert_eq!(after_snap, snapshot);

    if cfg!(target_os = "linux") {
        let sentinel = home.join("private-sentinel");
        run_with_env(
            &project,
            &[
                cli_s,
                "corepack",
                "pnpm",
                "exec",
                "/bin/sh",
                "-c",
                "test ! -e \"$1\"",
                "sh",
                sentinel.to_str().unwrap(),
            ],
            &env_map,
            Some(0),
        );
    }

    let home_pnpm = home.join("pnpm");
    fs::copy(standalone, &home_pnpm).unwrap();
    fs::write(
        project.join("package.json"),
        "{\"name\":\"test-standalone\",\"private\":true}\n",
    )
    .unwrap();
    let standalone_project = root.join("standalone");
    fs::create_dir_all(&standalone_project).unwrap();
    fs::copy(
        project.join("package.json"),
        standalone_project.join("package.json"),
    )
    .unwrap();
    fs::copy(
        project.join("pnpm-workspace.yaml"),
        standalone_project.join("pnpm-workspace.yaml"),
    )
    .unwrap();
    run_with_env(
        &standalone_project,
        &[cli_s, home_pnpm.to_str().unwrap(), "install", "--offline"],
        &env_map,
        Some(0),
    );
    println!(
        "{} corepack cold=125 cached_shim=0 explicit=0 home_pnpm=0",
        os_label()
    );
}

fn test_install_home_and_accept(cli: &Path, npm: &Path, node: &Path) {
    let tmp = tempfile::Builder::new()
        .prefix("veil-install-")
        .tempdir()
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let project = root.join("project");
    let tools = project.join("tools");
    fs::create_dir_all(&tools).unwrap();
    fs::copy(node, tools.join("node")).unwrap();
    copy_dir_all(
        npm.parent().unwrap().parent().unwrap(),
        &tools.join("npm-package"),
        None,
    );
    symlink(tools.join("npm-package/bin/npm-cli.js"), tools.join("npm")).unwrap();

    let mut env_map: BTreeMap<String, String> = env::vars().collect();
    env_map.remove("CI");
    env_map.remove("VEIL_TELL_PROJECT_HOME");
    let sys_path = env::var("PATH").unwrap_or_default();
    env_map.insert("PATH".to_string(), format!("{}:{sys_path}", tools.display()));
    env_map.insert(
        "NPM_CONFIG_PREFIX".to_string(),
        root.join("unused-prefix").display().to_string(),
    );

    write_json(
        &project.join("package.json"),
        &json!({
            "name": "install-home-fixture",
            "version": "1.0.0",
            "private": true,
            "scripts": {"postinstall": "node install.cjs"}
        }),
    );
    let script = project.join("install.cjs");
    let base_script = "\
const {writeFileSync} = require('node:fs');
const {homedir} = require('node:os');
const {join} = require('node:path');
writeFileSync(join(homedir(), 'fixture-program'), '#!/bin/sh\\nprintf \"ready\"\\n', {mode: 0o700});
";
    fs::write(&script, base_script).unwrap();

    let cli_s = cli.to_str().unwrap();
    let host_home = root.join("home");
    fs::create_dir_all(&host_home).unwrap();
    let mut native_env = env_map.clone();
    native_env.insert("HOME".to_string(), host_home.display().to_string());

    run_with_env(
        &project,
        &[cli_s, "npm", "install", "--offline", "--no-audit", "--no-fund"],
        &native_env,
        Some(0),
    );
    assert!(!host_home.join("fixture-program").exists());

    let project_home = project.join(".veil-home");
    symlink(&host_home, &project_home).unwrap();
    let mut persistent = native_env.clone();
    persistent.insert("VEIL_TELL_PROJECT_HOME".to_string(), ".veil-home".to_string());
    run_with_env(
        &project,
        &[cli_s, "npm", "install", "--offline", "--no-audit", "--no-fund"],
        &persistent,
        Some(125),
    );
    assert!(!host_home.join("fixture-program").exists());

    fs::rename(&project_home, project.join("invalid-home-link")).unwrap();
    run_with_env(
        &project,
        &[cli_s, "npm", "install", "--offline", "--no-audit", "--no-fund"],
        &persistent,
        Some(0),
    );
    assert_eq!(
        fs::symlink_metadata(&project_home).unwrap().mode() & 0o077,
        0
    );
    let prog = project_home.join("fixture-program");
    let prog_out = run_with_env(&project, &[prog.to_str().unwrap()], &persistent, Some(0));
    assert_eq!(String::from_utf8_lossy(&prog_out.stdout), "ready");

    let baseline = project.join(".veil-tell/npm.json");
    let pending = baseline.with_file_name("pending.json");
    let original = fs::read(&baseline).unwrap();
    let external = root.join("baseline.json");
    fs::write(&external, &original).unwrap();

    fs::write(
        &script,
        format!(
            "{base_script}\n\
const {{lookup}} = require('node:dns');
lookup('new-install-host.invalid', error => {{
  if (error?.code !== 'ENOTFOUND') process.exitCode = 1;
}});
try {{
  writeFileSync('.veil-tell/pending.json', 'forged');
  process.exitCode = 2;
}} catch (error) {{
  if (!['EACCES', 'EPERM', 'EROFS'].includes(error.code)) throw error;
}}
"
        ),
    )
    .unwrap();

    let explicit = run_with_env(
        &project,
        &[
            cli_s,
            "ci",
            "--baseline",
            external.to_str().unwrap(),
            "--json",
            "--",
            "npm",
            "install",
            "--offline",
            "--no-audit",
            "--no-fund",
        ],
        &persistent,
        Some(21),
    );
    assert!(!explicit.stdout.is_empty());
    assert_eq!(fs::read(&external).unwrap(), original);
    assert!(!pending.exists());
    assert_eq!(fs::read(&baseline).unwrap(), original);

    let mut persistent_ci = persistent.clone();
    persistent_ci.insert("CI".to_string(), "true".to_string());

    for (args, run_env) in [
        (
            vec![
                cli_s,
                "ci",
                "--json",
                "--",
                "npm",
                "install",
                "--offline",
                "--no-audit",
                "--no-fund",
            ],
            &persistent,
        ),
        (
            vec![
                cli_s,
                "--json",
                "npm",
                "install",
                "--offline",
                "--no-audit",
                "--no-fund",
            ],
            &persistent_ci,
        ),
    ] {
        let changed = run_with_env(&project, &args, run_env, Some(21));
        let report: Value = serde_json::from_slice(&changed.stdout).unwrap();
        assert_eq!(report["child_status"]["exit_code"], 0);
        let err_s = String::from_utf8_lossy(&changed.stderr);
        assert!(err_s.contains("veil-tell accept") && !err_s.contains("attribution is off"));
        let entry = &report["comparison"]["attempted_added"][0];
        let source = &entry["attribution"][0];
        assert_eq!(source["package"]["name"], "install-home-fixture");
        assert_eq!(fs::read(&baseline).unwrap(), original);
        let pend_val: Value =
            serde_json::from_str(&fs::read_to_string(&pending).unwrap()).unwrap();
        assert_eq!(pend_val["key"], "npm");
        run_with_env(&project, &[cli_s, "accept"], run_env, Some(0));
        assert!(!pending.exists());
        run_with_env(&project, &args, run_env, Some(0));
        fs::write(&baseline, &original).unwrap();
    }
    println!(
        "{} persistent_home=0 unsafe_home=125 npm_prefix=attributed ci=21/accept=0/ci=0",
        os_label()
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let cli = PathBuf::from(&args[1]).canonicalize().unwrap();
    let mut tools: Vec<(String, PathBuf)> = Vec::new();
    for arg in &args[2..] {
        let (name, path) = arg.split_once('=').unwrap();
        let p = PathBuf::from(path);
        let abs = if p.is_absolute() {
            p
        } else {
            env::current_dir().unwrap().join(p)
        };
        tools.push((name.to_string(), abs));
    }

    if let Some((_, corepack)) = tools.iter().find(|(n, _)| n == "corepack") {
        let node = &tools.iter().find(|(n, _)| n == "node").unwrap().1;
        let npm = tools
            .iter()
            .find(|(n, _)| n == "npm")
            .unwrap()
            .1
            .canonicalize()
            .unwrap();
        let standalone = &tools.iter().find(|(n, _)| n == "standalone").unwrap().1;
        test_corepack(&cli, corepack, standalone, node);
        test_install_home_and_accept(&cli, &npm, node);
    }

    for (name, path) in &tools {
        if name == "cargo" {
            test_cargo_roundtrip(&cli, path);
        } else if !matches!(name.as_str(), "corepack" | "node" | "standalone") {
            test_manager(&cli, path, name);
        }
    }
}
