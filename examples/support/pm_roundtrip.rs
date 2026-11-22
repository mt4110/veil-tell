use crate::{copy_dir_all, os_label, run_with_env, write_json};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

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
        gz_bytes[4..8].fill(0);
        gz_bytes[9] = 255;
    }
    fs::write(target_tgz, gz_bytes).unwrap();
}

pub(crate) fn test_pnpm_store(
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

pub(crate) fn test_native_isolated_native_roundtrip(
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
