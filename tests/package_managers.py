"""Local dependency lifecycle fixtures. Pass the executable paths to test."""

import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


def write_json(path, value):
    path.write_text(json.dumps(value) + "\n")


def test_pnpm_store(cli, tool, workspace, env, version):
    project = workspace / "store-interoperability"
    project.mkdir()
    home = workspace / "native-home"
    home.mkdir()
    env = dict(env, HOME=str(home), XDG_DATA_HOME=str(home / "data"))
    if sys.platform == "linux":
        runtime = project / "runtime"
        shutil.copytree(tool.parent.parent, runtime, symlinks=True)
        tool = runtime / tool.parent.name / tool.name
        env["PATH"] = f"{tool.parent}:{env['PATH']}"
    dependency = project / "fixture"
    dependency.mkdir()
    write_json(dependency / "package.json", {
        "name": "test-store-dependency",
        "version": "1.0.0",
        "main": "index.js",
        "bin": {"test-store-bin": "bin.js"},
    })
    (dependency / "index.js").write_text("module.exports = 'store-dep-ok';\n")
    (dependency / "bin.js").write_text("#!/usr/bin/env node\nconsole.log('store-bin-ok');\n")
    (dependency / "bin.js").chmod(0o755)
    marker_file = project / "precheck-ran.marker"
    precheck_dep = project / "precheck-marker-dep"
    precheck_dep.mkdir()
    write_json(precheck_dep / "package.json", {
        "name": "precheck-marker-dep",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node -e \"require('fs').writeFileSync(process.env.PRECHECK_MARKER, 'ran')\""
        },
    })
    env["PRECHECK_MARKER"] = str(marker_file)
    for name in ("plain-extra", "wrapped-extra"):
        extra = project / name
        extra.mkdir()
        write_json(extra / "package.json", {"name": name, "version": "1.0.0"})
    write_json(project / "package.json", {
        "name": "test-store-project", "version": "1.0.0", "private": True,
        "dependencies": {"test-store-dependency": "file:./fixture"},
    })

    def invoke(*args, expected=0):
        child = subprocess.run(args, cwd=project, env=env, text=True, capture_output=True, timeout=30)
        assert child.returncode == expected, (args, child.stdout, child.stderr)
        return child

    def snapshot_modules(root):
        entries = {}
        for path in (root, *root.rglob("*")):
            metadata = path.lstat()
            contents = None
            if stat.S_ISLNK(metadata.st_mode):
                contents = os.readlink(path)
            elif stat.S_ISREG(metadata.st_mode):
                contents = path.read_bytes()
            entries[path.relative_to(root)] = (metadata.st_mode, metadata.st_mtime_ns, contents)
        return entries

    guarded = invoke(cli, tool, "install", "--offline", expected=125)
    assert "storeDir: .pnpm-store" in guarded.stderr, guarded.stderr
    modules_dir = project / "node_modules"
    assert not modules_dir.exists()
    # The guard also preserves a dependency tree previously installed by plain pnpm.
    invoke(tool, "install", "--offline")
    modules = modules_dir / ".modules.yaml"
    assert modules.is_file()
    native_modules = snapshot_modules(modules_dir)
    # Existing dependency remains executable before and after a pre-flight 125 denial.
    assert invoke("node", "-e", "if (require('test-store-dependency') !== 'store-dep-ok') process.exit(1)").returncode == 0
    assert invoke(modules_dir / ".bin" / "test-store-bin").stdout.strip() == "store-bin-ok"
    guarded = invoke(cli, tool, "install", "--offline", expected=125)
    assert "storeDir: .pnpm-store" in guarded.stderr, guarded.stderr
    assert not marker_file.exists()
    assert snapshot_modules(modules_dir) == native_modules
    assert invoke("node", "-e", "if (require('test-store-dependency') !== 'store-dep-ok') process.exit(1)").returncode == 0
    assert invoke(modules_dir / ".bin" / "test-store-bin").stdout.strip() == "store-bin-ok"
    # Even when adding a package with postinstall, pre-flight denial must not spawn the child.
    denied_add = invoke(cli, tool, "add", "-w", "--offline", "file:./precheck-marker-dep", expected=125)
    assert "storeDir: .pnpm-store" in denied_add.stderr, denied_add.stderr
    assert not marker_file.exists()
    assert snapshot_modules(modules_dir) == native_modules

    config = project / "pnpm-workspace.yaml"
    install_settings = "packages: ['.']\nstoreDir: .pnpm-store\n"
    config.write_text(install_settings)
    if version.startswith("9."):
        wrong_store = invoke(cli, tool, "install", "--offline", expected=125)
        assert "pnpm store path" in wrong_store.stderr, wrong_store.stderr
        (project / ".npmrc").write_text("store-dir=.pnpm-store\n")
    # Keep the original tree for the test. The next install starts empty.
    modules_dir.rename(project / "native-modules")
    override = invoke(cli, tool, "--store-dir", ".other-store", "install", "--offline", expected=125)
    assert "workspace configured in the current directory" in override.stderr, override.stderr
    assert not modules.exists()
    invoke(cli, tool, "install", "--offline")
    store = Path(invoke(tool, "store", "path").stdout.strip()).resolve()
    assert store.parent == project / ".pnpm-store", store
    assert str(store) in modules.read_text(), modules.read_text()
    config_state = config.read_bytes()
    assert config_state.decode() == install_settings
    invoke(tool, "add", "-w", "--offline", "file:./plain-extra")
    invoke(cli, tool, "add", "-w", "--offline", "file:./wrapped-extra")
    installed = json.loads((project / "package.json").read_text())["dependencies"]
    assert {"plain-extra", "wrapped-extra"} <= installed.keys()
    report = invoke(cli, "--json", tool, "install", "--offline")
    assert json.loads(report.stdout)["run_status"]["exit_code"] == 0
    assert str(store) in modules.read_text() and config.read_bytes() == config_state
    print(
        f"{sys.platform} pnpm {version} store_missing=125 existing_node_modules=unchanged "
        "isolated_install=0 native_add=0 isolated_add=0",
        flush=True,
    )


def write_tarball_package(target_tgz):
    files = {
        "package/package.json": (
            json.dumps(
                {
                    "name": "roundtrip-dep",
                    "version": "1.0.0",
                    "main": "index.js",
                    "bin": {"roundtrip-cli": "bin.js"},
                }
            )
            + "\n",
            0o644,
        ),
        "package/index.js": ("module.exports = { ok: true, version: '1.0.0' };\n", 0o644),
        "package/bin.js": ("#!/usr/bin/env node\nconsole.log('roundtrip-ok');\n", 0o755),
    }
    with tarfile.open(target_tgz, "w:gz") as tar:
        for name, (content, mode) in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))


def test_native_isolated_native_roundtrip(cli, tool, manager, workspace, base_env, version, yarn_pnp=False):
    variant_tag = f"{manager}-pnp" if yarn_pnp else manager
    roundtrip_root = workspace / f"roundtrip-interoperability-{variant_tag}"
    roundtrip_root.mkdir()
    home = workspace / f"roundtrip-home-{variant_tag}"
    home.mkdir()
    env = dict(base_env, HOME=str(home), XDG_DATA_HOME=str(home / "data"), XDG_CACHE_HOME=str(home / "cache"))
    env.pop("CI", None)

    def prepare_project(name):
        proj = roundtrip_root / name
        proj.mkdir()
        vendor = proj / "vendor"
        vendor.mkdir()
        write_tarball_package(vendor / "roundtrip-dep-1.0.0.tgz")
        write_json(
            proj / "package.json",
            {
                "name": "roundtrip-app",
                "version": "1.0.0",
                "private": True,
                "dependencies": {"roundtrip-dep": "file:./vendor/roundtrip-dep-1.0.0.tgz"},
            },
        )
        local_tool = tool
        local_env = dict(env)
        if sys.platform == "linux":
            runtime = proj / "runtime"
            shutil.copytree(tool.parent.parent, runtime, symlinks=True)
            local_tool = runtime / tool.parent.name / tool.name
            local_env["PATH"] = f"{local_tool.parent}:{os.environ['PATH']}"
        if manager == "npm":
            (proj / ".npmrc").write_text("audit=false\nfund=false\n")
            lock_name = "package-lock.json"
            lock_cmd = [local_tool, "install", "--package-lock-only", "--offline", "--no-audit", "--no-fund"]
            frozen_cmd = [local_tool, "ci", "--offline", "--no-audit", "--no-fund"]
            tracked = ("package.json", "package-lock.json", ".npmrc")
        elif manager == "pnpm":
            (proj / "pnpm-workspace.yaml").write_text(
                "packages:\n  - '.'\nstoreDir: .pnpm-store\nupdateNotifier: false\n"
            )
            npmrc = "update-notifier=false\n"
            if version.startswith("9."):
                npmrc += "store-dir=.pnpm-store\n"
            (proj / ".npmrc").write_text(npmrc)
            lock_name = "pnpm-lock.yaml"
            lock_cmd = [local_tool, "install", "--lockfile-only", "--offline"]
            frozen_cmd = [local_tool, "install", "--frozen-lockfile", "--offline"]
            tracked = ("package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc")
        elif manager == "yarn" and version.startswith("1."):
            lock_name = "yarn.lock"
            lock_cmd = [local_tool, "install", "--offline"]
            frozen_cmd = [local_tool, "install", "--frozen-lockfile", "--offline"]
            tracked = ("package.json", "yarn.lock")
        elif manager == "yarn":
            linker = "pnp" if yarn_pnp else "node-modules"
            (proj / ".yarnrc.yml").write_text(
                f"enableNetwork: false\nenableScripts: true\nenableGlobalCache: false\n"
                f"enableImmutableInstalls: false\nnodeLinker: {linker}\n"
            )
            lock_name = "yarn.lock"
            lock_cmd = [local_tool, "install"]
            frozen_cmd = [local_tool, "install", "--immutable"]
            tracked = ("package.json", "yarn.lock", ".yarnrc.yml")
        elif manager == "bun":
            lock_name = "bun.lock"
            lock_cmd = [local_tool, "install"]
            frozen_cmd = [local_tool, "install", "--frozen-lockfile"]
            tracked = ("package.json", "bun.lock")
        else:
            raise ValueError(f"unsupported manager: {manager}")
        return proj, local_tool, local_env, lock_name, lock_cmd, frozen_cmd, tracked

    def run_in(proj, args, run_env, expected=0):
        res = subprocess.run(args, cwd=proj, env=run_env, text=True, capture_output=True, timeout=30)
        assert res.returncode == expected, (args, res.stdout, res.stderr)
        return res

    def verify_installed_dependency(proj, local_tool, run_env):
        if yarn_pnp:
            run_in(
                proj,
                [local_tool, "node", "-e", "const d = require('roundtrip-dep'); if (!d.ok || d.version !== '1.0.0') process.exit(1);"],
                run_env,
            )
            out = run_in(proj, [local_tool, "roundtrip-cli"], run_env)
            assert "roundtrip-ok" in out.stdout, out.stdout
            return
        js_runner = local_tool if manager == "bun" else "node"
        run_in(
            proj,
            [js_runner, "-e", "const d = require('roundtrip-dep'); if (!d.ok || d.version !== '1.0.0') process.exit(1);"],
            run_env,
        )
        cli_bin = proj / "node_modules" / ".bin" / "roundtrip-cli"
        out = run_in(proj, [cli_bin], run_env)
        assert out.stdout.strip() == "roundtrip-ok", out.stdout

    # Generate a real lockfile cleanly first, then copy locked inputs to control and roundtrip projects.
    seed, _, seed_env, lock_name, seed_lock_cmd, _, _ = prepare_project("seed")
    run_in(seed, seed_lock_cmd, seed_env)

    control, control_tool, control_env, _, _, control_cmd, tracked = prepare_project("control")
    roundtrip, rt_tool, rt_env, _, _, rt_cmd, _ = prepare_project("roundtrip")
    lock_bytes = (seed / lock_name).read_bytes()
    (control / lock_name).write_bytes(lock_bytes)
    (roundtrip / lock_name).write_bytes(lock_bytes)
    if manager == "yarn" and not version.startswith("1.") and (seed / ".yarn").exists():
        for dst in (control / ".yarn", roundtrip / ".yarn"):
            shutil.copytree(seed / ".yarn", dst, symlinks=True)

    # Control: plain frozen install + verify dependency execution
    run_in(control, control_cmd, control_env)
    verify_installed_dependency(control, control_tool, control_env)
    expected_files = {rel: (control / rel).read_bytes() for rel in tracked}

    # Roundtrip Step 1: plain frozen install + execute dependency
    run_in(roundtrip, rt_cmd, rt_env)
    verify_installed_dependency(roundtrip, rt_tool, rt_env)

    # Roundtrip Step 2: isolated warm cache (initial baseline save + CI compare)
    run_in(roundtrip, [cli, *rt_cmd], rt_env)
    baseline = roundtrip / ".veil-tell" / f"{manager}.json"
    baseline_data = json.loads(baseline.read_text())
    assert baseline_data["backend"] == "isolated"
    assert baseline_data["lockfile"]["ecosystem"] == manager
    warm_ci = run_in(roundtrip, [cli, "ci", "--json", "--", *rt_cmd], rt_env)
    assert json.loads(warm_ci.stdout)["comparison"]["status"] == "compared"

    # Roundtrip Step 3: isolated cold cache (remove installed outputs / store)
    for cache_rel in ("node_modules", ".pnpm-store", ".pnp.cjs", ".pnp.loader.mjs", ".yarn/unplugged"):
        cache_path = roundtrip / cache_rel
        if cache_path.is_dir():
            shutil.rmtree(cache_path)
        elif cache_path.exists():
            cache_path.unlink()
    cold_ci = run_in(roundtrip, [cli, "ci", "--json", "--", *rt_cmd], rt_env)
    assert json.loads(cold_ci.stdout)["comparison"]["status"] == "compared"

    # Roundtrip Step 4: plain frozen install again after isolation (native -> isolated -> native)
    run_in(roundtrip, rt_cmd, rt_env)
    verify_installed_dependency(roundtrip, rt_tool, rt_env)

    # Verify config/lock invariants match control byte-for-byte
    for rel in tracked:
        assert (roundtrip / rel).read_bytes() == expected_files[rel], f"{rel} changed during roundtrip"

    if manager == "pnpm":
        native_store = Path(run_in(roundtrip, [rt_tool, "store", "path"], rt_env).stdout.strip()).resolve()
        isolated_store_res = run_in(
            roundtrip,
            [cli, "observe", "--backend", "isolated", "--", rt_tool, "store", "path"],
            rt_env,
        )
        assert Path(isolated_store_res.stdout.strip()).resolve() == native_store, isolated_store_res.stdout
        assert native_store.parent == roundtrip / ".pnpm-store", native_store
        modules_yaml = (roundtrip / "node_modules" / ".modules.yaml").read_text()
        assert str(native_store) in modules_yaml, modules_yaml

    print(
        f"{sys.platform} {variant_tag} {version} roundtrip=native->isolated(warm+cold)->native "
        "invariants=matched dependency_exec=ok",
        flush=True,
    )


def test_cargo_roundtrip(cli, cargo_tool):
    with tempfile.TemporaryDirectory(prefix="veil-pm-cargo-") as folder:
        root = Path(folder).resolve()
        env = dict(os.environ, PATH=f"{cargo_tool.parent}:{os.environ['PATH']}")
        env.pop("CI", None)
        version = subprocess.check_output([cargo_tool, "-V"], env=env, text=True).strip()

        def prepare_cargo_workspace(name):
            ws = root / name
            dep = ws / "dep"
            app = ws / "app"
            (dep / "src").mkdir(parents=True)
            (app / "src").mkdir(parents=True)
            (dep / "Cargo.toml").write_text(
                '[package]\nname = "roundtrip-dep"\nversion = "0.1.0"\nedition = "2024"\n'
            )
            (dep / "src" / "lib.rs").write_text(
                'pub fn greeting() -> &\'static str { "cargo-roundtrip-ok" }\n'
            )
            (app / "Cargo.toml").write_text(
                '[package]\nname = "roundtrip-app"\nversion = "0.1.0"\nedition = "2024"\n'
                '[dependencies]\nroundtrip-dep = { path = "../dep" }\n'
            )
            (app / "build.rs").write_text('fn main() { println!("cargo:rerun-if-changed=build.rs"); }\n')
            (app / "src" / "main.rs").write_text(
                'fn main() { println!("{}", roundtrip_dep::greeting()); }\n'
            )
            return ws, app

        def run_in(cwd, args, expected=0):
            res = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=60)
            assert res.returncode == expected, (args, res.stdout, res.stderr)
            return res

        _, seed_app = prepare_cargo_workspace("seed")
        run_in(seed_app, [cargo_tool, "generate-lockfile", "--offline"])
        lock_bytes = (seed_app / "Cargo.lock").read_bytes()

        _, ctrl_app = prepare_cargo_workspace("control")
        (ctrl_app / "Cargo.lock").write_bytes(lock_bytes)
        run_in(ctrl_app, [cargo_tool, "build", "--locked", "--offline"])
        assert run_in(ctrl_app, [ctrl_app / "target" / "debug" / "roundtrip-app"]).stdout.strip() == "cargo-roundtrip-ok"
        tracked = ("Cargo.toml", "Cargo.lock", "build.rs")
        expected_files = {rel: (ctrl_app / rel).read_bytes() for rel in tracked}

        _, rt_app = prepare_cargo_workspace("roundtrip")
        (rt_app / "Cargo.lock").write_bytes(lock_bytes)
        build_cmd = ["cargo", "build", "--locked", "--offline"]

        # Step 1: plain cargo build + run
        run_in(rt_app, build_cmd)
        assert run_in(rt_app, [rt_app / "target" / "debug" / "roundtrip-app"]).stdout.strip() == "cargo-roundtrip-ok"

        # Step 2: isolated warm build (save baseline + CI compare)
        run_in(rt_app, [cli, *build_cmd])
        baseline = json.loads((rt_app / ".veil-tell" / "cargo.json").read_text())
        assert baseline["backend"] == "isolated"
        assert baseline["lockfile"]["ecosystem"] == "cargo"
        warm_ci = run_in(rt_app, [cli, "ci", "--json", "--", *build_cmd])
        assert json.loads(warm_ci.stdout)["comparison"]["status"] == "compared"

        # Step 3: isolated cold build (remove target)
        shutil.rmtree(rt_app / "target")
        cold_ci = run_in(rt_app, [cli, "ci", "--json", "--", *build_cmd])
        assert json.loads(cold_ci.stdout)["comparison"]["status"] == "compared"

        # Step 4: plain cargo build again + run built binary
        run_in(rt_app, build_cmd)
        assert run_in(rt_app, [rt_app / "target" / "debug" / "roundtrip-app"]).stdout.strip() == "cargo-roundtrip-ok"
        for rel in tracked:
            assert (rt_app / rel).read_bytes() == expected_files[rel], f"{rel} changed during roundtrip"

        print(
            f"{sys.platform} cargo ({version}) roundtrip=native->isolated(warm+cold)->native "
            "invariants=matched binary_exec=ok",
            flush=True,
        )


def test_manager(cli, tool, manager):
    with tempfile.TemporaryDirectory(prefix=f"veil-pm-{manager}-") as folder:
        root = Path(folder).resolve()
        project = root / "project"
        project.mkdir()
        env = dict(os.environ, PATH=f"{tool.parent}:{os.environ['PATH']}")
        version = subprocess.check_output([tool, "--version"], env=env, text=True).strip()
        env.pop("CI", None)
        runtime_tool = tool
        if sys.platform == "linux":
            # Bubblewrap exposes the workspace, /usr and /nix/store.
            runtime = project / "runtime"
            shutil.copytree(tool.parent.parent, runtime, symlinks=True)
            runtime_tool = runtime / tool.parent.name / tool.name
            env["PATH"] = f"{runtime_tool.parent}:{os.environ['PATH']}"
        if manager == "pnpm":
            test_pnpm_store(cli, runtime_tool, project, env, version)
        if manager in ("npm", "pnpm", "yarn", "bun"):
            test_native_isolated_native_roundtrip(cli, tool, manager, project, env, version)
            if manager == "yarn" and not version.startswith("1."):
                test_native_isolated_native_roundtrip(cli, tool, manager, project, env, version, yarn_pnp=True)
        package = {"name": "fixture", "private": True, "version": "1.0.0"}
        if manager == "bun":
            package["trustedDependencies"] = ["probe"]
        before = project / "before"
        before.mkdir()
        package["dependencies"] = {"probe": "file:./before"}
        write_json(before / "package.json", {
            "name": "probe", "version": "1.2.2",
            "scripts": {"postinstall": "node -e 'process.exit(0)'"},
        })
        write_json(project / "package.json", package)
        command = [runtime_tool, "install"]
        if manager == "npm":
            (project / ".npmrc").write_text("install-links=true\naudit=false\nfund=false\n")
        elif manager == "pnpm":
            lifecycle = ("allowBuilds:\n  probe: true\n  probe@file:before: true\n  probe@file:dep: true\n"
                         if not version.startswith("9.") else (
                "onlyBuiltDependencies:\n  - probe\nmanagePackageManagerVersions: false\n"
            ))
            (project / "pnpm-workspace.yaml").write_text(
                "packages:\n  - no-workspaces/*\n" + lifecycle + "updateNotifier: false\nstoreDir: .pnpm-store\n"
            )
            npmrc = "update-notifier=false\n"
            if version.startswith("9."):
                npmrc += "store-dir=.pnpm-store\n"
            (project / ".npmrc").write_text(npmrc)
            command += ["--offline"]
        elif manager == "yarn":
            if version.startswith("1."):
                command += ["--offline"]
            else:
                (project / ".yarnrc.yml").write_text("enableNetwork: false\nenableScripts: true\nenableGlobalCache: false\nenableImmutableInstalls: false\n")

        def run(args):
            start = time.monotonic()
            child = subprocess.run(args, cwd=project, env=env, text=True, capture_output=True, timeout=30)
            return child, time.monotonic() - start

        # Measure from equivalent source and empty project caches.
        control_project = root / "control"
        shutil.copytree(project, control_project, symlinks=True, ignore=shutil.ignore_patterns("runtime"))
        start = time.monotonic()
        control = subprocess.run(command, cwd=control_project, env=env, text=True, capture_output=True, timeout=30)
        elapsed = time.monotonic() - start
        assert control.returncode == 0, (control.stdout, control.stderr)
        local, isolated = run([cli, *command])
        assert local.returncode == 0, (local.stdout, local.stderr)
        baseline = project / ".veil-tell" / f"{manager}.json"
        recorded = json.loads(baseline.read_text())
        assert recorded["backend"] == "isolated"
        assert recorded["lockfile"]["ecosystem"] == manager, recorded
        for i in range(10):
            if i >= 5:
                hold = root / f"cold-cache-{i}"
                hold.mkdir()
                for relative in ("node_modules", ".pnpm-store", ".yarn", ".pnp.cjs", ".pnp.loader.mjs"):
                    cache = project / relative
                    if cache.exists():
                        cache.rename(hold / relative)
            stable, _ = run([cli, *command])
            assert stable.returncode == 0 and "veil-tell accept" not in stable.stderr, stable.stderr
            assert "volume anomaly" not in stable.stderr, stable.stderr
            assert not (baseline.parent / "pending.json").exists()
        stable_ci, _ = run([cli, "ci", "--json", "--", *command])
        comparison = json.loads(stable_ci.stdout)["comparison"]
        assert stable_ci.returncode == 0 and comparison["status"] == "compared", stable_ci
        assert "lockfile_changes" in comparison, comparison
        short_ci = subprocess.run([cli, "--json", *command], cwd=project, env=dict(env, CI="true"),
                                  text=True, capture_output=True, timeout=30)
        assert short_ci.returncode == 0, short_ci.stderr
        assert json.loads(short_ci.stdout)["comparison"]["status"] == "compared"
        print(f"{sys.platform} {manager} {version} warm=5 cold=5 ci=0 control={elapsed:.3f}s isolated={isolated:.3f}s", flush=True)

        dep = project / "dep"
        dep.mkdir()
        package["dependencies"] = {"probe": "file:./dep"}
        write_json(project / "package.json", package)
        write_json(dep / "package.json", {
            "name": "probe", "version": "1.2.3", "scripts": {"postinstall": "node probe.cjs"},
        })
        (dep / "probe.cjs").write_text(
            'require("node:dns").promises.lookup("new-package.invalid").then(() => process.exit(2), '
            'error => { if (error.code !== "ENOTFOUND") process.exit(3) });\n'
        )
        update_flags = ["--force"] if manager == "pnpm" and version.startswith("9.") else []
        updated, _ = run([cli, "ci", "--json", "--", *command, *update_flags])
        assert updated.returncode == 21, (updated.stdout, updated.stderr)
        report = json.loads(updated.stdout)
        attempt, = report["comparison"]["attempted_added"]
        source, = attempt["attribution"]
        assert attempt["host"] == "new-package.invalid"
        if manager == "bun":
            assert source == {"confidence": "unknown"}, report
            print(f"{sys.platform} bun changed=21 attribution=unknown", flush=True)
            return
        assert source["confidence"] == "inferred"
        assert source["package"]["name"] == "probe" and source["package"]["version"] == "1.2.3"
        assert source["package"]["script"] == "postinstall"
        print(next(line for line in updated.stderr.splitlines() if "attempted (blocked)" in line), flush=True)


def test_corepack(cli, corepack, standalone, node):
    with tempfile.TemporaryDirectory(prefix="veil-corepack-") as folder:
        root = Path(folder).resolve()
        project = root / "project"
        project.mkdir()
        home = root / "home"
        bin_dir = home / "bin"
        bin_dir.mkdir(parents=True)
        cache = home / ".cache/node/corepack"
        (bin_dir / "corepack").symlink_to(corepack)
        (bin_dir / "pnpm").symlink_to(corepack.with_name("pnpm.js"))
        shutil.copy2(node, bin_dir / "node")
        (home / "private-sentinel").write_text("outside the sandbox")
        env = dict(os.environ, HOME=str(home), COREPACK_HOME=str(cache),
                   PATH=f"{bin_dir}:{os.environ['PATH']}")
        env.pop("CI", None)

        def run(*args, env=env, expected=0):
            result = subprocess.run(args, cwd=project, env=env, text=True, capture_output=True, timeout=30)
            assert result.returncode == expected, (args, result.stdout, result.stderr)
            return result

        write_json(project / "package.json", {
            "name": "test-corepack", "private": True, "packageManager": "pnpm@10.34.9",
        })
        (project / "pnpm-workspace.yaml").write_text("storeDir: .pnpm-store\n")
        cold = run(cli, "pnpm", "install", "--offline", expected=125)
        assert "failed during the isolated store probe" in cold.stderr, cold.stderr
        assert "corepack install" in cold.stderr and "storeDir:" not in cold.stderr, cold.stderr
        assert not (project / "node_modules").exists()

        run("corepack", "install")
        snapshot = {p.relative_to(cache) for p in cache.rglob("*")}
        del env["COREPACK_HOME"]
        env["XDG_CACHE_HOME"] = str(home / ".cache")
        run(cli, "pnpm", "install", "--offline")
        run(cli, "corepack", "pnpm", "install", "--offline")
        assert json.loads((project / ".veil-tell/pnpm.json").read_text())["backend"] == "isolated"
        run(cli, "corepack", "pnpm", "exec", "/bin/sh", "-c",
            'test -d "$COREPACK_HOME/v1/pnpm" && ! touch "$COREPACK_HOME/v1/pnpm/probe"')
        assert {p.relative_to(cache) for p in cache.rglob("*")} == snapshot
        if sys.platform == "linux":
            run(cli, "corepack", "pnpm", "exec", "/bin/sh", "-c", 'test ! -e "$1"', "sh",
                home / "private-sentinel")

        # Exercise a standalone pnpm copied into the home directory outside the workspace.
        standalone = shutil.copy2(standalone, home / "pnpm")
        (project / "package.json").write_text('{"name":"test-standalone","private":true}\n')
        standalone_project = root / "standalone"
        standalone_project.mkdir()
        shutil.copy2(project / "package.json", standalone_project)
        shutil.copy2(project / "pnpm-workspace.yaml", standalone_project)
        result = subprocess.run([cli, standalone, "install", "--offline"], cwd=standalone_project,
                                env=env, text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, (result.stdout, result.stderr)
        print(f"{sys.platform} corepack cold=125 cached_shim=0 explicit=0 home_pnpm=0", flush=True)


def test_install_home_and_accept(cli, npm, node):
    with tempfile.TemporaryDirectory(prefix="veil-install-") as folder:
        root = Path(folder).resolve()
        project = root / "project"
        project.mkdir()
        tools = project / "tools"
        tools.mkdir()
        shutil.copy2(node, tools / "node")
        shutil.copytree(npm.parent.parent, tools / "npm-package")
        (tools / "npm").symlink_to(tools / "npm-package/bin/npm-cli.js")
        env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}",
                   NPM_CONFIG_PREFIX=str(root / "unused-prefix"))
        env.pop("CI", None)
        env.pop("VEIL_TELL_PROJECT_HOME", None)

        def run(*args, env=env, expected=0):
            result = subprocess.run(args, cwd=project, env=env, text=True, capture_output=True, timeout=30)
            assert result.returncode == expected, (args, result.stdout, result.stderr)
            return result

        (project / "package.json").write_text(json.dumps({
            "name": "install-home-fixture", "version": "1.0.0", "private": True,
            "scripts": {"postinstall": "node install.cjs"},
        }))
        script = project / "install.cjs"
        script.write_text("""
const {writeFileSync} = require('node:fs');
const {homedir} = require('node:os');
const {join} = require('node:path');
writeFileSync(join(homedir(), 'fixture-program'), '#!/bin/sh\\nprintf "ready"\\n', {mode: 0o700});
""")
        command = ["npm", "install", "--offline", "--no-audit", "--no-fund"]
        host_home = root / "home"
        host_home.mkdir()
        native = dict(env, HOME=str(host_home))
        run(cli, *command, env=native)
        assert not (host_home / "fixture-program").exists()
        project_home = project / ".veil-home"
        project_home.symlink_to(host_home)
        persistent = dict(native, VEIL_TELL_PROJECT_HOME=project_home.name)
        run(cli, *command, env=persistent, expected=125)
        assert not (host_home / "fixture-program").exists()
        project_home.rename(project / "invalid-home-link")
        run(cli, *command, env=persistent)
        assert project_home.stat().st_mode & 0o077 == 0
        assert run(project_home / "fixture-program").stdout == "ready"

        baseline = project / ".veil-tell/npm.json"
        pending = baseline.with_name("pending.json")
        original = baseline.read_bytes()
        external = root / "baseline.json"
        external.write_bytes(original)
        script.write_text(script.read_text() + """
const {lookup} = require('node:dns');
lookup('new-install-host.invalid', error => {
  if (error?.code !== 'ENOTFOUND') process.exitCode = 1;
});
try {
  writeFileSync('.veil-tell/pending.json', 'forged');
  process.exitCode = 2;
} catch (error) {
  if (!['EACCES', 'EPERM', 'EROFS'].includes(error.code)) throw error;
}
""")
        # Explicit CI inputs retain a read-only review workflow.
        explicit = run(cli, "ci", "--baseline", external, "--json", "--", *command,
                       env=persistent, expected=21)
        assert explicit.stdout and external.read_bytes() == original
        assert not pending.exists() and baseline.read_bytes() == original
        for args, run_env in [
            (["ci", "--json", "--", *command], persistent),
            (["--json", *command], dict(persistent, CI="true")),
        ]:
            changed = run(cli, *args, env=run_env, expected=21)
            report = json.loads(changed.stdout)
            assert report["child_status"]["exit_code"] == 0, report
            assert "veil-tell accept" in changed.stderr and "attribution is off" not in changed.stderr
            entry, = report["comparison"]["attempted_added"]
            source, = entry["attribution"]
            assert source["package"]["name"] == "install-home-fixture", source
            assert baseline.read_bytes() == original
            assert json.loads(pending.read_text())["key"] == "npm"
            run(cli, "accept", env=run_env)
            assert not pending.exists()
            run(cli, *args, env=run_env)
            baseline.write_bytes(original)
        print(f"{sys.platform} persistent_home=0 unsafe_home=125 npm_prefix=attributed ci=21/accept=0/ci=0",
              flush=True)


if __name__ == "__main__":
    cli = Path(sys.argv[1]).resolve()
    if len(sys.argv)>2 and sys.argv[2]=="--persistent":
        from agent_env import trial
        trial(str(cli.parent/"examples/receiver_cli"),sys.argv[3],cache=True)
        sys.exit(0)
    tools = [(name, Path(path).absolute()) for name, path in (arg.split("=", 1) for arg in sys.argv[2:])]
    if compatibility := [path for name, path in tools if name == "corepack"]:
        corepack, = compatibility
        node = next(path for name, path in tools if name == "node")
        npm = next(path for name, path in tools if name == "npm").resolve()
        standalone = next(path for name, path in tools if name == "standalone")
        test_corepack(cli, corepack, standalone, node)
        test_install_home_and_accept(cli, npm, node)
    for name, path in tools:
        if name == "cargo":
            test_cargo_roundtrip(cli, path)
        elif name not in ("corepack", "node", "standalone"):
            test_manager(cli, path, name)
