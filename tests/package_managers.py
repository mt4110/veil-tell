"""Local dependency lifecycle fixtures. Pass the executable paths to test."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
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
    write_json(dependency / "package.json", {"name": "test-store-dependency", "version": "1.0.0"})
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
    guarded = invoke(cli, tool, "install", "--offline", expected=125)
    assert "storeDir: .pnpm-store" in guarded.stderr, guarded.stderr
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
            'fetch("https://new-package.invalid").then(() => process.exit(2), '
            'error => { if (error.cause?.code !== "ENOTFOUND") process.exit(3) });\n'
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
    tools = [(name, Path(path).absolute()) for name, path in (arg.split("=", 1) for arg in sys.argv[2:])]
    if compatibility := [path for name, path in tools if name == "corepack"]:
        corepack, = compatibility
        node = next(path for name, path in tools if name == "node")
        npm = next(path for name, path in tools if name == "npm").resolve()
        standalone = next(path for name, path in tools if name == "standalone")
        test_corepack(cli, corepack, standalone, node)
        test_install_home_and_accept(cli, npm, node)
    for name, path in tools:
        if name not in ("corepack", "node", "standalone"):
            test_manager(cli, path, name)
