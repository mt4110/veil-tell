"""Local dependency lifecycle fixtures. Pass the executable paths to test."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def write_json(path, value):
    path.write_text(json.dumps(value) + "\n")


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
            (project / ".npmrc").write_text("update-notifier=false\n")
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
        for _ in range(5):
            stable, _ = run([cli, *command])
            assert stable.returncode == 0 and "veil-tell accept" not in stable.stderr, stable.stderr
            assert "volume anomaly" not in stable.stderr, stable.stderr
            assert not (baseline.parent / "pending.json").exists()
        stable_ci, _ = run([cli, "ci", "--json", "--", *command])
        comparison = json.loads(stable_ci.stdout)["comparison"]
        assert stable_ci.returncode == 0 and comparison["status"] == "compared", stable_ci
        assert "lockfile_changes" in comparison, comparison
        print(f"{sys.platform} {manager} {version} stable=5 ci=0 control={elapsed:.3f}s isolated={isolated:.3f}s", flush=True)

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


if __name__ == "__main__":
    cli = Path(sys.argv[1]).resolve()
    for argument in sys.argv[2:]:
        name, path = argument.split("=", 1)
        test_manager(cli, Path(path).absolute(), name)
