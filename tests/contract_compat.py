"""C01 compatibility contract tests against frozen v0.6.0 fixtures."""

from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "compat-v0.6.0"
SUMMARY_SCRIPT = ROOT / ".github" / "destination-summary.py"
BINARY_PATH = (
    Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "debug" / "veil-tell"
).resolve()


def load_summary_module():
    spec = importlib.util.spec_from_file_location("destination_summary", SUMMARY_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CompatV060Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
        cls.summary_mod = load_summary_module()

    def test_manifest_files_exist(self):
        for name in self.manifest["fixtures"]:
            self.assertTrue((FIXTURES / name).is_file(), f"missing fixture {name}")

    def test_report_fixtures_against_summary_contract(self):
        for name, expected in self.manifest["fixtures"].items():
            if not name.startswith("report-"):
                continue
            data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], 1)
            res = self.summary_mod.analyze_report(data)
            self.assertEqual(res["should_comment"], expected["should_comment"], name)
            self.assertEqual(res["has_findings"], expected["has_findings"], name)
            self.assertEqual(res["reasons"], expected["reasons"], name)

    def test_verify_fixtures_contract(self):
        for name, expected in self.manifest["fixtures"].items():
            if not name.startswith("verify-"):
                continue
            data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(data["verdict"], expected["verdict"])
            self.assertEqual(data["exit_code"], expected["exit_code"])
            self.assertIn("trials", data)

    @unittest.skipUnless(BINARY_PATH.is_file(), "veil-tell binary not built")
    def test_real_binary_reads_v060_baselines_policy_and_logs(self):
        with tempfile.TemporaryDirectory(prefix="veil-c01-") as tmp:
            td = Path(tmp).resolve()
            # 1. Valid minimal & full v1 baselines
            for name in ("baseline-minimal.json", "baseline-full.json"):
                exp = self.manifest["fixtures"][name]
                proc = subprocess.run(
                    [
                        str(BINARY_PATH),
                        "observe",
                        "--backend",
                        "proxy",
                        "--baseline",
                        str(FIXTURES / name),
                        "--json",
                        "--",
                        "/bin/sh",
                        "-c",
                        "exit 0",
                    ],
                    cwd=td,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, exp["expected_exit"], proc.stderr)
                report = json.loads(proc.stdout)
                self.assertEqual(report["comparison"]["status"], exp["expected_comparison_status"])

            # 2. Invalid baselines rejected with exit 125
            for name in ("baseline-invalid-unknown-version.json", "baseline-invalid-unknown-field.json"):
                proc = subprocess.run(
                    [
                        str(BINARY_PATH),
                        "observe",
                        "--backend",
                        "proxy",
                        "--baseline",
                        str(FIXTURES / name),
                        "--",
                        "/bin/sh",
                        "-c",
                        "exit 0",
                    ],
                    cwd=td,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 125, (name, proc.stderr))

            # 3. Restrict TOML v1 policy accepted
            pol = subprocess.run(
                [
                    str(BINARY_PATH),
                    "restrict",
                    "--backend",
                    "proxy",
                    "--policy",
                    str(FIXTURES / "policy-v1.toml"),
                    "--json",
                    "--",
                    "/bin/sh",
                    "-c",
                    "exit 0",
                ],
                cwd=td,
                capture_output=True,
                text=True,
            )
            self.assertEqual(pol.returncode, 0, pol.stderr)
            self.assertEqual(json.loads(pol.stdout)["mode"], "restrict")

            # 4. Agent JSONL v0.6.0 log (without session_id/operation_id) readable by `log --today --json`
            state_root = td / "state"
            log_dir = state_root / "veil-tell" / "log"
            log_dir.mkdir(parents=True)
            (state_root / "veil-tell").chmod(0o700)
            log_dir.chmod(0o700)
            today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            now_ts = int(time.time())
            raw_lines = (FIXTURES / "agent-log-v0.6.0.jsonl").read_text(encoding="utf-8").splitlines()
            rewritten = []
            for idx, line in enumerate(raw_lines):
                obj = json.loads(line)
                obj["time"] = now_ts - 10 + idx
                rewritten.append(json.dumps(obj))
            log_file = log_dir / f"{today_utc}.jsonl"
            log_file.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
            log_file.chmod(0o600)

            env = dict(os.environ, HOME=str(td), XDG_STATE_HOME=str(state_root))
            log_res = subprocess.run(
                [str(BINARY_PATH), "log", "--today", "--json"],
                cwd=td,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(log_res.returncode, 0, log_res.stderr)
            parsed = [json.loads(line) for line in log_res.stdout.strip().splitlines() if line]
            self.assertEqual(len(parsed), 2)
            self.assertEqual(parsed[0].get("scope"), "agent_session")
            self.assertEqual(parsed[1].get("agent", {}).get("name"), "codex")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
