"""A01 acceptance tests for action.yml, npm workflow template, and destination-summary.py."""

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SUMMARY_SCRIPT = ROOT / ".github" / "destination-summary.py"
ACTION_YML = ROOT / "action.yml"
NPM_TEMPLATE_YML = ROOT / "examples" / "github-actions" / "veil-tell-npm.yml"
BINARY_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "debug" / "veil-tell"


def load_summary_module():
    spec = importlib.util.spec_from_file_location("destination_summary", SUMMARY_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_yaml_file(path):
    try:
        import yaml  # type: ignore

        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except ImportError:
        out = subprocess.check_output(
            [
                "ruby",
                "-ryaml",
                "-rjson",
                "-e",
                "puts JSON.generate(YAML.load_file(ARGV[0]))",
                str(path),
            ],
            text=True,
        )
        return json.loads(out)


def base_report(**overrides):
    report = {
        "schema_version": 1,
        "backend": "isolated",
        "mode": "observe",
        "isolation": "applied",
        "coverage": {
            "proxy": "http_connect_requests",
            "direct_attempt_destinations": "ip_port",
            "dns_attempts": "node_dns_lookup_hook",
            "proxy_capture": "while_running",
        },
        "direct_attempts": [],
        "child_status": {"exit_code": 0, "signal": None},
        "run_status": {"exit_code": 0, "reason": "completed"},
        "destinations": [
            {
                "host": "registry.npmjs.org",
                "port": 443,
                "decision": "allow",
                "reason": "baseline",
                "result": "connected",
                "connected_ip": "104.16.0.1",
                "attempts": 3,
                "sent_bytes": 1200,
                "max_connection_bytes": 600,
                "received_bytes": 8000,
            }
        ],
        "volume_anomalies": [],
        "attempted": [],
        "comparison": {
            "status": "compared",
            "backend_changed": False,
            "added": [],
            "removed": [],
            "attempted_added": [],
            "count_changes": [],
        },
    }
    report.update(overrides)
    return report


class ActionWorkflowTests(unittest.TestCase):
    def test_yaml_validity_and_version_alignment(self):
        action_data = load_yaml_file(ACTION_YML)
        template_data = load_yaml_file(NPM_TEMPLATE_YML)

        self.assertEqual(action_data["runs"]["using"], "composite")
        comment_step = next(
            step for step in action_data["runs"]["steps"] if step.get("name") == "Comment on new destinations"
        )
        self.assertIn("steps.check.outputs.should_comment == 'true'", comment_step["if"])
        self.assertNotIn("steps.check.outputs.status == '21'", comment_step["if"])

        action_text = ACTION_YML.read_text(encoding="utf-8")
        m_action = re.search(r"version=(\d+\.\d+\.\d+)", action_text)
        self.assertIsNotNone(m_action)
        self.assertEqual(template_data["env"]["VEIL_TELL_VERSION"], m_action.group(1))

        job_steps = template_data["jobs"]["npm-destinations"]["steps"]
        for step in job_steps:
            run_body = step.get("run", "")
            self.assertNotIn("sudo apt-get", run_body)

        prereq_step = next(
            step for step in job_steps if step.get("name") == "Check isolation prerequisites"
        )
        self.assertIn("/usr/bin/bwrap --unshare-user --unshare-net", prereq_step["run"])


class DestinationSummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_summary_module()

    def test_quiet_success_single_line_even_with_removed(self):
        report = base_report()
        report["comparison"]["removed"] = [
            {"host": "old-mirror.example.test", "port": 443, "attempts": 1}
        ]
        res = self.mod.analyze_report(report)
        self.assertFalse(res["should_comment"])
        self.assertFalse(res["has_findings"])
        self.assertEqual(len(res["markdown"].splitlines()), 1)
        self.assertIn("OK (quiet)", res["markdown"])

    def test_new_connect_and_dns_attempt_trigger_alert_and_comment(self):
        report = base_report(
            run_status={"exit_code": 21, "reason": "new_destination"},
            child_status={"exit_code": 1, "signal": None},
        )
        report["destinations"].append(
            {
                "host": "storage.googleapis.com",
                "port": 443,
                "decision": "deny",
                "reason": "new_destination",
                "result": "blocked",
                "connected_ip": None,
                "attempts": 1,
                "sent_bytes": 0,
                "max_connection_bytes": 0,
                "received_bytes": 0,
                "attribution": [
                    {
                        "confidence": "inferred",
                        "package": {
                            "name": "puppeteer",
                            "version": "24.0.0",
                            "script": "postinstall",
                            "path": "node_modules/puppeteer",
                        },
                    }
                ],
            }
        )
        report["comparison"]["status"] = "new_destinations_only"
        report["comparison"]["added"] = [
            {
                "host": "storage.googleapis.com",
                "port": 443,
                "attempts": 1,
                "attribution": report["destinations"][-1]["attribution"],
            }
        ]
        report["comparison"]["attempted_added"] = [
            {"host": "telemetry.example.test", "attempts": 2, "attribution": []}
        ]
        res = self.mod.analyze_report(report)
        self.assertTrue(res["should_comment"])
        self.assertTrue(res["has_findings"])
        self.assertIn("新規・拒否", res["markdown"])
        self.assertIn("storage.googleapis.com:443", res["markdown"])
        self.assertIn("puppeteer@24.0.0", res["markdown"])
        self.assertIn("telemetry.example.test", res["markdown"])
        self.assertIn("特定できず (unknown)", res["markdown"])

    def test_known_destination_explicit_deny_and_direct_attempts(self):
        report = base_report(
            direct_attempts=[{"ip": "203.0.113.10", "port": 443, "attempts": 5}],
        )
        report["destinations"].append(
            {
                "host": "telemetry.npmjs.org",
                "port": 443,
                "decision": "deny",
                "reason": "policy_deny",
                "result": "blocked",
                "connected_ip": None,
                "attempts": 2,
                "sent_bytes": 0,
                "max_connection_bytes": 0,
                "received_bytes": 0,
            }
        )
        res = self.mod.analyze_report(report)
        self.assertFalse(res["should_comment"])
        self.assertTrue(res["has_findings"])
        self.assertIn("telemetry.npmjs.org:443", res["markdown"])
        self.assertIn("policy_deny", res["markdown"])
        self.assertIn("203.0.113.10:443", res["markdown"])
        self.assertIn("5 回", res["markdown"])

    def test_direct_attempts_hidden_when_not_observed(self):
        report = base_report(
            direct_attempts=[{"ip": "203.0.113.10", "port": 443, "attempts": 5}],
        )
        report["coverage"]["direct_attempt_destinations"] = "not_observed"
        res = self.mod.analyze_report(report)
        self.assertFalse(res["has_findings"])

    def test_volume_anomaly_observed_and_cut(self):
        for blocked, expected_text in ((False, "observed / 観測"), (True, "cut / 切断")):
            report = base_report(
                run_status={
                    "exit_code": 22 if blocked else 21,
                    "reason": "volume_limit_exceeded" if blocked else "volume_anomaly",
                },
                volume_anomalies=[
                    {
                        "host": "registry.npmjs.org",
                        "port": 443,
                        "observed": {"sent_bytes": 300000, "connections": 4, "max_connection_bytes": 150000},
                        "limits": {"sent_bytes": 262144, "connections": 64, "max_connection_bytes": 131072},
                        "blocked": blocked,
                        "attribution": [],
                    }
                ],
            )
            res = self.mod.analyze_report(report)
            self.assertFalse(res["should_comment"])
            self.assertTrue(res["has_findings"])
            self.assertIn(expected_text, res["markdown"])
            self.assertIn("300000/262144", res["markdown"])

    def test_new_destination_and_volume_anomaly_together(self):
        report = base_report(
            run_status={"exit_code": 21, "reason": "new_destination"},
            volume_anomalies=[
                {
                    "host": "registry.npmjs.org",
                    "port": 443,
                    "observed": {"sent_bytes": 300000, "connections": 4, "max_connection_bytes": 150000},
                    "limits": {"sent_bytes": 262144, "connections": 64, "max_connection_bytes": 131072},
                    "blocked": True,
                    "attribution": [],
                }
            ],
        )
        report["comparison"]["added"] = [
            {"host": "new.example.test", "port": 443, "attempts": 1, "attribution": []}
        ]
        res = self.mod.analyze_report(report)
        self.assertTrue(res["should_comment"])
        self.assertTrue(res["has_findings"])
        self.assertIn("new.example.test:443", res["markdown"])
        self.assertIn("registry.npmjs.org:443", res["markdown"])
        self.assertIn("送信量上限で切断", res["markdown"])

    def test_child_own_exit_21_does_not_fabricate_destination_or_comment(self):
        for code in (20, 21, 22, 125):
            report = base_report(
                child_status={"exit_code": code, "signal": None},
                run_status={"exit_code": code, "reason": "child_failed"},
            )
            report["comparison"] = {"status": "skipped", "added": [], "removed": [], "count_changes": []}
            res = self.mod.analyze_report(report)
            self.assertFalse(res["should_comment"])
            self.assertFalse(res["has_findings"])
            self.assertIn("child failed", res["markdown"])
            self.assertIn(f"exit {code}", res["markdown"])
            self.assertNotIn("New destination", res["markdown"])

    def test_incomplete_capture_with_blocked_destination(self):
        report = base_report(
            run_status={"exit_code": 125, "reason": "incomplete_capture"},
        )
        report["coverage"]["proxy_capture"] = "incomplete"
        report["destinations"].append(
            {
                "host": "blocked.example.test",
                "port": 443,
                "decision": "deny",
                "reason": "policy_deny",
                "result": "blocked",
                "connected_ip": None,
                "attempts": 1,
                "sent_bytes": 0,
                "max_connection_bytes": 0,
                "received_bytes": 0,
            }
        )
        res = self.mod.analyze_report(report)
        self.assertFalse(res["should_comment"])
        self.assertTrue(res["has_findings"])
        self.assertIn("blocked.example.test:443", res["markdown"])
        self.assertIn("run_status.reason=incomplete_capture", res["markdown"])

    def test_cli_missing_and_malformed_report_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            missing = tmp_dir / "absent.json"
            out_file = tmp_dir / "github_output.txt"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SUMMARY_SCRIPT),
                    str(missing),
                    "--github-output",
                    str(out_file),
                    "--missing-reason",
                    "Missing baseline in PR base",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("Missing baseline in PR base", proc.stdout)
            output_text = out_file.read_text(encoding="utf-8")
            self.assertIn("should_comment=false", output_text)
            self.assertIn("has_findings=false", output_text)

            bad_json = tmp_dir / "bad.json"
            bad_json.write_text("{not json", encoding="utf-8")
            proc_bad = subprocess.run(
                [sys.executable, str(SUMMARY_SCRIPT), str(bad_json)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("Could not parse report JSON", proc_bad.stdout)


@unittest.skipUnless(BINARY_PATH.is_file(), "veil-tell binary not built")
class RealBinarySummaryTests(unittest.TestCase):
    def test_real_binary_quiet_and_child_exit_21(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            base = td / "base.json"
            base.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "coverage": "http_connect_requests",
                        "backend": "proxy",
                        "destinations": [],
                    }
                ),
                encoding="utf-8",
            )

            # 1. Quiet success
            quiet_report = td / "quiet.json"
            p_ok = subprocess.run(
                [
                    str(BINARY_PATH),
                    "observe",
                    "--backend",
                    "proxy",
                    "--baseline",
                    str(base),
                    "--report",
                    str(quiet_report),
                    "--",
                    "/bin/sh",
                    "-c",
                    "exit 0",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(p_ok.returncode, 0, p_ok.stderr)
            out_ok = td / "out_ok.txt"
            s_ok = subprocess.run(
                [
                    sys.executable,
                    str(SUMMARY_SCRIPT),
                    str(quiet_report),
                    "--github-output",
                    str(out_ok),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(len(s_ok.stdout.strip().splitlines()), 1)
            self.assertIn("OK (quiet)", s_ok.stdout)
            self.assertIn("should_comment=false", out_ok.read_text(encoding="utf-8"))

            # 2. Child exits 21 without any new destination
            fail_report = td / "fail21.json"
            p_21 = subprocess.run(
                [
                    str(BINARY_PATH),
                    "observe",
                    "--backend",
                    "proxy",
                    "--baseline",
                    str(base),
                    "--report",
                    str(fail_report),
                    "--",
                    "/bin/sh",
                    "-c",
                    "exit 21",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(p_21.returncode, 21, p_21.stderr)
            out_21 = td / "out_21.txt"
            s_21 = subprocess.run(
                [
                    sys.executable,
                    str(SUMMARY_SCRIPT),
                    str(fail_report),
                    "--github-output",
                    str(out_21),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("child failed", s_21.stdout)
            self.assertIn("exit 21", s_21.stdout)
            self.assertIn("should_comment=false", out_21.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
