"""Load runner never relays DB diagnostics and never marks partial runs successful."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import quota_load


class QuotaLoadTest(unittest.TestCase):
    def test_worker_counts_are_bounded_and_distinct(self):
        self.assertEqual(quota_load.positive_list("1,8,32"), [1, 8, 32])
        for value in ("0", "257", "8,8", "bad"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                quota_load.positive_list(value)

    def test_inconsistent_results_are_refused(self):
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            quota_load.parse_result('QUOTA_LOAD {"admitted":10,"refused":1,"requests":100}')
        self.assertIsNone(quota_load.parse_result("password=do-not-relay"))

    def run_fixture(self, returncode, include_result):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        report = Path(folder.name) / "report.json"
        result = {"scenario": "passkey_ip", "workers": 8, "admitted": 60, "refused": 40,
                  "requests": 100, "transactions_per_second": 100, "latency": {"p95_ms": 2}}
        output = io.StringIO()
        with patch("sys.argv", ["quota_load.py", "--requests", "100", "--workers", "8", "--scenarios", "passkey_ip", "--output", str(report)]), \
                patch.dict("os.environ", {"AIRLANCE_AUTH_TEST_DATABASE_URL": "postgres://private-password@host/db"}), \
                patch("quota_load.subprocess.Popen") as popen, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            process = popen.return_value.__enter__.return_value
            process.stdout = ["secret-password diagnostic\n"]
            if include_result:
                process.stdout.append("quota_load_test.go: QUOTA_LOAD " + json.dumps(result) + "\n")
            process.wait.return_value = returncode
            status = quota_load.main()
        self.assertNotIn("secret-password", output.getvalue())
        self.assertNotIn("private-password", output.getvalue())
        self.assertFalse(popen.call_args.kwargs.get("shell", False))
        return status, json.loads(report.read_text()), report

    def test_successful_run_saves_private_report(self):
        status, report, path = self.run_fixture(0, True)
        self.assertEqual(status, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(len(report["results"]), 1)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_failed_or_incomplete_run_is_not_reported_as_success(self):
        for returncode, complete in ((1, True), (0, False)):
            with self.subTest(returncode=returncode, complete=complete):
                status, report, _ = self.run_fixture(returncode, complete)
                self.assertNotEqual(status, 0)
                self.assertFalse(report["passed"])
