import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from least_privilege_bot.cli import main


class CLITest(unittest.TestCase):
    def test_local_scan_reports_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/risky.yml").write_text("on: push\npermissions: write-all\njobs: {test: {}}")
            report_dir = root / "out"
            status = main(["scan", "--path", str(root), "--output-dir", str(report_dir), "--fail-on", "high"])
            self.assertEqual(status, 2)
            data = json.loads((report_dir / "report.json").read_text())
            self.assertEqual(data["counts"]["high"], 1)
            self.assertFalse(data["runtime_usage_observed"])
            self.assertIn("WRITE_ALL", (report_dir / "report.md").read_text())

    def test_publish_rejects_cross_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            report.write_text(json.dumps({"schema_version": "0.1", "analysis_type": "static-only",
                                          "repositories": ["another/repo"], "findings": []}))
            with patch.dict("os.environ", {"GITHUB_TOKEN": "fake"}):
                self.assertEqual(main(["publish-issue", "--repo", "owner/repo", "--report", str(report)]), 1)

    def test_publish_no_finding_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            report.write_text(json.dumps({"schema_version": "0.1", "analysis_type": "static-only",
                                          "repositories": ["o/r"], "findings": []}))
            with patch.dict("os.environ", {"GITHUB_TOKEN": "fake"}):
                self.assertEqual(main(["publish-issue", "--repo", "o/r", "--report", str(report)]), 0)


if __name__ == "__main__":
    unittest.main()
