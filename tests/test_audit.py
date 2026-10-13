import tempfile
import unittest
from pathlib import Path

from least_privilege_bot.audit import WorkflowLoader, analyze_workflow, local_workflows
import yaml


class AuditTest(unittest.TestCase):
    def analyze(self, raw):
        return analyze_workflow("example/repo", ".github/workflows/test.yml", raw)

    def test_on_is_not_boolean(self):
        doc = yaml.load("on: [push]\njobs: {}", Loader=WorkflowLoader)
        self.assertIn("on", doc)
        self.assertNotIn(True, doc)

    def test_missing_permissions_per_job(self):
        found = self.analyze("on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
        self.assertEqual([x.rule for x in found], ["IMPLICIT_DEFAULT"])
        self.assertEqual(found[0].job, "test")

    def test_inherited_write_all_and_job_override(self):
        raw = """on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
  test:
    permissions:
      contents: read
"""
        found = self.analyze(raw)
        self.assertEqual([(x.job, x.rule) for x in found], [("build", "WRITE_ALL")])

    def test_job_scopes_override_whole_workflow(self):
        raw = """on: push
permissions:
  issues: write
jobs:
  one:
    permissions:
      contents: read
  two:
    runs-on: ubuntu-latest
"""
        found = self.analyze(raw)
        self.assertEqual([(x.job, x.rule) for x in found], [("two", "WRITE_SCOPE")])

    def test_scoped_write_never_claimed_unnecessary(self):
        found = self.analyze("on: push\njobs:\n  a:\n    permissions: {contents: write}\n")
        self.assertEqual(found[0].rule, "WRITE_SCOPE")
        self.assertIn("cannot be determined", found[0].recommendation)

    def test_pull_request_target_write(self):
        found = self.analyze("on: [pull_request_target]\njobs:\n  test:\n    permissions: write-all\n")
        self.assertEqual({f.rule for f in found}, {"PR_TARGET_WRITE", "WRITE_ALL"})

    def test_none_permissions_clean(self):
        for value in ("{}", "{contents: read}"):
            with self.subTest(value=value):
                self.assertEqual(self.analyze(f"jobs:\n  a:\n    permissions: {value}\n"), [])

    def test_read_all_low(self):
        found = self.analyze("permissions: read-all\njobs:\n  a: {}\n")
        self.assertEqual((found[0].rule, found[0].severity), ("READ_ALL", "low"))

    def test_invalid_permissions(self):
        found = self.analyze("jobs:\n  a:\n    permissions: [contents, write]\n")
        self.assertEqual(found[0].rule, "INVALID_PERMISSIONS")

    def test_invalid_yaml_fail_closed(self):
        found = self.analyze("jobs: [unterminated\n")
        self.assertEqual(found[0].rule, "PARSE_ERROR")

    def test_yaml_rce_not_executed(self):
        found = self.analyze("!!python/object/apply:os.system [echo bad]")
        self.assertEqual(found[0].rule, "PARSE_ERROR")

    def test_local_workflows_only_direct_yaml(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / ".github/workflows"
            folder.mkdir(parents=True)
            (folder / "run.yaml").write_text("jobs: {a: {permissions: {}}}")
            (folder / "ignore.txt").write_text("ignore")
            (folder / "sub").mkdir()
            (folder / "sub" / "nested.yaml").write_text("ignore")
            found = local_workflows(root)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0][0], ".github/workflows/run.yaml")

    def test_findings_have_stable_identity(self):
        raw = "jobs: {a: {permissions: write-all}}"
        self.assertEqual(self.analyze(raw)[0].to_dict()["id"], self.analyze(raw)[0].to_dict()["id"])


if __name__ == "__main__":
    unittest.main()
