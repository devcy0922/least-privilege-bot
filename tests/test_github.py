import base64
import unittest
from unittest.mock import patch

from least_privilege_bot.github import GitHubClient, GitHubError


class GitHubTest(unittest.TestCase):
    def test_repo_rejects_path_traversal(self):
        for value in ("owner/../repo", "owner/repo/foo", "owner/", "owner/repo?x=1", "//"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    GitHubClient._repo_path(value)

    def test_collect_workflows(self):
        client = GitHubClient(token="test")
        def fake(method, path, data=None):
            if path == "/repos/owner/repo":
                return {"default_branch": "main"}
            if path.startswith("/repos/owner/repo/git/trees/"):
                return {"truncated": False, "tree": [
                    {"path": ".github/workflows/test.yml", "type": "blob"},
                    {"path": ".github/workflows/more.yaml", "type": "blob"},
                    {"path": "docs/not.yml", "type": "blob"},
                ]}
            if "/contents/" in path:
                return {"encoding": "base64", "size": 14,
                        "content": base64.b64encode(b"jobs:\n  a: {}\n").decode()}
            raise AssertionError(path)
        with patch.object(client, "request", side_effect=fake):
            data = client.workflows("owner/repo")
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0][0], ".github/workflows/more.yaml")

    def test_truncated_tree_fails_closed(self):
        client = GitHubClient(token="x")
        with patch.object(client, "request", side_effect=[{"default_branch": "main"}, {"truncated": True}]):
            with self.assertRaises(GitHubError):
                client.workflows("owner/repo")

    def test_issue_idempotency(self):
        client = GitHubClient(token="x")
        with patch.object(client, "request", return_value=[{
            "number": 5, "title": "audit", "body": "same", "html_url": "https://github.com/o/r/issues/5"}]) as mocked:
            url = client.sync_issue("o/r", "audit", "same")
            self.assertTrue(url.endswith("/5"))
            self.assertEqual(mocked.call_count, 1)

    def test_issue_skips_prs(self):
        client = GitHubClient(token="x")
        with patch.object(client, "request", side_effect=[
            [{"title": "audit", "number": 1, "pull_request": {}}],
            {"html_url": "https://github.com/o/r/issues/2"}
        ]) as mocked:
            self.assertTrue(client.sync_issue("o/r", "audit", "body").endswith("/2"))
            self.assertEqual(mocked.call_count, 2)


if __name__ == "__main__":
    unittest.main()
