import json
import unittest
from email.message import Message
from urllib.error import HTTPError

from least_privilege_bot.enterprise import EnterpriseExport, ExportError


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, count):
        return self.body[:count]


class FakeOpener:
    def __init__(self):
        self.calls = []

    def open(self, req, timeout=25):
        self.calls.append(req)
        if len(self.calls) == 1:
            return FakeResponse(202, json.dumps({"export_id": "a" * 32}).encode())
        if len(self.calls) == 2:
            return FakeResponse(200, b'{"status":"queued"}')
        if len(self.calls) == 3:
            headers = Message()
            headers.add_header("Location", "https://objects.githubusercontent.com/export/file.csv?sig=123")
            raise HTTPError(req.full_url, 302, "ready", headers, None)
        return FakeResponse(200, b"credential_type,owner,last_used_at\nclassic_pat,test,\n")


class EnterpriseTests(unittest.TestCase):
    def test_async_export_and_no_auth_leakage(self):
        opener = FakeOpener()
        client = EnterpriseExport("TOP_SECRET_TOKEN", opener=opener, sleeper=lambda _: None)
        content = client.export("my-enterprise", organization="eng", polls=3)
        self.assertIn(b"classic_pat", content)
        self.assertEqual(len(opener.calls), 4)
        self.assertEqual(json.loads(opener.calls[0].data), {"organization": "eng"})
        self.assertIn("Authorization", opener.calls[0].headers)
        self.assertNotIn("Authorization", opener.calls[3].headers)

    def test_reject_unsafe_download_url(self):
        client = EnterpriseExport("TEST", opener=FakeOpener())
        for loc in ["http://example.com/file", "https://user:pass@example.com/path", "file:///etc/passwd"]:
            with self.assertRaises(ExportError):
                client._download(loc)

    def test_poll_exhaustion(self):
        opener = FakeOpener()
        with self.assertRaises(ExportError):
            EnterpriseExport("TEST", opener=opener, sleeper=lambda _: None).export("company", polls=1)

    def test_invalid_slug(self):
        with self.assertRaises(ValueError):
            EnterpriseExport("TEST", opener=FakeOpener()).export("../evil")


if __name__ == "__main__":
    unittest.main()
