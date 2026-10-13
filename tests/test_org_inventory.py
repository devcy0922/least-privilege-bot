import json
import unittest
from least_privilege_bot.org_inventory import OrganizationInventory
from least_privilege_bot.enterprise import ExportError


class Resp:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, length): return self.payload[:length]


class OrgTests(unittest.TestCase):
    def test_pat_mapping(self):
        requests = []
        def fake(req, timeout):
            requests.append(req)
            return Resp([{"token_id": 14, "token_name": "bot", "owner": {"login": "alice"},
                         "repository_selection": "all", "token_last_used_at": "2026-01-01T00:00:00Z",
                         "permissions": {"repository": {"contents": "write"}}}])
        rows = OrganizationInventory("secret", requester=fake).fetch("my-org")
        self.assertEqual(rows[0]["permissions"], "repository.contents:write")
        self.assertEqual(rows[0]["owner"], "alice")
        self.assertEqual(rows[0]["expiry_status"], "unknown")
        self.assertEqual(len(requests), 1)
        self.assertIn("Authorization", requests[0].headers)

    def test_bad_payload_fails_closed(self):
        with self.assertRaises(ExportError):
            OrganizationInventory("token", requester=lambda req,timeout: Resp({"error": "bad"})).fetch("my-org")


if __name__ == "__main__": unittest.main()
