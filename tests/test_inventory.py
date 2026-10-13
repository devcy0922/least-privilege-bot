"""Credential inventory scenarios use synthetic data; never real secret values."""
import csv
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from least_privilege_bot.inventory import parse_inventory, analyze_inventory, inventory_markdown, write_inventory_report
from least_privilege_bot.cli import main

HEADERS = ["credential_type", "credential_id", "display_name", "owner", "owner_id", "credential_state",
           "last_used_at", "created_at", "expires_at", "expiry_status", "repository_selection", "scopes",
           "permissions", "organization", "hashed_token", "fingerprint"]
NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


def data(rows):
    text = StringIO()
    writer = csv.DictWriter(text, fieldnames=HEADERS)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return text.getvalue().encode()


class InventoryTests(unittest.TestCase):
    def test_flags_and_deduplicates_multi_org(self):
        base = dict(credential_type="classic_pat", credential_id="42", owner="alice", display_name="build-pat",
                    credential_state="active", last_used_at="2026-01-01T00:00:00Z", scopes="repo; read:org",
                    expiry_status="never", repository_selection="all", hashed_token="secret-hash")
        records = parse_inventory(data([dict(base, organization="a"), dict(base, organization="b")]))
        report = analyze_inventory(records, as_of=NOW)
        self.assertEqual(report["credential_count"], 1)
        self.assertEqual(report["credentials"][0]["organizations"], ["a", "b"])
        self.assertEqual({x["rule"] for x in report["findings"]},
                         {"STALE_CREDENTIAL", "NO_EXPIRATION", "ALL_REPOSITORIES", "BROAD_CLASSIC_SCOPE"})
        self.assertNotIn("secret-hash", str(report))
        self.assertNotIn("42", report["credentials"][0]["id"])

    def test_no_last_used_is_unknown_not_stale(self):
        records = parse_inventory(data([dict(credential_type="fine_grained_pat", credential_id="13",
                                             owner="bob", created_at="2025-01-01T00:00:00Z",
                                             expiry_status="unknown")]))
        r = analyze_inventory(records, as_of=NOW)
        self.assertNotIn("STALE_CREDENTIAL", {f["rule"] for f in r["findings"]})
        self.assertNotIn("NO_EXPIRATION", {f["rule"] for f in r["findings"]})
        self.assertIn("USAGE_UNKNOWN", {f["rule"] for f in r["findings"]})

    def test_all_rights_not_proof_of_overpermission(self):
        records = parse_inventory(data([dict(credential_type="fine_grained_pat", credential_id="1", owner="user",
                                             permissions="contents:write; issues:read", last_used_at="2026-10-01T00:00:00Z")]))
        r = analyze_inventory(records, as_of=NOW)
        self.assertIn("WRITE_PERMISSION", {f["rule"] for f in r["findings"]})
        self.assertTrue(r["coverage"]["not_a_minimum_permission_proof"])

    def test_organization_filter(self):
        base = dict(credential_type="classic_pat", credential_id="12", owner="bob")
        records = parse_inventory(data([dict(base, organization="alpha"), dict(base, organization="beta"),
                                       dict(credential_type="classic_pat", credential_id="13", owner="carol", organization="other")]))
        report = analyze_inventory(records, organization="alpha", as_of=NOW)
        self.assertEqual(report["credential_count"], 1)
        self.assertEqual(report["credentials"][0]["organizations"], ["alpha"])

    def test_csv_quotes_and_newlines_escape(self):
        records = parse_inventory(data([dict(credential_type="ssh_key", owner="@all|<script>x</script>",
                                             display_name="two\nlines", fingerprint="SHA256:abc")]))
        r = analyze_inventory(records, as_of=NOW)
        md = inventory_markdown(r)
        self.assertNotIn("<script>", md)
        self.assertNotIn("@all", md)
        self.assertIn("&#64;all", md)
        self.assertIn("\\|", md)
        self.assertNotIn("SHA256:abc", md)

    def test_bad_input_rejected(self):
        with self.assertRaises(ValueError):
            parse_inventory(b"owner,foo\na,b\n")
        with self.assertRaises(ValueError):
            parse_inventory(data([dict(credential_type="pat", owner="a")]).replace(b"pat", b"pat,unexpected", 1))

    def test_cli_offline(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "inventory.csv").write_bytes(data([dict(credential_type="classic_pat", credential_id="1", owner="x")]))
            code = main(["inventory", "--csv", str(p / "inventory.csv"), "--output-dir", str(p / "out"),
                         "--as-of", "2026-10-14T00:00:00Z"])
            self.assertEqual(code, 0)
            self.assertTrue((p / "out" / "inventory.md").exists())
            self.assertTrue((p / "out" / "inventory.json").exists())


if __name__ == "__main__":
    unittest.main()
