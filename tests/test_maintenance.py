import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from crisisweave_platform import PlatformDB
from maintenance import prune


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = PlatformDB(root / "platform.db", root / "private.db", "x" * 32)
        self.db.create_organisation("org1", "Organisation")
        self.db.create_principal("p1", "org1", "Person", "admin")

    def tearDown(self):
        self.tmp.cleanup()

    def test_dry_run_does_not_delete(self):
        self.db.put_private("org1", "record1", {"secret": "value"})
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat().replace("+00:00", "Z")
        with self.db._db(True) as c:
            c.execute("UPDATE private_records SET updated_at=?", (old,))
        result = prune(self.db, 90, 30, apply=False)
        self.assertEqual(result["private_records_eligible"], 1)
        self.assertFalse(result["applied"])
        self.assertEqual(self.db.get_private("org1", "record1")["payload"]["secret"], "value")

    def test_apply_prunes_private_and_expired_tokens_but_keeps_audit(self):
        self.db.put_private("org1", "old", {"value": 1})
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat().replace("+00:00", "Z")
        expired = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat().replace("+00:00", "Z")
        with self.db._db(True) as c:
            c.execute("UPDATE private_records SET updated_at=? WHERE record_key='old'", (old,))
        token = self.db.issue_token("p1", 3600)
        with self.db._db() as c:
            c.execute("UPDATE tokens SET expires_at=? WHERE digest=?", (expired, self.db.digest(token)))
        result = prune(self.db, 90, 30, apply=True)
        self.assertEqual(result["private_records_deleted"], 1)
        self.assertEqual(result["tokens_deleted"], 1)
        with self.assertRaises(KeyError):
            self.db.get_private("org1", "old")
        rows = self.db.audit_rows("org1", 100)
        self.assertTrue(any(row["action"] == "token.issue" for row in rows))
        with self.db._db() as c:
            system_rows = c.execute("SELECT action FROM audit WHERE action='maintenance.retention_prune'").fetchall()
        self.assertEqual(len(system_rows), 1)


if __name__ == "__main__":
    unittest.main()
