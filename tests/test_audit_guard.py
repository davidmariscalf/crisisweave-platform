import sqlite3
import tempfile
import unittest
from pathlib import Path

from audit_guard import install, verify
from crisisweave_platform import PlatformDB


class AuditGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db_path = root / "platform.db"
        self.private_path = root / "private.db"
        self.db = PlatformDB(self.db_path, self.private_path, "p" * 32)
        self.db.create_organisation("org-a", "Organisation A")
        install(str(self.db_path))

    def tearDown(self):
        self.tmp.cleanup()

    def connect(self):
        return sqlite3.connect(self.db_path)

    def test_guard_is_installed_and_append_still_works(self):
        status = verify(str(self.db_path))
        self.assertTrue(status["ok"])
        self.assertEqual(status["triggers"], ["audit_no_delete", "audit_no_update"])
        before = status["audit_rows"]
        self.db.audit("test.append", "success", "org-a")
        self.assertEqual(verify(str(self.db_path))["audit_rows"], before + 1)

    def test_historical_update_is_rejected(self):
        with self.connect() as con:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "audit log is immutable"):
                con.execute("UPDATE audit SET outcome='tampered' WHERE seq=(SELECT MIN(seq) FROM audit)")

    def test_historical_delete_is_rejected(self):
        with self.connect() as con:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "audit log is immutable"):
                con.execute("DELETE FROM audit WHERE seq=(SELECT MIN(seq) FROM audit)")

    def test_verify_fails_if_guard_was_removed(self):
        with self.connect() as con:
            con.execute("DROP TRIGGER audit_no_update")
        with self.assertRaisesRegex(RuntimeError, "missing"):
            verify(str(self.db_path))


if __name__ == "__main__":
    unittest.main()
