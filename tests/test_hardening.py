import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from crisisweave_platform import PlatformDB, WorksiteClient, build_server

PEPPER = "test-pepper-value-that-is-long-enough-123"


class HardeningDBTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        root = Path(self.t.name)
        self.db = PlatformDB(root / "platform.db", root / "private.db", PEPPER)
        self.db.create_organisation("org", "Org")
        self.db.create_principal("coord", "org", "Coordinator", "coordinator")

    def tearDown(self):
        self.t.cleanup()

    def test_token_revocation(self):
        token = self.db.issue_token("coord")
        token_id = self.db.authenticate(token)["token_id"]
        self.db.revoke_token(token_id)
        self.assertIsNone(self.db.authenticate(token))

    def test_deactivation_revokes_existing_tokens(self):
        token = self.db.issue_token("coord")
        self.db.set_principal_active("coord", False)
        self.assertIsNone(self.db.authenticate(token))
        rows = self.db.list_tokens("coord")
        self.assertIsNotNone(rows[0]["revoked_at"])

    def test_expired_token_rejected(self):
        token = self.db.issue_token("coord")
        token_id = self.db.authenticate(token)["token_id"]
        with self.db._db() as c:
            c.execute("UPDATE tokens SET expires_at='2000-01-01T00:00:00Z' WHERE id=?", (token_id,))
        self.assertIsNone(self.db.authenticate(token))

    def test_private_optimistic_concurrency(self):
        self.db.put_private("org", "case", {"v": 1})
        with self.assertRaises(RuntimeError):
            self.db.put_private("org", "case", {"v": 2}, expected_version=0)
        meta = self.db.put_private("org", "case", {"v": 2}, expected_version=1)
        self.assertEqual(meta["version"], 2)

    def test_backup_manifest_and_integrity(self):
        result = self.db.backup(Path(self.t.name) / "backups")
        manifest = json.loads(Path(result["manifest"]).read_text())
        self.assertEqual(set(manifest["files"]), {"platform", "private"})
        self.assertTrue(self.db.verify_sqlite(result["platform"])["ok"])
        self.assertTrue(self.db.verify_sqlite(result["private"])["ok"])


class CorsAndGatewayTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        root = Path(self.t.name)
        self.db = PlatformDB(root / "platform.db", root / "private.db", PEPPER)
        self.db.create_organisation("org", "Org")
        self.db.create_principal("viewer", "org", "Viewer", "viewer")
        self.token = self.db.issue_token("viewer")
        self.client = WorksiteClient("http://127.0.0.1:9", timeout=0.05)
        self.server = build_server(
            self.db, self.client, "127.0.0.1", 0, 100,
            allowed_origin="https://crisisweave.netlify.app",
        )
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.t.cleanup()

    def request(self, method, path, headers=None, data=None):
        req = Request(self.base + path, method=method, headers=headers or {}, data=data)
        try:
            with urlopen(req, timeout=2) as r:
                return r.status, dict(r.headers), r.read()
        except HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def test_preflight_allows_configured_origin(self):
        status, headers, _ = self.request("OPTIONS", "/api/v1/worksites", {
            "Origin": "https://crisisweave.netlify.app",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        })
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "https://crisisweave.netlify.app")

    def test_preflight_rejects_other_origin(self):
        status, _, _ = self.request("OPTIONS", "/api/v1/worksites", {
            "Origin": "https://attacker.invalid",
            "Access-Control-Request-Headers": "Authorization",
        })
        self.assertEqual(status, 403)

    def test_upstream_outage_is_502_not_connection_drop(self):
        status, _, body = self.request("GET", "/api/v1/worksites", {
            "Authorization": "Bearer " + self.token,
        })
        self.assertEqual(status, 502)
        self.assertEqual(json.loads(body)["error"], "worksite service unavailable")

    def test_security_and_request_id_headers(self):
        status, headers, _ = self.request("GET", "/healthz", {"X-Request-ID": "test-request-1"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("X-Request-ID"), "test-request-1")
        self.assertEqual(headers.get("X-CrisisWeave-Version"), "0.2")


if __name__ == "__main__":
    unittest.main()
