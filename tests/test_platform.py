import tempfile, unittest
from pathlib import Path
from crisisweave_platform import PlatformDB, RateLimiter

PEPPER="test-pepper-value-that-is-long-enough-123"

class DBTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); r=Path(self.t.name); self.db=PlatformDB(r/"platform.db",r/"private.db",PEPPER)
        self.db.create_organisation("a","A"); self.db.create_organisation("b","B")
        self.db.create_principal("admin","a","Admin","admin"); self.db.create_principal("coord","a","Coord","coordinator"); self.db.create_principal("vol","a","Vol","volunteer")
    def tearDown(self): self.t.cleanup()
    def test_token_not_plaintext(self):
        token=self.db.issue_token("coord")
        with self.db._db() as c: row=c.execute("SELECT digest FROM tokens").fetchone()
        self.assertNotEqual(row["digest"],token); self.assertNotIn(token,Path(self.db.db_path).read_bytes().decode("latin1","ignore")); self.assertEqual(self.db.authenticate(token)["id"],"coord")
    def test_roles(self):
        c=self.db.authenticate(self.db.issue_token("coord")); v=self.db.authenticate(self.db.issue_token("vol"))
        self.assertTrue(self.db.allowed(c,"worksites:write")); self.assertFalse(self.db.allowed(v,"worksites:write")); self.assertTrue(self.db.allowed(v,"worksites:read"))
    def test_private_org_isolation(self):
        self.db.put_private("a","case",{"synthetic":True}); self.assertTrue(self.db.get_private("a","case")["payload"]["synthetic"])
        with self.assertRaises(KeyError): self.db.get_private("b","case")
    def test_private_version(self):
        self.db.put_private("a","case",{"v":1}); self.assertEqual(self.db.put_private("a","case",{"v":2})["version"],2)
    def test_audit_redaction(self):
        self.db.audit("x","success","a",details={"token":"secret","safe":"ok"}); row=self.db.audit_rows("a",1)[0]; self.assertEqual(row["details"]["token"],"[redacted]")
    def test_backup(self):
        out=self.db.backup(Path(self.t.name)/"backup"); self.assertTrue(Path(out["platform"]).exists()); self.assertTrue(Path(out["private"]).exists())

    def test_atomic_bootstrap_creates_admin_and_one_time_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); db=PlatformDB(root/"platform.db",root/"private.db",PEPPER)
            result=db.bootstrap_organisation("relief","Relief Org","owner","Owner",3600)
            self.assertEqual(result["organisation"]["id"],"relief")
            self.assertEqual(result["principal"]["role"],"admin")
            self.assertTrue(result["token"].startswith("cw_"))
            principal=db.authenticate(result["token"])
            self.assertEqual(principal["id"],"owner")
            self.assertEqual(principal["role"],"admin")
            self.assertNotIn(result["token"],Path(db.db_path).read_bytes().decode("latin1","ignore"))
            with db._db() as c:
                self.assertEqual(c.execute("SELECT COUNT(*) FROM organisations").fetchone()[0],1)
                self.assertEqual(c.execute("SELECT COUNT(*) FROM principals").fetchone()[0],1)
                self.assertEqual(c.execute("SELECT COUNT(*) FROM tokens").fetchone()[0],1)
                actions=[r[0] for r in c.execute("SELECT action FROM audit ORDER BY seq").fetchall()]
            self.assertEqual(actions,["organisation.create","principal.create","token.issue"])

    def test_bootstrap_rejects_existing_org_without_partial_admin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); db=PlatformDB(root/"platform.db",root/"private.db",PEPPER)
            db.create_organisation("existing","Existing")
            with self.assertRaises(ValueError):
                db.bootstrap_organisation("existing","Existing","owner","Owner",3600)
            with db._db() as c:
                self.assertEqual(c.execute("SELECT COUNT(*) FROM principals WHERE id='owner'").fetchone()[0],0)
                self.assertEqual(c.execute("SELECT COUNT(*) FROM tokens").fetchone()[0],0)

class LimiterTests(unittest.TestCase):
    def test_window(self):
        l=RateLimiter(2,10); self.assertTrue(l.allow("x",0)[0]); self.assertTrue(l.allow("x",1)[0]); self.assertFalse(l.allow("x",2)[0]); self.assertTrue(l.allow("x",11)[0])

if __name__=="__main__": unittest.main()
