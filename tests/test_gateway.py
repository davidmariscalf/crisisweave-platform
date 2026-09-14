import json,tempfile,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from crisisweave_platform import PlatformDB,WorksiteClient,build_server

PEPPER="test-pepper-value-that-is-long-enough-123"

class Fake(BaseHTTPRequestHandler):
    last=None
    def log_message(self,*a): return
    def sendj(self,s,p):
        b=json.dumps(p).encode(); self.send_response(s); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path=="/api/health": return self.sendj(200,{"ok":True})
        if self.path=="/api/worksites": return self.sendj(200,{"worksites":[{"id":"w1","state":"ready"}]})
        if self.path=="/api/worksites/w1": return self.sendj(200,{"id":"w1","state":"ready"})
        return self.sendj(404,{"error":"not found"})
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); d=json.loads(self.rfile.read(n) or b"{}"); type(self).last=(self.path,d); return self.sendj(200,{"id":"w1","state":"assigned","assigned_team":d.get("team_id")})

class Gateway(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); r=Path(self.t.name); self.db=PlatformDB(r/"p.db",r/"private.db",PEPPER); self.db.create_organisation("a","A")
        for pid,role in (("coord","coordinator"),("vol","volunteer"),("viewer","viewer")): self.db.create_principal(pid,"a",pid,role)
        self.ct=self.db.issue_token("coord"); self.vt=self.db.issue_token("vol"); self.rt=self.db.issue_token("viewer")
        self.verified=r/"verified.jsonl"; self.verified.write_text(json.dumps({"id":"inc1"})+"\n"); self.alerts=r/"alerts.jsonl"; self.alerts.write_text(json.dumps({"id":"al1"})+"\n")
        self.up=ThreadingHTTPServer(("127.0.0.1",0),Fake); threading.Thread(target=self.up.serve_forever,daemon=True).start(); client=WorksiteClient(f"http://127.0.0.1:{self.up.server_address[1]}")
        self.s=build_server(self.db,client,"127.0.0.1",0,100,verified_feed=str(self.verified),alerts_feed=str(self.alerts)); threading.Thread(target=self.s.serve_forever,daemon=True).start(); self.base=f"http://127.0.0.1:{self.s.server_address[1]}"
    def tearDown(self): self.s.shutdown(); self.s.server_close(); self.up.shutdown(); self.up.server_close(); self.t.cleanup()
    def req(self,m,p,t=None,d=None):
        b=None if d is None else json.dumps(d).encode(); h={}
        if t:h["Authorization"]="Bearer "+t
        if b is not None:h["Content-Type"]="application/json"
        try:
            with urlopen(Request(self.base+p,method=m,data=b,headers=h),timeout=2) as r:return r.status,json.loads(r.read())
        except HTTPError as e:return e.code,json.loads(e.read())
    def test_auth_and_roles(self):
        self.assertEqual(self.req("GET","/api/v1/worksites")[0],401); self.assertEqual(self.req("GET","/api/v1/worksites",self.vt)[0],200); self.assertEqual(self.req("POST","/api/v1/worksites/w1/assign",self.vt,{"team_id":"t1"})[0],403)
    def test_actor_spoof_blocked(self):
        s,p=self.req("POST","/api/v1/worksites/w1/assign",self.ct,{"team_id":"t1","actor":"spoof"}); self.assertEqual(s,200); self.assertEqual(Fake.last[1]["actor"],"a:coord")
    def test_incident_permissions(self):
        self.assertEqual(self.req("GET","/api/v1/incidents",self.rt)[0],200); self.assertEqual(self.req("GET","/api/v1/incidents",self.vt)[0],403)
    def test_private_roundtrip(self):
        self.assertEqual(self.req("POST","/api/v1/private/case",self.ct,{"note":"synthetic"})[0],200); s,p=self.req("GET","/api/v1/private/case",self.ct); self.assertEqual(s,200); self.assertEqual(p["payload"]["note"],"synthetic")

if __name__=="__main__":unittest.main()
