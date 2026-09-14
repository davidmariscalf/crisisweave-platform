#!/usr/bin/env python3
from __future__ import annotations

import argparse, collections, hashlib, hmac, json, os, secrets, sqlite3, threading, time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen

ROLES = ("admin", "coordinator", "volunteer", "viewer")
PERMISSIONS = {
    "admin": {"*"},
    "coordinator": {"worksites:read", "worksites:write", "incidents:read", "alerts:read", "private:read", "private:write", "audit:read", "org:read"},
    "volunteer": {"worksites:read", "org:read"},
    "viewer": {"worksites:read", "incidents:read", "alerts:read", "org:read"},
}
MAX_PRIVATE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 128 * 1024
MAX_FEED_BYTES = 5 * 1024 * 1024

def utcnow(): return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def _json_bytes(v): return json.dumps(v, ensure_ascii=False, separators=(",", ":")).encode()
def _safe_id(v, field="id"):
    v = str(v or "").strip(); allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
    if not v or len(v) > 128 or any(c not in allowed for c in v): raise ValueError(f"invalid {field}")
    return v

def _pepper(v):
    b=(v or "").encode()
    if len(b)<24: raise ValueError("CW_TOKEN_PEPPER must contain at least 24 bytes")
    return b

class PlatformDB:
    def __init__(self, db, private_db, pepper):
        self.db_path=str(db); self.private_db_path=str(private_db); self.pepper=_pepper(pepper); self.init()
    def _connect(self):
        c=sqlite3.connect(self.db_path, timeout=10); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA journal_mode=WAL"); return c
    def _connect_private(self):
        c=sqlite3.connect(self.private_db_path, timeout=10); c.row_factory=sqlite3.Row; c.execute("PRAGMA journal_mode=WAL"); return c
    @contextmanager
    def _db(self, private=False):
        c=self._connect_private() if private else self._connect()
        try: yield c; c.commit()
        except Exception: c.rollback(); raise
        finally: c.close()
    def init(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True); Path(self.private_db_path).parent.mkdir(parents=True, exist_ok=True)
        try: os.chmod(Path(self.private_db_path).parent,0o700)
        except (OSError,PermissionError): pass
        with self._db() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS organisations(id TEXT PRIMARY KEY,name TEXT NOT NULL,created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS principals(id TEXT PRIMARY KEY,organisation_id TEXT NOT NULL REFERENCES organisations(id),display_name TEXT NOT NULL,role TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,principal_id TEXT NOT NULL REFERENCES principals(id),digest TEXT NOT NULL UNIQUE,prefix TEXT NOT NULL,created_at TEXT NOT NULL,revoked_at TEXT);
            CREATE INDEX IF NOT EXISTS idx_tokens_digest ON tokens(digest);
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,organisation_id TEXT,principal_id TEXT,action TEXT NOT NULL,target TEXT,outcome TEXT NOT NULL,details TEXT NOT NULL DEFAULT '{}');
            CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(organisation_id,seq);
            """)
        with self._db(True) as c:
            c.execute("CREATE TABLE IF NOT EXISTS private_records(organisation_id TEXT NOT NULL,record_key TEXT NOT NULL,payload TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(organisation_id,record_key))")
        try: os.chmod(self.private_db_path,0o600)
        except (OSError,PermissionError): pass
    def digest(self, token): return hmac.new(self.pepper,token.encode(),hashlib.sha256).hexdigest()
    def audit(self, action, outcome, organisation_id=None, principal_id=None, target=None, details=None):
        d=dict(details or {})
        for k in tuple(d):
            if any(x in k.lower() for x in ("token","secret","password")): d[k]="[redacted]"
        with self._db() as c: c.execute("INSERT INTO audit(at,organisation_id,principal_id,action,target,outcome,details) VALUES(?,?,?,?,?,?,?)",(utcnow(),organisation_id,principal_id,action,target,outcome,json.dumps(d,ensure_ascii=False)))
    def create_organisation(self, oid, name):
        oid=_safe_id(oid,"organisation id"); name=str(name or "").strip()
        if not name or len(name)>200: raise ValueError("invalid organisation name")
        with self._db() as c: c.execute("INSERT INTO organisations(id,name,created_at) VALUES(?,?,?)",(oid,name,utcnow()))
        self.audit("organisation.create","success",oid,target=oid); return {"id":oid,"name":name}
    def create_principal(self, pid, oid, name, role):
        pid=_safe_id(pid,"principal id"); oid=_safe_id(oid,"organisation id"); name=str(name or "").strip()
        if role not in ROLES or not name or len(name)>200: raise ValueError("invalid principal")
        with self._db() as c:
            if not c.execute("SELECT 1 FROM organisations WHERE id=?",(oid,)).fetchone(): raise KeyError("organisation not found")
            c.execute("INSERT INTO principals(id,organisation_id,display_name,role,created_at) VALUES(?,?,?,?,?)",(pid,oid,name,role,utcnow()))
        self.audit("principal.create","success",oid,pid,pid,{"role":role}); return {"id":pid,"organisation_id":oid,"display_name":name,"role":role}
    def issue_token(self,pid):
        pid=_safe_id(pid,"principal id")
        with self._db() as c:
            p=c.execute("SELECT organisation_id,active FROM principals WHERE id=?",(pid,)).fetchone()
            if not p: raise KeyError("principal not found")
            if not p["active"]: raise ValueError("principal inactive")
            token="cw_"+secrets.token_urlsafe(32); tid="tok_"+secrets.token_hex(8)
            c.execute("INSERT INTO tokens(id,principal_id,digest,prefix,created_at) VALUES(?,?,?,?,?)",(tid,pid,self.digest(token),token[:12],utcnow()))
        self.audit("token.issue","success",p["organisation_id"],pid,tid,{"prefix":token[:12]}); return token
    def authenticate(self, token):
        if not token: return None
        with self._db() as c:
            r=c.execute("SELECT p.id,p.organisation_id,p.display_name,p.role,p.active,t.id token_id FROM tokens t JOIN principals p ON p.id=t.principal_id WHERE t.digest=? AND t.revoked_at IS NULL",(self.digest(token),)).fetchone()
        return dict(r) if r and r["active"] else None
    @staticmethod
    def allowed(p, perm):
        a=PERMISSIONS.get(p.get("role"),set()); return "*" in a or perm in a
    def public_principal(self,p): return {k:p[k] for k in ("id","organisation_id","display_name","role")}
    def organisation(self, oid):
        with self._db() as c: r=c.execute("SELECT id,name,created_at FROM organisations WHERE id=?",(oid,)).fetchone()
        if not r: raise KeyError("organisation not found")
        return dict(r)
    def put_private(self,oid,key,payload):
        oid=_safe_id(oid,"organisation id"); key=_safe_id(key,"record key")
        if not isinstance(payload,dict): raise ValueError("private payload must be an object")
        raw=_json_bytes(payload)
        if len(raw)>MAX_PRIVATE_BYTES: raise ValueError("private record exceeds size limit")
        now=utcnow()
        with self._db(True) as c:
            r=c.execute("SELECT version,created_at FROM private_records WHERE organisation_id=? AND record_key=?",(oid,key)).fetchone()
            if r:
                version=r["version"]+1; created=r["created_at"]; c.execute("UPDATE private_records SET payload=?,version=?,updated_at=? WHERE organisation_id=? AND record_key=?",(raw.decode(),version,now,oid,key))
            else:
                version=1; created=now; c.execute("INSERT INTO private_records VALUES(?,?,?,?,?,?)",(oid,key,raw.decode(),version,created,now))
        return {"key":key,"version":version,"created_at":created,"updated_at":now}
    def get_private(self,oid,key):
        with self._db(True) as c: r=c.execute("SELECT record_key,payload,version,created_at,updated_at FROM private_records WHERE organisation_id=? AND record_key=?",(oid,key)).fetchone()
        if not r: raise KeyError("private record not found")
        return {"key":r["record_key"],"payload":json.loads(r["payload"]),"version":r["version"],"created_at":r["created_at"],"updated_at":r["updated_at"]}
    def audit_rows(self,oid,limit=100):
        limit=max(1,min(int(limit),500))
        with self._db() as c: rows=c.execute("SELECT * FROM audit WHERE organisation_id=? ORDER BY seq DESC LIMIT ?",(oid,limit)).fetchall()
        return [{**dict(r),"details":json.loads(r["details"])} for r in rows]
    def backup(self,out):
        out=Path(out); out.mkdir(parents=True,exist_ok=True); stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"); result={}
        for label,srcpath,private in (("platform",self.db_path,False),("private",self.private_db_path,True)):
            dest=out/f"{label}-{stamp}.sqlite3"; src=sqlite3.connect(srcpath); dst=sqlite3.connect(dest)
            try: src.backup(dst)
            finally: dst.close(); src.close()
            if private:
                try: os.chmod(dest,0o600)
                except (OSError,PermissionError): pass
            result[label]=str(dest)
        return result
    def health(self):
        r={"platform_db":False,"private_db":False}
        try:
            with self._db() as c: r["platform_db"]=c.execute("SELECT 1").fetchone()[0]==1
            with self._db(True) as c: r["private_db"]=c.execute("SELECT 1").fetchone()[0]==1
        except sqlite3.Error: pass
        return r

def read_jsonl_feed(path):
    if not path: raise FileNotFoundError("feed is not configured")
    p=Path(path)
    if not p.is_file(): raise FileNotFoundError("configured feed is unavailable")
    if p.stat().st_size>MAX_FEED_BYTES: raise ValueError("configured feed exceeds size limit")
    rows=[]
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            v=json.loads(line)
            if not isinstance(v,dict): raise ValueError("feed rows must be objects")
            rows.append(v)
    return rows

class RateLimiter:
    def __init__(self,limit=120,window_seconds=60): self.limit=max(1,int(limit)); self.window=max(1,int(window_seconds)); self.hits={}; self.lock=threading.Lock()
    def allow(self,key,now_value=None):
        t=time.monotonic() if now_value is None else now_value
        with self.lock:
            q=self.hits.setdefault(key,collections.deque()); cutoff=t-self.window
            while q and q[0]<=cutoff: q.popleft()
            if len(q)>=self.limit: return False,max(1,int(self.window-(t-q[0]))+1)
            q.append(t); return True,0

class WorksiteClient:
    def __init__(self,base_url,token=None,timeout=2):
        u=urlparse(base_url)
        if u.scheme not in {"http","https"} or not u.netloc: raise ValueError("CW_WORKSITES_URL must be http(s)")
        self.base=base_url.rstrip("/"); self.token=token; self.timeout=float(timeout)
    def request(self,method,path,body=None):
        data=None if body is None else _json_bytes(body); headers={"Accept":"application/json"}
        if data is not None: headers["Content-Type"]="application/json"
        if self.token: headers["Authorization"]="Bearer "+self.token
        try:
            with urlopen(Request(self.base+path,method=method,data=data,headers=headers),timeout=self.timeout) as r:
                raw=r.read(MAX_REQUEST_BYTES+1)
                if len(raw)>MAX_REQUEST_BYTES: raise ValueError("upstream response too large")
                return r.status,json.loads(raw or b"{}")
        except HTTPError as e:
            raw=e.read(MAX_REQUEST_BYTES+1)
            try: payload=json.loads(raw or b"{}")
            except json.JSONDecodeError: payload={"error":"upstream error"}
            return e.code,payload
    def health(self):
        try: s,p=self.request("GET","/api/health"); return s==200 and bool(p.get("ok"))
        except (URLError,TimeoutError,OSError,ValueError): return False

class PlatformHandler(BaseHTTPRequestHandler):
    db=None; worksites=None; limiter=None; allowed_origin=None; verified_feed=None; alerts_feed=None; admin_html=None
    server_version="CrisisWeavePlatform/0.1"
    def log_message(self,*a): return
    def _send(self,status,payload,headers=None):
        b=_json_bytes(payload); self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Referrer-Policy","no-referrer")
        if self.allowed_origin: self.send_header("Access-Control-Allow-Origin",self.allowed_origin); self.send_header("Vary","Origin")
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(b)
    def _html(self,text):
        b=text.encode(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.send_header("Cache-Control","no-store"); self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"); self.send_header("Referrer-Policy","no-referrer"); self.end_headers(); self.wfile.write(b)
    def _principal(self):
        h=self.headers.get("Authorization",""); return self.db.authenticate(h[7:].strip()) if h.startswith("Bearer ") else None
    def _auth(self,perm):
        p=self._principal(); ok,retry=self.limiter.allow("principal:"+p["id"] if p else "ip:"+str(self.client_address[0]))
        if not ok: self._send(429,{"error":"rate limit exceeded"},{"Retry-After":str(retry)}); return None
        if not p: self._send(401,{"error":"authentication required"}); return None
        if not self.db.allowed(p,perm): self.db.audit("authorisation","denied",p["organisation_id"],p["id"],self.path,{"permission":perm}); self._send(403,{"error":"permission denied"}); return None
        return p
    def _body(self):
        n=int(self.headers.get("Content-Length") or 0)
        if n<0 or n>MAX_REQUEST_BYTES: raise ValueError("request body too large")
        v=json.loads(self.rfile.read(n) if n else b"{}")
        if not isinstance(v,dict): raise ValueError("JSON body must be an object")
        return v
    def do_GET(self):
        u=urlparse(self.path); path=u.path
        if path=="/healthz":
            h=self.db.health(); return self._send(200 if all(h.values()) else 503,{"ok":all(h.values()),**h})
        if path=="/readyz":
            h=self.db.health(); w=self.worksites.health(); return self._send(200 if all(h.values()) and w else 503,{"ok":all(h.values()) and w,**h,"worksites":w})
        if path in {"/admin","/admin.html"}: return self._html(self.admin_html) if self.admin_html else self._send(404,{"error":"admin unavailable"})
        if path=="/api/v1/incidents":
            p=self._auth("incidents:read")
            if not p:return
            try:return self._send(200,{"incidents":read_jsonl_feed(self.verified_feed)})
            except Exception as e:return self._send(503,{"error":str(e)})
        if path=="/api/v1/alerts":
            p=self._auth("alerts:read")
            if not p:return
            try:return self._send(200,{"alerts":read_jsonl_feed(self.alerts_feed)})
            except Exception as e:return self._send(503,{"error":str(e)})
        if path=="/api/v1/me":
            p=self._auth("org:read"); return self._send(200,self.db.public_principal(p)) if p else None
        if path=="/api/v1/organisation":
            p=self._auth("org:read"); return self._send(200,self.db.organisation(p["organisation_id"])) if p else None
        if path=="/api/v1/worksites":
            p=self._auth("worksites:read")
            if p: s,v=self.worksites.request("GET","/api/worksites"); return self._send(s,v)
            return
        if path.startswith("/api/v1/worksites/"):
            p=self._auth("worksites:read")
            if not p:return
            wid=_safe_id(path.split("/")[-1],"worksite id"); s,v=self.worksites.request("GET","/api/worksites/"+quote(wid,safe="")); return self._send(s,v)
        if path.startswith("/api/v1/private/"):
            p=self._auth("private:read")
            if not p:return
            key=_safe_id(path.split("/")[-1],"record key")
            try:r=self.db.get_private(p["organisation_id"],key)
            except KeyError:return self._send(404,{"error":"private record not found"})
            self.db.audit("private.read","success",p["organisation_id"],p["id"],key); return self._send(200,r)
        if path=="/api/v1/audit":
            p=self._auth("audit:read")
            if not p:return
            try:limit=int(parse_qs(u.query).get("limit",["100"])[0])
            except ValueError:return self._send(400,{"error":"limit must be integer"})
            return self._send(200,{"audit":self.db.audit_rows(p["organisation_id"],limit)})
        return self._send(404,{"error":"not found"})
    def do_POST(self):
        try:body=self._body()
        except Exception as e:return self._send(400,{"error":str(e)})
        path=urlparse(self.path).path
        if path.startswith("/api/v1/private/"):
            p=self._auth("private:write")
            if not p:return
            key=_safe_id(path.split("/")[-1],"record key")
            try:m=self.db.put_private(p["organisation_id"],key,body)
            except ValueError as e:return self._send(400,{"error":str(e)})
            self.db.audit("private.write","success",p["organisation_id"],p["id"],key,{"version":m["version"]}); return self._send(200,m)
        parts=[x for x in path.split("/") if x]
        if len(parts)==5 and parts[:3]==["api","v1","worksites"]:
            p=self._auth("worksites:write")
            if not p:return
            wid=_safe_id(parts[3],"worksite id"); op=parts[4]; actor=f"{p['organisation_id']}:{p['id']}"
            if op=="assign":f={"team_id":_safe_id(body.get("team_id"),"team id"),"actor":actor}
            elif op=="release":f={"actor":actor}
            elif op=="transition":f={"state":str(body.get("state") or ""),"actor":actor,"note":str(body.get("note") or "")[:1000]}
            else:return self._send(404,{"error":"not found"})
            s,v=self.worksites.request("POST",f"/api/worksites/{quote(wid,safe='')}/{op}",f); self.db.audit("worksite."+op,"success" if 200<=s<300 else "upstream_error",p["organisation_id"],p["id"],wid,{"upstream_status":s}); return self._send(s,v)
        return self._send(404,{"error":"not found"})

def build_server(db,worksites,host,port,rate_limit,allowed_origin=None,verified_feed=None,alerts_feed=None,admin_html=None):
    h=type("BoundPlatformHandler",(PlatformHandler,),{}); h.db=db; h.worksites=worksites; h.limiter=RateLimiter(rate_limit); h.allowed_origin=allowed_origin; h.verified_feed=verified_feed; h.alerts_feed=alerts_feed; h.admin_html=admin_html
    return ThreadingHTTPServer((host,port),h)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--db",default=os.getenv("CW_DB","./data/platform.db")); ap.add_argument("--private-db",default=os.getenv("CW_PRIVATE_DB","./data/private.db")); ap.add_argument("--pepper",default=os.getenv("CW_TOKEN_PEPPER","")); sub=ap.add_subparsers(dest="cmd",required=True); sub.add_parser("init")
    o=sub.add_parser("create-org"); o.add_argument("id"); o.add_argument("name")
    p=sub.add_parser("create-principal"); p.add_argument("id"); p.add_argument("--org",required=True); p.add_argument("--name",required=True); p.add_argument("--role",choices=ROLES,required=True)
    t=sub.add_parser("issue-token"); t.add_argument("principal_id"); b=sub.add_parser("backup"); b.add_argument("--out",default="./backups")
    s=sub.add_parser("serve"); s.add_argument("--host",default=os.getenv("CW_HOST","127.0.0.1")); s.add_argument("--port",type=int,default=int(os.getenv("CW_PORT","8080"))); s.add_argument("--worksites-url",default=os.getenv("CW_WORKSITES_URL","http://127.0.0.1:8787")); s.add_argument("--rate-limit",type=int,default=int(os.getenv("CW_RATE_LIMIT_PER_MINUTE","120"))); s.add_argument("--allowed-origin",default=os.getenv("CW_ALLOWED_ORIGIN") or None); s.add_argument("--verified-feed",default=os.getenv("CW_VERIFIED_FEED") or None); s.add_argument("--alerts-feed",default=os.getenv("CW_ALERTS_FEED") or None)
    a=ap.parse_args(); db=PlatformDB(a.db,a.private_db,a.pepper)
    if a.cmd=="init":print(json.dumps({"ok":True,"db":a.db,"private_db":a.private_db}))
    elif a.cmd=="create-org":print(json.dumps(db.create_organisation(a.id,a.name)))
    elif a.cmd=="create-principal":print(json.dumps(db.create_principal(a.id,a.org,a.name,a.role)))
    elif a.cmd=="issue-token":print(json.dumps({"token":db.issue_token(a.principal_id),"warning":"shown once; store securely"}))
    elif a.cmd=="backup":print(json.dumps(db.backup(a.out)))
    else:
        html=Path(__file__).with_name("admin.html"); ws=WorksiteClient(a.worksites_url,os.getenv("CW_WORKSITES_TOKEN") or None); srv=build_server(db,ws,a.host,a.port,a.rate_limit,a.allowed_origin,a.verified_feed,a.alerts_feed,html.read_text() if html.is_file() else None)
        print(f"CrisisWeave platform listening on http://{a.host}:{a.port}")
        try:srv.serve_forever()
        except KeyboardInterrupt:pass
        finally:srv.server_close()
    return 0

if __name__=="__main__": raise SystemExit(main())
