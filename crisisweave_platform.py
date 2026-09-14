#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen

ROLES = ("admin", "coordinator", "volunteer", "viewer")
PERMISSIONS = {
    "admin": {"*"},
    "coordinator": {
        "worksites:read", "worksites:write", "incidents:read", "alerts:read",
        "private:read", "private:write", "audit:read", "org:read",
    },
    "volunteer": {"worksites:read", "org:read"},
    "viewer": {"worksites:read", "incidents:read", "alerts:read", "org:read"},
}
MAX_PRIVATE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 128 * 1024
MAX_FEED_BYTES = 5 * 1024 * 1024
SERVER_VERSION = "0.2"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _safe_id(value, field="id") -> str:
    value = str(value or "").strip()
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
    if not value or len(value) > 128 or any(c not in allowed for c in value):
        raise ValueError(f"invalid {field}")
    return value


def _pepper(value: str) -> bytes:
    raw = (value or "").encode()
    if len(raw) < 24:
        raise ValueError("CW_TOKEN_PEPPER must contain at least 24 bytes")
    return raw


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class PlatformDB:
    def __init__(self, db, private_db, pepper):
        self.db_path = str(db)
        self.private_db_path = str(private_db)
        self.pepper = _pepper(pepper)
        self.init()

    def _connect(self):
        c = sqlite3.connect(self.db_path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=10000")
        return c

    def _connect_private(self):
        c = sqlite3.connect(self.private_db_path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=10000")
        return c

    @contextmanager
    def _db(self, private=False):
        c = self._connect_private() if private else self._connect()
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def init(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.private_db_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(Path(self.private_db_path).parent, 0o700)
        except (OSError, PermissionError):
            pass

        with self._db() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS organisations(
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS principals(
                id TEXT PRIMARY KEY,
                organisation_id TEXT NOT NULL REFERENCES organisations(id),
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tokens(
                id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL REFERENCES principals(id),
                digest TEXT NOT NULL UNIQUE,
                prefix TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_digest ON tokens(digest);
            CREATE TABLE IF NOT EXISTS audit(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                organisation_id TEXT,
                principal_id TEXT,
                action TEXT NOT NULL,
                target TEXT,
                outcome TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(organisation_id,seq);
            """)
            token_cols = {r["name"] for r in c.execute("PRAGMA table_info(tokens)").fetchall()}
            if "expires_at" not in token_cols:
                c.execute("ALTER TABLE tokens ADD COLUMN expires_at TEXT")
            if "last_used_at" not in token_cols:
                c.execute("ALTER TABLE tokens ADD COLUMN last_used_at TEXT")

        with self._db(True) as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS private_records(
                    organisation_id TEXT NOT NULL,
                    record_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(organisation_id,record_key)
                )
            """)

        try:
            os.chmod(self.private_db_path, 0o600)
        except (OSError, PermissionError):
            pass

    def digest(self, token):
        return hmac.new(self.pepper, token.encode(), hashlib.sha256).hexdigest()

    def audit(self, action, outcome, organisation_id=None, principal_id=None, target=None, details=None):
        d = dict(details or {})
        for key in tuple(d):
            if any(x in key.lower() for x in ("token", "secret", "password", "pepper", "credential")):
                d[key] = "[redacted]"
        with self._db() as c:
            c.execute(
                "INSERT INTO audit(at,organisation_id,principal_id,action,target,outcome,details) "
                "VALUES(?,?,?,?,?,?,?)",
                (utcnow(), organisation_id, principal_id, action, target, outcome, json.dumps(d, ensure_ascii=False)),
            )

    def create_organisation(self, oid, name):
        oid = _safe_id(oid, "organisation id")
        name = str(name or "").strip()
        if not name or len(name) > 200:
            raise ValueError("invalid organisation name")
        with self._db() as c:
            c.execute("INSERT INTO organisations(id,name,created_at) VALUES(?,?,?)", (oid, name, utcnow()))
        self.audit("organisation.create", "success", oid, target=oid)
        return {"id": oid, "name": name}

    def create_principal(self, pid, oid, name, role):
        pid = _safe_id(pid, "principal id")
        oid = _safe_id(oid, "organisation id")
        name = str(name or "").strip()
        if role not in ROLES or not name or len(name) > 200:
            raise ValueError("invalid principal")
        with self._db() as c:
            if not c.execute("SELECT 1 FROM organisations WHERE id=?", (oid,)).fetchone():
                raise KeyError("organisation not found")
            c.execute(
                "INSERT INTO principals(id,organisation_id,display_name,role,created_at) VALUES(?,?,?,?,?)",
                (pid, oid, name, role, utcnow()),
            )
        self.audit("principal.create", "success", oid, pid, pid, {"role": role})
        return {"id": pid, "organisation_id": oid, "display_name": name, "role": role}

    def set_principal_active(self, pid, active: bool):
        pid = _safe_id(pid, "principal id")
        with self._db() as c:
            p = c.execute("SELECT organisation_id FROM principals WHERE id=?", (pid,)).fetchone()
            if not p:
                raise KeyError("principal not found")
            c.execute("UPDATE principals SET active=? WHERE id=?", (1 if active else 0, pid))
            if not active:
                c.execute("UPDATE tokens SET revoked_at=COALESCE(revoked_at,?) WHERE principal_id=?", (utcnow(), pid))
        self.audit(
            "principal.activate" if active else "principal.deactivate",
            "success",
            p["organisation_id"],
            pid,
            pid,
        )
        return {"id": pid, "active": bool(active)}

    def issue_token(self, pid, ttl_seconds=None):
        pid = _safe_id(pid, "principal id")
        ttl = None if ttl_seconds in (None, 0) else int(ttl_seconds)
        if ttl is not None and not 60 <= ttl <= 90 * 24 * 3600:
            raise ValueError("token TTL must be between 60 seconds and 90 days")
        with self._db() as c:
            p = c.execute("SELECT organisation_id,active FROM principals WHERE id=?", (pid,)).fetchone()
            if not p:
                raise KeyError("principal not found")
            if not p["active"]:
                raise ValueError("principal inactive")
            token = "cw_" + secrets.token_urlsafe(32)
            tid = "tok_" + secrets.token_hex(8)
            created = utcnow()
            expires = (
                (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat().replace("+00:00", "Z")
                if ttl is not None else None
            )
            c.execute(
                "INSERT INTO tokens(id,principal_id,digest,prefix,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                (tid, pid, self.digest(token), token[:12], created, expires),
            )
        self.audit(
            "token.issue", "success", p["organisation_id"], pid, tid,
            {"prefix": token[:12], "expires_at": expires},
        )
        return token

    def list_tokens(self, pid):
        pid = _safe_id(pid, "principal id")
        with self._db() as c:
            rows = c.execute(
                "SELECT id,prefix,created_at,expires_at,last_used_at,revoked_at FROM tokens "
                "WHERE principal_id=? ORDER BY created_at DESC", (pid,),
            ).fetchall()
        return [dict(r) for r in rows]

    def revoke_token(self, token_id):
        token_id = _safe_id(token_id, "token id")
        with self._db() as c:
            r = c.execute(
                "SELECT t.id,t.principal_id,p.organisation_id,t.revoked_at "
                "FROM tokens t JOIN principals p ON p.id=t.principal_id WHERE t.id=?",
                (token_id,),
            ).fetchone()
            if not r:
                raise KeyError("token not found")
            when = r["revoked_at"] or utcnow()
            c.execute("UPDATE tokens SET revoked_at=COALESCE(revoked_at,?) WHERE id=?", (when, token_id))
        self.audit("token.revoke", "success", r["organisation_id"], r["principal_id"], token_id)
        return {"id": token_id, "revoked_at": when}

    def authenticate(self, token):
        if not token:
            return None
        digest = self.digest(token)
        with self._db() as c:
            r = c.execute(
                "SELECT p.id,p.organisation_id,p.display_name,p.role,p.active,"
                "t.id token_id,t.expires_at,t.last_used_at "
                "FROM tokens t JOIN principals p ON p.id=t.principal_id "
                "WHERE t.digest=? AND t.revoked_at IS NULL",
                (digest,),
            ).fetchone()
            if not r or not r["active"]:
                return None
            expires = _parse_utc(r["expires_at"])
            if expires is not None and expires <= datetime.now(timezone.utc):
                return None
            now = utcnow()
            c.execute("UPDATE tokens SET last_used_at=? WHERE id=?", (now, r["token_id"]))
            out = dict(r)
            out["last_used_at"] = now
            return out

    @staticmethod
    def allowed(principal, permission):
        allowed = PERMISSIONS.get(principal.get("role"), set())
        return "*" in allowed or permission in allowed

    def public_principal(self, principal):
        return {k: principal[k] for k in ("id", "organisation_id", "display_name", "role")}

    def organisation(self, oid):
        with self._db() as c:
            r = c.execute("SELECT id,name,created_at FROM organisations WHERE id=?", (oid,)).fetchone()
        if not r:
            raise KeyError("organisation not found")
        return dict(r)

    def put_private(self, oid, key, payload, expected_version=None):
        oid = _safe_id(oid, "organisation id")
        key = _safe_id(key, "record key")
        if not isinstance(payload, dict):
            raise ValueError("private payload must be an object")
        raw = _json_bytes(payload)
        if len(raw) > MAX_PRIVATE_BYTES:
            raise ValueError("private record exceeds size limit")
        if expected_version is not None:
            expected_version = int(expected_version)
            if expected_version < 0:
                raise ValueError("expected version must be non-negative")

        now = utcnow()
        with self._db(True) as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute(
                "SELECT version,created_at FROM private_records WHERE organisation_id=? AND record_key=?",
                (oid, key),
            ).fetchone()
            current = int(r["version"]) if r else 0
            if expected_version is not None and expected_version != current:
                raise RuntimeError(f"version conflict: expected {expected_version}, current {current}")
            if r:
                version = current + 1
                created = r["created_at"]
                c.execute(
                    "UPDATE private_records SET payload=?,version=?,updated_at=? "
                    "WHERE organisation_id=? AND record_key=?",
                    (raw.decode(), version, now, oid, key),
                )
            else:
                version = 1
                created = now
                c.execute(
                    "INSERT INTO private_records VALUES(?,?,?,?,?,?)",
                    (oid, key, raw.decode(), version, created, now),
                )
        return {"key": key, "version": version, "created_at": created, "updated_at": now}

    def get_private(self, oid, key):
        with self._db(True) as c:
            r = c.execute(
                "SELECT record_key,payload,version,created_at,updated_at FROM private_records "
                "WHERE organisation_id=? AND record_key=?",
                (oid, key),
            ).fetchone()
        if not r:
            raise KeyError("private record not found")
        return {
            "key": r["record_key"],
            "payload": json.loads(r["payload"]),
            "version": r["version"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def delete_private(self, oid, key, expected_version=None):
        oid = _safe_id(oid, "organisation id")
        key = _safe_id(key, "record key")
        with self._db(True) as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute(
                "SELECT version FROM private_records WHERE organisation_id=? AND record_key=?",
                (oid, key),
            ).fetchone()
            if not r:
                raise KeyError("private record not found")
            current = int(r["version"])
            if expected_version is not None and int(expected_version) != current:
                raise RuntimeError(f"version conflict: expected {expected_version}, current {current}")
            c.execute(
                "DELETE FROM private_records WHERE organisation_id=? AND record_key=?",
                (oid, key),
            )
        return {"key": key, "deleted": True, "version": current}

    def audit_rows(self, oid, limit=100):
        limit = max(1, min(int(limit), 500))
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM audit WHERE organisation_id=? ORDER BY seq DESC LIMIT ?",
                (oid, limit),
            ).fetchall()
        return [{**dict(r), "details": json.loads(r["details"])} for r in rows]

    @staticmethod
    def verify_sqlite(path):
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(str(path))
        c = sqlite3.connect(path)
        try:
            result = c.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            c.close()
        return {"path": str(path), "ok": result == "ok", "integrity": result, "sha256": _sha256_file(path)}

    def backup(self, out):
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        result = {}
        manifest = {"created_at": utcnow(), "files": {}}
        for label, srcpath, private in (
            ("platform", self.db_path, False),
            ("private", self.private_db_path, True),
        ):
            dest = out / f"{label}-{stamp}.sqlite3"
            src = sqlite3.connect(srcpath)
            dst = sqlite3.connect(dest)
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
            if private:
                try:
                    os.chmod(dest, 0o600)
                except (OSError, PermissionError):
                    pass
            check = self.verify_sqlite(dest)
            if not check["ok"]:
                raise RuntimeError(f"backup integrity check failed for {label}")
            result[label] = str(dest)
            manifest["files"][label] = {
                "path": dest.name,
                "sha256": check["sha256"],
                "size": dest.stat().st_size,
            }
        manifest_path = out / f"manifest-{stamp}.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        result["manifest"] = str(manifest_path)
        return result

    def health(self):
        result = {"platform_db": False, "private_db": False}
        try:
            with self._db() as c:
                result["platform_db"] = c.execute("SELECT 1").fetchone()[0] == 1
            with self._db(True) as c:
                result["private_db"] = c.execute("SELECT 1").fetchone()[0] == 1
        except sqlite3.Error:
            pass
        return result


def read_jsonl_feed(path):
    if not path:
        raise FileNotFoundError("feed is not configured")
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError("configured feed is unavailable")
    if p.stat().st_size > MAX_FEED_BYTES:
        raise ValueError("configured feed exceeds size limit")
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("feed rows must be objects")
            rows.append(value)
    return rows


class RateLimiter:
    def __init__(self, limit=120, window_seconds=60):
        self.limit = max(1, int(limit))
        self.window = max(1, int(window_seconds))
        self.hits = {}
        self.lock = threading.Lock()
        self._ops = 0

    def allow(self, key, now_value=None):
        now = time.monotonic() if now_value is None else now_value
        with self.lock:
            q = self.hits.setdefault(key, collections.deque())
            cutoff = now - self.window
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.limit:
                return False, max(1, int(self.window - (now - q[0])) + 1)
            q.append(now)
            self._ops += 1
            if self._ops % 1000 == 0:
                stale = [k for k, v in self.hits.items() if not v or v[-1] <= cutoff]
                for k in stale:
                    self.hits.pop(k, None)
            return True, 0


class WorksiteClient:
    def __init__(self, base_url, token=None, timeout=2):
        parsed = urlparse(base_url)
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.query or parsed.fragment
        ):
            raise ValueError("CW_WORKSITES_URL must be a plain http(s) origin/base URL")
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = float(timeout)

    def request(self, method, path, body=None):
        data = None if body is None else _json_bytes(body)
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            with urlopen(
                Request(self.base + path, method=method, data=data, headers=headers),
                timeout=self.timeout,
            ) as r:
                raw = r.read(MAX_REQUEST_BYTES + 1)
                if len(raw) > MAX_REQUEST_BYTES:
                    raise ValueError("upstream response too large")
                return r.status, json.loads(raw or b"{}")
        except HTTPError as e:
            raw = e.read(MAX_REQUEST_BYTES + 1)
            try:
                payload = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                payload = {"error": "upstream error"}
            return e.code, payload
        except (URLError, TimeoutError, OSError) as e:
            return 502, {"error": "worksite service unavailable", "detail": type(e).__name__}

    def health(self):
        try:
            status, payload = self.request("GET", "/api/health")
            return status == 200 and bool(payload.get("ok"))
        except (ValueError, json.JSONDecodeError):
            return False


def _parse_allowed_origins(value):
    if not value:
        return set()
    out = set()
    for raw in str(value).split(","):
        origin = raw.strip().rstrip("/")
        if not origin:
            continue
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
            raise ValueError("CW_ALLOWED_ORIGIN entries must be http(s) origins")
        out.add(origin)
    return out


class PlatformHandler(BaseHTTPRequestHandler):
    db = None
    worksites = None
    limiter = None
    allowed_origins = set()
    verified_feed = None
    alerts_feed = None
    admin_html = None
    server_version = f"CrisisWeavePlatform/{SERVER_VERSION}"
    sys_version = ""

    def log_message(self, *args):
        return

    def _request_id(self):
        incoming = self.headers.get("X-Request-ID", "").strip()
        if incoming and len(incoming) <= 80 and all(c.isalnum() or c in "._:-" for c in incoming):
            return incoming
        return "req_" + secrets.token_hex(8)

    def _cors_origin(self):
        origin = self.headers.get("Origin")
        if origin and origin.rstrip("/") in self.allowed_origins:
            return origin.rstrip("/")
        return None

    def _base_headers(self):
        return {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "X-CrisisWeave-Version": SERVER_VERSION,
            "X-Request-ID": self._request_id(),
        }

    def _send(self, status, payload, headers=None):
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in self._base_headers().items():
            self.send_header(k, v)
        cors = self._cors_origin()
        if cors:
            self.send_header("Access-Control-Allow-Origin", cors)
            self.send_header("Vary", "Origin")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in self._base_headers().items():
            self.send_header(k, v)
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "").rstrip("/")
        if not origin or origin not in self.allowed_origins:
            return self._send(403, {"error": "origin not allowed"})
        requested = self.headers.get("Access-Control-Request-Headers", "")
        requested_headers = {x.strip().lower() for x in requested.split(",") if x.strip()}
        allowed_headers = {"authorization", "content-type", "if-match", "x-request-id"}
        if not requested_headers.issubset(allowed_headers):
            return self._send(403, {"error": "requested headers not allowed"})
        self.send_response(204)
        for k, v in self._base_headers().items():
            self.send_header(k, v)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, X-Request-ID")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def _principal(self):
        header = self.headers.get("Authorization", "")
        return self.db.authenticate(header[7:].strip()) if header.startswith("Bearer ") else None

    def _auth(self, permission):
        principal = self._principal()
        key = "token:" + principal["token_id"] if principal else "ip:" + str(self.client_address[0])
        ok, retry = self.limiter.allow(key)
        if not ok:
            self._send(429, {"error": "rate limit exceeded"}, {"Retry-After": str(retry)})
            return None
        if not principal:
            self._send(401, {"error": "authentication required"})
            return None
        if not self.db.allowed(principal, permission):
            self.db.audit(
                "authorisation", "denied", principal["organisation_id"], principal["id"],
                self.path, {"permission": permission},
            )
            self._send(403, {"error": "permission denied"})
            return None
        return principal

    def _body(self):
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or 0)
        except ValueError as e:
            raise ValueError("invalid Content-Length") from e
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body too large")
        value = json.loads(self.rfile.read(length) if length else b"{}")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _expected_version(self):
        value = self.headers.get("If-Match")
        if value is None:
            return None
        value = value.strip().strip('"')
        try:
            return int(value)
        except ValueError as e:
            raise ValueError("If-Match must be an integer record version") from e

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        try:
            if path == "/healthz":
                health = self.db.health()
                return self._send(200 if all(health.values()) else 503, {"ok": all(health.values()), **health})
            if path == "/readyz":
                health = self.db.health()
                worksites = self.worksites.health()
                ok = all(health.values()) and worksites
                return self._send(200 if ok else 503, {"ok": ok, **health, "worksites": worksites})
            if path in {"/admin", "/admin.html"}:
                return self._html(self.admin_html) if self.admin_html else self._send(404, {"error": "admin unavailable"})
            if path == "/api/v1/incidents":
                principal = self._auth("incidents:read")
                if not principal:
                    return
                try:
                    return self._send(200, {"incidents": read_jsonl_feed(self.verified_feed)})
                except Exception as e:
                    return self._send(503, {"error": str(e)})
            if path == "/api/v1/alerts":
                principal = self._auth("alerts:read")
                if not principal:
                    return
                try:
                    return self._send(200, {"alerts": read_jsonl_feed(self.alerts_feed)})
                except Exception as e:
                    return self._send(503, {"error": str(e)})
            if path == "/api/v1/me":
                principal = self._auth("org:read")
                return self._send(200, self.db.public_principal(principal)) if principal else None
            if path == "/api/v1/organisation":
                principal = self._auth("org:read")
                return self._send(200, self.db.organisation(principal["organisation_id"])) if principal else None
            if path == "/api/v1/worksites":
                principal = self._auth("worksites:read")
                if not principal:
                    return
                status, value = self.worksites.request("GET", "/api/worksites")
                return self._send(status, value)
            if path.startswith("/api/v1/worksites/"):
                principal = self._auth("worksites:read")
                if not principal:
                    return
                wid = _safe_id(path.split("/")[-1], "worksite id")
                status, value = self.worksites.request("GET", "/api/worksites/" + quote(wid, safe=""))
                return self._send(status, value)
            if path.startswith("/api/v1/private/"):
                principal = self._auth("private:read")
                if not principal:
                    return
                key = _safe_id(path.split("/")[-1], "record key")
                try:
                    record = self.db.get_private(principal["organisation_id"], key)
                except KeyError:
                    return self._send(404, {"error": "private record not found"})
                self.db.audit("private.read", "success", principal["organisation_id"], principal["id"], key)
                return self._send(200, record, {"ETag": f'"{record["version"]}"'})
            if path == "/api/v1/audit":
                principal = self._auth("audit:read")
                if not principal:
                    return
                try:
                    limit = int(parse_qs(u.query).get("limit", ["100"])[0])
                except ValueError:
                    return self._send(400, {"error": "limit must be integer"})
                return self._send(200, {"audit": self.db.audit_rows(principal["organisation_id"], limit)})
            return self._send(404, {"error": "not found"})
        except ValueError as e:
            return self._send(400, {"error": str(e)})

    def do_POST(self):
        try:
            body = self._body()
            path = urlparse(self.path).path
            if path.startswith("/api/v1/private/"):
                principal = self._auth("private:write")
                if not principal:
                    return
                key = _safe_id(path.split("/")[-1], "record key")
                expected = self._expected_version()
                try:
                    meta = self.db.put_private(principal["organisation_id"], key, body, expected)
                except RuntimeError as e:
                    return self._send(409, {"error": str(e)})
                self.db.audit(
                    "private.write", "success", principal["organisation_id"], principal["id"],
                    key, {"version": meta["version"]},
                )
                return self._send(200, meta, {"ETag": f'"{meta["version"]}"'})

            parts = [x for x in path.split("/") if x]
            if len(parts) == 5 and parts[:3] == ["api", "v1", "worksites"]:
                principal = self._auth("worksites:write")
                if not principal:
                    return
                wid = _safe_id(parts[3], "worksite id")
                op = parts[4]
                actor = f"{principal['organisation_id']}:{principal['id']}"
                if op == "assign":
                    forwarded = {"team_id": _safe_id(body.get("team_id"), "team id"), "actor": actor}
                elif op == "release":
                    forwarded = {"actor": actor}
                elif op == "transition":
                    forwarded = {
                        "state": str(body.get("state") or ""),
                        "actor": actor,
                        "note": str(body.get("note") or "")[:1000],
                    }
                else:
                    return self._send(404, {"error": "not found"})
                status, value = self.worksites.request(
                    "POST", f"/api/worksites/{quote(wid, safe='')}/{op}", forwarded,
                )
                self.db.audit(
                    "worksite." + op,
                    "success" if 200 <= status < 300 else "upstream_error",
                    principal["organisation_id"], principal["id"], wid,
                    {"upstream_status": status},
                )
                return self._send(status, value)
            return self._send(404, {"error": "not found"})
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid JSON"})
        except ValueError as e:
            return self._send(400, {"error": str(e)})

    def do_DELETE(self):
        try:
            path = urlparse(self.path).path
            if path.startswith("/api/v1/private/"):
                principal = self._auth("private:write")
                if not principal:
                    return
                key = _safe_id(path.split("/")[-1], "record key")
                expected = self._expected_version()
                try:
                    result = self.db.delete_private(principal["organisation_id"], key, expected)
                except KeyError:
                    return self._send(404, {"error": "private record not found"})
                except RuntimeError as e:
                    return self._send(409, {"error": str(e)})
                self.db.audit(
                    "private.delete", "success", principal["organisation_id"], principal["id"],
                    key, {"version": result["version"]},
                )
                return self._send(200, result)
            return self._send(404, {"error": "not found"})
        except ValueError as e:
            return self._send(400, {"error": str(e)})


def build_server(
    db, worksites, host, port, rate_limit, allowed_origin=None,
    verified_feed=None, alerts_feed=None, admin_html=None,
):
    handler = type("BoundPlatformHandler", (PlatformHandler,), {})
    handler.db = db
    handler.worksites = worksites
    handler.limiter = RateLimiter(rate_limit)
    handler.allowed_origins = _parse_allowed_origins(allowed_origin)
    handler.verified_feed = verified_feed
    handler.alerts_feed = alerts_feed
    handler.admin_html = admin_html
    return ThreadingHTTPServer((host, port), handler)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.getenv("CW_DB", "./data/platform.db"))
    ap.add_argument("--private-db", default=os.getenv("CW_PRIVATE_DB", "./data/private.db"))
    ap.add_argument("--pepper", default=os.getenv("CW_TOKEN_PEPPER", ""))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")

    org = sub.add_parser("create-org")
    org.add_argument("id")
    org.add_argument("name")

    principal = sub.add_parser("create-principal")
    principal.add_argument("id")
    principal.add_argument("--org", required=True)
    principal.add_argument("--name", required=True)
    principal.add_argument("--role", choices=ROLES, required=True)

    issue = sub.add_parser("issue-token")
    issue.add_argument("principal_id")
    issue.add_argument(
        "--ttl-hours", type=float,
        default=float(os.getenv("CW_TOKEN_TTL_HOURS", "24")),
        help="token lifetime in hours; use 0 for no expiry (default: 24)",
    )

    revoke = sub.add_parser("revoke-token")
    revoke.add_argument("token_id")

    tokens = sub.add_parser("list-tokens")
    tokens.add_argument("principal_id")

    deactivate = sub.add_parser("deactivate-principal")
    deactivate.add_argument("principal_id")

    activate = sub.add_parser("activate-principal")
    activate.add_argument("principal_id")

    backup = sub.add_parser("backup")
    backup.add_argument("--out", default="./backups")

    verify = sub.add_parser("verify-backup")
    verify.add_argument("sqlite_file")

    serve = sub.add_parser("serve")
    serve.add_argument("--host", default=os.getenv("CW_HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.getenv("CW_PORT", "8080")))
    serve.add_argument("--worksites-url", default=os.getenv("CW_WORKSITES_URL", "http://127.0.0.1:8787"))
    serve.add_argument("--rate-limit", type=int, default=int(os.getenv("CW_RATE_LIMIT_PER_MINUTE", "120")))
    serve.add_argument("--allowed-origin", default=os.getenv("CW_ALLOWED_ORIGIN") or None)
    serve.add_argument("--verified-feed", default=os.getenv("CW_VERIFIED_FEED") or None)
    serve.add_argument("--alerts-feed", default=os.getenv("CW_ALERTS_FEED") or None)

    args = ap.parse_args()
    db = PlatformDB(args.db, args.private_db, args.pepper)

    if args.cmd == "init":
        print(json.dumps({"ok": True, "db": args.db, "private_db": args.private_db}))
    elif args.cmd == "create-org":
        print(json.dumps(db.create_organisation(args.id, args.name)))
    elif args.cmd == "create-principal":
        print(json.dumps(db.create_principal(args.id, args.org, args.name, args.role)))
    elif args.cmd == "issue-token":
        ttl = None if args.ttl_hours == 0 else int(args.ttl_hours * 3600)
        print(json.dumps({
            "token": db.issue_token(args.principal_id, ttl),
            "warning": "shown once; store securely",
        }))
    elif args.cmd == "revoke-token":
        print(json.dumps(db.revoke_token(args.token_id)))
    elif args.cmd == "list-tokens":
        print(json.dumps({"tokens": db.list_tokens(args.principal_id)}))
    elif args.cmd == "deactivate-principal":
        print(json.dumps(db.set_principal_active(args.principal_id, False)))
    elif args.cmd == "activate-principal":
        print(json.dumps(db.set_principal_active(args.principal_id, True)))
    elif args.cmd == "backup":
        print(json.dumps(db.backup(args.out)))
    elif args.cmd == "verify-backup":
        print(json.dumps(db.verify_sqlite(args.sqlite_file)))
    else:
        html = Path(__file__).with_name("admin.html")
        worksites = WorksiteClient(args.worksites_url, os.getenv("CW_WORKSITES_TOKEN") or None)
        server = build_server(
            db, worksites, args.host, args.port, args.rate_limit,
            args.allowed_origin, args.verified_feed, args.alerts_feed,
            html.read_text(encoding="utf-8") if html.is_file() else None,
        )
        print(f"CrisisWeave platform listening on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
