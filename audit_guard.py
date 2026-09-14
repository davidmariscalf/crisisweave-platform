#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path

from crisisweave_platform import PlatformDB

TRIGGERS = {
    "audit_no_update": """
        CREATE TRIGGER IF NOT EXISTS audit_no_update
        BEFORE UPDATE ON audit
        BEGIN
            SELECT RAISE(ABORT, 'audit log is immutable');
        END;
    """,
    "audit_no_delete": """
        CREATE TRIGGER IF NOT EXISTS audit_no_delete
        BEFORE DELETE ON audit
        BEGIN
            SELECT RAISE(ABORT, 'audit log is immutable');
        END;
    """,
}


def connect(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=10000")
    return con


def install(path: str) -> dict:
    with connect(path) as con:
        for sql in TRIGGERS.values():
            con.execute(sql)
    return verify(path)


def verify(path: str) -> dict:
    with connect(path) as con:
        table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit'"
        ).fetchone()
        if not table:
            raise RuntimeError("audit table is missing")
        rows = con.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name IN (?,?)",
            tuple(TRIGGERS),
        ).fetchall()
        found = {r["name"]: r["sql"] for r in rows}
        missing = sorted(set(TRIGGERS) - set(found))
        if missing:
            raise RuntimeError("audit immutability triggers missing: " + ", ".join(missing))
        count = con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    return {"ok": True, "audit_rows": count, "triggers": sorted(found)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Install or verify CrisisWeave audit immutability guards")
    parser.add_argument("command", choices=("install", "verify"), nargs="?", default="install")
    parser.add_argument("--db", default=os.getenv("CW_DB", "/data/platform.db"))
    parser.add_argument("--private-db", default=os.getenv("CW_PRIVATE_DB", "/data/private.db"))
    parser.add_argument("--pepper", default=os.getenv("CW_TOKEN_PEPPER", ""))
    args = parser.parse_args()

    if args.command == "install":
        # PlatformDB owns schema creation. Initialising it here keeps the guard
        # compatible with both fresh and existing deployments before the HTTP
        # process starts. No default account or credential is created.
        PlatformDB(args.db, args.private_db, args.pepper)
        result = install(args.db)
    else:
        result = verify(args.db)

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
