#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

from crisisweave_platform import PlatformDB, utcnow


def cutoff(days: int) -> str:
    if not 1 <= int(days) <= 3650:
        raise ValueError("retention days must be between 1 and 3650")
    return (datetime.now(timezone.utc) - timedelta(days=int(days))).isoformat().replace("+00:00", "Z")


def report(db: PlatformDB, private_days: int, token_days: int) -> dict:
    private_cutoff = cutoff(private_days)
    token_cutoff = cutoff(token_days)
    with db._db(True) as c:
        private_count = c.execute(
            "SELECT COUNT(*) FROM private_records WHERE updated_at < ?", (private_cutoff,)
        ).fetchone()[0]
    with db._db() as c:
        token_count = c.execute(
            "SELECT COUNT(*) FROM tokens WHERE "
            "(revoked_at IS NOT NULL AND revoked_at < ?) OR "
            "(expires_at IS NOT NULL AND expires_at < ?)",
            (token_cutoff, token_cutoff),
        ).fetchone()[0]
    return {
        "generated_at": utcnow(),
        "private_retention_days": int(private_days),
        "token_retention_days": int(token_days),
        "private_records_eligible": int(private_count),
        "tokens_eligible": int(token_count),
    }


def prune(db: PlatformDB, private_days: int, token_days: int, *, apply: bool) -> dict:
    result = report(db, private_days, token_days)
    result["applied"] = bool(apply)
    if not apply:
        return result

    private_cutoff = cutoff(private_days)
    token_cutoff = cutoff(token_days)
    with db._db(True) as c:
        c.execute("BEGIN IMMEDIATE")
        deleted_private = c.execute(
            "DELETE FROM private_records WHERE updated_at < ?", (private_cutoff,)
        ).rowcount
    with db._db() as c:
        c.execute("BEGIN IMMEDIATE")
        deleted_tokens = c.execute(
            "DELETE FROM tokens WHERE "
            "(revoked_at IS NOT NULL AND revoked_at < ?) OR "
            "(expires_at IS NOT NULL AND expires_at < ?)",
            (token_cutoff, token_cutoff),
        ).rowcount

    db.audit(
        "maintenance.retention_prune",
        "success",
        details={
            "private_retention_days": int(private_days),
            "token_retention_days": int(token_days),
            "private_records_deleted": int(deleted_private),
            "tokens_deleted": int(deleted_tokens),
        },
    )
    result.update(
        {
            "private_records_deleted": int(deleted_private),
            "tokens_deleted": int(deleted_tokens),
            "completed_at": utcnow(),
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="CrisisWeave privacy and credential retention maintenance")
    parser.add_argument("--db", required=True)
    parser.add_argument("--private-db", required=True)
    parser.add_argument("--pepper", required=True)
    parser.add_argument("--private-retention-days", type=int, default=90)
    parser.add_argument("--token-retention-days", type=int, default=30)
    parser.add_argument("--apply", action="store_true", help="actually delete eligible records; default is dry-run")
    args = parser.parse_args()

    db = PlatformDB(args.db, args.private_db, args.pepper)
    result = prune(
        db,
        args.private_retention_days,
        args.token_retention_days,
        apply=args.apply,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
