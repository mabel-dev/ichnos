#!/usr/bin/env python3
"""Seed the VersionIndex DynamoDB table from the fingerprints already published.

Run once, as part of the duplicate-rows migration - see the ORDER OF OPERATIONS block in
`dedupe_versions_ctas.sql`, where this is step 4. Without it the newly-deployed worker
starts with an empty index, treats every fingerprint ever published as brand new, and
appends a fresh duplicate copy of each one the next time it meets it.

Input is a newline-delimited file of fingerprint_ids, from:

    SELECT DISTINCT fingerprint_id FROM ichnos.landing.versions

Idempotent: writes are unconditional puts of a key that carries no other meaningful
state, so re-running is harmless and a partial run can simply be repeated. That is
deliberately different from the worker's own conditional-put claim (storage/dynamodb.py)
- the worker needs to know whether it won the race, this only needs the key to exist.

    python scripts/seed_version_index.py fingerprints.txt [--table VersionIndex]
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from datetime import timezone

import boto3


def load_fingerprints(path: str) -> list:
    seen = set()
    ordered = []
    with open(path) as f:
        for line in f:
            # Tolerates a CSV export that kept its header, and stray quoting/whitespace -
            # a stray "fingerprint_id" row would otherwise be silently seeded as if it
            # were a real hash.
            value = line.strip().strip('"').strip("'")
            if not value or value == "fingerprint_id":
                continue
            if value not in seen:
                seen.add(value)
                ordered.append(value)
    return ordered


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="newline-delimited file of fingerprint_ids")
    parser.add_argument("--table", default="VersionIndex")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="parse and count the input without writing anything",
    )
    args = parser.parse_args(argv)

    fingerprints = load_fingerprints(args.path)
    print(f"{len(fingerprints)} distinct fingerprint_ids read from {args.path}")
    if args.dry_run:
        return 0
    if not fingerprints:
        print("nothing to seed - refusing to continue, check the export", file=sys.stderr)
        return 1

    table = boto3.resource("dynamodb").Table(args.table)
    claimed_at = datetime.now(timezone.utc).isoformat()
    written = 0
    with table.batch_writer(overwrite_by_pkeys=["fingerprint_id"]) as batch:
        for fingerprint_id in fingerprints:
            batch.put_item(Item={"fingerprint_id": fingerprint_id, "claimed_at": claimed_at})
            written += 1
            if written % 5000 == 0:
                print(f"  {written}/{len(fingerprints)}")

    print(f"seeded {written} fingerprints into {args.table}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
