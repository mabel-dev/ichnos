"""Optional S3 persistence for the jurisdiction blocklist (config.py's
`jurisdiction_s3_bucket`/`_key`). Only touched when a bucket is configured - local
dev/tests with an empty `jurisdiction_s3_bucket` never import boto3 through this path.

Why this exists: the jurisdiction pre-exclusion list (design doc §3.1.1) is otherwise
purely local to one instance, refreshed weekly by cron. A freshly-replaced instance
(the ASG can do this at any time, by design - see design doc §2's stateless-worker
principle) would start with an *empty* list and scan without the JP/KP/KR/CN/RU/IR
exclusion until the next weekly refresh happened to run. `download_file` lets `scan`
pull the last-known-good list at startup instead of starting from nothing.
"""
from __future__ import annotations

import os
from typing import Any
from typing import Optional


def _client(client: Optional[Any] = None):
    if client is not None:
        return client
    import boto3

    return boto3.client("s3")


def upload_file(bucket: str, key: str, local_path: str, *, client: Optional[Any] = None) -> None:
    _client(client).upload_file(local_path, bucket, key)


def download_file(
    bucket: str, key: str, local_path: str, *, client: Optional[Any] = None
) -> bool:
    """Returns True if the object existed and was downloaded, False if it doesn't
    exist yet (expected on the very first deployment, before any jurisdiction-refresh
    has ever run) - that's a normal case, not an error. Any other failure (permissions,
    network) is re-raised rather than silently degrading to "no jurisdiction list"."""
    from botocore.exceptions import ClientError

    os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
    s3 = _client(client)
    try:
        s3.download_file(bucket, key, local_path)
        return True
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")
        if error_code in ("404", "NoSuchKey"):
            return False
        raise
