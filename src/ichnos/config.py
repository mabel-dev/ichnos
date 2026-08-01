"""Environment-driven settings.

Everything here has an `ICHNOS_`-prefixed environment variable so the worker's
behaviour is configurable without a redeploy (design doc §5, §9) - config lives in SSM
Parameter Store / Secrets Manager in the real deployment, exposed to the process as
plain environment variables by the instance's startup script.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    return os.environ.get(f"ICHNOS_{name}", default)


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(f"ICHNOS_{name}")
    return float(value) if value is not None else default


@dataclass(frozen=True)
class Settings:
    # DynamoDB table names (design doc §3.1)
    exclusions_table: str = "Exclusions"
    schedule_table: str = "ScanSchedule"
    scan_metadata_table: str = "ScanMetadata"
    current_state_table: str = "CurrentState"

    # Local filesystem paths on the worker
    blocklist_path: str = "/var/lib/ichnos/blocklist.conf"
    jurisdiction_blocklist_path: str = "/var/lib/ichnos/jurisdiction-blocklist.conf"
    pending_dir: str = "/var/lib/ichnos/pending"
    publish_tmp_dir: str = "/var/lib/ichnos/publish-tmp"

    # S3 persistence for the jurisdiction blocklist (empty = local-only, e.g. dev/test).
    # Without this, a freshly-replaced instance starts with an EMPTY jurisdiction
    # exclusion list until the next weekly refresh - up to a week of scanning without
    # the JP/KP/KR/CN/RU/IR exclusion in effect. `scan` pulls this at startup if the
    # local file is missing; `jurisdiction-refresh` pushes to it after every refresh.
    jurisdiction_s3_bucket: str = ""
    jurisdiction_s3_key: str = "jurisdiction/jurisdiction-blocklist.conf"

    # Throttle (design doc §4) - global budget shared across all enabled protocols
    rate_interval_seconds: float = 5.0

    # Opteryx publish target (design doc §3.2)
    opteryx_workspace: str = "ichnos"
    opteryx_collection: str = "landing"
    opteryx_client_id: str = ""
    opteryx_client_secret: str = ""

    # Public site (design doc §6)
    site_organisation: str = "TBD"
    site_contact_email: str = "abuse@example.invalid"
    site_form_secret: str = "change-me-in-production"
    # True in the real deployment - nginx terminates TLS and reverse-proxies to this
    # app on loopback, so the opt-out form must read the client IP from the header
    # nginx sets, not request.client.host (see webapp/app.py's module docstring).
    trust_proxy_headers: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            exclusions_table=_env("EXCLUSIONS_TABLE", cls.exclusions_table),
            schedule_table=_env("SCHEDULE_TABLE", cls.schedule_table),
            scan_metadata_table=_env("SCAN_METADATA_TABLE", cls.scan_metadata_table),
            current_state_table=_env("CURRENT_STATE_TABLE", cls.current_state_table),
            blocklist_path=_env("BLOCKLIST_PATH", cls.blocklist_path),
            jurisdiction_blocklist_path=_env(
                "JURISDICTION_BLOCKLIST_PATH", cls.jurisdiction_blocklist_path
            ),
            pending_dir=_env("PENDING_DIR", cls.pending_dir),
            publish_tmp_dir=_env("PUBLISH_TMP_DIR", cls.publish_tmp_dir),
            jurisdiction_s3_bucket=_env("JURISDICTION_S3_BUCKET", cls.jurisdiction_s3_bucket),
            jurisdiction_s3_key=_env("JURISDICTION_S3_KEY", cls.jurisdiction_s3_key),
            rate_interval_seconds=_env_float("RATE_INTERVAL_SECONDS", cls.rate_interval_seconds),
            opteryx_workspace=_env("OPTERYX_WORKSPACE", cls.opteryx_workspace),
            opteryx_collection=_env("OPTERYX_COLLECTION", cls.opteryx_collection),
            opteryx_client_id=_env("OPTERYX_CLIENT_ID", cls.opteryx_client_id),
            opteryx_client_secret=_env("OPTERYX_CLIENT_SECRET", cls.opteryx_client_secret),
            site_organisation=_env("SITE_ORGANISATION", cls.site_organisation),
            site_contact_email=_env("SITE_CONTACT_EMAIL", cls.site_contact_email),
            site_form_secret=_env("SITE_FORM_SECRET", cls.site_form_secret),
            trust_proxy_headers=_env("TRUST_PROXY_HEADERS", "") == "1",
        )
