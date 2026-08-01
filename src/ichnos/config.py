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

    # Throttle (design doc §4) - global budget shared across all enabled protocols
    rate_interval_seconds: float = 5.0

    # Opteryx publish target (design doc §3.2)
    opteryx_workspace: str = "scan"
    opteryx_collection: str = "measurement"
    opteryx_client_id: str = ""
    opteryx_client_secret: str = ""

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
            rate_interval_seconds=_env_float("RATE_INTERVAL_SECONDS", cls.rate_interval_seconds),
            opteryx_workspace=_env("OPTERYX_WORKSPACE", cls.opteryx_workspace),
            opteryx_collection=_env("OPTERYX_COLLECTION", cls.opteryx_collection),
            opteryx_client_id=_env("OPTERYX_CLIENT_ID", cls.opteryx_client_id),
            opteryx_client_secret=_env("OPTERYX_CLIENT_SECRET", cls.opteryx_client_secret),
        )
