"""Converts staged NDJSON to Parquet via `rugo` before uploading to Opteryx.

Opteryx is a relational, Parquet-backed engine - the Upload Service accepts NDJSON
directly, but that's a convenience path, not the recommended one for regular batch
loads. The documented pattern is to convert to Parquet first with `rugo`
(https://docs.opteryx.app/docs/guides/rugo-standalone): `rugo convert in.jsonl
out.parquet` infers format from the file extensions, no flags needed for this case.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Callable
from typing import List
from typing import Optional

CommandRunner = Callable[[List[str]], None]


def _default_run_command(cmd: List[str]) -> None:
    subprocess.run(cmd, check=True)


def _rugo_binary() -> str:
    """Resolve `rugo` next to the current Python interpreter rather than trusting
    PATH - cron and systemd both invoke `ichnos` by its full venv path without
    activating the venv, so a bare "rugo" wouldn't reliably resolve otherwise."""
    return os.path.join(os.path.dirname(sys.executable), "rugo")


def convert_to_parquet(
    ndjson_path: str,
    parquet_path: str,
    *,
    run_command: Optional[CommandRunner] = None,
) -> None:
    run_command = run_command or _default_run_command
    run_command([_rugo_binary(), "convert", ndjson_path, parquet_path])
