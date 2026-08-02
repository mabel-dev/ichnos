"""Converts staged NDJSON to Parquet via `rugo` before uploading to Opteryx.

Opteryx is a relational, Parquet-backed engine - the Upload Service accepts NDJSON
directly, but that's a convenience path, not the recommended one for regular batch
loads. The documented pattern is to convert to Parquet first with `rugo`
(https://docs.opteryx.app/docs/guides/rugo-standalone).

When `schema` is given, conversion goes through rugo's Python API
(`read_jsonl(..., explicit_schema=...)` + `write_parquet`) instead of the `rugo
convert` CLI, so every column gets its type from `schema`, not from inferring over
whatever rows happen to be in this particular batch. That distinction is the actual
fix for a real, repeated production incident: Opteryx pins a table's schema from
whichever batch creates it, and columns that are all-null in that founding batch
(e.g. `redirect_location` when no scan in the batch happened to hit a redirect) get
inferred as a void/null type - every later batch with a real value for that column
then gets rejected outright ("table structure doesn't match"), which blocked the
`http` dataset's hourly publish repeatedly. Confirmed directly against the real
`rugo` binary: an explicit-schema column that's all-null in the data still comes out
typed VARCHAR, not void. Falls back to the plain CLI conversion (rugo's own
inference) when no schema is given, for any dataset that doesn't have one registered.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Callable
from typing import Dict
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
    schema: Optional[Dict[str, str]] = None,
    run_command: Optional[CommandRunner] = None,
) -> None:
    if schema is None:
        run_command = run_command or _default_run_command
        run_command([_rugo_binary(), "convert", ndjson_path, parquet_path])
        return

    import rugo.jsonl as rugo_jsonl
    import rugo.parquet as rugo_parquet

    with rugo_jsonl.read_jsonl(ndjson_path, explicit_schema=schema) as reader:
        morsels = list(reader)
    # Observed (and documented) as always exactly one for jsonl regardless of row
    # count - fail loudly rather than silently dropping data if that ever changes.
    if len(morsels) != 1:
        raise RuntimeError(
            f"expected exactly one morsel converting {ndjson_path}, got {len(morsels)}"
        )
    with open(parquet_path, "wb") as f:
        f.write(rugo_parquet.write_parquet(morsels[0]))
