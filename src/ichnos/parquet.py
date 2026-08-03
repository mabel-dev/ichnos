"""Converts staged NDJSON to Parquet via `rugo` before uploading to Opteryx.

Opteryx is a relational, Parquet-backed engine - the Upload Service accepts NDJSON
directly, but that's a convenience path, not the recommended one for regular batch
loads. The documented pattern is to convert to Parquet first with `rugo`
(https://docs.opteryx.app/docs/guides/rugo-standalone).

When `schema` is given, conversion goes through rugo's Python API
(`read_jsonl(..., explicit_schema=...)` + `write_parquet`) instead of the `rugo
convert` CLI, so every column gets its type from `schema`, not from inferring over
whatever rows happen to be in this particular batch. `schema` also decides which
columns are written at all, and in what order - `explicit_schema` types the columns
it names but reads undeclared keys through anyway, so the projection in
`_project_and_retype` is what actually makes a batch's shape independent of its
contents. That distinction is the actual
fix for a real, repeated production incident: Opteryx pins a table's schema from
whichever batch creates it, and columns that are all-null in that founding batch
(e.g. `redirect_location` when no scan in the batch happened to hit a redirect) get
inferred as a void/null type - every later batch with a real value for that column
then gets rejected outright ("table structure doesn't match"), which blocked the
`http` dataset's hourly publish repeatedly. Confirmed directly against the real
`rugo` binary: an explicit-schema column that's all-null in the data still comes out
typed VARCHAR, not void. Falls back to the plain CLI conversion (rugo's own
inference) when no schema is given, for any dataset that doesn't have one registered.

`"timestamp"` is this module's own schema type, not one of rugo's: `explicit_schema`
only accepts "string"/"int64"/"double"/"boolean", so a declared-timestamp column is
read as a string (every value is an `isoformat()` string in the staged NDJSON) and its
vector is then rebuilt as a draken TIMESTAMP64 before the Parquet write. Without that
step every instant in every dataset publishes as VARCHAR - which is exactly what
happened, and why `first_seen`/`observed_at`/`started_at`/`ended_at` all show up in
the catalog as strings that merely look like timestamps. Verified against the real
rugo/draken: a TIMESTAMP64 vector round-trips through Parquet as `timestamp[us]`, and
an all-null one still comes out TIMESTAMP64 rather than void, so this keeps the
founding-batch property the explicit schema exists for (`ended_at` is null for every
row of a batch whose scans all failed).
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional

CommandRunner = Callable[[List[str]], None]

# Schema type names this module accepts on top of rugo's own - mapped to the rugo type
# the column is *parsed* as, before any post-read retyping.
_RUGO_TYPE_OF = {
    "string": "string",
    "int64": "int64",
    "double": "double",
    "boolean": "boolean",
    "timestamp": "string",
}


def _default_run_command(cmd: List[str]) -> None:
    subprocess.run(cmd, check=True)


def _rugo_binary() -> str:
    """Resolve `rugo` next to the current Python interpreter rather than trusting
    PATH - cron and systemd both invoke `ichnos` by its full venv path without
    activating the venv, so a bare "rugo" wouldn't reliably resolve otherwise."""
    return os.path.join(os.path.dirname(sys.executable), "rugo")


def _project_and_retype(morsel, schema: Dict[str, str]):
    """Return `morsel` reduced to exactly `schema`'s columns, in `schema`'s order, with
    each declared-timestamp column rebuilt as TIMESTAMP64.

    The projection is not incidental tidying - `explicit_schema` types the columns it
    names but does not restrict the morsel to them, so any key present in the staged
    NDJSON and absent from `schema` is read anyway and published as a real column. A
    column dropped from a dataset therefore keeps being uploaded until the last row
    written by the old code drains, and every batch in between is rejected outright
    ("table structure doesn't match"). That is what happened to `favicon_hash` and
    `jarm`: both were removed from SCHEMAS and from the published tables, and the
    hourly publish then failed against rows still carrying them. Declaring the schema
    is meant to make a batch's shape independent of its contents, which it only is if
    undeclared columns are dropped here. Fixing the order too keeps a batch's layout
    from depending on the key order of whichever row happened to be written first.

    Timestamp parsing is strict, matching rugo's own explicit-schema behaviour: a value
    that isn't a valid ISO-8601 instant raises rather than silently publishing as a
    string or a null. Every writer of these columns goes through `datetime.isoformat()`
    (models.py), so anything else is a bug worth surfacing at publish time."""
    import draken.draken_native as draken_native
    from draken.morsels.morsel import Morsel

    present = {
        name.decode() if isinstance(name, bytes) else name for name in morsel.column_names
    }
    missing = [name for name in schema if name not in present]
    if missing:
        raise RuntimeError(f"declared column(s) {missing} missing after read")

    names: List[str] = []
    vectors = []
    for name, type_ in schema.items():
        vector = morsel.column(name)
        if type_ == "timestamp":
            values = [
                datetime.fromisoformat(value) if value is not None else None
                for value in vector.to_pylist()
            ]
            vector = draken_native.vector_timestamp_from_sequence(values)
        names.append(name)
        vectors.append(vector)
    return Morsel.from_vectors(names, vectors)


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

    unknown = sorted(set(schema.values()) - set(_RUGO_TYPE_OF))
    if unknown:
        raise ValueError(f"unsupported schema type(s) {unknown} converting {ndjson_path}")
    rugo_schema = {name: _RUGO_TYPE_OF[type_] for name, type_ in schema.items()}

    with rugo_jsonl.read_jsonl(ndjson_path, explicit_schema=rugo_schema) as reader:
        morsels = list(reader)
    # Observed (and documented) as always exactly one for jsonl regardless of row
    # count - fail loudly rather than silently dropping data if that ever changes.
    if len(morsels) != 1:
        raise RuntimeError(
            f"expected exactly one morsel converting {ndjson_path}, got {len(morsels)}"
        )
    morsel = _project_and_retype(morsels[0], schema)
    with open(parquet_path, "wb") as f:
        f.write(rugo_parquet.write_parquet(morsel))
