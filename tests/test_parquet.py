import json
import os
from datetime import datetime
from datetime import timezone

import pytest

from ichnos.parquet import _rugo_binary
from ichnos.parquet import convert_to_parquet


def test_convert_to_parquet_invokes_rugo_convert_with_resolved_binary():
    calls = []
    convert_to_parquet("in.jsonl", "out.parquet", run_command=calls.append)
    assert calls == [[_rugo_binary(), "convert", "in.jsonl", "out.parquet"]]


def test_rugo_binary_is_resolved_next_to_the_current_interpreter():
    import sys

    assert _rugo_binary() == os.path.join(os.path.dirname(sys.executable), "rugo")


def test_convert_to_parquet_with_schema_ignores_run_command(tmp_path):
    # When a schema is given, conversion goes through rugo's Python API directly, not
    # the CLI - run_command must never be invoked in that path.
    ndjson_path = str(tmp_path / "in.ndjson")
    parquet_path = str(tmp_path / "out.parquet")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"a": "x"}) + "\n")

    calls = []
    convert_to_parquet(
        ndjson_path, parquet_path, schema={"a": "string"}, run_command=calls.append
    )
    assert calls == []


def test_convert_to_parquet_with_schema_types_an_all_null_column_as_string_not_void(tmp_path):
    # Regression test for a real, repeated production incident, verified directly
    # against the real rugo binary (not mocked): Opteryx pins a table's schema from
    # whichever batch creates it, and a column that's all-null in that founding batch
    # gets inferred as a void/null type by plain schema inference - every later batch
    # with a real value for that column then gets rejected outright ("table structure
    # doesn't match"). An explicit schema must produce the declared type regardless of
    # whether this particular batch happens to have any non-null values for it.
    import rugo.parquet as rugo_parquet

    ndjson_path = str(tmp_path / "in.ndjson")
    parquet_path = str(tmp_path / "out.parquet")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"redirect_location": None, "status_code": 200}) + "\n")
        f.write(json.dumps({"redirect_location": None, "status_code": 404}) + "\n")

    convert_to_parquet(
        ndjson_path, parquet_path,
        schema={"redirect_location": "string", "status_code": "int64"},
    )

    with rugo_parquet.read_parquet(parquet_path) as reader:
        morsels = list(reader)
    assert len(morsels) == 1
    schema = morsels[0].schema  # {column_name: DrakenType}
    assert schema["redirect_location"].name == "VARCHAR"
    assert schema["status_code"].name == "INT64"


def test_convert_to_parquet_writes_declared_timestamp_columns_as_timestamps(tmp_path):
    # The instants in every dataset (observed_at, first_seen, started_at, ended_at) are
    # staged as isoformat() strings, and rugo's explicit_schema has no timestamp type -
    # so without parquet.py's retyping step they publish as VARCHAR, which is exactly
    # how they ended up in the catalog: text that looks like a timestamp but sorts and
    # ranges as a string.
    import rugo.parquet as rugo_parquet

    ndjson_path = str(tmp_path / "in.ndjson")
    parquet_path = str(tmp_path / "out.parquet")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"started_at": "2026-08-03T12:00:00.123456+00:00", "seed": 1}) + "\n")
        f.write(json.dumps({"started_at": "2026-08-03T13:00:00+00:00", "seed": 2}) + "\n")

    convert_to_parquet(
        ndjson_path, parquet_path, schema={"started_at": "timestamp", "seed": "int64"}
    )

    with rugo_parquet.read_parquet(parquet_path) as reader:
        morsels = list(reader)
    assert morsels[0].schema["started_at"].name == "TIMESTAMP64"
    assert morsels[0].column("started_at").to_pylist() == [
        datetime(2026, 8, 3, 12, 0, 0, 123456, tzinfo=timezone.utc),
        datetime(2026, 8, 3, 13, 0, 0, tzinfo=timezone.utc),
    ]


def test_convert_to_parquet_drops_columns_the_schema_does_not_declare(tmp_path):
    # explicit_schema types the columns it names but reads undeclared keys through
    # anyway, so a column dropped from SCHEMAS kept being published until the last row
    # written by the old code drained - and every batch in between was rejected with
    # "table structure doesn't match". favicon_hash and jarm are the real instances.
    import rugo.parquet as rugo_parquet

    ndjson_path = str(tmp_path / "in.ndjson")
    parquet_path = str(tmp_path / "out.parquet")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"server": "nginx", "favicon_hash": None, "status_code": 200}) + "\n")
        f.write(json.dumps({"server": "apache", "favicon_hash": "abc", "status_code": 404}) + "\n")

    convert_to_parquet(
        ndjson_path, parquet_path, schema={"status_code": "int64", "server": "string"}
    )

    with rugo_parquet.read_parquet(parquet_path) as reader:
        morsels = list(reader)
    names = [
        name.decode() if isinstance(name, bytes) else name for name in morsels[0].column_names
    ]
    # Declared columns only, in the order the schema declares them - not the key order
    # of whichever row happened to be written first.
    assert names == ["status_code", "server"]


def test_convert_to_parquet_raises_when_a_declared_column_is_absent(tmp_path):
    ndjson_path = str(tmp_path / "in.ndjson")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"server": "nginx"}) + "\n")

    with pytest.raises(RuntimeError, match="missing after read"):
        convert_to_parquet(
            ndjson_path,
            str(tmp_path / "out.parquet"),
            schema={"server": "string", "nope": "string"},
        )


def test_convert_to_parquet_types_an_all_null_timestamp_column_as_timestamp(tmp_path):
    # Same founding-batch property the string case above relies on, for the one column
    # that genuinely is null for whole batches: ended_at, when every scan in the hour
    # failed. If an all-null batch created the table as void/VARCHAR, every later batch
    # with a real end time would be rejected.
    import rugo.parquet as rugo_parquet

    ndjson_path = str(tmp_path / "in.ndjson")
    parquet_path = str(tmp_path / "out.parquet")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"ended_at": None}) + "\n")
        f.write(json.dumps({"ended_at": None}) + "\n")

    convert_to_parquet(ndjson_path, parquet_path, schema={"ended_at": "timestamp"})

    with rugo_parquet.read_parquet(parquet_path) as reader:
        morsels = list(reader)
    assert morsels[0].schema["ended_at"].name == "TIMESTAMP64"
    assert morsels[0].column("ended_at").to_pylist() == [None, None]


def test_convert_to_parquet_rejects_an_unparseable_timestamp(tmp_path):
    # Strict, matching rugo's own explicit-schema behaviour: a declared-type mismatch
    # is a real data bug, not something to paper over by publishing it as a string.
    ndjson_path = str(tmp_path / "in.ndjson")
    parquet_path = str(tmp_path / "out.parquet")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"observed_at": "not-a-timestamp"}) + "\n")

    with pytest.raises(ValueError):
        convert_to_parquet(ndjson_path, parquet_path, schema={"observed_at": "timestamp"})


def test_convert_to_parquet_rejects_an_unknown_schema_type(tmp_path):
    ndjson_path = str(tmp_path / "in.ndjson")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"a": "x"}) + "\n")

    with pytest.raises(ValueError, match="unsupported schema type"):
        convert_to_parquet(ndjson_path, str(tmp_path / "out.parquet"), schema={"a": "nvarchar"})


def test_convert_to_parquet_without_schema_falls_back_to_cli_inference(tmp_path):
    # No explicit_schema for this dataset -> the old rugo-convert-CLI path, whatever
    # rugo's own inference produces - unaffected by the fix, still exercised via the
    # real binary rather than a mock.
    ndjson_path = str(tmp_path / "in.ndjson")
    parquet_path = str(tmp_path / "out.parquet")
    with open(ndjson_path, "w") as f:
        f.write(json.dumps({"a": 1}) + "\n")

    convert_to_parquet(ndjson_path, parquet_path)

    assert os.path.exists(parquet_path)
