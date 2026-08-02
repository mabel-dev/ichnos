import json
import os

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
