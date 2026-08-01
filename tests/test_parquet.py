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
