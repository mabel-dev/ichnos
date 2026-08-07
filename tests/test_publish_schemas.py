"""Every declared column type must be one the Parquet writer actually understands.

Not a style check. Opteryx pins a table's schema on first commit, so a dataset that
publishes with the wrong type is not a one-run problem - and a type name the writer
does not recognise fails at publish time, which is an hour after the run that produced
the rows and on a box nobody is watching. `extended` on the smtp dataset was written as
"bool" and the accepted spelling is "boolean"; nothing in the test suite would have
caught it, and the first publish of the new datasets would have been the discovery.
"""
from ichnos.parquet import _RUGO_TYPE_OF
from ichnos.publish import SCHEMAS


def test_every_declared_column_type_is_one_the_writer_accepts():
    unknown = {
        (dataset, column, type_)
        for dataset, schema in SCHEMAS.items()
        for column, type_ in schema.items()
        if type_ not in _RUGO_TYPE_OF
    }
    assert not unknown, f"unsupported column types declared: {sorted(unknown)}"
