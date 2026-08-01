from ichnos.fingerprint import canonicalize
from ichnos.fingerprint import fingerprint_id


def test_key_order_does_not_affect_fingerprint():
    a = {"b": 1, "a": 2, "nested": {"y": 1, "x": 2}}
    b = {"a": 2, "nested": {"x": 2, "y": 1}, "b": 1}
    assert fingerprint_id(a) == fingerprint_id(b)


def test_value_change_changes_fingerprint():
    assert fingerprint_id({"status_code": 200}) != fingerprint_id({"status_code": 301})


def test_canonicalize_is_deterministic_json():
    assert canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'
