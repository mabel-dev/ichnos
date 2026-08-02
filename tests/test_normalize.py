from ichnos.normalize import normalize_http
from ichnos.normalize import normalize_tls


def test_normalize_http_extracts_core_fields():
    result = {
        "result": {
            "response": {
                "status_code": 200,
                "headers": {"Server": ["nginx"], "Content-Type": ["text/html"]},
                "body": "<html><head><title>Hello World</title></head></html>",
            }
        }
    }
    out = normalize_http(result)
    assert out["status_code"] == 200
    assert out["server"] == ["nginx"]
    assert out["title"] == "Hello World"
    assert out["favicon_hash"] is None


def test_normalize_http_headers_is_a_json_string_not_a_native_dict():
    # Regression test for a real production incident: raw HTTP headers vary
    # arbitrarily by target (confirmed against real published data - 13 distinct
    # header key-sets across 107 real rows). Publishing that as a native nested
    # column made Opteryx's inferred table schema depend on whichever header
    # combinations happened to appear in the first commit, and every later batch with
    # a combination that commit hadn't seen got rejected - silently blocking the
    # `http` dataset's hourly publish for 10 straight hours. A JSON string is a single
    # stable column type regardless of what's inside it.
    import json

    result = {
        "result": {
            "response": {
                "status_code": 200,
                "headers": {"Server": ["nginx"], "Content-Type": ["text/html"]},
            }
        }
    }
    out = normalize_http(result)
    assert isinstance(out["headers"], str)
    assert json.loads(out["headers"]) == {"server": ["nginx"], "content-type": ["text/html"]}


def test_normalize_http_redirect_location_from_headers():
    result = {
        "result": {
            "response": {"status_code": 301, "headers": {"Location": ["https://example.com/"]}}
        }
    }
    out = normalize_http(result)
    assert out["redirect_location"] == ["https://example.com/"]


def test_normalize_http_redirect_location_from_chain():
    result = {
        "result": {
            "response": {"status_code": 200, "headers": {}},
            "redirect_response_chain": [{"headers": {"location": "https://final.example/"}}],
        }
    }
    out = normalize_http(result)
    assert out["redirect_location"] == "https://final.example/"


def test_normalize_http_handles_missing_fields_gracefully():
    out = normalize_http({})
    assert out == {
        "status_code": None,
        "headers": "{}",
        "server": None,
        "title": None,
        "favicon_hash": None,
        "redirect_location": None,
    }


def test_normalize_tls_extracts_core_fields():
    result = {
        "result": {
            "handshake_log": {
                "server_hello": {
                    "version": {"name": "TLS 1.2"},
                    "cipher_suite": {"name": "TLS_AES_128_GCM_SHA256"},
                },
                "server_certificates": {
                    "certificate": {
                        "parsed": {
                            "subject": {"common_name": ["example.com"]},
                            "issuer": {"common_name": ["Let's Encrypt"]},
                            "serial_number": "123",
                            "signature_algorithm": {"name": "SHA256WithRSA"},
                            "fingerprint_sha256": "deadbeef",
                        }
                    }
                },
            }
        }
    }
    out = normalize_tls(result)
    assert out["version"] == "TLS 1.2"
    assert out["cipher_suite"] == "TLS_AES_128_GCM_SHA256"
    assert out["certificate"]["subject_cn"] == "example.com"
    assert out["certificate"]["issuer_cn"] == "Let's Encrypt"
    assert out["certificate"]["fingerprint_sha256"] == "deadbeef"
    assert out["jarm"] is None


def test_normalize_tls_handles_missing_fields_gracefully():
    out = normalize_tls({})
    assert out["version"] is None
    assert out["certificate"]["subject_cn"] is None
