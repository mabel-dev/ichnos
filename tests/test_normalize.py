import copy
import json

from ichnos.normalize import normalize_http
from ichnos.normalize import normalize_ssh
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
    assert out["server"] == "nginx"
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


def test_normalize_http_excludes_volatile_headers_from_fingerprint_input():
    # Regression test for a real production incident: `date` (and `expires`, usually
    # computed relative to it, and `age`) change on every single request, so including
    # them meant an unchanged host produced a *different* fingerprint on every scan -
    # confirmed directly against production data, one real host generating dozens of
    # spurious "new version" rows over a few hours for a target that never changed.
    result_a = {
        "result": {
            "response": {
                "status_code": 200,
                "headers": {
                    "Server": ["nginx"],
                    "Date": ["Sun, 02 Aug 2026 10:00:00 GMT"],
                    "Expires": ["Sun, 02 Aug 2026 10:00:00 GMT"],
                    "Age": ["12"],
                },
            }
        }
    }
    result_b = copy.deepcopy(result_a)
    result_b["result"]["response"]["headers"]["Date"] = ["Sun, 02 Aug 2026 11:00:00 GMT"]
    result_b["result"]["response"]["headers"]["Expires"] = ["Sun, 02 Aug 2026 11:00:00 GMT"]
    result_b["result"]["response"]["headers"]["Age"] = ["9999"]

    out_a = normalize_http(result_a)
    out_b = normalize_http(result_b)

    assert out_a == out_b  # identical despite different date/expires/age
    stored_headers = json.loads(out_a["headers"])
    assert "date" not in stored_headers
    assert "expires" not in stored_headers
    assert "age" not in stored_headers
    assert stored_headers["server"] == ["nginx"]  # unaffected, non-volatile header kept


def test_normalize_http_excludes_unknown_headers_bucket_from_fingerprint_input():
    # ZGrab2's `unknown` bucket holds headers it couldn't map to a named field -
    # arbitrary and unbounded, exactly where a CDN/server's own per-request tracing
    # header would land (a cf_ray-style ID, but there's no fixed name to filter for
    # across every vendor). Excluded wholesale rather than risk the same class of bug
    # as date/expires/age recurring through a header this project doesn't recognize.
    result_a = {
        "result": {
            "response": {
                "status_code": 200,
                "headers": {
                    "Server": ["nginx"],
                    "unknown": [{"key": "cf_ray", "value": ["aaaa1111-XYZ"]}],
                },
            }
        }
    }
    result_b = copy.deepcopy(result_a)
    result_b["result"]["response"]["headers"]["unknown"] = [
        {"key": "cf_ray", "value": ["bbbb2222-ABC"]}
    ]

    out_a = normalize_http(result_a)
    out_b = normalize_http(result_b)

    assert out_a == out_b  # identical despite different per-request tracing IDs
    stored_headers = json.loads(out_a["headers"])
    assert "unknown" not in stored_headers
    assert stored_headers["server"] == ["nginx"]


def test_normalize_http_redirect_location_from_headers():
    # Regression test for a real production incident: this path produces a list (like
    # all header values) while the redirect-chain path below produces a plain string -
    # three possible types (None, str, list) for one field, confirmed against real
    # published data (3 of 22 real pending rows had it as a list). That blocked
    # publishing the same way the `headers` bug did - coerced to a single Optional[str].
    result = {
        "result": {
            "response": {"status_code": 301, "headers": {"Location": ["https://example.com/"]}}
        }
    }
    out = normalize_http(result)
    assert out["redirect_location"] == "https://example.com/"


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
    # certificate is a JSON string, not a native dict - same fix as normalize_http's
    # headers, applied pre-emptively here (see normalize_tls's docstring).
    certificate = json.loads(out["certificate"])
    assert certificate["subject_cn"] == "example.com"
    assert certificate["issuer_cn"] == "Let's Encrypt"
    assert certificate["fingerprint_sha256"] == "deadbeef"
    assert out["jarm"] is None


def test_normalize_tls_handles_missing_fields_gracefully():
    out = normalize_tls({})
    assert out["version"] is None
    assert json.loads(out["certificate"])["subject_cn"] is None


# Shape below is a trimmed real zgrab2 ssh-module result, captured against a real
# host during this project's SSH rollout - not a made-up fixture.
_REAL_SSH_RESULT = {
    "result": {
        "server_id": {
            "raw": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10",
            "version": "2.0",
            "software": "OpenSSH_9.2p1",
            "comment": "Debian-2+deb12u10",
        },
        "server_key_exchange": {
            "cookie": "qbyjPVplJ/MHS6dg67VhBg==",
            "kex_algorithms": ["curve25519-sha256", "diffie-hellman-group16-sha512"],
            "host_key_algorithms": ["rsa-sha2-512", "ssh-ed25519"],
        },
        "key_exchange": {
            "curve25519_sha256_params": {"server_public": "d29FbEyZOxWOvZyPl8cuHZcGwFKHkzG5JwTBgrStNTc="},
            "server_signature": {
                "parsed": {"algorithm": "ssh-ed25519", "value": "k082v1QG..."},
                "raw": "AAAAC3NzaC1lZDI1NTE5...",
            },
            "server_host_key": {
                "algorithm": "ssh-ed25519",
                "fingerprint_sha256": "fed8ca18933043aab8ff47ee163230b9306f889d7ad69f86b16cb2b6ee747d49",
            },
        },
    }
}


def test_normalize_ssh_extracts_core_fields():
    out = normalize_ssh(_REAL_SSH_RESULT)
    assert out["banner"] == "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10"
    assert out["version"] == "2.0"
    assert out["software"] == "OpenSSH_9.2p1"
    assert out["comment"] == "Debian-2+deb12u10"
    assert out["host_key_algorithm"] == "ssh-ed25519"
    assert out["host_key_fingerprint_sha256"] == (
        "fed8ca18933043aab8ff47ee163230b9306f889d7ad69f86b16cb2b6ee747d49"
    )


def test_normalize_ssh_ignores_per_connection_randomness():
    # This is the whole reason server_key_exchange/key_exchange aren't in the output:
    # cookie, the ephemeral key-exchange public value, and the handshake signature are
    # randomized fresh on every single connection by design, even against a completely
    # unchanged host. If any of those leaked into the normalized payload, the
    # fingerprint would change on every scan and defeat the purpose of fingerprinting.
    result_a = copy.deepcopy(_REAL_SSH_RESULT)
    result_b = copy.deepcopy(_REAL_SSH_RESULT)
    result_b["result"]["server_key_exchange"]["cookie"] = "totally-different-cookie=="
    result_b["result"]["key_exchange"]["curve25519_sha256_params"]["server_public"] = "different-key="
    result_b["result"]["key_exchange"]["server_signature"]["raw"] = "different-signature-bytes"

    assert normalize_ssh(result_a) == normalize_ssh(result_b)


def test_normalize_ssh_handles_missing_fields_gracefully():
    out = normalize_ssh({})
    assert out == {
        "banner": None,
        "version": None,
        "software": None,
        "comment": None,
        "host_key_algorithm": None,
        "host_key_fingerprint_sha256": None,
    }
