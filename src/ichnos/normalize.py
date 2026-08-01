"""Extract protocol-relevant fields from raw ZGrab2 output (design doc §3.2, "Protocol
Datasets" / "Data Collection").

Each `normalize_*` function takes the `data.<module>` sub-object from one line of
ZGrab2's JSON output and returns a flat dict containing *only* the fields that should
affect the fingerprint - deliberately excluding anything timestamp-like or otherwise
non-semantic (request duration, connection timestamps, TTLs). That's what lets
fingerprint.py hash the result directly: if two scans of the same host produce the same
normalized dict, they produce the same fingerprint, regardless of when they ran.

All lookups are defensive (`.get()` chains, never raises on a missing key) because
ZGrab2 output shape varies with success/failure/partial-handshake outcomes - a scan
that failed halfway through still needs to normalize to *something* rather than crash
the pipeline.
"""
from __future__ import annotations

import re
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _get(d: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def _extract_title(body: Optional[str]) -> Optional[str]:
    """Best-effort <title> extraction via regex, not a full HTML parser - fine for a
    metadata field, not meant to be a robust HTML processor."""
    if not body:
        return None
    match = _TITLE_RE.search(body.encode("utf-8", errors="ignore"))
    if not match:
        return None
    return match.group(1).decode("utf-8", errors="ignore").strip() or None


def normalize_http(http_result: Dict[str, Any]) -> Dict[str, Any]:
    """`http_result` is the `data.http` object from one ZGrab2 http-module result line.

    Spec fields covered: status code, headers, server, title, redirect location.
    `favicon_hash` is intentionally left `None` - the plain `http` module doesn't fetch
    /favicon.ico, that needs a dedicated follow-up request wired into the scanner. Not
    faked here.
    """
    response = _get(http_result, "result", "response")
    headers = _get(response, "headers") or {}
    # ZGrab2 header values are lists (repeated headers); normalize casing and keep as-is.
    normalized_headers = {k.lower(): v for k, v in sorted(headers.items())}

    redirect_chain = _get(http_result, "result", "redirect_response_chain") or []
    redirect_location = None
    if redirect_chain:
        redirect_location = _get(redirect_chain[-1], "headers", "location")
    elif normalized_headers.get("location"):
        redirect_location = normalized_headers["location"]

    return {
        "status_code": _get(response, "status_code"),
        "headers": normalized_headers,
        "server": normalized_headers.get("server"),
        "title": _extract_title(_get(response, "body")),
        "favicon_hash": None,
        "redirect_location": redirect_location,
    }


def normalize_tls(tls_result: Dict[str, Any]) -> Dict[str, Any]:
    """`tls_result` is the `data.tls` object from one ZGrab2 tls-module result line.

    Spec fields covered: protocol version, cipher suite, certificate metadata,
    fingerprint. `jarm` is out of MVP scope - that's a separate ZGrab2 module
    (`zgrab2 jarm`), not part of the plain `tls` handshake this design uses for HTTPS.
    """
    handshake = _get(tls_result, "result", "handshake_log")
    server_hello = _get(handshake, "server_hello") or {}
    cert = _get(handshake, "server_certificates", "certificate", "parsed") or {}
    subject = _get(cert, "subject", "common_name")
    issuer = _get(cert, "issuer", "common_name")

    return {
        "version": _get(server_hello, "version", "name"),
        "cipher_suite": _get(server_hello, "cipher_suite", "name"),
        "certificate": {
            "subject_cn": subject[0] if isinstance(subject, list) and subject else subject,
            "issuer_cn": issuer[0] if isinstance(issuer, list) and issuer else issuer,
            "serial_number": _get(cert, "serial_number"),
            "signature_algorithm": _get(cert, "signature_algorithm", "name"),
            "fingerprint_sha256": _get(
                handshake, "server_certificates", "certificate", "parsed", "fingerprint_sha256"
            ),
        },
        "jarm": None,
    }


NORMALIZERS = {
    "http": normalize_http,
    "tls": normalize_tls,
}


def normalize(protocol: str, module_result: Dict[str, Any]) -> Dict[str, Any]:
    try:
        normalizer = NORMALIZERS[protocol]
    except KeyError:
        raise ValueError(f"no normalizer registered for protocol {protocol!r}") from None
    return normalizer(module_result)
