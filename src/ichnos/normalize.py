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

import json
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


def _first_or_none(value: Any) -> Optional[str]:
    """ZGrab2 header values are lists (repeated headers), but not every source of a
    given field goes through that representation - coerce to a single stable scalar
    (or None) so the field's type never varies row-to-row."""
    if isinstance(value, list):
        return value[0] if value else None
    return value



# Header keys that are inherently volatile - they vary on every request (or close to
# it) rather than describing a stable property of the service, so they must never
# contribute to the fingerprint. Real, previously-undetected production bug: `date`
# (and `expires`, usually computed relative to it, and `age`) riding along inside
# `headers` meant an unchanged host produced a *different* fingerprint on every single
# scan - confirmed directly against production data, one real host generating dozens
# of spurious "new version" rows over a few hours, all for a target that never
# actually changed. `observed_at` on every Observation row already captures per-scan
# timing, so nothing informative is lost by excluding these.
_VOLATILE_HEADER_KEYS = {"date", "expires", "age"}


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

    `headers` is serialized to a JSON string rather than returned as a native dict.
    Real, previously-undetected production bug: unlike `normalize_tls`'s `certificate`
    (a fixed, hand-picked set of keys, always the same shape), raw HTTP headers vary
    arbitrarily by target - confirmed against real published data, 13 distinct header
    key-sets across just 107 real rows (some targets send `etag`/`vary`/`location`,
    most don't, etc). Publishing that as a native nested column makes each Parquet
    file's schema for it depend on whichever header combinations happened to appear in
    that batch, and Opteryx's table schema is pinned by the *first* commit - every
    later batch with a header combination that first batch didn't happen to see gets
    rejected outright ("table structure doesn't match"), which is exactly what
    silently blocked every hourly publish of the `http` dataset for 10 straight hours
    in production. A JSON string is a single stable column type regardless of what's
    inside it - the `server` header is still promoted to its own top-level field for
    the common case, so this only costs a JSON-parse for callers who need a specific
    other header.

    `redirect_location` has the same class of bug for a different reason: it can come
    from a redirect chain entry's headers (a scalar there) or from a direct `Location`
    response header (a list, like all header values) - three possible types (None,
    str, list) for one field depending on which path populated it. Confirmed against
    real published data: 3 of 22 real pending rows had it as a list, the rest None -
    that blocked publishing the same way `headers` did. Coerced to a single
    `Optional[str]` via `_first_or_none`. `server` gets the same treatment
    pre-emptively - same header-list-derived field, same latent risk, not yet observed
    broken but no reason to wait for it to be.

    Separately, `date`/`expires`/`age` are dropped from `headers` entirely (see
    `_VOLATILE_HEADER_KEYS`) - a different bug from the two above, at the fingerprint
    layer rather than the storage layer: these change on every single request, so an
    unchanged host produced a different fingerprint - and therefore a spurious "new
    version" row - on every scan. Confirmed directly against production data.
    """
    response = _get(http_result, "result", "response")
    headers = _get(response, "headers") or {}
    # ZGrab2 header values are lists (repeated headers); normalize casing and drop
    # anything known-volatile before it can reach the fingerprinted payload.
    normalized_headers = {
        k.lower(): v
        for k, v in sorted(headers.items())
        if k.lower() not in _VOLATILE_HEADER_KEYS
    }

    redirect_chain = _get(http_result, "result", "redirect_response_chain") or []
    redirect_location = None
    if redirect_chain:
        redirect_location = _get(redirect_chain[-1], "headers", "location")
    elif normalized_headers.get("location"):
        redirect_location = normalized_headers["location"]

    return {
        "status_code": _get(response, "status_code"),
        "headers": json.dumps(normalized_headers, sort_keys=True),
        "server": _first_or_none(normalized_headers.get("server")),
        "title": _extract_title(_get(response, "body")),
        "favicon_hash": None,
        "redirect_location": _first_or_none(redirect_location),
    }


def normalize_tls(tls_result: Dict[str, Any]) -> Dict[str, Any]:
    """`tls_result` is the `data.tls` object from one ZGrab2 tls-module result line.

    Spec fields covered: protocol version, cipher suite, certificate metadata,
    fingerprint. `jarm` is out of MVP scope - that's a separate ZGrab2 module
    (`zgrab2 jarm`), not part of the plain `tls` handshake this design uses for HTTPS.

    `certificate` is serialized to a JSON string rather than returned as a native
    dict, matching `normalize_http`'s `headers` fix and for the same reason: Opteryx's
    published-dataset columns need a single stable type regardless of a batch's
    values, and a native nested dict isn't one (see publish.py's explicit per-dataset
    Parquet schemas). This field's key set happens to always be the same 5 keys today,
    so it hasn't actually broken publishing the way `headers` did - but there's no
    reason to leave it exposed to the same bug once a new cert field gets added later.
    """
    handshake = _get(tls_result, "result", "handshake_log")
    server_hello = _get(handshake, "server_hello") or {}
    cert = _get(handshake, "server_certificates", "certificate", "parsed") or {}
    subject = _get(cert, "subject", "common_name")
    issuer = _get(cert, "issuer", "common_name")

    certificate = {
        "subject_cn": subject[0] if isinstance(subject, list) and subject else subject,
        "issuer_cn": issuer[0] if isinstance(issuer, list) and issuer else issuer,
        "serial_number": _get(cert, "serial_number"),
        "signature_algorithm": _get(cert, "signature_algorithm", "name"),
        "fingerprint_sha256": _get(
            handshake, "server_certificates", "certificate", "parsed", "fingerprint_sha256"
        ),
    }

    return {
        "version": _get(server_hello, "version", "name"),
        "cipher_suite": _get(server_hello, "cipher_suite", "name"),
        "certificate": json.dumps(certificate, sort_keys=True),
        "jarm": None,
    }


def normalize_ssh(ssh_result: Dict[str, Any]) -> Dict[str, Any]:
    """`ssh_result` is the `data.ssh` object from one ZGrab2 ssh-module result line.

    Spec fields covered: banner, software identification, host key algorithm and
    fingerprint. Deliberately excludes ZGrab2's `server_key_exchange` (the server's
    offered-algorithm lists - kex/cipher/mac/compression) and most of `key_exchange`
    (the actual per-connection cryptographic exchange - cookie, ephemeral public
    values, the signature over this specific handshake): confirmed against real
    banners that offered-algorithm lists are just negotiation capability, already
    summarized by `software`, and the exchange material is randomized fresh on every
    single connection by design - including it would make the fingerprint change on
    every scan of a completely unchanged host, defeating the reason fingerprinting
    exists. `host_key_fingerprint_sha256` is the actual stable per-host identity
    signal here, analogous to normalize_tls's certificate fingerprint. Every field is
    already a plain scalar (or None) - no JSON-string treatment needed, unlike
    `headers`/`certificate`.
    """
    result = _get(ssh_result, "result") or {}
    server_id = _get(result, "server_id") or {}
    host_key = _get(result, "key_exchange", "server_host_key") or {}

    return {
        "banner": _get(server_id, "raw"),
        "version": _get(server_id, "version"),
        "software": _get(server_id, "software"),
        "comment": _get(server_id, "comment"),
        "host_key_algorithm": _get(host_key, "algorithm"),
        "host_key_fingerprint_sha256": _get(host_key, "fingerprint_sha256"),
    }


NORMALIZERS = {
    "http": normalize_http,
    "tls": normalize_tls,
    "ssh": normalize_ssh,
}


def normalize(protocol: str, module_result: Dict[str, Any]) -> Dict[str, Any]:
    try:
        normalizer = NORMALIZERS[protocol]
    except KeyError:
        raise ValueError(f"no normalizer registered for protocol {protocol!r}") from None
    return normalizer(module_result)
