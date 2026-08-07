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
#
# `unknown` is excluded for a different reason: it's ZGrab2's catch-all bucket for
# headers it couldn't map to a named field - arbitrary and unbounded, exactly where a
# CDN or server's own per-request tracing header (a cf_ray-style ID, for example, but
# there's no fixed list of these across every vendor's convention) would land. There's
# no reliable way to allowlist "stable custom header" vs "volatile per-request ID"
# inside that bucket by name, so the safe default is excluding the whole thing rather
# than risk the same class of bug recurring through a header this project doesn't
# recognize.
_VOLATILE_HEADER_KEYS = {"date", "expires", "age", "unknown"}


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

    No `favicon_hash`: the plain `http` module doesn't fetch /favicon.ico, so this was
    emitted as a hardcoded `None` on every row since the first scan - a column that is
    null for 100% of published rows describes nothing, and one that's *always* null
    also can't be told apart from one that's merely null so far. Reinstate it together
    with the follow-up request that would actually populate it (a second fetch per
    host, i.e. roughly double the request volume - a scan-rate decision, not a
    normalizer one), not before.

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

    Separately, `date`/`expires`/`age`/`unknown` are dropped from `headers` entirely
    (see `_VOLATILE_HEADER_KEYS`) - a different bug from the two above, at the
    fingerprint layer rather than the storage layer: these can change on every single
    request, so an unchanged host produced a different fingerprint - and therefore a
    spurious "new version" row - on every scan. `date`/`expires`/`age` confirmed
    directly against production data; `unknown` (ZGrab2's catch-all for headers it
    couldn't map to a named field) excluded pre-emptively for the same reason, since
    it's exactly where an unrecognized per-request tracing header would land.
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
        "redirect_location": _first_or_none(redirect_location),
    }


def normalize_tls(tls_result: Dict[str, Any]) -> Dict[str, Any]:
    """`tls_result` is the `data.tls` object from one ZGrab2 tls-module result line.

    Spec fields covered: protocol version, cipher suite, certificate metadata,
    fingerprint.

    No `jarm`: it's a separate ZGrab2 module (`zgrab2 jarm`), not part of the plain
    `tls` handshake this design uses for HTTPS, so - like `normalize_http`'s
    `favicon_hash` - it was a hardcoded `None` on every published row rather than a
    field anything ever filled in. It comes back when the jarm module is actually wired
    into the scanner.

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


_DIGIT_RUN_RE = re.compile(r"\d{2,}")
_REPLY_CODE_PREFIX_RE = re.compile(r"^\d{3}[-\s]?")
_OPAQUE_TOKEN_RE = re.compile(r"\b(?=[A-Za-z0-9]{8,}\b)(?=[A-Za-z0-9]*\d)[A-Za-z0-9]+\b")


def _mask_volatile(text: str) -> str:
    """Two masks, in order, over one line of banner text.

    `_OPAQUE_TOKEN_RE` goes first and catches per-session identifiers - eight or more
    alphanumerics with at least one digit somewhere in them, which is the shape of
    `d9443c01a7336` in a real Gmail greeting and is not the shape of any software name.
    It has to run before the digit mask, because the digit mask would otherwise chew a
    session ID into fragments (`d#c#a#-#d8f9a4dsi`) that are still volatile but no
    longer look like one token.

    `_DIGIT_RUN_RE` then takes the rest: clocks, years, counters, port numbers, sizes.
    Software versions survive because they are conventionally single digits per
    component - `vsftpd 3.0.3`, `Exim 4.94`, `Pure-FTPd` all pass through untouched."""
    return _DIGIT_RUN_RE.sub("#", _OPAQUE_TOKEN_RE.sub("#", text))


def _stable_banner(raw: Optional[str]) -> Optional[str]:
    """A banner reduced to the part that describes the *service* rather than the
    *connection*, so it can be fingerprinted without churning on every scan.

    Banner protocols put live state in their greeting, which the header-based protocols
    mostly do not. Confirmed against real grabs from this scanner:

        ftp     220-You are user number 14 of 1000 allowed.
                220-Local time is now 22:24. Server port: 21.
        telnet  It is 12:25 pm on Friday, August 7, 2026 in Mountain View, California.
                There are 131 local users. There are 26649 hosts on the network.
        smtp    220 mx.google.com ESMTP d9443c01a7336-2913d8f9a4dsi ... - gsmtp

    Fingerprinted verbatim, every one of those produces a different fingerprint on every
    single scan of a completely unchanged host - and therefore a new `versions` row every
    time. That is not a hypothetical failure mode for this project: it is exactly what
    the `date` HTTP header did before `_VOLATILE_HEADER_KEYS` existed, one real host
    generating dozens of spurious versions in a few hours.

    Two reductions, in order:

    1. The first non-empty line only. Multi-line greetings put identity on the opening
       line and chat on the continuations - the counters and clocks above are all on
       continuation lines.
    2. The leading reply code stripped (it is carried separately as `reply_code`), then
       session identifiers and multi-digit runs masked - see `_mask_volatile`. These are
       heuristics and deliberately blunt ones: the cost of masking a genuine multi-digit
       version is one merged fingerprint, the cost of missing a volatile field is an
       unbounded stream of junk version rows.

    The raw banner is not kept alongside it. `normalize()`'s return value is both the
    published payload and the fingerprint input - there is no separate channel for
    "record this but do not hash it" - so anything preserved here is hashed here.
    """
    if not raw:
        return None
    first = next((line for line in raw.splitlines() if line.strip()), "")
    first = _REPLY_CODE_PREFIX_RE.sub("", first.strip())
    if not first:
        return None
    return _mask_volatile(first)


def _reply_code(raw: Optional[str]) -> Optional[int]:
    """The leading 3-digit reply code FTP and SMTP greet with (220 ready, 421 service
    unavailable, 554 rejected). Read off the raw banner before `_stable_banner` masks it
    - it is a multi-digit run, but a fixed-vocabulary one that says something real about
    the service, unlike the session IDs the mask exists for."""
    if not raw:
        return None
    first = next((line for line in raw.splitlines() if line.strip()), "")
    head = first.strip()[:3]
    return int(head) if head.isdigit() else None


def normalize_ftp(ftp_result: Dict[str, Any]) -> Dict[str, Any]:
    """`ftp_result` is the `data.ftp` object from one ZGrab2 ftp-module result line.

    ZGrab2's ftp module returns a single `banner` and nothing else (confirmed against
    real grabs), so the whole fingerprint rests on it - which is why the volatility
    handling in `_stable_banner` matters more here than it does for SSH, whose banner is
    a fixed `SSH-2.0-<software>` string."""
    return {
        "banner": _stable_banner(_get(ftp_result, "result", "banner")),
        "reply_code": _reply_code(_get(ftp_result, "result", "banner")),
    }


def normalize_telnet(telnet_result: Dict[str, Any]) -> Dict[str, Any]:
    """`telnet_result` is the `data.telnet` object from one ZGrab2 telnet-module line.

    The most volatile of the three by a distance - telnet greetings are written for a
    human sitting at a terminal, so live clocks, session counters and MOTD text are
    normal rather than exceptional. `_stable_banner` is doing real work here and it will
    not catch everything; a telnet host whose greeting rotates a quote of the day will
    still churn. Watch the `telnet` versions row count against its observation count
    over the first few hours, and tighten the reduction if the ratio is not close to the
    ratio the other protocols show."""
    return {
        "banner": _stable_banner(_get(telnet_result, "result", "banner")),
        "will_options": json.dumps(sorted(_get(telnet_result, "result", "will") or []),
                                   sort_keys=True),
        "do_options": json.dumps(sorted(_get(telnet_result, "result", "do") or []),
                                 sort_keys=True),
    }


def normalize_smtp(smtp_result: Dict[str, Any]) -> Dict[str, Any]:
    """`smtp_result` is the `data.smtp` object from one ZGrab2 smtp-module result line.

    Real grabs return `banner` plus exactly one of `ehlo` or `helo` - the server's
    response to the greeting ZGrab2 sends, and the more useful of the two fields: the
    EHLO response is the capability list (STARTTLS, SIZE, AUTH mechanisms, PIPELINING),
    which is a genuine description of the service rather than a vendor string. It gets
    the same reduction as the banner but line-by-line rather than first-line-only, since
    here every line is a distinct capability rather than continuation chat, and it is
    sorted so a server that reorders its advertisement does not read as a change.
    """
    banner = _get(smtp_result, "result", "banner")
    greeting = _get(smtp_result, "result", "ehlo") or _get(smtp_result, "result", "helo")
    capabilities = sorted(
        _mask_volatile(_REPLY_CODE_PREFIX_RE.sub("", line.strip()))
        for line in (greeting or "").splitlines()
        if line.strip()
    )
    return {
        "banner": _stable_banner(banner),
        "reply_code": _reply_code(banner),
        "capabilities": json.dumps(capabilities, sort_keys=True),
        "extended": bool(_get(smtp_result, "result", "ehlo")),
    }


NORMALIZERS = {
    "http": normalize_http,
    "tls": normalize_tls,
    "ssh": normalize_ssh,
    "ftp": normalize_ftp,
    "telnet": normalize_telnet,
    "smtp": normalize_smtp,
}


def normalize(protocol: str, module_result: Dict[str, Any]) -> Dict[str, Any]:
    try:
        normalizer = NORMALIZERS[protocol]
    except KeyError:
        raise ValueError(f"no normalizer registered for protocol {protocol!r}") from None
    return normalizer(module_result)
