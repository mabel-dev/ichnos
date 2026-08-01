"""Fingerprinting (design doc §3.3).

`fingerprint_id = sha256(canonicalised, protocol-relevant fields)`. The canonicalisation
here is generic - deterministic JSON serialisation with sorted keys - and deliberately
knows nothing about HTTP or TLS specifically. Deciding *which* fields are
protocol-relevant (and excluding volatile ones like timestamps/TTLs) is normalize.py's
job; by the time a payload reaches this module it should already contain only fields
that are supposed to affect the hash.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any
from typing import Dict


def canonicalize(payload: Dict[str, Any]) -> str:
    """Deterministic JSON: sorted keys, no whitespace padding, so semantically
    identical payloads always produce byte-identical output regardless of dict
    insertion order."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint_id(payload: Dict[str, Any]) -> str:
    canonical = canonicalize(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
