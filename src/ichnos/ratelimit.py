"""Rate limiting for the scan pipeline (design doc §4).

MVP constraint: no more than one outbound request per 5 seconds, enforced as a single
*global* budget shared across every enabled protocol (design doc's stated assumption,
flagged there for confirmation) rather than a separate budget per protocol. This is a
plain token bucket, not ZMap's own `--rate` flag - at sub-1-pps rates ZMap's internal
limiter isn't the right tool, so the orchestration script (scanner.py) paces target
selection and the ZGrab2 call directly.
"""
from __future__ import annotations

import threading
import time


class TokenBucket:
    """A minimal token bucket: one token every `interval_seconds`, capacity `burst`.

    `wait()` blocks the caller until a token is available and consumes it - this is
    what gives the scanner its "one request, then wait" pacing.
    """

    def __init__(self, interval_seconds: float, *, burst: int = 1, clock=time.monotonic):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if burst < 1:
            raise ValueError("burst must be at least 1")
        self._interval = interval_seconds
        self._capacity = burst
        self._clock = clock
        self._lock = threading.Lock()
        self._tokens = float(burst)
        self._last_refill = clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last_refill
        if elapsed <= 0:
            return
        self._tokens = min(self._capacity, self._tokens + elapsed / self._interval)
        self._last_refill = now

    def try_acquire(self) -> bool:
        """Non-blocking: consume a token if one is available right now."""
        with self._lock:
            self._refill()
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False

    def seconds_until_next_token(self) -> float:
        with self._lock:
            self._refill()
            if self._tokens >= 1:
                return 0.0
            return (1 - self._tokens) * self._interval

    def wait(self, *, sleep=time.sleep) -> None:
        """Block until a token is available, then consume it."""
        while True:
            if self.try_acquire():
                return
            sleep(self.seconds_until_next_token())


def global_request_budget(min_interval_seconds: float = 5.0) -> TokenBucket:
    """The service-wide throttle: no more than one request per `min_interval_seconds`.

    `burst=1` deliberately - this isn't meant to allow catch-up bursts after idle
    periods, just a steady trickle, per the "minimum scan rate needed" guidance in the
    design doc's ZMap best-practices grounding.
    """
    return TokenBucket(min_interval_seconds, burst=1)
