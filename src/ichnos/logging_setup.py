"""Timestamped, structured logging (design doc §10: "structured logs should be
produced for scan execution, protocol execution, exclusions, ... operational
failures"). In the real AWS deployment CloudWatch stamps every line with its own
ingestion time regardless, but that's not a substitute for the event's own timestamp
in the message - and for anything read outside CloudWatch (a local run, `journalctl`,
piping to a file) there's no timestamp at all without this.
"""
from __future__ import annotations

import logging
import sys
import time


def configure_logging(level: int = logging.INFO, *, stream=None) -> None:
    """Call once, at process start (`cli.py`'s `main()`). Idempotent - safe to call
    more than once (e.g. from a test) without stacking duplicate handlers."""
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s.%(msecs)03dZ %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    handler.converter = time.gmtime  # UTC, not local time
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
