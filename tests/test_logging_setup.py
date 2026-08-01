import io
import logging

from ichnos.logging_setup import configure_logging
from ichnos.logging_setup import get_logger


def test_configure_logging_stamps_timestamp_and_level():
    buffer = io.StringIO()
    configure_logging(stream=buffer)
    logger = get_logger("ichnos.test")
    logger.info("hello %s", "world")

    output = buffer.getvalue()
    assert "hello world" in output
    assert "INFO" in output
    assert "ichnos.test" in output
    # ISO-ish date prefix, e.g. "2026-08-01T13:40:23.123Z"
    assert output[:4].isdigit()
    assert "T" in output.split(" ")[0]
    assert output.split(" ")[0].endswith("Z")


def test_configure_logging_is_idempotent_no_duplicate_handlers():
    buffer = io.StringIO()
    configure_logging(stream=buffer)
    configure_logging(stream=buffer)
    logger = get_logger("ichnos.test2")
    logger.info("once")
    assert buffer.getvalue().count("once") == 1


def test_configure_logging_respects_level():
    buffer = io.StringIO()
    configure_logging(level=logging.WARNING, stream=buffer)
    logger = get_logger("ichnos.test3")
    logger.info("should not appear")
    logger.warning("should appear")
    output = buffer.getvalue()
    assert "should not appear" not in output
    assert "should appear" in output
