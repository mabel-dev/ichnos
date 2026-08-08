"""The public pages have to describe what the scanner actually does.

This is a compliance surface, not documentation. Someone who sees a probe and looks us
up arrives at /responsible-scanning or /scanner.txt, and AWS's network-scanning
guidelines - which this project cites and claims to follow - turn on being observable
and identifiable. A page listing three protocols while six are being scanned fails that
on its own terms.

The port table is generated from the ScanSchedule so it cannot drift, but the prose
around it is hand-written and did drift: FTP, Telnet and SMTP ran for nine hours
against a page that said "HTTP/HTTPS/SSH".
"""
from ichnos.models import ScheduleEntry
from ichnos.storage.memory import InMemoryStore
from ichnos.webapp import SiteConfig
from ichnos.webapp import create_app

from fastapi.testclient import TestClient

ALL_PROTOCOLS = [
    ("http", 80, "http"), ("https", 443, "tls"), ("ssh", 22, "ssh"),
    ("ftp", 21, "ftp"), ("telnet", 23, "telnet"), ("smtp", 25, "smtp"),
]


def _client():
    store = InMemoryStore()
    for protocol, port, module in ALL_PROTOCOLS:
        store.schedule.put(ScheduleEntry(protocol=protocol, port=port,
                                         zgrab2_module=module, cadence="daily"))
    return TestClient(create_app(store, SiteConfig(form_secret="s")))


def test_every_scanned_port_appears_on_the_responsible_scanning_page():
    page = _client().get("/responsible-scanning").text
    for protocol, port, _ in ALL_PROTOCOLS:
        assert f"<td>{port}</td>" in page, f"port {port} ({protocol}) not disclosed"


def test_the_page_denies_the_two_things_these_ports_are_feared_for():
    """Port 25 and port 23 carry specific reputations - spam relay and IoT botnet login
    attempts - and a reader who has just seen us on one of them is looking for exactly
    that. Saying "no exploitation" in general does not answer it."""
    page = _client().get("/responsible-scanning").text.lower()
    assert "relay" in page and "mail" in page
    assert "login" in page and "credential" in page


def test_scanner_txt_does_not_claim_a_narrower_scope_than_we_scan():
    """The machine-readable half. An abuse-triage pipeline is more likely to parse this
    than the page, so it must not name a protocol subset that will read as a denial."""
    txt = _client().get("/scanner.txt").text
    purpose = next(l for l in txt.splitlines() if l.startswith("Purpose:"))
    for stale in ("HTTP/HTTPS/SSH", "HTTP/HTTPS"):
        assert stale not in purpose, f"scanner.txt still claims {stale} only"


def test_the_faq_does_not_enumerate_a_stale_protocol_list():
    page = _client().get("/").text
    assert "HTTP/HTTPS/SSH protocol-negotiation" not in page
    for name in ("FTP", "Telnet", "SMTP"):
        assert name in page, f"{name} missing from the front-page FAQ"
