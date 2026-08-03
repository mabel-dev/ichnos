import re

from fastapi.testclient import TestClient

from ichnos.models import ScheduleEntry
from ichnos.storage.memory import InMemoryStore
from ichnos.webapp import SiteConfig
from ichnos.webapp import create_app


def _client(*, trust_proxy_headers=False, scan_source_ips=("203.0.113.7",)):
    store = InMemoryStore()
    store.schedule.put(ScheduleEntry(protocol="http", port=80, zgrab2_module="http"))
    app = create_app(
        store,
        SiteConfig(
            form_secret="test-secret",
            contact_email="abuse@example.invalid",
            trust_proxy_headers=trust_proxy_headers,
            scan_source_ips=list(scan_source_ips),
            scan_hostname="scan.example.invalid",
            scan_user_agent="ichnos/1.0 (+https://example.invalid/responsible-scanning)",
        ),
    )
    return TestClient(app), store


def _scrape_challenge(html_text):
    a = int(re.search(r'name="a" value="(\d+)"', html_text).group(1))
    b = int(re.search(r'name="b" value="(\d+)"', html_text).group(1))
    token = re.search(r'name="token" value="([0-9a-f]+)"', html_text).group(1)
    return a, b, token


def test_info_page_lists_enabled_schedule_and_contact():
    client, _ = _client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert "http" in resp.text
    assert "abuse@example.invalid" in resp.text


def test_info_page_nav_links_to_responsible_scanning_and_opt_out():
    client, _ = _client()
    resp = client.get("/")
    assert 'href="/responsible-scanning"' in resp.text
    assert 'href="/opt-out"' in resp.text


def test_responsible_scanning_page_lists_schedule_contact_and_opt_out():
    client, _ = _client()
    resp = client.get("/responsible-scanning")
    assert resp.status_code == 200
    assert "http" in resp.text
    assert "abuse@example.invalid" in resp.text
    assert 'href="/opt-out"' in resp.text


def test_security_txt_has_required_rfc9116_fields():
    client, _ = _client()
    for path in ("/.well-known/security.txt", "/security.txt"):
        resp = client.get(path)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert "Contact: mailto:abuse@example.invalid" in resp.text
        assert "Expires:" in resp.text


def test_scanner_txt_has_contact_and_opt_out():
    client, _ = _client()
    resp = client.get("/scanner.txt")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "Contact: abuse@example.invalid" in resp.text
    assert "/opt-out" in resp.text
    assert "/responsible-scanning" in resp.text


def test_scanner_txt_publishes_the_scanner_identity():
    # AWS's network-scanning guidelines ("identifiable") ask scanners to publish their
    # sources so a target can verify a probe's authenticity. scanner.txt is the
    # machine-readable half - what an automated abuse-triage pipeline would parse.
    client, _ = _client()
    resp = client.get("/scanner.txt")
    assert "Source-IP: 203.0.113.7" in resp.text
    assert "Source-Hostname: scan.example.invalid" in resp.text
    assert "User-Agent: ichnos/1.0 (+https://example.invalid/responsible-scanning)" in resp.text


def test_scanner_txt_omits_source_ip_when_not_configured():
    # The address comes from the deployment's Elastic IP, so it's genuinely absent in
    # dev/test. Better to publish no Source-IP line at all than an empty one that reads
    # as "we scan from nowhere" to whoever's parsing it.
    client, _ = _client(scan_source_ips=())
    resp = client.get("/scanner.txt")
    assert "Source-IP:" not in resp.text
    assert "Source-Hostname: scan.example.invalid" in resp.text


def test_responsible_scanning_page_publishes_the_scanner_identity():
    # The human-readable half, for the operator who found the address in a firewall log
    # and wants to confirm what it is before deciding whether to report it as abuse.
    client, _ = _client()
    resp = client.get("/responsible-scanning")
    assert "203.0.113.7" in resp.text
    assert "scan.example.invalid" in resp.text
    assert "ichnos/1.0 (+https://example.invalid/responsible-scanning)" in resp.text


def test_responsible_scanning_page_reads_correctly_without_configured_ips():
    # The prose has to survive the address list being absent - it genuinely is in
    # dev/test and on any deployment that hasn't set ICHNOS_SITE_SCAN_SOURCE_IPS.
    client, _ = _client(scan_source_ips=())
    resp = client.get("/responsible-scanning")
    assert resp.status_code == 200
    assert "Those addresses" not in resp.text
    assert "Our scanning addresses reverse-resolve" in resp.text
    assert "scan.example.invalid" in resp.text


def test_responsible_scanning_page_cites_guidelines_without_claiming_endorsement():
    # The AWS article is cited because a large share of scanned hosts are AWS-hosted
    # and that article is where AWS directs customers to report abusive scanning - but
    # it disclaims endorsement in its own text, so the page must not imply AWS has
    # approved or reviewed this project.
    client, _ = _client()
    resp = client.get("/responsible-scanning")
    assert "zmap/wiki/Scanning-Best-Practices" in resp.text
    assert "aws-guidelines-for-network-scanning" in resp.text
    assert "do not imply any endorsement" in resp.text


def test_opt_out_form_renders_challenge_fields():
    client, _ = _client()
    resp = client.get("/opt-out")
    assert resp.status_code == 200
    assert 'name="token"' in resp.text


def test_opt_out_submit_records_exclusion_on_correct_answer():
    client, store = _client()
    a, b, token = _scrape_challenge(client.get("/opt-out").text)

    resp = client.post(
        "/opt-out",
        data={
            "ip_or_cidr": "203.0.113.5",
            "reason": "testing",
            "answer": str(a + b),
            "a": a,
            "b": b,
            "token": token,
        },
    )
    assert resp.status_code == 200
    assert any(e.ip_or_cidr == "203.0.113.5" for e in store.exclusions.list_all())


def test_opt_out_submit_wrong_answer_is_rejected():
    client, store = _client()
    a, b, token = _scrape_challenge(client.get("/opt-out").text)

    resp = client.post(
        "/opt-out",
        data={
            "ip_or_cidr": "203.0.113.5",
            "reason": "",
            "answer": str(a + b + 1),
            "a": a,
            "b": b,
            "token": token,
        },
    )
    assert resp.status_code == 400
    assert store.exclusions.list_all() == []


def test_opt_out_submit_tampered_token_is_rejected():
    client, store = _client()
    a, b, _token = _scrape_challenge(client.get("/opt-out").text)

    resp = client.post(
        "/opt-out",
        data={
            "ip_or_cidr": "203.0.113.5",
            "reason": "",
            "answer": str(a + b),
            "a": a,
            "b": b,
            "token": "0" * 64,
        },
    )
    assert resp.status_code == 400
    assert store.exclusions.list_all() == []


def test_opt_out_ignores_forwarded_header_when_not_trusted():
    # Default (no proxy in front, e.g. local dev/tests): trust the raw connection,
    # never a client-suppliable header.
    client, _ = _client(trust_proxy_headers=False)
    resp = client.get("/opt-out", headers={"X-Forwarded-For": "203.0.113.9"})
    assert "203.0.113.9" not in resp.text


def test_opt_out_uses_forwarded_header_when_trusted():
    # Real deployment: nginx sits in front on loopback and overwrites this header
    # with what it observed, so it's safe to trust here (see webapp/app.py docstring).
    client, _ = _client(trust_proxy_headers=True)
    resp = client.get("/opt-out", headers={"X-Forwarded-For": "203.0.113.9"})
    assert "203.0.113.9" in resp.text


def test_opt_out_submit_invalid_ip_is_rejected():
    client, store = _client()
    a, b, token = _scrape_challenge(client.get("/opt-out").text)

    resp = client.post(
        "/opt-out",
        data={
            "ip_or_cidr": "not-an-ip",
            "reason": "",
            "answer": str(a + b),
            "a": a,
            "b": b,
            "token": token,
        },
    )
    assert resp.status_code == 400
    assert store.exclusions.list_all() == []
