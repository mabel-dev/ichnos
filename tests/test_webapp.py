import re

from fastapi.testclient import TestClient

from ichnos.models import ScheduleEntry
from ichnos.storage.memory import InMemoryStore
from ichnos.webapp import SiteConfig
from ichnos.webapp import create_app


def _client(*, trust_proxy_headers=False):
    store = InMemoryStore()
    store.schedule.put(ScheduleEntry(protocol="http", port=80, zgrab2_module="http"))
    app = create_app(
        store,
        SiteConfig(
            form_secret="test-secret",
            contact_email="abuse@example.invalid",
            trust_proxy_headers=trust_proxy_headers,
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
