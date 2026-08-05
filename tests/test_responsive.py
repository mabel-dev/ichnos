from datetime import datetime
from datetime import timezone

import pytest

from ichnos.odata import ODataError
from ichnos.odata import distinct_values
from ichnos.odata import fetch_access_token
from ichnos.responsive import fetch_responsive_hosts
from ichnos.responsive import read_responsive_file
from ichnos.responsive import read_responsive_hosts
from ichnos.responsive import refresh_protocol
from ichnos.responsive import window_start
from ichnos.responsive import write_responsive_file


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("not json")
        return self._payload


def _fake_get(pages, calls=None):
    """Serve a list of payloads in order, recording the URLs requested."""
    remaining = list(pages)

    def get(url, headers=None, timeout=None):
        if calls is not None:
            calls.append(url)
        return FakeResponse(remaining.pop(0))

    return get


def test_distinct_values_composes_the_filter_inside_apply():
    # $filter and $apply are not siblings - passing both as separate query options is a
    # 400 ("Unknown column"), because $filter is evaluated against the aggregated
    # projection where the filtered column no longer exists. Confirmed against the live
    # service; this pins the composed form that actually works.
    calls = []
    distinct_values(
        "ws/coll/observations", "ip", where="protocol eq 'http'",
        get=_fake_get([{"value": []}], calls),
    )
    assert "%24apply" not in calls[0]  # we build it, we don't re-encode it
    assert "$apply=filter(protocol%20eq%20%27http%27)/groupby((ip))" in calls[0]
    assert "$top=25000" in calls[0]


def test_iter_rows_follows_nextlink_without_re_encoding_it():
    # The service hands back a *relative* link with its $ already percent-encoded as
    # %24. Re-encoding it (or handing it to requests as params) corrupts it.
    calls = []
    pages = [
        {"value": [{"ip": "1.1.1.1"}], "@odata.nextLink": "/api/v4/ws/coll/observations?%24skip=1"},
        {"value": [{"ip": "2.2.2.2"}]},
    ]
    ips = distinct_values("ws/coll/observations", "ip", get=_fake_get(pages, calls))
    assert ips == ["1.1.1.1", "2.2.2.2"]
    assert calls[1] == "https://odata.opteryx.app/api/v4/ws/coll/observations?%24skip=1"


def test_a_failed_page_raises_rather_than_returning_a_partial_result():
    # A caller cannot otherwise tell "that was the last page" from "page four 500'd",
    # and this list is used to decide what NOT to scan.
    pages = [
        {"value": [{"ip": "1.1.1.1"}], "@odata.nextLink": "/api/v4/x?%24skip=1"},
    ]

    def get(url, headers=None, timeout=None):
        if "skip" in url:
            return FakeResponse({"error": {"message": "boom"}}, status_code=500)
        return FakeResponse(pages[0])

    with pytest.raises(ODataError) as exc:
        distinct_values("ws/coll/observations", "ip", get=get)
    assert "500" in str(exc.value)


def test_token_exchange_rejects_a_response_without_an_access_token():
    def post(url, data=None, timeout=None):
        return FakeResponse({"token_type": "Bearer"})

    with pytest.raises(ODataError):
        fetch_access_token("id", "secret", post=post)


def test_window_start_is_an_unquoted_iso_literal():
    # Quoting makes it a VARCHAR literal, and comparing that to a TIMESTAMP column is a
    # 400 rather than a silent empty result.
    boundary = window_start(datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc), 15)
    assert boundary == "2026-07-20T12:00:00Z"
    assert "'" not in boundary


def test_fetch_responsive_ips_asks_only_for_successful_grabs():
    # Observations are also written for "closed" (an RST - host up, port refused) and
    # "grab-failed". Neither is a host refresh can re-grab, and a closed port is exactly
    # what discovery should keep sampling, so neither belongs in this list.
    calls = []
    fetch_responsive_hosts(
        "https", workspace="ichnos", collection="landing", token="t",
        now=datetime(2026, 8, 4, tzinfo=timezone.utc),
        get=_fake_get([{"value": []}], calls),
    )
    url = calls[0]
    assert "response_status%20eq%20%27success%27" in url
    assert "aggregate(observed_at%20with%20max%20as%20last_seen)" in url
    assert "protocol%20eq%20%27https%27" in url
    assert "observed_at%20ge%202026-07-20T00%3A00%3A00Z" in url
    assert url.startswith("https://odata.opteryx.app/api/v4/ichnos/landing/observations?")


def test_refresh_keeps_the_previous_list_when_the_read_fails(tmp_path):
    # The critical property: a transient outage must not wipe the exclusion list. An
    # empty list is not a mild version of a stale one - it means discovery spends the
    # next day re-finding every host it already knew.
    path = str(tmp_path / "known-responsive-http.conf")
    write_responsive_file(path, [("203.0.113.1", "2026-07-30"), ("203.0.113.2", "2026-08-01")])

    def failing_get(url, headers=None, timeout=None):
        return FakeResponse({"error": {"message": "upstream down"}}, status_code=503)

    ok = refresh_protocol(
        "http", path, workspace="ichnos", collection="landing", token="t", get=failing_get
    )
    assert ok is False
    assert read_responsive_file(path) == ["203.0.113.1", "203.0.113.2"]


def test_a_genuinely_empty_result_is_allowed_to_write_an_empty_list(tmp_path):
    # The other half of the contract. The feed guarantees a failed read is never a 200
    # with an empty `value`, so an empty result is real data and must be written -
    # otherwise a list could never shrink to nothing.
    path = str(tmp_path / "known-responsive-ssh.conf")
    write_responsive_file(path, [("203.0.113.9", "2026-08-01")])

    ok = refresh_protocol(
        "ssh", path, workspace="ichnos", collection="landing", token="t",
        get=_fake_get([{"value": []}]),
    )
    assert ok is True
    assert read_responsive_file(path) == []


def test_missing_file_reads_as_empty_not_an_error(tmp_path):
    # A freshly-built instance has no copy yet, and that must not stop it scanning -
    # the list is an efficiency mechanism, not a safety one.
    assert read_responsive_file(str(tmp_path / "nope.conf")) == []


def test_write_is_atomic_leaving_no_partial_file(tmp_path):
    # Same hazard write_blocklist_file guards: this is read at the start of every scan,
    # and a reader catching a half-written file would silently under-exclude.
    path = str(tmp_path / "known-responsive-http.conf")
    write_responsive_file(path, [("198.51.100.1", "2026-08-01")] * 3)
    assert not (tmp_path / "known-responsive-http.conf.tmp").exists()
    assert len(read_responsive_file(path)) == 3


def test_responsive_file_roundtrips_pairs_and_tolerates_address_only_lines(tmp_path):
    """The file carries `<ip> <last_seen>` because refresh orders by last-checked and
    that ordering replaced the CurrentState column that used to hold it. An older
    address-only file still has to parse - a rebuilt instance can find one on disk -
    and those lines sort first, which reads as "we do not know when this was last
    checked, so check it soonest"."""
    path = str(tmp_path / "known-responsive-http.conf")
    write_responsive_file(path, [("203.0.113.1", "2026-07-30T00:00:00Z"),
                                 ("203.0.113.2", "2026-08-01T00:00:00Z")])

    assert read_responsive_hosts(path) == [
        ("203.0.113.1", "2026-07-30T00:00:00Z"),
        ("203.0.113.2", "2026-08-01T00:00:00Z"),
    ]
    assert read_responsive_file(path) == ["203.0.113.1", "203.0.113.2"]

    with open(path, "w") as f:
        f.write("203.0.113.9\n203.0.113.8 2026-08-02T00:00:00Z\n")
    hosts = read_responsive_hosts(path)
    assert hosts == [("203.0.113.9", ""), ("203.0.113.8", "2026-08-02T00:00:00Z")]
    assert sorted(hosts, key=lambda h: h[1])[0][0] == "203.0.113.9"  # unknown -> first


def test_fetch_returns_hosts_oldest_seen_first(tmp_path):
    """refresh streams the file and stops when its budget runs out, so the ordering has
    to be applied here rather than there - the feed will not $orderby an aggregate
    alias, so it is sorted client-side after the groupby."""
    pages = [{"value": [
        {"ip": "203.0.113.3", "last_seen": "2026-08-04T00:00:00Z"},
        {"ip": "203.0.113.1", "last_seen": "2026-07-30T00:00:00Z"},
        {"ip": "203.0.113.2", "last_seen": "2026-08-02T00:00:00Z"},
    ]}]
    hosts = fetch_responsive_hosts(
        "http", workspace="ichnos", collection="landing", token="t",
        now=datetime(2026, 8, 5, tzinfo=timezone.utc), get=_fake_get(pages),
    )
    assert [ip for ip, _ in hosts] == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
