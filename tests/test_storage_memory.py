from ichnos.models import CurrentStateRecord
from ichnos.models import Exclusion
from ichnos.models import ExclusionSource
from ichnos.models import ScheduleEntry
from ichnos.storage.memory import InMemoryStore


def test_exclusions_add_and_list():
    store = InMemoryStore()
    store.exclusions.add(Exclusion(ip_or_cidr="203.0.113.1", source=ExclusionSource.SELF_SERVE))
    store.exclusions.add(Exclusion(ip_or_cidr="203.0.113.2", source=ExclusionSource.JURISDICTION))
    assert {e.ip_or_cidr for e in store.exclusions.list_all()} == {"203.0.113.1", "203.0.113.2"}


def test_exclusions_add_is_upsert():
    store = InMemoryStore()
    store.exclusions.add(Exclusion(ip_or_cidr="203.0.113.1", source=ExclusionSource.SELF_SERVE, reason="a"))
    store.exclusions.add(Exclusion(ip_or_cidr="203.0.113.1", source=ExclusionSource.SELF_SERVE, reason="b"))
    rows = store.exclusions.list_all()
    assert len(rows) == 1
    assert rows[0].reason == "b"


def test_schedule_get_and_list_enabled():
    store = InMemoryStore()
    store.schedule.put(ScheduleEntry(protocol="http", port=80, zgrab2_module="http", enabled=True))
    store.schedule.put(ScheduleEntry(protocol="mysql", port=3306, zgrab2_module="mysql", enabled=False))
    assert store.schedule.get("http").port == 80
    assert [e.protocol for e in store.schedule.list_enabled()] == ["http"]
    assert store.schedule.get("nonexistent") is None


def test_current_state_roundtrip_and_count():
    store = InMemoryStore()
    assert store.current_state.get("http", "1.2.3.4", 80) is None
    record = CurrentStateRecord(
        protocol="http", ip="1.2.3.4", port=80, fingerprint_id="abc", last_seen_date="2026-08-01"
    )
    store.current_state.put(record)
    fetched = store.current_state.get("http", "1.2.3.4", 80)
    assert fetched.fingerprint_id == "abc"
    assert store.current_state.count() == 1


def test_current_state_list_all_filters_by_protocol():
    store = InMemoryStore()
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="1.2.3.4", port=80, fingerprint_id="a", last_seen_date="2026-08-01"
        )
    )
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="5.6.7.8", port=80, fingerprint_id="b", last_seen_date="2026-08-01"
        )
    )
    store.current_state.put(
        CurrentStateRecord(
            protocol="https", ip="9.9.9.9", port=443, fingerprint_id="c", last_seen_date="2026-08-01"
        )
    )
    http_hosts = store.current_state.list_all("http")
    assert {r.ip for r in http_hosts} == {"1.2.3.4", "5.6.7.8"}
    assert store.current_state.list_all("https")[0].ip == "9.9.9.9"


def test_version_index_claim_succeeds_exactly_once_per_fingerprint():
    store = InMemoryStore()
    assert store.version_index.claim("abc") is True
    assert store.version_index.claim("abc") is False
    assert store.version_index.claim("def") is True


def test_version_index_is_independent_of_current_state():
    # The two stores answer different questions and must not share state - a host
    # recorded in CurrentState says nothing about whether that fingerprint's version row
    # has been published, and conflating the two is what produced duplicate rows.
    store = InMemoryStore()
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="1.2.3.4", port=80, fingerprint_id="abc",
            last_seen_date="2026-08-01",
        )
    )
    assert store.version_index.claim("abc") is True
    assert store.current_state.list_all("mysql") == []
