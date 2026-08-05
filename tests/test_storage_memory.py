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


def test_version_index_claim_succeeds_exactly_once_per_fingerprint():
    store = InMemoryStore()
    assert store.version_index.claim("abc") is True
    assert store.version_index.claim("abc") is False
    assert store.version_index.claim("def") is True

