"""The known-responsive file is `refresh`'s cursor, and a run has to advance it.

`refresh` reads the list, walks it from the top, and stops when its time budget runs
out. Nothing moved the hosts it had just checked, so the file sat unchanged between one
`responsive-refresh` and the next - once a day - and every hourly run in between read
the same prefix. Production evidence before the fix: an ssh run grabbed 724 of 724 hosts
from the head of the file, and four consecutive hourly runs returned 905/905/906/908
responsive out of an identical 1101 attempted. Coverage was 1101 hosts a day, not 1101
an hour, which is a 78-day cycle for ssh against the 3.3 days hourly cadence was
supposed to buy.
"""
from datetime import datetime
from datetime import timezone

from ichnos.responsive import advance_responsive_cursor
from ichnos.responsive import read_responsive_hosts
from ichnos.responsive import write_responsive_file


def _at(hour):
    return datetime(2026, 8, 7, hour, 0, 0, tzinfo=timezone.utc)


def _list(path, n=10):
    """Oldest-first, which is the state `responsive-refresh` leaves the file in and the
    precondition refresh's stream-and-stop relies on."""
    write_responsive_file(path, [(f"203.0.113.{i}", f"2026-08-01T00:{i:02d}:00+00:00")
                                 for i in range(1, n + 1)])


def test_consecutive_budget_limited_runs_cover_different_hosts(tmp_path):
    """The regression. Two runs, each with a budget for three hosts, must between them
    check six distinct hosts - not the same three twice."""
    path = str(tmp_path / "known-responsive-ssh.conf")
    _list(path)

    first = [ip for ip, _ in read_responsive_hosts(path)][:3]
    advance_responsive_cursor(path, first, now=_at(1))

    second = [ip for ip, _ in read_responsive_hosts(path)][:3]
    advance_responsive_cursor(path, second, now=_at(2))

    third = [ip for ip, _ in read_responsive_hosts(path)][:3]

    assert not set(first) & set(second), f"re-checked {set(first) & set(second)}"
    assert not set(second) & set(third)
    assert len(set(first) | set(second) | set(third)) == 9


def test_rotation_loses_no_hosts_and_keeps_the_order_oldest_first(tmp_path):
    """A cursor that drops hosts is worse than one that stalls - a dropped host is never
    refreshed again and silently ages out of the 15-day window."""
    path = str(tmp_path / "list.conf")
    _list(path)
    before = {ip for ip, _ in read_responsive_hosts(path)}

    advance_responsive_cursor(path, [f"203.0.113.{i}" for i in (1, 2, 3)], now=_at(9))
    after = read_responsive_hosts(path)

    assert {ip for ip, _ in after} == before
    assert [ip for ip, _ in after][-3:] == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    # Still oldest-first, which is the property refresh's stream-and-stop depends on.
    assert [seen for _, seen in after] == sorted(seen for _, seen in after)


def test_a_derivation_landing_mid_run_is_not_clobbered(tmp_path):
    """`responsive-refresh` rebuilds the file from published observations at 03:30 and
    that copy is authoritative. A refresh run that started before it must not reinstate
    hosts the rebuild dropped - an opted-out host would come back."""
    path = str(tmp_path / "list.conf")
    _list(path)
    checked = [ip for ip, _ in read_responsive_hosts(path)][:3]

    # The nightly rebuild lands, and one of the hosts just checked is gone from it.
    write_responsive_file(path, [("198.51.100.1", "2026-08-01T00:00:00+00:00"),
                                 (checked[0], "2026-08-01T00:30:00+00:00")])
    advance_responsive_cursor(path, checked, now=_at(4))

    survivors = {ip for ip, _ in read_responsive_hosts(path)}
    assert survivors == {"198.51.100.1", checked[0]}
    assert checked[1] not in survivors and checked[2] not in survivors


def test_nothing_processed_leaves_the_file_untouched(tmp_path):
    """A run that was blocked before it checked anything must not restamp the list and
    push genuinely-old hosts to the back of the queue."""
    path = str(tmp_path / "list.conf")
    _list(path)
    before = read_responsive_hosts(path)

    assert advance_responsive_cursor(path, [], now=_at(5)) is False
    assert advance_responsive_cursor(path, ["10.0.0.1"], now=_at(5)) is False
    assert read_responsive_hosts(path) == before
