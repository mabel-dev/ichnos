import os

from ichnos.blocklist import build_blocklist
from ichnos.blocklist import is_blocked
from ichnos.blocklist import read_blocklist_file
from ichnos.blocklist import write_blocklist_file


def test_includes_bogons_by_default():
    cidrs = build_blocklist()
    assert "10.0.0.0/8" in cidrs
    assert "127.0.0.0/8" in cidrs


def test_merges_exclusions_and_jurisdiction_cidrs():
    cidrs = build_blocklist(
        exclusion_entries=["8.8.8.8"],
        jurisdiction_cidrs=["5.6.7.0/24"],
    )
    assert "8.8.8.8/32" in cidrs
    assert "5.6.7.0/24" in cidrs


def test_invalid_entries_are_skipped_not_raised():
    cidrs = build_blocklist(exclusion_entries=["not-an-ip", "", "999.999.999.999"])
    assert "10.0.0.0/8" in cidrs  # bogons still present, nothing blew up


def test_overlapping_entries_are_collapsed():
    cidrs = build_blocklist(exclusion_entries=["203.0.113.0/24"], jurisdiction_cidrs=["203.0.113.5"])
    # 203.0.113.5 is inside the /24 already being excluded - collapse_addresses should
    # merge them rather than keeping a redundant /32 alongside the /24.
    assert "203.0.113.0/24" in cidrs
    assert "203.0.113.5/32" not in cidrs


def test_write_blocklist_file_creates_parent_directory(tmp_path):
    path = str(tmp_path / "nested" / "does" / "not" / "exist" / "blocklist.conf")
    write_blocklist_file(path, ["10.0.0.0/8"])
    assert os.path.exists(path)
    with open(path) as f:
        assert f.read() == "10.0.0.0/8\n"


def test_read_blocklist_file_roundtrips_write_blocklist_file(tmp_path):
    path = str(tmp_path / "blocklist.conf")
    write_blocklist_file(path, ["10.0.0.0/8", "175.45.176.0/22"])
    assert read_blocklist_file(path) == ["10.0.0.0/8", "175.45.176.0/22"]


def test_read_blocklist_file_missing_file_returns_empty():
    assert read_blocklist_file("/nonexistent/path/for/sure/blocklist.conf") == []


def test_write_blocklist_file_leaves_no_temp_files_behind(tmp_path):
    # Regression test for a real production incident: http/https/ssh each rebuild and
    # rewrite this same shared path within the same cron tick (all three fire within
    # the same second) - a concurrently-running ZMap process reading the file
    # mid-write saw a truncated CIDR ("103." - cut off mid-address), which made ZMap
    # fatal-error and refuse to start. Writing to a temp file and atomically
    # os.replace-ing it into place means a concurrent reader always sees either the
    # complete old file or the complete new one - this just confirms no stray temp
    # file is left in the directory afterward.
    path = str(tmp_path / "blocklist.conf")
    write_blocklist_file(path, ["10.0.0.0/8"])
    write_blocklist_file(path, ["10.0.0.0/8", "175.45.176.0/22"])

    assert os.listdir(tmp_path) == ["blocklist.conf"]
    with open(path) as f:
        assert f.read() == "10.0.0.0/8\n175.45.176.0/22\n"


def test_is_blocked_true_inside_a_cidr():
    assert is_blocked("175.45.176.5", ["175.45.176.0/22"]) is True


def test_is_blocked_false_outside_all_cidrs():
    assert is_blocked("8.8.8.8", ["175.45.176.0/22", "10.0.0.0/8"]) is False


def test_is_blocked_true_for_exact_bare_ip_entry():
    assert is_blocked("8.8.8.8", ["8.8.8.8"]) is True


def test_is_blocked_invalid_address_treated_as_blocked():
    # fail closed, not open - an unparseable "address" should never be treated as safe
    assert is_blocked("not-an-ip", ["8.8.8.8"]) is True
