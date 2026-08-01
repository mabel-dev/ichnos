from ichnos.blocklist import build_blocklist


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
