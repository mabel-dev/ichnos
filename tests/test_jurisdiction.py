import pytest

from ichnos.jurisdiction import RIR_DELEGATED_STATS_URLS
from ichnos.jurisdiction import parse_delegated_stats
from ichnos.jurisdiction import refresh_from_ipdeny
from ichnos.jurisdiction import refresh_from_rir

APNIC_SAMPLE = "\n".join(
    [
        "2|apnic|1|20260101|...|...|...",
        "apnic|JP|ipv4|1.0.16.0|4096|20110413|allocated",  # aligned -> /20
        "apnic|CN|ipv4|1.0.32.0|8192|20100101|allocated",  # aligned -> /19
        "apnic|AU|ipv4|1.0.64.0|1024|20100101|allocated",  # not a wanted country
    ]
)

RIPENCC_SAMPLE = "\n".join(
    [
        "2|ripencc|1|20260101|...|...|...",
        "ripencc|RU|ipv4|5.1.0.0|65536|20100101|allocated",  # aligned -> /16
        "ripencc|IR|ipv4|5.22.0.0|16384|20100101|allocated",  # aligned -> /18
        "ripencc|DE|ipv4|5.9.0.0|1024|20100101|allocated",  # not a wanted country
    ]
)


def test_parse_delegated_stats_filters_by_country():
    assert parse_delegated_stats(APNIC_SAMPLE, ["JP"]) == ["1.0.16.0/20"]


def test_parse_delegated_stats_ignores_header_and_comments():
    text = "# comment\n2|apnic|1|...\napnic|JP|ipv4|1.0.16.0|4096|20110413|allocated"
    assert parse_delegated_stats(text, ["JP"]) == ["1.0.16.0/20"]


def test_refresh_from_rir_only_fetches_registries_it_needs():
    fetched_urls = []

    def fake_fetch(url):
        fetched_urls.append(url)
        if url == RIR_DELEGATED_STATS_URLS["apnic"]:
            return APNIC_SAMPLE
        if url == RIR_DELEGATED_STATS_URLS["ripencc"]:
            return RIPENCC_SAMPLE
        raise AssertionError(f"unexpected fetch: {url}")

    result = refresh_from_rir(["JP", "CN", "RU", "IR"], fetch=fake_fetch)

    assert set(fetched_urls) == {
        RIR_DELEGATED_STATS_URLS["apnic"],
        RIR_DELEGATED_STATS_URLS["ripencc"],
    }
    assert "1.0.16.0/20" in result.cidrs
    assert "5.1.0.0/16" in result.cidrs
    assert result.source == "rir"
    assert result.countries == ("JP", "CN", "RU", "IR")


def test_refresh_from_rir_unknown_country_raises_rather_than_fetching_everything():
    with pytest.raises(ValueError):
        refresh_from_rir(["ZZ"], fetch=lambda url: (_ for _ in ()).throw(AssertionError()))


def test_refresh_from_ipdeny_fetches_one_zone_file_per_country():
    def fake_fetch(url):
        assert url.endswith("kp.zone")
        # deliberately non-adjacent so collapse_addresses (already covered by
        # test_blocklist.py) can't merge them - keeps this test about fetch wiring.
        return "175.45.176.0/22\n175.45.200.0/22\n"

    result = refresh_from_ipdeny(["KP"], fetch=fake_fetch)
    assert result.cidrs == ["175.45.176.0/22", "175.45.200.0/22"]
    assert result.source == "ipdeny"
