"""FTP/Telnet/SMTP normalization.

Every banner in this file is a real one captured from the production scanner against a
real host, not invented - the volatility these tests pin down is the reason the
normalizers reduce banners at all rather than hashing them whole.
"""
import json

from ichnos.fingerprint import fingerprint_id
from ichnos.normalize import normalize


def _ftp(banner):
    return {"status": "success", "result": {"banner": banner}}


def _telnet(banner, will=None, do=None):
    return {"status": "success",
            "result": {"banner": banner, "will": will or [], "do": do or []}}


def _smtp(banner, ehlo=None, helo=None):
    result = {"banner": banner}
    if ehlo is not None:
        result["ehlo"] = ehlo
    if helo is not None:
        result["helo"] = helo
    return {"status": "success", "result": result}


# Real ftp.funet.fi greeting - the counter and the clock are what make this the test
# case that matters. Captured 2026-08-07.
PURE_FTPD = (
    "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n"
    "220-You are user number {users} of 1000 allowed.\r\n"
    "220-Local time is now {clock}. Server port: 21.\r\n"
    "220-Only anonymous FTP is allowed here\r\n"
    "220 You will be disconnected after 30 minutes of inactivity.\r\n"
)


def test_an_ftp_banner_carrying_a_live_counter_and_clock_fingerprints_stably():
    """The whole reason banners are reduced. This host reports how many users are
    currently connected and what time it is locally - fingerprinted verbatim it would
    produce a new `versions` row on essentially every scan of a host that never
    changed, which is precisely the bug `_VOLATILE_HEADER_KEYS` was added to fix for
    HTTP after it was found doing exactly that in production."""
    first = normalize("ftp", _ftp(PURE_FTPD.format(users=14, clock="22:24")))
    later = normalize("ftp", _ftp(PURE_FTPD.format(users=907, clock="03:11")))

    assert fingerprint_id(first) == fingerprint_id(later)
    assert first["banner"] == "--------- Welcome to Pure-FTPd [privsep] [TLS] ----------"
    assert first["reply_code"] == 220


def test_a_genuine_software_version_still_distinguishes_two_ftp_servers():
    """The masking has to be blunt enough to kill clocks without being blunt enough to
    make every FTP server look alike - version components are single digits, so they
    survive."""
    a = normalize("ftp", _ftp("220 (vsFTPd 3.0.3)"))
    b = normalize("ftp", _ftp("220 (vsFTPd 3.0.5)"))
    c = normalize("ftp", _ftp("220 GNU FTP server ready.\r\n"))

    assert a["banner"] == "(vsFTPd 3.0.3)"
    assert len({fingerprint_id(x) for x in (a, b, c)}) == 3


def test_smtp_session_identifiers_do_not_reach_the_fingerprint():
    """Real Gmail greeting. The per-connection id is the volatile part, and it is not
    multi-digit - masking digit runs alone leaves `d#c#a#-#d8f9a4dsi` behind, which is
    still different on every connection. It has to be caught as a whole token."""
    banner = "220 mx.google.com ESMTP {sid} - gsmtp"
    first = normalize("smtp", _smtp(banner.format(sid="d9443c01a7336-2913d8f9a4dsi")))
    later = normalize("smtp", _smtp(banner.format(sid="a1b2c3d4e5f6g-7h8i9j0k1l2m3")))

    assert fingerprint_id(first) == fingerprint_id(later)
    assert "gsmtp" in first["banner"]  # the identifying part is kept


def test_smtp_capabilities_are_the_signal_and_are_order_independent():
    """The EHLO response describes what the service can actually do, which is a better
    fingerprint than any vendor string. A server that reorders its advertisement has
    not changed."""
    a = normalize("smtp", _smtp("220 mail ESMTP", ehlo="250-SIZE 157286400\n250-PIPELINING\n250 STARTTLS"))
    b = normalize("smtp", _smtp("220 mail ESMTP", ehlo="250 STARTTLS\n250-PIPELINING\n250-SIZE 157286400"))

    assert fingerprint_id(a) == fingerprint_id(b)
    assert json.loads(a["capabilities"]) == ["PIPELINING", "SIZE #", "STARTTLS"]
    assert a["extended"] is True

    plain = normalize("smtp", _smtp("220 mail SMTP", helo="250 mail"))
    assert plain["extended"] is False
    assert fingerprint_id(plain) != fingerprint_id(a)


def test_a_telnet_banner_full_of_live_state_still_fingerprints_stably():
    """Real telehack.com greeting, and the worst case of the three - a telnet MOTD is
    written for a human, so a clock, a user count and a host count are all normal."""
    motd = (
        "\r\nConnected to TELEHACK port {port}\r\n\r\n"
        "It is {time} on Friday, August 7, 2026 in Mountain View, California, USA.\r\n"
        "There are {users} local users. There are {hosts} hosts on the network.\r\n"
    )
    first = normalize("telnet", _telnet(motd.format(port=116, time="12:25 pm", users=131, hosts=26649)))
    later = normalize("telnet", _telnet(motd.format(port=4021, time="04:02 am", users=9, hosts=26702)))

    assert fingerprint_id(first) == fingerprint_id(later)


def test_telnet_option_negotiation_is_part_of_the_fingerprint():
    """What the server offers to negotiate is a stable property of the implementation,
    and for a host with a bare or empty banner it is the only signal there is."""
    a = normalize("telnet", _telnet("login:", will=["ECHO", "SUPPRESS_GO_AHEAD"], do=["TERMINAL_TYPE"]))
    b = normalize("telnet", _telnet("login:", will=["ECHO"], do=[]))

    assert fingerprint_id(a) != fingerprint_id(b)
    # Sorted, so a server listing the same options in another order is not a change.
    assert json.loads(a["will_options"]) == ["ECHO", "SUPPRESS_GO_AHEAD"]


def test_a_missing_banner_normalizes_rather_than_raising():
    """Same defensive contract every other normalizer has - ZGrab2's output shape varies
    with how far the handshake got, and a partial result must not crash the pipeline."""
    for module in ("ftp", "telnet", "smtp"):
        payload = normalize(module, {"status": "success", "result": {}})
        assert payload["banner"] is None
        assert fingerprint_id(payload)  # still hashable
