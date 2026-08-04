"""Environment-driven settings.

Everything here has an `ICHNOS_`-prefixed environment variable so the worker's
behaviour is configurable without a redeploy (design doc §5, §9) - config lives in SSM
Parameter Store / Secrets Manager in the real deployment, exposed to the process as
plain environment variables by the instance's startup script.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    return os.environ.get(f"ICHNOS_{name}", default)


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(f"ICHNOS_{name}")
    return float(value) if value is not None else default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(f"ICHNOS_{name}")
    return int(value) if value is not None else default


@dataclass(frozen=True)
class Settings:
    # DynamoDB table names (design doc §3.1)
    exclusions_table: str = "Exclusions"
    schedule_table: str = "ScanSchedule"
    current_state_table: str = "CurrentState"
    version_index_table: str = "VersionIndex"

    # Local filesystem paths on the worker
    blocklist_path: str = "/var/lib/ichnos/blocklist.conf"
    jurisdiction_blocklist_path: str = "/var/lib/ichnos/jurisdiction-blocklist.conf"
    pending_dir: str = "/var/lib/ichnos/pending"
    publish_tmp_dir: str = "/var/lib/ichnos/publish-tmp"

    # The known-responsive host list, derived nightly from published Observations (see
    # responsive.py). `{protocol}` is substituted per list - http/https/ssh each get
    # their own, since discovery excludes and refresh targets them independently.
    known_responsive_path: str = "/var/lib/ichnos/known-responsive-{protocol}.conf"
    # How far back an observation still counts as responsive. Also, with a nightly
    # refresh, how many consecutive non-responses before a host is given up on.
    responsive_window_days: int = 15
    # Read path to Opteryx (odata.py). Separate host from the Upload Service's, and a
    # separate auth step - the PAT below is not a bearer token and has to be exchanged
    # for a JWT first.
    odata_base_url: str = "https://odata.opteryx.app"
    odata_token_url: str = "https://authenticate.opteryx.app/token"

    # S3 persistence for the jurisdiction blocklist (empty = local-only, e.g. dev/test).
    # Without this, a freshly-replaced instance starts with an EMPTY jurisdiction
    # exclusion list until the next weekly refresh - up to a week of scanning without
    # the JP/KP/KR/CN/RU/IR exclusion in effect. `scan` pulls this at startup if the
    # local file is missing; `jurisdiction-refresh` pushes to it after every refresh.
    jurisdiction_s3_bucket: str = ""
    jurisdiction_s3_key: str = "jurisdiction/jurisdiction-blocklist.conf"

    # Throttle (design doc §4) - global budget shared across all enabled protocols
    rate_interval_seconds: float = 5.0

    # ZMap's own runtime gateway-MAC ARP resolution turned out to be unreliable at the
    # invocation volume this project's earlier per-candidate design made (see
    # scanner.py's module docstring) - resolved once at boot (the OS's own ARP, via
    # ordinary traffic, not ZMap's raw one) and pinned here instead. Empty means "let
    # ZMap resolve it itself".
    zmap_gateway_mac: str = ""

    # How many ZGrab2 grabs discovery may have in flight at once. See scanner.py's
    # DEFAULT_GRAB_CONCURRENCY for the sizing; the short version is that grabs were
    # serial in the reader loop, their share of a run's window is proportional to
    # zmap_rate_pps rather than to the slice size, and that capped the design near
    # 50pps regardless of how the window was sized. Concurrency is the only lever that
    # moves that ceiling - buffer, cadence and candidate count do not.
    grab_concurrency: int = 8

    # ZMap's own default (8s) is sized for one large campaign - now a single tail wait
    # at the end of each scan window rather than per-target, so a smaller value is
    # appropriate - see scanner.py's DEFAULT_ZMAP_COOLDOWN_SECONDS for the measurements
    # behind this default.
    zmap_cooldown_seconds: int = 3

    # ZMap's own native discovery throttle (`--rate`, whole packets/second only - it
    # rejects fractional values outright). Replaces this project's earlier approach of
    # externally pacing repeated single-target ZMap invocations with our own rate
    # limiter - see scanner.py's module docstring. Started at 1pps (ZMap's practical
    # floor) deliberately, to observe real production behaviour before committing to
    # anything faster; raised to 2pps once that observation period showed a low,
    # stable hit rate (~0.3-0.6% new fingerprints per candidate) and no operational
    # issues at 1pps - a data-driven increase, not a re-guess. Raised again to 4pps on
    # the same basis, after two clean hours at 2pps: every completed run measured
    # 804.2-804.3s against the 803s the model predicts, and the one run that absorbed a
    # full 30s zgrab2 timeout finished within 0.1s of the two that did not - so grab
    # time is absorbed inside the paced discovery loop rather than added to it, and
    # doubling the hit count does not spend the cron-interval buffer.
    #
    # Raised again to 8pps. This one went out ahead of its observation window rather
    # than after it, so the window was run immediately afterwards: 7h45m, 93 completed
    # runs (31 per protocol, 2026-08-03 22:45Z to 2026-08-04 06:30Z). Median run 803.3s
    # against the 803s the model predicts, worst case 825.7s - still 74s inside the
    # 900s cron interval - with zero flock skips and zero ZMap failures.
    #
    # That window also settled the thing worth worrying about at higher rates, which is
    # the grab backlog rather than the discovery pace. ZMap finishes on schedule no
    # matter what we do; ZGrab2 grabs are serial in the reader loop at up to 30s each on
    # timeout, and they scale with candidates rather than staying fixed. 199 grab
    # timeouts across those runs (~2 per run, ~60s of blocking) did not extend a single
    # run measurably - the grabs overlap ZMap's paced sending through the stdout pipe
    # buffer instead of adding to it. So the arithmetic (`candidates / rate_pps +
    # cooldown`) holds with grab load included, at this volume. It will stop holding
    # eventually: grab work was ~10% of the window here, and it doubles with every
    # candidate doubling while the window stays fixed at ~803s.
    #
    # Measured hit rates from the same window, which correct the ~0.3-0.6% figure above
    # (that was an early cross-protocol estimate, and it holds only for ssh now):
    #
    #     http    1.52% responsive, 0.94% new fingerprints per candidate
    #     https   1.71% responsive, 1.19% new
    #     ssh     0.77% responsive, 0.64% new
    #
    # These matter beyond bookkeeping: grab count is hit rate x candidates, so an
    # understated hit rate understates exactly the load that eventually binds.
    #
    # Skipped ticks remain the signal that a rate is too fast - the flock guard
    # (user_data.sh.tftpl) turns an overrun into a dropped tick rather than overlapping
    # runs, so overruns are silent unless counted. A skip costs more than it used to:
    # the cron interval is now hourly rather than the 900s the measurements above were
    # taken against (see variables.tf's scan_candidates_per_cron_tick), so a dropped
    # tick loses an hour of scanning rather than a quarter of one. The rate itself is
    # unchanged by that - only the slice size - so the per-run arithmetic and the
    # measured hit rates below carry over untouched.
    #
    # Now 16pps, with candidates doubled to 12800 alongside it. Deliberately a smaller
    # claim than the steps above: the 8pps window measured grab work at ~10% of the
    # run, so 16pps puts it at ~20%, still well inside the buffer. Nothing was measured
    # at 16pps before this went out.
    #
    # Worth being honest about what this series of doublings can and cannot tell us.
    # Doubling candidates and rate together is runtime-neutral by construction, so run
    # duration reads ~803s at every step and will keep reading ~803s until grab work
    # fills the window - four or five doublings out, by which point the outbound rate is
    # in the hundreds of pps. Local timing is therefore a late signal, not an early one,
    # and the backpressure that actually matters for a scanner (abuse reports, upstream
    # intervention, being firewalled) arrives out-of-band days later and never appears
    # in these logs at all. "No skipped ticks" means the box is coping. It does not mean
    # the rate is acceptable to anyone else.
    #
    # 16pps was then measured over 21 runs (7 per protocol, 12800 candidates on the old
    # 15-minute cadence): median 803.3s against a predicted 803.0, no skipped ticks, no
    # ZMap failures. The spread is the interesting part - http peaked at 819.6s (+2.07%)
    # and ssh at 803.5s (+0.06%), but https reached 864.3s (+7.64%). https has the
    # highest hit rate, so the most grabs and the most 30s timeouts, and that run's grab
    # backlog ran ~61s past ZMap finishing. That is the first time the backlog has shown
    # up as real variance rather than as a projection, and it is what sizes the buffer
    # in variables.tf.
    #
    # Now 32pps, with 105000 candidates per hourly run (~3284s, 9.6% buffer).
    #
    # This is expected to be the last doubling this architecture supports, and the
    # reason is worth stating precisely because it is not a tuning problem. Grab work
    # scales with candidates; the run window is candidates/rate; so the share of the
    # window spent grabbing is proportional to *rate*, and is completely independent of
    # the slice size, the cron cadence and the buffer:
    #
    #      8pps   ~11% of the window   (measured)
    #     16pps   ~30%                 (measured)
    #     32pps   ~60%                 (projected)
    #     64pps   ~120%                - cannot fit, at any slice size
    #
    # Grabs currently run inline in the reader loop, one host at a time, at up to 30s
    # each on timeout (_grab_and_record, called from _stream_discover_and_grab). They
    # overlap ZMap's paced sending through the stdout pipe buffer, which is why runs
    # finish at the predicted time despite substantial grab load - but they do not
    # overlap *each other*, so past ~50pps the loop cannot drain a run's hits within
    # that run's window no matter how the window is sized. Going beyond this rate needs
    # a bounded worker pool for the ZGrab2 calls first; that is a change to make before
    # the rate that requires it, not after a wave of skipped hours reveals it.
    zmap_rate_pps: int = 32

    # User-Agent sent by ZGrab2's http module. AWS's network-scanning guidelines
    # (repost.aws, "AWS Guidelines for network scanning") ask under their "identifiable"
    # pillar that HTTP scanners carry "meaningful content in user agent strings, such as
    # names from your public DNS zones or the URL for opt-out". ZGrab2's own default is
    # a generic scanner string, which leaves an operator reading their access log with
    # no route back to the opt-out page this project already publishes - the one place
    # our transparency posture didn't reach the actual packets. Both the DNS zone and
    # the opt-out URL are included; a few dozen bytes per request is not a real cost.
    # HTTPS is scanned via ZGrab2's *tls* module, which sends no HTTP request at all,
    # so this legitimately applies to the http module only (see scanner.py's grab_one).
    scan_user_agent: str = (
        "ichnos/1.0 (+https://ichnos.online/responsible-scanning; "
        "opt-out https://ichnos.online/opt-out)"
    )

    # Opteryx publish target (design doc §3.2)
    opteryx_workspace: str = "ichnos"
    opteryx_collection: str = "landing"
    opteryx_client_id: str = ""
    opteryx_client_secret: str = ""

    # Public site (design doc §6)
    site_organisation: str = "TBD"
    site_contact_email: str = "abuse@example.invalid"
    site_form_secret: str = "change-me-in-production"
    # Used to build absolute URLs in security.txt's Canonical field and scanner.txt -
    # both are meant to be fetched standalone (not always via a browser following
    # relative links), so they need the real external URL, not a relative path.
    site_url: str = "https://ichnos.online"
    # The scanner's own public identity, published on the site and in scanner.txt.
    # Same AWS "identifiable" pillar as scan_user_agent above ("publishing scanning IP
    # address ranges"): someone holding a probe in their firewall log can then confirm
    # it's this project without having to think to do a reverse lookup first. The
    # hostname is stable and known to this repo; the address is not (it's whatever EIP
    # Terraform allocated), so it's set from the EIP by user_data. Comma-separated -
    # one address today, but a fleet is the documented scaling direction. Empty means
    # "not configured", and the page/scanner.txt name the hostname alone rather than
    # printing a misleading blank.
    site_scan_hostname: str = "scan.ichnos.online"
    site_scan_source_ips: str = ""
    # True in the real deployment - nginx terminates TLS and reverse-proxies to this
    # app on loopback, so the opt-out form must read the client IP from the header
    # nginx sets, not request.client.host (see webapp/app.py's module docstring).
    trust_proxy_headers: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            exclusions_table=_env("EXCLUSIONS_TABLE", cls.exclusions_table),
            schedule_table=_env("SCHEDULE_TABLE", cls.schedule_table),
            current_state_table=_env("CURRENT_STATE_TABLE", cls.current_state_table),
            version_index_table=_env("VERSION_INDEX_TABLE", cls.version_index_table),
            blocklist_path=_env("BLOCKLIST_PATH", cls.blocklist_path),
            jurisdiction_blocklist_path=_env(
                "JURISDICTION_BLOCKLIST_PATH", cls.jurisdiction_blocklist_path
            ),
            pending_dir=_env("PENDING_DIR", cls.pending_dir),
            publish_tmp_dir=_env("PUBLISH_TMP_DIR", cls.publish_tmp_dir),
            known_responsive_path=_env("KNOWN_RESPONSIVE_PATH", cls.known_responsive_path),
            responsive_window_days=_env_int(
                "RESPONSIVE_WINDOW_DAYS", cls.responsive_window_days
            ),
            odata_base_url=_env("ODATA_BASE_URL", cls.odata_base_url),
            odata_token_url=_env("ODATA_TOKEN_URL", cls.odata_token_url),
            jurisdiction_s3_bucket=_env("JURISDICTION_S3_BUCKET", cls.jurisdiction_s3_bucket),
            jurisdiction_s3_key=_env("JURISDICTION_S3_KEY", cls.jurisdiction_s3_key),
            rate_interval_seconds=_env_float("RATE_INTERVAL_SECONDS", cls.rate_interval_seconds),
            zmap_gateway_mac=_env("ZMAP_GATEWAY_MAC", cls.zmap_gateway_mac),
            zmap_cooldown_seconds=_env_int("ZMAP_COOLDOWN_SECONDS", cls.zmap_cooldown_seconds),
            zmap_rate_pps=_env_int("ZMAP_RATE_PPS", cls.zmap_rate_pps),
            grab_concurrency=_env_int("GRAB_CONCURRENCY", cls.grab_concurrency),
            scan_user_agent=_env("SCAN_USER_AGENT", cls.scan_user_agent),
            opteryx_workspace=_env("OPTERYX_WORKSPACE", cls.opteryx_workspace),
            opteryx_collection=_env("OPTERYX_COLLECTION", cls.opteryx_collection),
            opteryx_client_id=_env("OPTERYX_CLIENT_ID", cls.opteryx_client_id),
            opteryx_client_secret=_env("OPTERYX_CLIENT_SECRET", cls.opteryx_client_secret),
            site_organisation=_env("SITE_ORGANISATION", cls.site_organisation),
            site_contact_email=_env("SITE_CONTACT_EMAIL", cls.site_contact_email),
            site_form_secret=_env("SITE_FORM_SECRET", cls.site_form_secret),
            site_url=_env("SITE_URL", cls.site_url),
            site_scan_hostname=_env("SITE_SCAN_HOSTNAME", cls.site_scan_hostname),
            site_scan_source_ips=_env("SITE_SCAN_SOURCE_IPS", cls.site_scan_source_ips),
            trust_proxy_headers=_env("TRUST_PROXY_HEADERS", "") == "1",
        )
