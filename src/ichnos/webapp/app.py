"""Public information page + self-service opt-out (design doc §6).

Served by the same instance/IP that does the scanning - deliberately no ALB/CloudFront
in front (design doc §2), so there's no *network-level* hop with a different public
identity between the visitor and this service. There is, however, a *local* nginx
terminating TLS and reverse-proxying to this app on loopback (needed for certbot) - to
that process, every request's `request.client.host` would read as nginx's loopback
address, not the real visitor.

`trust_proxy_headers=True` (set by the deployment, not the default) tells `_client_ip`
to read `X-Forwarded-For` instead. This is only safe because nginx is configured to
*overwrite* that header with what nginx itself observed (`proxy_set_header
X-Forwarded-For $remote_addr;`, not the append-if-present form) rather than passing
through whatever a client sent - so a spoofed header from the visitor never survives
the hop. Leave this off (the default) for local dev/tests, where there's no proxy and
`request.client.host` is already correct.

The arithmetic challenge replaces a CAPTCHA per the spec: two small numbers are
rendered into hidden form fields along with an HMAC over them, and the server re-derives
the expected sum and HMAC on submit. This isn't meant to stop a determined attacker -
it's meant to be a cheap deterrent against unsophisticated bulk-submission bots, per the
design doc's "minimise opportunities for abuse while keeping the process straightforward
for legitimate users."
"""
from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import random
from dataclasses import dataclass
from dataclasses import field
from typing import List
from typing import Optional

from fastapi import FastAPI
from fastapi import Form
from fastapi import Request
from fastapi.responses import HTMLResponse

from ..models import Exclusion
from ..models import ExclusionSource
from ..storage.base import Store


@dataclass(frozen=True)
class SiteConfig:
    project_name: str = "ichnos"
    organisation: str = "TBD"
    contact_email: str = "abuse@example.invalid"
    source_repo_url: str = "https://github.com/mabel-dev/ichnos"
    form_secret: str = "change-me-in-production"
    trust_proxy_headers: bool = False
    faq: List[tuple] = field(
        default_factory=lambda: [
            (
                "What is this?",
                "An Internet measurement research project. It sends a small number of "
                "HTTP/HTTPS protocol-negotiation requests to publicly routable hosts and "
                "records only the metadata exposed during that negotiation.",
            ),
            (
                "Is this an attack or a vulnerability scan?",
                "No. Nothing here attempts to authenticate, exploit, or access anything "
                "beyond a normal HTTP/HTTPS handshake, exactly as a browser would.",
            ),
            (
                "How often are you scanning me?",
                "At most once every few seconds across this project's entire scan "
                "volume, project-wide - not targeted, repeated, or high-frequency "
                "against any one host.",
            ),
            (
                "How do I stop being scanned?",
                "Use the opt-out form below. It takes effect before the next scheduled scan.",
            ),
        ]
    )


def _client_ip(request: Request, *, trust_proxy_headers: bool) -> Optional[str]:
    if trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _make_challenge(secret: str) -> tuple:
    a, b = random.randint(1, 9), random.randint(1, 9)
    token = hmac.new(secret.encode(), f"{a}:{b}".encode(), hashlib.sha256).hexdigest()
    return a, b, token


def _verify_challenge(secret: str, a: int, b: int, token: str, answer: int) -> bool:
    expected = hmac.new(secret.encode(), f"{a}:{b}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(token, expected) and answer == a + b


def _valid_ip_or_cidr(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}
  h1, h2 {{ line-height: 1.2; }}
  code {{ background: #f0f0f0; padding: 0.1rem 0.3rem; border-radius: 3px; }}
  form {{ margin: 1.5rem 0; }}
  label {{ display: block; margin: 0.75rem 0 0.25rem; }}
  input[type=text] {{ width: 100%; max-width: 24rem; padding: 0.4rem; }}
  button {{ margin-top: 1rem; padding: 0.5rem 1rem; }}
  .muted {{ color: #555; font-size: 0.9em; }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def create_app(store: Store, config: SiteConfig = SiteConfig()) -> FastAPI:
    app = FastAPI(title=config.project_name)

    @app.get("/", response_class=HTMLResponse)
    def info_page() -> str:
        schedule = store.schedule.list_enabled()
        schedule_rows = "".join(
            f"<tr><td>{html.escape(e.protocol)}</td><td>{e.port}</td>"
            f"<td>{html.escape(e.cadence)}</td></tr>"
            for e in schedule
        ) or "<tr><td colspan=3>No protocols currently enabled.</td></tr>"

        faq_html = "".join(
            f"<h3>{html.escape(q)}</h3><p>{html.escape(a)}</p>" for q, a in config.faq
        )

        body = f"""
<h1>{html.escape(config.project_name)}</h1>
<p><strong>Purpose:</strong> Internet measurement and research. This service collects
protocol metadata from publicly accessible Internet hosts to build analytical datasets.
It does not exploit vulnerabilities, authenticate to services, brute force credentials,
or execute commands. Only metadata exposed during normal protocol negotiation is
collected.</p>

<p><strong>Organisation:</strong> {html.escape(config.organisation)}<br>
<strong>Abuse contact:</strong> <a href="mailto:{html.escape(config.contact_email)}">{html.escape(config.contact_email)}</a><br>
<strong>Source:</strong> <a href="{html.escape(config.source_repo_url)}">{html.escape(config.source_repo_url)}</a></p>

<h2>What is collected</h2>
<p>Currently HTTP and HTTPS only (status code, headers, TLS certificate metadata) - see
the scan schedule below. Nothing beyond protocol negotiation is intentionally collected;
no request is ever authenticated.</p>

<h2>Scan schedule</h2>
<table><tr><th>Protocol</th><th>Port</th><th>Cadence</th></tr>{schedule_rows}</table>

<h2>Privacy statement</h2>
<p>Collected data is limited to protocol metadata and does not include application
content. Data tied to an opted-out IP or CIDR is excluded from all scans going forward.
See <a href="/opt-out">opt-out</a> below to request exclusion.</p>

<h2>FAQ</h2>
{faq_html}

<p class="muted"><a href="/opt-out">Request exclusion from future scans &rarr;</a></p>
"""
        return _page(config.project_name, body)

    @app.get("/opt-out", response_class=HTMLResponse)
    def opt_out_form(request: Request) -> str:
        detected_ip = _client_ip(request, trust_proxy_headers=config.trust_proxy_headers) or ""
        a, b, token = _make_challenge(config.form_secret)
        body = f"""
<h1>Request exclusion</h1>
<p>Submitting this form adds the given IP address or CIDR range to the exclusion list.
It takes effect before the next scheduled scan.</p>
<form method="post" action="/opt-out">
  <label for="ip">IP address or CIDR to exclude</label>
  <input type="text" id="ip" name="ip_or_cidr" value="{html.escape(detected_ip)}" required>
  <p class="muted">Detected from your connection: {html.escape(detected_ip) or "unknown"}.
  Change it above if you're excluding a different range you manage.</p>

  <label>Optional reason</label>
  <input type="text" name="reason">

  <label for="answer">What is {a} + {b}?</label>
  <input type="text" id="answer" name="answer" required>
  <input type="hidden" name="a" value="{a}">
  <input type="hidden" name="b" value="{b}">
  <input type="hidden" name="token" value="{token}">

  <button type="submit">Request exclusion</button>
</form>
"""
        return _page("Opt out", body)

    @app.post("/opt-out", response_class=HTMLResponse)
    def opt_out_submit(
        request: Request,
        ip_or_cidr: str = Form(...),
        reason: str = Form(""),
        answer: str = Form(...),
        a: int = Form(...),
        b: int = Form(...),
        token: str = Form(...),
    ) -> HTMLResponse:
        try:
            answer_int = int(answer)
        except ValueError:
            answer_int = -1

        if not _verify_challenge(config.form_secret, a, b, token, answer_int):
            return HTMLResponse(
                _page("Opt out", "<h1>Incorrect answer</h1><p><a href='/opt-out'>Try again</a></p>"),
                status_code=400,
            )

        ip_or_cidr = ip_or_cidr.strip()
        if not _valid_ip_or_cidr(ip_or_cidr):
            return HTMLResponse(
                _page(
                    "Opt out",
                    "<h1>Invalid IP or CIDR</h1><p><a href='/opt-out'>Try again</a></p>",
                ),
                status_code=400,
            )

        store.exclusions.add(
            Exclusion(
                ip_or_cidr=ip_or_cidr,
                source=ExclusionSource.SELF_SERVE,
                reason=reason.strip() or None,
                requester_ip=_client_ip(request, trust_proxy_headers=config.trust_proxy_headers),
            )
        )

        body = f"""
<h1>Exclusion recorded</h1>
<p><code>{html.escape(ip_or_cidr)}</code> has been added to the exclusion list and will
take effect before the next scheduled scan.</p>
<p><a href="/">Back to the info page</a></p>
"""
        return HTMLResponse(_page("Opt out", body))

    return app
