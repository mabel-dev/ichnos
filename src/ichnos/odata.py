"""Read path to Opteryx, via the hosted OData v4 feed at `odata.opteryx.app`.

The counterpart to publish.py's write path, and held to the same boundary: this is the
same public surface any external Opteryx customer uses, not the engine. Importing
`opteryx` itself would read our own published datasets through internals we've
deliberately never depended on (see publish.py's module docstring), so the feed is used
instead - it also keeps `requests`, already a dependency, as the only thing needed.

Three details about the service are load-bearing here, all confirmed against the live
API rather than inferred from the spec:

`$filter` and `$apply` are not siblings. Passing both as separate query options fails
with `400 Unknown column '<x>'`, because `$filter` is evaluated against the *aggregated*
projection, where the column being filtered on no longer exists. The composed form
`$apply=filter(...)/groupby((col))` is the one that works, and it's what
`distinct_values` builds.

Aggregate results page like any other. A `groupby` returning more rows than `$top`
comes back with an `@odata.nextLink`, so a distinct list of any size can be read in
full. The link is *relative* (resolve against the base host) and arrives with its `$`
already percent-encoded as `%24`, which must be passed through untouched rather than
re-encoded - hence the deliberate absence of a `params=` dict anywhere below, since
requests would re-encode what the service handed us.

"Empty" is unambiguous. The service guarantees a failed read is never a 200 with an
empty `value` array: an empty `value` means the query ran and matched nothing, and
anything else is a non-2xx with an error body. That guarantee is what lets callers
treat an empty result as real data rather than a possible failure - so this module
raises on every non-2xx and never returns a partial page as if it were complete.
"""
from __future__ import annotations

from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from urllib.parse import quote

from .logging_setup import get_logger

logger = get_logger(__name__)

DEFAULT_ODATA_BASE = "https://odata.opteryx.app"
DEFAULT_ODATA_PREFIX = "/api/v4"
DEFAULT_TOKEN_URL = "https://authenticate.opteryx.app/token"

MAX_TOP = 25000
"""The service's documented ceiling for a single request's `$top`; a larger value is
rejected with a 400. Set deliberately high rather than left to the default of 100 -
this module's reads are bulk reads, and the default would turn one page into 250."""


class ODataError(Exception):
    """Any failure reading the feed - transport, auth, or a non-2xx from the service.

    Deliberately distinct from "the query matched nothing", which is an ordinary empty
    result. Callers that cache what they read (see responsive.py) rely on that split to
    decide whether to keep the previous copy or accept a genuinely empty answer.
    """


def fetch_access_token(
    client_id: str,
    client_secret: str,
    *,
    token_url: str = DEFAULT_TOKEN_URL,
    post: Optional[Callable[..., Any]] = None,
) -> str:
    """Exchange a PAT (`client_id`/`client_secret`) for a short-lived JWT access token.

    The PAT itself is *not* a bearer token - the feed rejects it. This is the same
    credential pair `opteryx_upload`'s PATAuthenticator uses for the write path, so
    nothing new needs provisioning; it just has to be exchanged first.
    """
    if post is None:
        import requests

        post = requests.post

    try:
        response = post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=30,
        )
    except Exception as exc:  # transport-level: DNS, TLS, timeout
        raise ODataError(f"token request to {token_url} failed: {exc}") from exc

    if response.status_code != 200:
        # Deliberately does not include the body - it is an auth endpoint and the
        # response may echo credentials back.
        raise ODataError(f"token request to {token_url} returned {response.status_code}")

    token = response.json().get("access_token")
    if not token:
        raise ODataError(f"token response from {token_url} carried no access_token")
    return token


def _get_json(url: str, token: Optional[str], get: Callable[..., Any]) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        response = get(url, headers=headers, timeout=120)
    except Exception as exc:
        raise ODataError(f"GET {url} failed: {exc}") from exc

    if response.status_code != 200:
        # The service returns {"error": {"code", "message"}} - surface the message,
        # since a 400 here is nearly always a malformed $filter/$apply worth reading.
        try:
            detail = response.json().get("error", {}).get("message", "")
        except Exception:
            detail = ""
        raise ODataError(f"GET {url} returned {response.status_code}: {detail}".rstrip(": "))

    return response.json()


def iter_rows(
    path: str,
    query: str,
    *,
    token: Optional[str] = None,
    base_url: str = DEFAULT_ODATA_BASE,
    prefix: str = DEFAULT_ODATA_PREFIX,
    get: Optional[Callable[..., Any]] = None,
) -> Iterator[Dict[str, Any]]:
    """Yield every row of a query, following `@odata.nextLink` until the feed stops
    offering one.

    `path` is the three-part `{workspace}/{collection}/{dataset}` address - the same
    triple the Upload API's `Target` uses. `query` is a pre-encoded query string; it is
    not built from a dict on purpose, see the module docstring.

    Raises ODataError rather than yielding a partial result if any page fails: a caller
    cannot otherwise distinguish "that's all of them" from "the fourth page 500'd".
    """
    if get is None:
        import requests

        get = requests.get

    url = f"{base_url}{prefix}/{path}?{query}"
    pages = 0
    while url:
        payload = _get_json(url, token, get)
        pages += 1
        for row in payload.get("value", []):
            yield row

        next_link = payload.get("@odata.nextLink")
        if not next_link:
            break
        # Relative, and already percent-encoded - concatenate, never re-encode.
        url = next_link if next_link.startswith("http") else f"{base_url}{next_link}"

    logger.info("odata: %s read in %d page(s)", path, pages)


def grouped_max(
    path: str,
    column: str,
    max_column: str,
    alias: str,
    *,
    where: str = "",
    token: Optional[str] = None,
    base_url: str = DEFAULT_ODATA_BASE,
    prefix: str = DEFAULT_ODATA_PREFIX,
    top: int = MAX_TOP,
    get: Optional[Callable[..., Any]] = None,
) -> List[Dict[str, Any]]:
    """One row per distinct `column`, carrying `max(max_column)` as `alias`.

    `$apply=filter(...)/groupby((col),aggregate(other with max as alias))`, confirmed
    against the live feed. The aggregate is what turns a plain distinct list into an
    ordered one without a second query or a stored cursor - see responsive.py.

    Note the feed will not `$orderby` an aggregate alias, so callers sort the result
    themselves; at the sizes this returns that is trivial next to the transfer saved by
    aggregating server-side.
    """
    inner = f"groupby(({column}),aggregate({max_column} with max as {alias}))"
    apply_expr = f"filter({where})/{inner}" if where else inner
    query = f"$apply={quote(apply_expr, safe='()/,')}&$top={top}"
    return [
        row
        for row in iter_rows(path, query, token=token, base_url=base_url, prefix=prefix, get=get)
        if row.get(column) is not None
    ]


def distinct_values(
    path: str,
    column: str,
    *,
    where: str = "",
    token: Optional[str] = None,
    base_url: str = DEFAULT_ODATA_BASE,
    prefix: str = DEFAULT_ODATA_PREFIX,
    top: int = MAX_TOP,
    get: Optional[Callable[..., Any]] = None,
) -> List[str]:
    """Distinct values of `column`, optionally restricted by an OData filter expression.

    Built as `$apply=filter(<where>)/groupby((<column>))` - grouping by a column without
    aggregating it further is how the feed expresses DISTINCT, and composing the filter
    *inside* `$apply` is the only form that works (see the module docstring). Doing the
    dedupe server-side matters: the alternative is pulling every underlying row back and
    reducing locally, which for observations is hundreds of thousands of rows to recover
    a list a fraction of that size.
    """
    apply_expr = f"filter({where})/groupby(({column}))" if where else f"groupby(({column}))"
    # safe="" would encode the parentheses and commas $apply's own grammar needs, so
    # only the characters that must not reach the wire raw are escaped: spaces, quotes.
    query = f"$apply={quote(apply_expr, safe='()/,')}&$top={top}"

    values = []
    for row in iter_rows(
        path, query, token=token, base_url=base_url, prefix=prefix, get=get
    ):
        value = row.get(column)
        if value is not None:
            values.append(value)
    return values
