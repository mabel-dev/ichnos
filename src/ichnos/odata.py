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

MAX_TOP = 100000
"""The service's ceiling for a single request's `$top` - 100001 is rejected with
"$top must be between 0 and 100000". Set to exactly the ceiling, and that is not just
about efficiency: a read that fits in one page is the only read this feed answers
correctly.

Paginated `$apply` results are unstable. The row *count* is right and matches the
equivalent SQL exactly, but the contents are not: rows are duplicated and others
dropped, differently on every run. Measured against ssh observations, one query,
same data, minutes apart:

    $top=100000 (1 page)    86184 rows, 86184 distinct ip, 0 duplicated
    $top=100000 (again)     86184 rows, 86184 distinct ip, 0 duplicated - identical
    $top=25000  (4 pages)   86184 rows, 61348 distinct ip, 24836 duplicated
    $top=25000  (again)     86184 rows, 57882 distinct ip, 28302 duplicated
    $top=10000  (9 pages)   86184 rows, 58991 distinct ip

SQL over the same window returns 86184 rows and 86184 distinct ip, so the engine, the
filter and the aggregate are all correct - each page appears to be a fresh execution of
an unordered query, so `$skip` lands somewhere different every time.

The damage was silent. Nothing errors, the row count looks right, and the derived
known-responsive lists simply carried duplicates and were missing hosts: 130408 lines
for 80048 real http hosts, 123701 for 90221 https. Hence `_reject_paged_result` below -
at 100000 nothing this project reads pages today, and the day something does, it must
fail loudly rather than quietly produce a plausible wrong answer."""


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
    single_page: bool = False,
) -> Iterator[Dict[str, Any]]:
    """Yield every row of a query, following `@odata.nextLink` until the feed stops
    offering one.

    `single_page=True` refuses to follow the link at all and raises instead, for callers
    whose answer would be silently wrong if it did - see MAX_TOP for the measurements.
    Paging this feed returns the right number of rows with the wrong rows in them.

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
        if single_page:
            raise ODataError(
                f"{path}: result needs more than one page at $top={MAX_TOP}, and paged "
                "reads from this feed are not trustworthy - the row count is right but "
                "rows are duplicated and dropped non-deterministically (see MAX_TOP). "
                "Narrow the query or fix the feed; do not page it."
            )
        # Relative, and already percent-encoded - concatenate, never re-encode.
        url = next_link if next_link.startswith("http") else f"{base_url}{next_link}"

    logger.info("odata: %s read in %d page(s)", path, pages)


def grouped_max(
    path: str,
    column,
    max_column: str,
    alias: str,
    *,
    where: str = "",
    token: Optional[str] = None,
    base_url: str = DEFAULT_ODATA_BASE,
    prefix: str = DEFAULT_ODATA_PREFIX,
    top: int = MAX_TOP,
    order_by: Optional[str] = None,
    get: Optional[Callable[..., Any]] = None,
) -> List[Dict[str, Any]]:
    """One row per distinct `column`, carrying `max(max_column)` as `alias`.

    `$apply=filter(...)/groupby((col),aggregate(other with max as alias))`, confirmed
    against the live feed. The aggregate is what turns a plain distinct list into an
    ordered one without a second query or a stored cursor - see responsive.py.

    `column` may be a sequence, which groups by the tuple - `groupby((ip,status),...)`,
    also confirmed against the live feed rather than assumed from the OData spec. That
    is what lets responsive.py answer two questions in one round trip ("did this host
    ever succeed" and "when did we last try it") instead of issuing a second query and
    joining the results here. Grouping is what the feed is for.

    `order_by` sorts server-side, and it may name the aggregate alias - `$orderby=last_at`
    against a `last_at` produced by the aggregate is accepted and correct, verified
    against the live feed. This module used to assert the opposite and sort client-side,
    which is what forced whole-result reads: to find the thousand oldest hosts it pulled
    all 130408 of them, and so needed a page size it did not have. Ordering here instead
    turns `$top` from a completeness problem into a deliberate truncation of the end of
    the queue nobody reaches.
    """
    columns = [column] if isinstance(column, str) else list(column)
    inner = f"groupby(({','.join(columns)}),aggregate({max_column} with max as {alias}))"
    apply_expr = f"filter({where})/{inner}" if where else inner
    query = f"$apply={quote(apply_expr, safe='()/,')}"
    if order_by:
        query += f"&$orderby={quote(order_by, safe='')}"
    query += f"&$top={top}"
    return [
        row
        for row in iter_rows(path, query, token=token, base_url=base_url, prefix=prefix,
                             get=get, single_page=True)
        if all(row.get(c) is not None for c in columns)
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
        path, query, token=token, base_url=base_url, prefix=prefix, get=get,
        single_page=True,
    ):
        value = row.get(column)
        if value is not None:
            values.append(value)
    return values
