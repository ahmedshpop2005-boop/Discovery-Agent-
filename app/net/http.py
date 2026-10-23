"""Bounded, classified HTTP client shared by the Web tools.

The goal is honesty under failure: every exchange is classified (2xx, 3xx,
401, 403, 404, 429, 5xx, timeout, DNS, TLS, connection), retries happen only
for transient failures with exponential backoff + jitter, and a partial result
is preserved instead of being reported as a clean scan.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.contracts.enums import ResponseClass
from app.safety.redaction import redact

_MAX_BODY = 200_000
_SNIPPET = 240

_TRANSIENT_STATUS = {429, 500, 502, 503, 504, 507, 508, 509, 521, 522, 523, 524}
_DETERMINISTIC_STATUS = {400, 401, 403, 404, 405, 406, 410, 422}

_EDGE_TOKENS: dict[str, tuple[str, ...]] = {
    "cloudflare": ("cf-ray", "cf-cache-status", "server: cloudflare", "__cfduid", "cf_clearance"),
    "akamai": ("akamai-grn", "x-akamai-", "server: akamaighost"),
    "cloudfront": ("x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront"),
    "fastly": ("x-fastly-", "x-served-by"),
    "imperva": ("x-iinfo", "incap_ses", "visid_incap"),
    "sucuri": ("x-sucuri-",),
    "azure-front-door": ("x-azure-ref", "x-fd-healthprobe"),
}


@dataclass
class HttpResult:
    url: str
    method: str = "GET"
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie: list[str] = field(default_factory=list)
    body: bytes = b""
    response_class: ResponseClass = ResponseClass.UNKNOWN
    error: str | None = None
    attempts: int = 0
    retries: int = 0
    retry_reasons: list[str] = field(default_factory=list)
    edge_indicators: list[str] = field(default_factory=list)
    elapsed_ms: int = 0
    redirect_chain: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300

    @property
    def edge_likely(self) -> bool:
        return bool(self.edge_indicators)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def snippet(self, limit: int = _SNIPPET) -> str:
        import re

        collapsed = re.sub(r"\s+", " ", self.text).strip()
        return redact(collapsed[:limit])


def classify_response(status: int | None) -> ResponseClass:
    """Map an HTTP status to a deterministic class (no vendor assumptions)."""
    if status is None:
        return ResponseClass.UNKNOWN
    if 200 <= status < 300:
        return ResponseClass.SUCCESS
    if 300 <= status < 400:
        return ResponseClass.REDIRECT
    if status == 401:
        return ResponseClass.AUTH_REQUIRED
    if status == 403:
        return ResponseClass.FORBIDDEN
    if status == 404:
        return ResponseClass.NOT_FOUND
    if status == 429:
        return ResponseClass.RATE_LIMITED
    if 500 <= status < 600:
        return ResponseClass.SERVER_ERROR
    if 400 <= status < 500:
        return ResponseClass.CLIENT_ERROR
    return ResponseClass.UNKNOWN


def classify_exception(exc: BaseException) -> ResponseClass:
    """Classify a transport error without retrying deterministic failures."""
    if isinstance(exc, httpx.TimeoutException):
        return ResponseClass.TIMEOUT
    if isinstance(exc, httpx.ConnectError):
        message = str(exc).lower()
        if any(token in message for token in ("certificate", "ssl", "tls", "cert verify")):
            return ResponseClass.TLS_ERROR
        if any(
            token in message
            for token in (
                "name or service not known",
                "nodename nor servname",
                "getaddrinfo",
                "no address associated",
                "temporary failure in name resolution",
                "dns",
            )
        ):
            return ResponseClass.DNS_FAILURE
        return ResponseClass.CONNECTION_ERROR
    if isinstance(exc, (httpx.ReadError, httpx.WriteError, httpx.NetworkError, httpx.ProtocolError)):
        return ResponseClass.CONNECTION_ERROR
    if isinstance(exc, httpx.HTTPError):
        return ResponseClass.CONNECTION_ERROR
    return ResponseClass.CONNECTION_ERROR


def detect_edge(headers: dict[str, str], body: bytes = b"") -> list[str]:
    """Return specific CDN/WAF indicators, never a generic guess.

    A 403 alone is *not* attributed to Cloudflare; only distinctive headers or
    cookies produce an indicator.
    """
    lowered = {key.lower(): str(value).lower() for key, value in headers.items()}
    haystack = "\n".join(f"{key}: {value}" for key, value in lowered.items())
    cookie_header = lowered.get("set-cookie", "")
    found: list[str] = []
    for vendor, tokens in _EDGE_TOKENS.items():
        if any(token in haystack or token in cookie_header for token in tokens):
            found.append(vendor)
    return sorted(set(found))


def _retry_after_seconds(headers: dict[str, str]) -> float | None:
    value = headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        return None


def _backoff(attempt: int, base: float, maximum: float, jitter: float) -> float:
    delay = min(maximum, base * (2**attempt))
    if jitter > 0:
        delay += random.uniform(0, jitter)  # noqa: S311 - jitter, not crypto
    return min(maximum + jitter, delay)


def request_with_retries(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
    retries: int | None = None,
    backoff: float | None = None,
    max_backoff: float | None = None,
    jitter: float | None = None,
    follow_redirects: bool = False,
    client: httpx.Client | None = None,
) -> HttpResult:
    """Perform one bounded request with retries for transient failures only.

    ``401/403/404`` and other deterministic client errors are returned after a
    single attempt. ``429``/``5xx``/timeouts/connection resets are retried up
    to ``retries`` times with exponential backoff (+ optional jitter).
    """
    timeout = settings.http_timeout if timeout is None else timeout
    retries = settings.http_retries if retries is None else max(0, retries)
    backoff = settings.http_retry_backoff if backoff is None else max(0.0, backoff)
    max_backoff = settings.http_retry_max_backoff if max_backoff is None else max(0.0, max_backoff)
    jitter = settings.http_retry_jitter if jitter is None else max(0.0, jitter)

    request_headers = {"User-Agent": settings.user_agent}
    request_headers.update(headers or {})

    owned_client = client is None
    if owned_client:
        client = httpx.Client(follow_redirects=follow_redirects, timeout=timeout)
    assert client is not None

    result = HttpResult(url=url, method=method.upper())
    started = time.perf_counter()
    attempt = 0
    try:
        for attempt in range(retries + 1):
            result.attempts = attempt + 1
            try:
                response = client.request(
                    method,
                    url,
                    headers=request_headers,
                    follow_redirects=follow_redirects,
                )
            except Exception as exc:  # transport error: classify, maybe retry
                result.response_class = classify_exception(exc)
                result.error = redact(f"{type(exc).__name__}: {exc}")
                transient = result.response_class in {
                    ResponseClass.TIMEOUT,
                    ResponseClass.CONNECTION_ERROR,
                }
                if transient and attempt < retries:
                    result.retries += 1
                    result.retry_reasons.append(result.response_class.value)
                    time.sleep(_backoff(attempt, backoff, max_backoff, jitter))
                    continue
                break

            result.status_code = response.status_code
            result.final_url = str(response.url)
            result.response_class = classify_response(response.status_code)
            result.headers = {key.lower(): redact(value) for key, value in response.headers.items()}
            result.set_cookie = [redact(value) for value in response.headers.get_list("set-cookie")]
            result.content_type = result.headers.get("content-type")
            result.body = response.content[:_MAX_BODY]
            result.redirect_chain = [str(item.url) for item in response.history]
            result.edge_indicators = detect_edge(result.headers, result.body)

            retryable = response.status_code in _TRANSIENT_STATUS
            if retryable and attempt < retries:
                result.retries += 1
                result.retry_reasons.append(f"http-{response.status_code}")
                delay = _retry_after_seconds(result.headers)
                if delay is None:
                    delay = _backoff(attempt, backoff, max_backoff, jitter)
                time.sleep(min(max_backoff + jitter, delay))
                continue
            break
    finally:
        if owned_client:
            client.close()
        result.elapsed_ms = int((time.perf_counter() - started) * 1000)

    return result


def is_retryable_status(status: int | None) -> bool:
    return status in _TRANSIENT_STATUS


def is_deterministic_status(status: int | None) -> bool:
    return status in _DETERMINISTIC_STATUS


def safe_url_origin(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    if not parsed.scheme or not parsed.netloc:
        return url
    return f"{parsed.scheme}://{parsed.netloc}"
