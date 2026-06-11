"""
SNI-preserving IP-pinning transport for httpx.

Closes the TOCTOU DNS-rebind window between invoke-time revalidation and the
actual TCP connection: once `revalidate_upstream_ip_at_invoke` has validated
the resolved IP, this transport pins every outbound TCP connection to that IP
while keeping the original hostname in the Host header and the TLS SNI
extension.  The OS resolver is never consulted again for the lifetime of this
transport.

httpx's native ``sni_hostname`` request extension (available since httpx 0.24)
is the mechanism used: we rewrite the request URL to point at the pinned IP and
inject the original hostname as the SNI name.  TLS certificate validation still
runs against the original hostname — a cert mismatch will raise an error as
normal.

Usage::

    pinned_ips = await revalidate_upstream_ip_at_invoke(
        upstream_url=upstream_url,
        registered_allowlist_entry=registered_allowlist_entry,
    )
    transport = PinnedIPTransport(
        pinned_ip=pinned_ips[0],
        original_hostname=parsed_host,
    )
    async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
        resp = await client.post(upstream_url, ...)
"""
from __future__ import annotations

import httpx


class PinnedIPTransport(httpx.AsyncHTTPTransport):
    """
    httpx async transport that pins every TCP connection to a pre-validated IP.

    The original hostname is preserved in:
    - The ``Host`` request header (required by HTTP/1.1 virtual hosting).
    - The ``sni_hostname`` request extension (used by httpcore/httpx for TLS
      Server Name Indication, ensuring certificate validation uses the hostname
      and not the raw IP).

    This eliminates the TOCTOU window: after invoke-time SSRF/rebind validation
    the OS resolver is never consulted again for this request.

    Args:
        pinned_ip:         IPv4 or IPv6 address string returned by
                           ``revalidate_upstream_ip_at_invoke``.
        original_hostname: The hostname portion of the upstream URL (no port).
                           Used for SNI and Host header.
        **kwargs:          Forwarded to ``httpx.AsyncHTTPTransport.__init__``
                           (e.g. ``verify``, ``cert``, ``retries``).
    """

    def __init__(self, pinned_ip: str, original_hostname: str, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._pinned_ip = pinned_ip
        self._original_hostname = original_hostname

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """
        Rewrite the target URL to use the pinned IP, keep Host/SNI correct.

        Steps:
        1. Replace the URL host with the pinned IP so httpcore connects to that
           address (no resolver call).
        2. Force the ``Host`` header to the original hostname — HTTP/1.1
           requires this for name-based virtual hosting; some upstreams reject
           requests with an IP in Host.
        3. Inject the ``sni_hostname`` extension so httpcore presents the
           original hostname during TLS negotiation (SNI) and validates the
           server cert against it, not against the IP string.
        """
        # Rewrite the URL: keep scheme/port/path/query, swap host to pinned IP.
        pinned_url = request.url.copy_with(host=self._pinned_ip)

        # Build a mutable headers mapping; ensure Host is the original name.
        headers = dict(request.headers)
        headers["host"] = self._original_hostname

        # Carry forward existing extensions (e.g. timeout) and add sni_hostname.
        extensions: dict[str, object] = dict(request.extensions)
        extensions["sni_hostname"] = self._original_hostname.encode("ascii")

        pinned_request = httpx.Request(
            method=request.method,
            url=pinned_url,
            headers=headers,
            stream=request.stream,
            extensions=extensions,
        )
        return await super().handle_async_request(pinned_request)
