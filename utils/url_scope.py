"""Deterministic URL scope checks for browser-driven scanning.

The scanner used to test scope with substring expressions such as
``target_domain in request_url``.  That is unsafe for short Docker service
names (for example, ``web`` also occurs in ``chromewebstore.google.com`` and
in many unrelated URL paths).  This module compares parsed HTTP origins
instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urljoin, urlsplit


_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Origin:
    scheme: str
    hostname: str
    port: int


def _origin(url: str) -> Optional[Origin]:
    """Return a normalized HTTP(S) origin, or ``None`` for an invalid URL."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in _DEFAULT_PORTS or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        hostname = parsed.hostname.rstrip(".").lower()
        port = parsed.port or _DEFAULT_PORTS[scheme]
        return Origin(scheme=scheme, hostname=hostname, port=port)
    except (TypeError, ValueError):
        return None


class UrlScope:
    """Exact-origin navigation scope with narrowly scoped request exceptions."""

    def __init__(self, base_url: str, request_exception_urls: Iterable[str] = ()):
        base_origin = _origin(base_url)
        if base_origin is None:
            raise ValueError(f"Invalid HTTP(S) scope base URL: {base_url!r}")
        self.base_url = base_url
        self.origin = base_origin
        self.request_exception_origins = frozenset(
            origin
            for origin in (_origin(url) for url in request_exception_urls)
            if origin is not None
        )

    def resolve(self, url: str, current_url: Optional[str] = None) -> Optional[str]:
        """Resolve a relative URL against the current page (or the scope base)."""
        if not isinstance(url, str) or not url.strip():
            return None
        return urljoin(current_url or self.base_url, url.strip())

    def allows_navigation(self, url: str, current_url: Optional[str] = None) -> bool:
        resolved = self.resolve(url, current_url=current_url)
        return resolved is not None and _origin(resolved) == self.origin

    def allows_request(self, url: str, current_url: Optional[str] = None) -> bool:
        resolved = self.resolve(url, current_url=current_url)
        if resolved is None:
            return False
        candidate_origin = _origin(resolved)
        return candidate_origin == self.origin or candidate_origin in self.request_exception_origins

