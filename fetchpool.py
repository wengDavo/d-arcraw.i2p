"""
Proxy and session management for the fetch layer.

The listed issue is written for clearnet scraping: a pool of residential or
datacenter IPs to rotate through, backoff when one gets blocked, and cookie
sessions to look like a returning browser. Most of that does not translate to I2P,
and pretending it does would be wrong, so the layer is split by where the target
lives:

- I2P targets (the common case) are reached through the I2P HTTP proxy, usually
  127.0.0.1:4444. The target sees an I2P destination, not an IP, so there is no IP
  to rotate and residential pools are meaningless. The real rotation knob is the
  outbound client tunnel / destination: scraping a site from a rotating set of
  local destinations spreads load and avoids one destination being throttled by a
  target. Cookie sessions still matter for stateful eepsites.
- Clearnet targets (mirrors D'Arcraw indexes to mark a site multi-homed) are where
  proxy rotation, backoff, and cookies apply as written.

Both share the pool, backoff, and session machinery below. The network call is an
injectable `opener`, so the policy is testable with no live proxy and the real
openers (urllib through the I2P proxy, or through a clearnet proxy) drop in behind
the same interface.
"""
import time as _time
from dataclasses import dataclass, field


# --- cookie session ----------------------------------------------------------

class Session:
    """Minimal per-host session: cookie jar plus sticky headers. Cookie parsing is
    deliberately simple (name=value up to the first ';'); swap in http.cookies for
    attribute handling if a target needs it."""

    def __init__(self, headers: dict = None):
        self.cookies = {}
        self.headers = dict(headers or {})

    def absorb(self, set_cookie_values):
        for sc in set_cookie_values or []:
            first = sc.split(";", 1)[0].strip()
            if "=" in first:
                name, value = first.split("=", 1)
                self.cookies[name.strip()] = value.strip()

    def request_headers(self) -> dict:
        h = dict(self.headers)
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        return h


# --- proxy pool with backoff -------------------------------------------------

@dataclass
class _ProxyEntry:
    proxy: str
    failures: int = 0
    blocked_until: float = 0.0


class ProxyPool:
    """Round-robin over proxies, skipping any in backoff. A failure schedules an
    exponential cooldown (base * 2**failures, capped); a success clears it. An empty
    pool means direct (one implicit None proxy that never backs off), which is the
    normal I2P case where the single I2P proxy is the route."""

    def __init__(self, proxies=None, base_backoff: float = 2.0,
                 max_backoff: float = 300.0, clock=_time.monotonic):
        self.clock = clock
        self.base = base_backoff
        self.max = max_backoff
        self._entries = [_ProxyEntry(p) for p in (proxies or [None])]
        self._rr = 0

    def pick(self):
        now = self.clock()
        n = len(self._entries)
        for _ in range(n):
            e = self._entries[self._rr % n]
            self._rr += 1
            if e.blocked_until <= now:
                return e.proxy
        return None               # every proxy is cooling down

    def _entry(self, proxy):
        for e in self._entries:
            if e.proxy == proxy:
                return e
        return None

    def report_failure(self, proxy):
        e = self._entry(proxy)
        if e is None:
            return
        e.failures += 1
        e.blocked_until = self.clock() + min(self.max, self.base * (2 ** (e.failures - 1)))

    def report_success(self, proxy):
        e = self._entry(proxy)
        if e is not None:
            e.failures = 0
            e.blocked_until = 0.0


# --- fetch backends ----------------------------------------------------------

@dataclass
class FetchResult:
    ok: bool
    status: int = 0
    content: bytes = b""
    media: list = field(default_factory=list)
    set_cookie: list = field(default_factory=list)


class FetchBackend:
    """fetch(url, session, proxy) -> FetchResult. `opener(url, proxy, headers)`
    returns (status, body_bytes, resp_headers) and is where the real network lives."""

    def __init__(self, opener):
        self._opener = opener

    def fetch(self, url: str, session: Session, proxy) -> FetchResult:
        status, body, headers = self._opener(url, proxy, session.request_headers())
        set_cookie = headers.get("Set-Cookie", []) if headers else []
        if isinstance(set_cookie, str):
            set_cookie = [set_cookie]
        ok = 200 <= status < 300
        return FetchResult(ok=ok, status=status, content=body or b"", set_cookie=set_cookie)


class I2PFetchBackend(FetchBackend):
    """Fetches eepsites through the I2P HTTP proxy. `proxy` here names the outbound
    client tunnel/destination to rotate, not an IP. The default opener routes urllib
    through 127.0.0.1:4444; inject a different opener to use a SAM-built stream."""

    def __init__(self, opener=None, i2p_http_proxy: str = "127.0.0.1:4444"):
        super().__init__(opener or _default_i2p_opener(i2p_http_proxy))


class ClearnetFetchBackend(FetchBackend):
    """Fetches clearnet mirror URLs. `proxy` is a real proxy to rotate; backoff and
    cookies apply as on any clearnet scraper."""
    pass


def _default_i2p_opener(i2p_http_proxy: str):
    def opener(url, proxy, headers):
        import urllib.request
        handler = urllib.request.ProxyHandler({"http": i2p_http_proxy, "https": i2p_http_proxy})
        o = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, headers=headers or {})
        with o.open(req, timeout=60) as resp:
            body = resp.read()
            return resp.status, body, dict(resp.headers)
    return opener


# --- the pool that ties it together -----------------------------------------

class FetchPool:
    """One fetch entry point for the orchestrator. Keeps a session per host, picks a
    proxy, retries with backoff, and returns (content, media) so it drops straight
    into the crawler's `fetcher` slot. Returns None when the fetch cannot be made,
    which the crawler already treats as a zero-reward dead address."""

    def __init__(self, backend: FetchBackend, proxy_pool: ProxyPool = None,
                 max_retries: int = 3, default_headers: dict = None):
        self.backend = backend
        self.proxies = proxy_pool or ProxyPool()
        self.max_retries = max_retries
        self.default_headers = dict(default_headers or {"User-Agent": "darcraw/0"})
        self._sessions = {}

    @staticmethod
    def host_of(url: str) -> str:
        rest = url.split("://", 1)[-1]
        return rest.split("/", 1)[0]

    def session_for(self, host: str) -> Session:
        s = self._sessions.get(host)
        if s is None:
            s = Session(self.default_headers)
            self._sessions[host] = s
        return s

    def fetch(self, url: str):
        host = self.host_of(url)
        session = self.session_for(host)
        for _ in range(self.max_retries):
            proxy = self.proxies.pick()
            if proxy is None and self.proxies._entries and self.proxies._entries[0].proxy is not None:
                return None                      # all proxies cooling down
            try:
                res = self.backend.fetch(url, session, proxy)
            except Exception:
                self.proxies.report_failure(proxy)
                continue
            if res.ok:
                self.proxies.report_success(proxy)
                session.absorb(res.set_cookie)
                return res.content, res.media
            self.proxies.report_failure(proxy)
        return None

    def as_fetcher(self):
        """The callable the crawler expects: fetch(url) -> (content, media) | None."""
        return self.fetch
