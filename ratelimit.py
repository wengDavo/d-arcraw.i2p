"""
Token-bucket rate limiting.

One primitive serves two of the listed issues, because they are the same shape at
different keys:

- Per-domain politeness (issue 7): the owner of a site throttles its own requests
  to that site. Because rendezvous gives a site exactly one owner, a single local
  bucket per domain is the whole politeness story. There is no central orchestrator
  to enforce it across peers, and none is needed: no second peer is scraping that
  site to coordinate with.
- Per-origin netDb admission (issue 1): a bucket keyed by the publishing identity
  caps how fast any one origin can inject records, so a node cannot flood the
  catalog regardless of how many records it signs.

The clock is injectable so the behavior is deterministic under test and can be
driven by a simulated timeline.
"""
import time as _time


class TokenBucket:
    """capacity tokens, refilled at rate per second, each take() spends one.
    Bursts up to capacity, then paced at rate."""

    def __init__(self, rate: float, capacity: float = None, clock=_time.monotonic):
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else rate)
        self.clock = clock
        self.tokens = self.capacity
        self._last = clock()

    def _refill(self):
        now = self.clock()
        if now > self._last:
            self.tokens = min(self.capacity, self.tokens + (now - self._last) * self.rate)
            self._last = now

    def take(self, n: float = 1.0) -> bool:
        self._refill()
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

    def wait_time(self, n: float = 1.0) -> float:
        """Seconds until n tokens would be available; 0 if available now."""
        self._refill()
        if self.tokens >= n:
            return 0.0
        return (n - self.tokens) / self.rate


class PerKeyRateLimiter:
    """A bucket per key (domain, origin, ...), created on first sight. Idle keys
    can be reaped so the table does not grow without bound on a long run."""

    def __init__(self, rate: float, capacity: float = None, clock=_time.monotonic):
        self.rate = rate
        self.capacity = capacity
        self.clock = clock
        self._buckets = {}

    def _bucket(self, key: str) -> TokenBucket:
        b = self._buckets.get(key)
        if b is None:
            b = TokenBucket(self.rate, self.capacity, self.clock)
            self._buckets[key] = b
        return b

    def allow(self, key: str, n: float = 1.0) -> bool:
        return self._bucket(key).take(n)

    def wait_time(self, key: str, n: float = 1.0) -> float:
        return self._bucket(key).wait_time(n)

    def reap(self, max_idle: float = 300.0):
        """Drop buckets untouched for longer than max_idle. A bucket idle that long
        would have refilled to full, so recreating it fresh on next use is
        behaviorally identical (assuming max_idle * rate >= capacity, true for sane
        configs). Keeps the table bounded on a long run."""
        now = self.clock()
        for key in [k for k, b in self._buckets.items() if now - b._last > max_idle]:
            del self._buckets[key]
