"""
URL deduplication before queuing.

A scrape that re-queues addresses it has already fetched wastes tunnels and hammers
targets that rendezvous already assigned elsewhere. The check has to be cheap and
bounded in memory, because the frontier is large and the loop runs in real time.

The list asked for "Bloom filters inside Redis". Redis is a single central store,
which a decentralized netDb does not have and should not depend on, so the shapes
are split:

- `BloomFilter` + `SeenSet` are the decentralized default: each peer keeps its own
  local Bloom. No false negatives, so a "seen" answer is always right to skip; a
  bounded false-positive rate means a few genuinely-new addresses get skipped,
  which the r-way rendezvous redundancy and periodic reconciliation recover.
- Peers close the gap between their local sets with `sketches.IBLT`, shipping cells
  proportional to the difference. That is the network-wide dedup, and it needs no
  central store.
- `RedisSeenBackend` is offered for the one case where a central store is correct:
  a *single operator* running many worker processes behind one owner peer, who
  wants those workers to share a seen-set. That is one operator's own fleet, not
  the network. It is optional and guarded; absent redis, everything runs on the
  local Bloom.
"""
import hashlib


class BloomFilter:
    """Classic Bloom filter. Sized from expected item count n and target false-
    positive rate p. No false negatives: contains() == False is always true."""

    def __init__(self, n: int = 1_000_000, p: float = 0.001):
        import math
        self.m = max(8, int(-(n * math.log(p)) / (math.log(2) ** 2)))
        self.k = max(1, round((self.m / n) * math.log(2)))
        self.bits = bytearray((self.m + 7) // 8)
        self.n = 0

    def _positions(self, item: str):
        # Two base hashes combined (Kirsch-Mitzenmacher) give k positions cheaply.
        d = hashlib.blake2b(item.encode(), digest_size=16).digest()
        h1 = int.from_bytes(d[:8], "big")
        h2 = int.from_bytes(d[8:], "big") | 1
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, item: str):
        for pos in self._positions(item):
            self.bits[pos >> 3] |= 1 << (pos & 7)
        self.n += 1

    def __contains__(self, item: str) -> bool:
        return all(self.bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(item))


class SeenSet:
    """Dedup gate for the frontier. Local Bloom by default. For small or
    correctness-critical runs, exact=True keeps an exact set alongside so there are
    no false-positive skips at all (at full memory cost)."""

    def __init__(self, n: int = 1_000_000, p: float = 0.001, exact: bool = False, backend=None):
        self.bloom = BloomFilter(n, p)
        self.exact = set() if exact else None
        self.backend = backend            # optional shared store for one operator's fleet

    def seen(self, url: str) -> bool:
        if self.backend is not None and self.backend.seen(url):
            return True
        if self.exact is not None:
            return url in self.exact
        return url in self.bloom

    def mark(self, url: str):
        self.bloom.add(url)
        if self.exact is not None:
            self.exact.add(url)
        if self.backend is not None:
            self.backend.mark(url)

    def check_and_mark(self, url: str) -> bool:
        """True if newly admitted (was unseen). False if a duplicate to skip."""
        if self.seen(url):
            return False
        self.mark(url)
        return True


class RedisSeenBackend:
    """Shared seen-set for ONE operator's worker fleet, not for the network. Uses a
    Redis set; if redis is not installed, construction raises and the caller falls
    back to the local Bloom. Keep this scoped to a trusted single-operator cluster:
    a network-wide shared Redis would recentralize what the netDb exists to avoid."""

    def __init__(self, url: str = "redis://127.0.0.1:6379/0", key: str = "darcraw:seen"):
        import redis  # guarded: optional dependency
        self._r = redis.Redis.from_url(url)
        self._key = key

    def seen(self, url: str) -> bool:
        return bool(self._r.sismember(self._key, url))

    def mark(self, url: str):
        self._r.sadd(self._key, url)
