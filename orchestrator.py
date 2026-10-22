"""
Distributed scrape orchestrator.

This is the back-end the issue list describes, assembled from the pieces around it
and built to stay decentralized. There is no central orchestrator process; every
peer runs this same object, and the coordination comes from rendezvous hashing, not
from a coordinator.

What a tick does:
  1. Admission. A candidate URL is admitted only if it is unseen (Bloom dedup,
     issue 5) and this peer is a rendezvous owner of its site (issue 7's politeness,
     made structural: one owner per site means no two peers scrape it at once).
     Non-owned or duplicate URLs are dropped here, before any fetch.
  2. Release under politeness. `pump` releases admitted candidates into the learned
     frontier only as each site's per-domain token bucket allows (issue 7). The
     bucket is local because the site has one owner, so no cross-peer coordination
     is required.
  3. Learned ordering and fetch. The contextual bandit in crawler.py orders the
     released frontier, fetches through the proxy/session pool (issue 6), gates at
     ingestion, publishes survivors to the netDb, and learns online from the
     outcome. This is the deep-learning aspect: the policy keeps re-pointing the
     scrape at frontiers that still surface new, native content.
  4. Real-time indexing. Each published item enters the OR-Set catalog, which
     range-based anti-entropy spreads to the k closest peers, so every peer's index
     tracks the network continuously rather than in batch rebuilds.

Cross-peer dedup (issue 5, network-wide) is `reconcile_seen`: two peers exchange an
IBLT of their seen-sets and learn exactly the addresses the other already covered,
in traffic proportional to the difference, with no central Redis.

The gate is untouched and still runs at ingestion and at every store-admission in
netdb.py. Nothing here can publish past it.
"""
from crawler import Crawler, Candidate
from dedup import SeenSet
from ratelimit import PerKeyRateLimiter
from sketches import HyperLogLog, IBLT, owners
from fetchpool import FetchPool


def host_of(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0]


def _url_key(url: str) -> int:
    import hashlib
    return int.from_bytes(hashlib.blake2b(url.encode(), digest_size=8).digest(), "big")


class Orchestrator:
    def __init__(self, node, gate, fetch_pool: FetchPool, self_peer: str, peers,
                 dim: int, redundancy: int = 1,
                 per_domain_rate: float = 0.5, per_domain_burst: float = 2.0,
                 seen: SeenSet = None, classifier=None, iblt_cells: int = 1024,
                 clock=None):
        import time
        self.node = node
        self.gate = gate
        self.fetch_pool = fetch_pool
        self.self_peer = self_peer
        self.peers = list(peers) if peers else [self_peer]
        self.redundancy = redundancy
        self.seen = seen or SeenSet()
        self.clock = clock or time.monotonic
        self.domain_limiter = PerKeyRateLimiter(per_domain_rate, per_domain_burst,
                                                clock=self.clock)
        self.crawler = Crawler(node, gate, fetch_pool.as_fetcher(), dim,
                               classifier=classifier)
        self.coverage = HyperLogLog(12)          # distinct sites this peer has seen
        self._pending = []                       # admitted, awaiting a politeness slot
        self._seen_iblt = IBLT(iblt_cells)
        self.stats = {"admitted": 0, "dup": 0, "not-owned": 0, "released": 0}

    # --- membership ----------------------------------------------------------
    def set_peers(self, peers):
        """Rendezvous assignment follows this list; update it as the peer set
        changes and ownership reshuffles only for the sites whose top owner moved."""
        self.peers = list(peers)

    def owns(self, site: str) -> bool:
        return self.self_peer in owners(site, self.peers, self.redundancy)

    # --- admission -----------------------------------------------------------
    def submit(self, url: str, source: str, features: list) -> str:
        """Returns why: 'dup', 'not-owned', or 'admitted'. Dedup first so a URL this
        peer does not own still counts as seen and is not reconsidered every round."""
        site = host_of(url)
        if self.seen.seen(url):
            self.stats["dup"] += 1
            return "dup"
        self.seen.mark(url)
        self._seen_iblt.insert(_url_key(url))
        self.coverage.add(site)
        if not self.owns(site):
            self.stats["not-owned"] += 1
            return "not-owned"               # the owning peer will scrape it
        self._pending.append(Candidate(url, source, features))
        self.stats["admitted"] += 1
        return "admitted"

    # --- one orchestration tick ---------------------------------------------
    def pump(self, consolidate_every: int = 10):
        """Release politeness-ready candidates into the learned frontier, then run
        one crawl tick. Returns the number released this tick."""
        released = 0
        still = []
        for cand in self._pending:
            if released >= self.crawler.tick_budget:
                still.append(cand)
                continue
            site = host_of(cand.url)
            if self.domain_limiter.allow(site):
                self.crawler.submit(cand)
                released += 1
            else:
                still.append(cand)           # not yet polite to fetch; hold it
        self._pending = still
        self.stats["released"] += released
        self.crawler.tick()
        self._ticks = getattr(self, "_ticks", 0) + 1
        if self._ticks % consolidate_every == 0:
            self.crawler.consolidate()
        return released

    def pending(self) -> int:
        return len(self._pending)

    # --- network-wide dedup reconciliation (issue 5, decentralized) ----------
    def seen_iblt(self) -> IBLT:
        """Hand this to a peer; they subtract to find exactly which addresses each
        side is missing, in difference-sized traffic."""
        return self._seen_iblt

    def reconcile_seen(self, other: IBLT):
        """Learn the addresses a peer has seen that we have not. We cannot recover
        the URL strings from hashes, so this marks their *keys* seen to suppress
        re-fetch; the catalog anti-entropy carries the actual content. Returns
        (learned_from_peer, we_had_extra, decoded_ok)."""
        only_mine, only_theirs, ok = self._seen_iblt.subtract(other).decode()
        if ok:
            for key in only_theirs:
                self._seen_iblt.insert(key)
        return len(only_theirs), len(only_mine), ok

    # --- real-time index spread ---------------------------------------------
    def reconcile_index(self, peer):
        """Run netDb anti-entropy with a peer so freshly published items propagate."""
        self.node.anti_entropy(peer)
