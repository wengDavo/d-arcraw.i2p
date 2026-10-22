"""
Coordination sketches for the distributed scrape.

Three demoscene-lineage structures carry the distributed back-end, and all three
are stdlib only (hashing via blake2b with a keyed salt, no mmh3):

- Rendezvous (HRW) hashing assigns each eepsite to a stable owner peer with no
  coordinator. One owner per site is what makes politeness local: only the owner
  scrapes a site, so two peers never hammer it at once, and the per-domain rate
  limit lives on that one peer instead of in a central orchestrator.
- HyperLogLog estimates how many distinct addresses a peer (or the whole network,
  by register-wise merge) has seen, at ~1.5 KB fixed. The crawler reads the
  novelty of a tick (new distinct / attempted) as a feature, so the policy learns
  to prefer frontiers that still surface unseen content and to back off ones that
  have gone stale.
- IBLT reconciles two peers' seen-sets by shipping cells proportional to the
  *difference*, not the set. This is the decentralized replacement for a central
  dedup store: peers subtract IBLTs and peel out exactly which addresses one has
  that the other lacks.
"""
import hashlib
import math


def _h64(data: bytes, seed: int) -> int:
    """64-bit keyed hash. blake2b salt is capped at 16 bytes, which is plenty for a seed."""
    salt = seed.to_bytes(16, "big")
    return int.from_bytes(hashlib.blake2b(data, digest_size=8, salt=salt).digest(), "big")


# --- rendezvous / highest-random-weight hashing -----------------------------

def _weight(peer: str, site: str) -> int:
    return _h64((peer + "\x00" + site).encode(), 0)


def owner(site: str, peers) -> str:
    """The single peer responsible for a site. Stable under membership churn:
    adding or dropping a peer only reassigns the sites whose top weight moved."""
    return max(peers, key=lambda p: _weight(p, site))


def owners(site: str, peers, r: int):
    """Top-r peers for a site, for r-way redundancy so a site is still covered
    when its primary owner is down. Highest weight first."""
    return sorted(peers, key=lambda p: _weight(p, site), reverse=True)[:r]


def owns(peer: str, site: str, peers, r: int = 1) -> bool:
    return peer in owners(site, peers, r)


# --- HyperLogLog -------------------------------------------------------------

class HyperLogLog:
    """Cardinality estimate over distinct items. p register bits -> 2**p registers.
    p=10 is ~1024 registers (~1.5 KB) and a few-percent standard error, fine for a
    coverage signal. Merge is register-wise max, which is exactly what makes a
    network-wide estimate possible: union the registers, not the sets."""

    def __init__(self, p: int = 10):
        self.p = p
        self.m = 1 << p
        self.reg = bytearray(self.m)

    def add(self, item: str):
        h = _h64(item.encode(), 1)
        idx = h >> (64 - self.p)                 # top p bits pick the register
        rest = (h << self.p) & ((1 << 64) - 1)   # remaining bits, left-justified
        rank = 1
        while rank <= 64 - self.p and not (rest >> (64 - rank)) & 1:
            rank += 1
        if rank > self.reg[idx]:
            self.reg[idx] = rank

    def merge(self, other: "HyperLogLog"):
        if other.p != self.p:
            raise ValueError("HLL precision mismatch")
        for i in range(self.m):
            if other.reg[i] > self.reg[i]:
                self.reg[i] = other.reg[i]

    def estimate(self) -> float:
        m = self.m
        alpha = 0.7213 / (1 + 1.079 / m) if m >= 128 else 0.709
        s = sum(2.0 ** -r for r in self.reg)
        raw = alpha * m * m / s
        if raw <= 2.5 * m:                       # small-range correction
            zeros = self.reg.count(0)
            if zeros:
                return m * math.log(m / zeros)
        return raw


# --- Invertible Bloom Lookup Table -------------------------------------------

class IBLT:
    """Set reconciliation sized to the difference, not the set. Insert the same
    elements on two peers, subtract one table from the other, and decode peels the
    elements that differ. Size cells at a small multiple of the expected difference,
    not the catalog: two peers 100k-strong that differ by 50 reconcile in a few
    hundred cells."""

    def __init__(self, cells: int = 256, k: int = 4):
        self.cells = cells
        self.k = k
        self.count = [0] * cells
        self.keysum = [0] * cells
        self.hashsum = [0] * cells

    def _positions(self, key: int):
        pos = set()
        i = 0
        while len(pos) < self.k:
            pos.add(_h64(key.to_bytes(8, "big"), 10 + i) % self.cells)
            i += 1
        return pos

    @staticmethod
    def _keyhash(key: int) -> int:
        return _h64(key.to_bytes(8, "big"), 99)

    def _apply(self, key: int, sign: int):
        kh = self._keyhash(key)
        for j in self._positions(key):
            self.count[j] += sign
            self.keysum[j] ^= key
            self.hashsum[j] ^= kh

    def insert(self, key: int):
        self._apply(key, +1)

    def subtract(self, other: "IBLT") -> "IBLT":
        if self.cells != other.cells or self.k != other.k:
            raise ValueError("IBLT geometry mismatch")
        d = IBLT(self.cells, self.k)
        for j in range(self.cells):
            d.count[j] = self.count[j] - other.count[j]
            d.keysum[j] = self.keysum[j] ^ other.keysum[j]
            d.hashsum[j] = self.hashsum[j] ^ other.hashsum[j]
        return d

    def decode(self):
        """Peel pure cells. Returns (only_in_self, only_in_other, ok). ok is False
        if the tables differed by more than the cells could carry."""
        a, b = set(), set()
        count = list(self.count)
        keysum = list(self.keysum)
        hashsum = list(self.hashsum)
        changed = True
        while changed:
            changed = False
            for j in range(self.cells):
                if count[j] in (1, -1) and hashsum[j] == self._keyhash(keysum[j]):
                    key = keysum[j]
                    (a if count[j] == 1 else b).add(key)
                    sign = count[j]
                    for p in self._positions(key):
                        count[p] -= sign
                        keysum[p] ^= key
                        hashsum[p] ^= self._keyhash(key)
                    changed = True
        ok = all(c == 0 for c in count) and all(h == 0 for h in hashsum)
        return a, b, ok
