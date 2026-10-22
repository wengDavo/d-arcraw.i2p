"""
Content fingerprinting for D'Arcraw (Stage 2).

SimHash over word shingles gives a 64-bit fingerprint where near-identical pages
sit a few bits apart. A banded LSH index makes near-duplicate lookup sub-linear,
so the crawler can ask "have I seen this content at another address" cheaply. This
is what turns the same content served from two destinations into a mirror signal.

Hashing uses blake2b (stdlib), so this module has no third-party dependency.
"""
import hashlib
import re

_WORD = re.compile(rb"[a-z0-9]+")
_TAG = re.compile(rb"<[^>]+>")


def shingles(content: bytes, k: int = 4):
    text = _TAG.sub(b" ", content).lower()
    words = _WORD.findall(text)
    if len(words) < k:
        return [b" ".join(words)] if words else []
    return [b" ".join(words[i:i + k]) for i in range(len(words) - k + 1)]


def _h64(b: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(b, digest_size=8).digest(), "big")


def simhash(tokens, bits: int = 64) -> int:
    v = [0] * bits
    for t in tokens:
        x = _h64(t)
        for i in range(bits):
            v[i] += 1 if (x >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if v[i] > 0:
            out |= (1 << i)
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def content_simhash(content: bytes) -> int:
    return simhash(shingles(content))


class SimHashIndex:
    """Banded LSH over 64-bit SimHashes. Pages that match on any band are candidates;
    candidates within `threshold` Hamming distance are reported as near-duplicates."""

    def __init__(self, bands: int = 4, threshold: int = 3):
        if 64 % bands:
            raise ValueError("bands must divide 64")
        self.bands = bands
        self.width = 64 // bands
        self.threshold = threshold
        self.buckets = [dict() for _ in range(bands)]
        self.items = {}     # key -> hash

    def _band_vals(self, h: int):
        mask = (1 << self.width) - 1
        return [(h >> (i * self.width)) & mask for i in range(self.bands)]

    def add(self, h: int, key: str):
        self.items[key] = h
        for i, bv in enumerate(self._band_vals(h)):
            self.buckets[i].setdefault(bv, set()).add(key)

    def query(self, h: int):
        cand = set()
        for i, bv in enumerate(self._band_vals(h)):
            cand |= self.buckets[i].get(bv, set())
        out = [(key, hamming(h, self.items[key])) for key in cand]
        out = [(k, d) for k, d in out if d <= self.threshold]
        out.sort(key=lambda kd: kd[1])
        return out
