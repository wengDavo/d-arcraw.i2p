"""
Content gate for D'Arcraw. Fixed, non-learned, authoritative.

It runs at two points and is never part of any learned policy:
  1. crawler ingestion, before fetched content is published to the netDb
  2. store-admission, on every node, before content enters the store or replicates

Content that matches the blocklist never gets a CID, never enters the store,
never replicates. The blocklist is maintainer-signed: exact content hashes plus
perceptual image hashes. Licensed CSAM hash sets (PhotoDNA / NCMEC) generally
cannot be redistributed to untrusted nodes, so this ships with a signed
community-blocklist interface. That limitation is real and documented; it is the
weakest point in the whole system and is tracked as such.
"""
import hashlib
import io
from dataclasses import dataclass


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    reason: str = ""


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def dhash_bytes(image_bytes: bytes, hash_size: int = 8):
    """Perceptual hash of an image, or None if the bytes are not a decodable image."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize(
            (hash_size + 1, hash_size))
    except Exception:
        return None
    bits = 0
    idx = 0
    for y in range(hash_size):
        for x in range(hash_size):
            if img.getpixel((x, y)) > img.getpixel((x + 1, y)):
                bits |= (1 << idx)
            idx += 1
    return bits


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


class ContentGate:
    """Exact-hash and perceptual-hash blocklist check. Deny-by-match, allow otherwise."""

    def __init__(self, exact_hashes: set, perceptual_hashes: list, phash_threshold: int = 6):
        self._exact = set(exact_hashes)          # set[bytes]: sha256 digests
        self._phash = list(perceptual_hashes)    # list[int]: dHash fingerprints
        self._threshold = phash_threshold
        self._version = 0
        self._armed = True                       # constructed with an explicit list

    @classmethod
    def unarmed(cls, phash_threshold: int = 6) -> "ContentGate":
        """A gate with no verified blocklist yet. Fails closed, blocking everything
        until update() arms it with a verified list. A fresh node must arm its gate
        from a signed blocklist before it stores or replicates anything."""
        g = cls(set(), [], phash_threshold)
        g._armed = False
        return g

    def update(self, exact_hashes, perceptual_hashes, version: int) -> None:
        """Atomically swap in a newer verified blocklist and arm the gate."""
        self._exact = set(exact_hashes)
        self._phash = list(perceptual_hashes)
        self._version = int(version)
        self._armed = True

    @property
    def version(self) -> int:
        return self._version

    def check(self, content: bytes, media=None) -> GateResult:
        if not self._armed:
            return GateResult(False, "gate-unarmed")
        if sha256(content) in self._exact:
            return GateResult(False, "exact-hash-match")
        for m in (media or []):
            if sha256(m) in self._exact:
                return GateResult(False, "media-exact-hash-match")
            ph = dhash_bytes(m)
            if ph is not None:
                for bad in self._phash:
                    if hamming(ph, bad) <= self._threshold:
                        return GateResult(False, "media-perceptual-match")
        return GateResult(True)
