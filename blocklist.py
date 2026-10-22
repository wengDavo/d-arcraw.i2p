"""
Signed blocklist for D'Arcraw: distribution and update path.

The content gate is only as strong as the list it enforces, so that list is a
maintainer-signed, versioned document of exact and perceptual hashes. Trust is
spread across a maintainer set with an M-of-N threshold, so no single key is a
single point of failure or compromise. Nodes only ever move forward in version,
which blocks rollback attacks, and a node with no verified list fails closed: it
will not store or replicate until its gate is armed.

Distribution can ride the netDb, but blocklist blobs are verified by signature,
not by the content gate, so fetching one does not need an armed gate. That is what
lets a fresh node bootstrap: fetch the signed list, verify it, arm, then take part.

Uses Ed25519 from the cryptography package.
"""
import base64
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _keyid(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes_raw()[:8].hex()


def canonical_payload(version: int, created: str, exact, phash) -> bytes:
    doc = {
        "version": int(version),
        "created": created,
        "exact": sorted(h.hex() if isinstance(h, (bytes, bytearray)) else str(h) for h in exact),
        "phash": sorted(int(x) for x in phash),
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def make_blocklist(version: int, created: str, exact, phash, signing_keys) -> bytes:
    """Build a blocklist blob signed by every key in signing_keys (Ed25519 private keys)."""
    payload = canonical_payload(version, created, exact, phash)
    sigs = [{"keyid": _keyid(sk.public_key()), "sig": sk.sign(payload).hex()}
            for sk in signing_keys]
    return json.dumps({"payload_b64": base64.b64encode(payload).decode(), "sigs": sigs}).encode()


@dataclass
class MaintainerSet:
    pubkeys: dict        # keyid(str) -> Ed25519PublicKey
    threshold: int


def verify_blocklist(blob: bytes, maintainers: MaintainerSet):
    """Return (version, created, exact:set[bytes], phash:list[int]).
    Raises ValueError unless at least `threshold` distinct maintainer signatures verify."""
    doc = json.loads(blob)
    payload = base64.b64decode(doc["payload_b64"])
    good = set()
    for s in doc.get("sigs", []):
        kid = s.get("keyid")
        pub = maintainers.pubkeys.get(kid)
        if pub is None or kid in good:
            continue
        try:
            pub.verify(bytes.fromhex(s["sig"]), payload)
            good.add(kid)
        except InvalidSignature:
            continue
    if len(good) < maintainers.threshold:
        raise ValueError(f"blocklist has {len(good)} valid signatures, need {maintainers.threshold}")
    p = json.loads(payload)
    exact = {bytes.fromhex(h) for h in p["exact"]}
    phash = [int(x) for x in p["phash"]]
    return int(p["version"]), p["created"], exact, phash


class BlocklistManager:
    """Owns version state and arms/updates the gate from verified blobs."""

    def __init__(self, gate, maintainers: MaintainerSet, state_path=None):
        self.gate = gate
        self.maintainers = maintainers
        self.state_path = state_path
        self.version = self._load_version()

    def _load_version(self) -> int:
        if self.state_path and os.path.exists(self.state_path):
            try:
                return int(open(self.state_path).read().strip())
            except Exception:
                return 0
        return 0

    def _save_version(self, v: int):
        if self.state_path:
            tmp = self.state_path + ".tmp"
            with open(tmp, "w") as f:
                f.write(str(v))
            os.replace(tmp, self.state_path)     # atomic on POSIX

    def apply(self, blob: bytes) -> bool:
        """Verify, and if strictly newer than the current version, arm/update the gate.
        Returns True if applied. Raises ValueError on an unverifiable blob. A verified
        but older-or-equal blob is ignored (rollback protection)."""
        version, _created, exact, phash = verify_blocklist(blob, self.maintainers)
        if version <= self.version:
            return False
        self.gate.update(exact, phash, version)
        self.version = version
        self._save_version(version)
        return True

    def fetch_and_apply(self, fetch_latest) -> bool:
        """fetch_latest() -> blob bytes, from the netDb or a maintainer mirror.
        Verification is by signature, so this works before the gate is armed."""
        blob = fetch_latest()
        if blob is None:
            return False
        return self.apply(blob)
