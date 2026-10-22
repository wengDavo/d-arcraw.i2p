"""
Signed, expiring netDb records.

Three of the listed issues meet here, because on an anonymity overlay they are one
mechanism: a record is trustworthy only if it is signed by the identity it claims,
and only while it is fresh.

- Self-signing keys (issue 3): every record carries the publisher's Ed25519 public
  key and a signature over its canonical bytes. `verify_record` checks the signature
  before the store will hold it, so a peer cannot inject a RouterInfo or LeaseSet it
  does not hold the key for. Tampering with any field breaks the signature.
- Data expiration (issue 4): records carry signed issued/expires timestamps, and the
  store refuses anything already expired or dated further out than its kind allows.
  LeaseSet-like records are capped under ten minutes, so they fall out of every
  store on their own and the publisher must re-sign to stay present. Expiry is part
  of the signed bytes, so it cannot be extended by a relay.
- Sybil admission (issue 1): a per-origin token bucket caps how fast any one
  publishing identity can land records, so signing many records buys no extra
  catalog share. The spirit of "limit entries per subnet" at a layer that cannot
  see subnets — see ORCHESTRATOR.md for why the IP-subnet form belongs to the I2P
  router beneath this, not here.

Ed25519 is implemented. Red25519 (I2P's blinded signature for encrypted LeaseSet2)
is a deliberate NotImplementedError rather than a fake: the blinding transform is
I2P-specific and must be ported from a router implementation before blinded records
are accepted. Until then, records verify on the unblinded Ed25519 path.
"""
import hashlib
import time as _time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from ratelimit import PerKeyRateLimiter

# Max lifetime per kind, seconds. LeaseSets expire fast to force republication;
# this is the "< 10 minutes" floor from the issue list.
MAX_TTL = {
    "leaseset": 600,       # under ten minutes
    "routerinfo": 7200,
    "announce": 86400,
}
CLOCK_SKEW = 60            # tolerate this much forward dating


def _u32(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


def canonical(kind: str, publisher: bytes, payload: bytes, issued: int, expires: int) -> bytes:
    """Deterministic, length-prefixed serialization of the signed fields. Length
    prefixes stop a field boundary from being shifted without changing the bytes."""
    parts = [kind.encode(), publisher, payload, _u32(issued), _u32(expires)]
    out = bytearray()
    for p in parts:
        out += _u32(len(p)) + p
    return bytes(out)


@dataclass(frozen=True)
class SignedRecord:
    kind: str
    publisher: bytes      # Ed25519 public key, raw 32 bytes
    payload: bytes
    issued: int
    expires: int
    signature: bytes

    def origin(self) -> str:
        """Stable per-identity key for rate limiting and storage."""
        return hashlib.sha256(self.publisher).hexdigest()

    def storage_key(self) -> str:
        return self.kind + ":" + self.origin()


def sign_record(private_key: ed25519.Ed25519PrivateKey, kind: str, payload: bytes,
                ttl: int, now: int = None) -> SignedRecord:
    if kind not in MAX_TTL:
        raise ValueError("unknown record kind: " + kind)
    if ttl > MAX_TTL[kind]:
        raise ValueError("ttl %d exceeds max %d for %s" % (ttl, MAX_TTL[kind], kind))
    now = int(now if now is not None else _time.time())
    issued, expires = now, now + ttl
    pub = private_key.public_key().public_bytes_raw()
    sig = private_key.sign(canonical(kind, pub, payload, issued, expires))
    return SignedRecord(kind, pub, payload, issued, expires, sig)


def verify_record(rec: SignedRecord, now: int = None, skew: int = CLOCK_SKEW):
    """(ok, reason). Checks kind, signature, freshness, and that the signed lifetime
    is within the kind's cap. Everything checked is inside the signed bytes."""
    now = int(now if now is not None else _time.time())
    if rec.kind not in MAX_TTL:
        return False, "unknown-kind"
    if rec.expires <= now:
        return False, "expired"
    if rec.issued > now + skew:
        return False, "future-dated"
    if rec.expires - rec.issued > MAX_TTL[rec.kind]:
        return False, "ttl-too-long"
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(rec.publisher)
        pk.verify(rec.signature, canonical(rec.kind, rec.publisher, rec.payload,
                                           rec.issued, rec.expires))
    except (InvalidSignature, ValueError):
        return False, "bad-signature"
    return True, "ok"


def verify_blinded(rec: SignedRecord, now: int = None):
    """Red25519 blinded verification for encrypted LeaseSet2. Not implemented: the
    blinding factor derivation is I2P-specific and must be ported from a router
    (i2pd or Java I2P) before blinded records are trusted."""
    raise NotImplementedError(
        "Red25519 blinded verification must be ported from an I2P router implementation; "
        "unblinded LeaseSets verify via verify_record on the Ed25519 path.")


class RecordStore:
    """Holds the freshest valid record per (kind, origin). Admission verifies the
    signature and freshness and enforces a per-origin injection rate. Expired records
    are reaped, which is what forces publishers to republish."""

    def __init__(self, per_origin_rate: float = 1.0, per_origin_burst: float = 5.0,
                 clock=_time.time):
        self._records = {}       # storage_key -> SignedRecord
        self._clock = clock
        self._limiter = PerKeyRateLimiter(per_origin_rate, per_origin_burst,
                                          clock=_time.monotonic)

    def admit(self, rec: SignedRecord):
        """(ok, reason). Rate limit is checked first so a flood of invalid records
        still costs the origin its budget."""
        now = int(self._clock())
        if not self._limiter.allow(rec.origin()):
            return False, "rate-limited"
        ok, reason = verify_record(rec, now)
        if not ok:
            return False, reason
        key = rec.storage_key()
        existing = self._records.get(key)
        if existing is not None and existing.issued >= rec.issued:
            return False, "stale"          # not newer than what we hold
        self._records[key] = rec
        return True, "ok"

    def get(self, kind: str, publisher: bytes):
        self._reap()
        return self._records.get(kind + ":" + hashlib.sha256(publisher).hexdigest())

    def present(self):
        self._reap()
        return dict(self._records)

    def _reap(self):
        now = int(self._clock())
        for k in [k for k, r in self._records.items() if r.expires <= now]:
            del self._records[k]

    def due_for_republish(self, rec: SignedRecord, margin: float = 0.2) -> bool:
        """True when a record is within `margin` of its lifetime from expiring, so a
        publisher re-signs before it drops out rather than after."""
        now = int(self._clock())
        life = rec.expires - rec.issued
        return now >= rec.expires - life * margin
