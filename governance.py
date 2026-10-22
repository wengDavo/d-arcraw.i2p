"""
Maintainer-set governance for the D'Arcraw blocklist.

Two signed, versioned artifacts carry the trust.

1. The maintainer set. A set document lists member keys, roles, and the
   threshold. Version N+1 must be signed by a threshold of version N's members,
   so the set can rotate (add members, drop a compromised key) with no central
   authority. Nodes pin the genesis set in the client and follow the signed chain
   forward. Hard limit: lose a threshold of keys at once and the chain cannot
   advance, so N is chosen large and keys are held independently.

2. Hash proposals. A proposal to add or remove hashes is signed by a proposer,
   reviewed, and co-signed by maintainers. Once a threshold has signed, it is
   promoted into a new signed blocklist version (the artifact nodes enforce).
   Removal runs the same path, which is how a false-positive block is lifted.

Uses Ed25519 from the cryptography package.
"""
import base64
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from blocklist import _keyid, make_blocklist, MaintainerSet


def _canon(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _verify_against(payload_raw: bytes, sigs, members_by_id) -> int:
    """Count distinct member signatures over payload_raw."""
    good = set()
    for s in sigs:
        kid = s.get("keyid")
        m = members_by_id.get(kid)
        if m is None or kid in good:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(m["pub"])).verify(
                bytes.fromhex(s["sig"]), payload_raw)
            good.add(kid)
        except InvalidSignature:
            continue
    return len(good)


def sign_doc(payload: dict, signing_keys) -> bytes:
    raw = _canon(payload)
    sigs = [{"keyid": _keyid(sk.public_key()), "sig": sk.sign(raw).hex()} for sk in signing_keys]
    return json.dumps({"payload_b64": base64.b64encode(raw).decode(), "sigs": sigs}).encode()


# ---------- maintainer set, versioned and signed ----------

def make_maintainer_set_doc(version: int, members, threshold: int, created=None) -> dict:
    """members: list of (Ed25519PublicKey, role). Returns the unsigned payload dict."""
    return {
        "version": int(version),
        "created": created or _now(),
        "threshold": int(threshold),
        "members": sorted(
            [{"keyid": _keyid(pk), "pub": pk.public_bytes_raw().hex(), "role": role}
             for pk, role in members],
            key=lambda m: m["keyid"]),
    }


def load_set(doc: dict) -> MaintainerSet:
    pubs = {m["keyid"]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(m["pub"]))
            for m in doc["members"]}
    return MaintainerSet(pubs, int(doc["threshold"]))


class MaintainerChain:
    """Follows the signed maintainer-set chain from a pinned genesis."""

    def __init__(self, genesis_doc: dict):
        self.current = genesis_doc          # trusted by pinning in the client

    def members_by_id(self):
        return {m["keyid"]: m for m in self.current["members"]}

    def apply_rotation(self, blob: bytes) -> bool:
        """Accept a new set version signed by a threshold of the CURRENT set."""
        obj = json.loads(blob)
        payload_raw = base64.b64decode(obj["payload_b64"])
        new_doc = json.loads(payload_raw)
        if new_doc["version"] <= self.current["version"]:
            return False
        got = _verify_against(payload_raw, obj["sigs"], self.members_by_id())
        need = int(self.current["threshold"])
        if got < need:
            raise ValueError(f"rotation signed by {got} current members, need {need}")
        self.current = new_doc
        return True

    def maintainer_set(self) -> MaintainerSet:
        return load_set(self.current)


# ---------- hash proposals ----------

def make_proposal(action: str, hashes, category: str, evidence_ref: str,
                  proposer_key, created=None) -> dict:
    if action not in ("add", "remove"):
        raise ValueError("action must be add or remove")
    payload = {
        "action": action,
        "hashes": sorted(h.hex() if isinstance(h, (bytes, bytearray)) else str(h) for h in hashes),
        "category": category,
        "evidence_ref": evidence_ref,
        "created": created or _now(),
        "proposer": _keyid(proposer_key.public_key()),
    }
    raw = _canon(payload)
    return {"payload_b64": base64.b64encode(raw).decode(),
            "sigs": [{"keyid": _keyid(proposer_key.public_key()), "sig": proposer_key.sign(raw).hex()}]}


def cosign_proposal(proposal: dict, key) -> dict:
    raw = base64.b64decode(proposal["payload_b64"])
    kid = _keyid(key.public_key())
    out = json.loads(json.dumps(proposal))      # copy
    if not any(s["keyid"] == kid for s in out["sigs"]):
        out["sigs"].append({"keyid": kid, "sig": key.sign(raw).hex()})
    return out


def proposal_support(proposal: dict, mset: MaintainerSet) -> int:
    raw = base64.b64decode(proposal["payload_b64"])
    members = {kid: {"pub": pk.public_bytes_raw().hex()} for kid, pk in mset.pubkeys.items()}
    return _verify_against(raw, proposal["sigs"], members)


def accepted(proposal: dict, mset: MaintainerSet) -> bool:
    return proposal_support(proposal, mset) >= mset.threshold


def promote(current_exact, current_phash, proposals, mset: MaintainerSet,
            signing_keys, next_version: int):
    """Apply threshold-supported proposals to the hash sets and emit a new signed
    blocklist. Only exact (sha256) hashes are handled here; perceptual proposals
    are analogous. Returns (blob, exact, phash, applied_payloads)."""
    exact = set(current_exact)
    phash = list(current_phash)
    applied = []
    for p in proposals:
        if not accepted(p, mset):
            continue
        payload = json.loads(base64.b64decode(p["payload_b64"]))
        hs = {bytes.fromhex(h) for h in payload["hashes"] if len(h) == 64}
        if payload["action"] == "add":
            exact |= hs
        else:
            exact -= hs
        applied.append(payload)
    blob = make_blocklist(next_version, _now(), exact, phash, signing_keys)
    return blob, exact, phash, applied
