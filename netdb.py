"""
Decentralized netDb for D'Arcraw.

Content-addressed store over a Kademlia-style DHT. Placement is deterministic
(the k closest node IDs to a key hold it), so there is no consensus to run.
Node IDs are bound to the I2P destination and carry a proof of work, which is the
Sybil cost. Lookups use disjoint paths (S/Kademlia flavored). Routing buckets use
LRU eviction with liveness pings, which keeps stable nodes and resists churn and
flooding. The catalog of what exists is an OR-Set CRDT reconciled by range-based
anti-entropy, so nodes converge by shipping only the delta, not the whole catalog.

The content gate runs at every store-admission: local publish, received store,
and replication. Gated content never acquires a CID and therefore never spreads.
"""
import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from gate import ContentGate

K = 20          # bucket size and default replication factor
AE_LEAF = 16    # anti-entropy: exchange elements once a range holds this many or fewer


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def xor_distance(a: bytes, b: bytes) -> int:
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


# --- node identity: bound to destination, gated by proof of work ---

def node_id(destination: str, nonce: int) -> bytes:
    return sha256(destination.encode() + nonce.to_bytes(8, "big"))


def pow_valid(destination: str, nonce: int, difficulty: int) -> bool:
    nid = node_id(destination, nonce)
    return int.from_bytes(nid, "big") >> (256 - difficulty) == 0


def mine_node_id(destination: str, difficulty: int):
    nonce = 0
    while not pow_valid(destination, nonce, difficulty):
        nonce += 1
    return nonce, node_id(destination, nonce)


@dataclass(frozen=True)
class Peer:
    node_id: bytes
    destination: str
    nonce: int


def peer_valid(peer: Peer, difficulty: int) -> bool:
    return (peer.node_id == node_id(peer.destination, peer.nonce)
            and pow_valid(peer.destination, peer.nonce, difficulty))


class RoutingTable:
    def __init__(self, self_id: bytes, k: int = K):
        self.self_id = self_id
        self.k = k
        self.buckets = [[] for _ in range(256)]

    def _bucket_index(self, nid: bytes) -> int:
        d = xor_distance(self.self_id, nid)
        return d.bit_length() - 1 if d else 0

    def add(self, peer: Peer, ping=None):
        """LRU insertion. A seen peer moves to the most-recent end. A new peer into
        a full bucket is admitted only if the least-recently-seen node fails a ping,
        which keeps established, responsive nodes (standard Kademlia behavior)."""
        b = self.buckets[self._bucket_index(peer.node_id)]
        existing = [p for p in b if p.node_id == peer.node_id]
        if existing:
            b.remove(existing[0])
            b.append(peer)
            return
        if len(b) < self.k:
            b.append(peer)
            return
        oldest = b[0]
        if ping is not None and ping(oldest):
            b.pop(0)
            b.append(oldest)          # alive: keep it, drop the newcomer
        else:
            b.pop(0)
            b.append(peer)            # dead or unpingable: evict, admit the newcomer

    def closest(self, key: bytes, n: int):
        peers = [p for b in self.buckets for p in b]
        peers.sort(key=lambda p: xor_distance(p.node_id, key))
        return peers[:n]


class ContentStore:
    """Content-addressed store. Every write passes the gate at admission."""

    def __init__(self, gate: ContentGate):
        self._gate = gate
        self._data = {}

    @staticmethod
    def cid(content: bytes) -> bytes:
        return sha256(content)

    def admit(self, content: bytes, media=None):
        if not self._gate.check(content, media).allowed:
            return None
        c = self.cid(content)
        self._data[c] = content
        return c

    def get(self, cid: bytes):
        return self._data.get(cid)

    def purge(self, cid: bytes):
        self._data.pop(cid, None)


class Catalog:
    """Observed-Remove Set of CIDs. Adds carry unique tags, removes tombstone them.
    Join is union of adds and union of removes: commutative, idempotent, leaderless.
    State is equivalently a set of dots, which is what range-based anti-entropy
    reconciles by shipping only the differing dots."""

    def __init__(self):
        self.adds = {}      # cid hex -> set(tags)
        self.removes = {}   # cid hex -> set(tags)

    def add(self, cid: bytes):
        self.adds.setdefault(cid.hex(), set()).add(os.urandom(16).hex())

    def remove(self, cid: bytes):
        h = cid.hex()
        self.removes.setdefault(h, set()).update(self.adds.get(h, set()))

    def present(self):
        return {h for h, tags in self.adds.items()
                if tags - self.removes.get(h, set())}

    def merge(self, other: "Catalog"):
        for h, tags in other.adds.items():
            self.adds.setdefault(h, set()).update(tags)
        for h, tags in other.removes.items():
            self.removes.setdefault(h, set()).update(tags)

    def digest(self) -> bytes:
        items = sorted(
            (h, tuple(sorted(a)), tuple(sorted(self.removes.get(h, set()))))
            for h, a in self.adds.items())
        return sha256(json.dumps(items).encode())

    # --- dot view, for delta anti-entropy ---
    def dots(self):
        out = []
        for h, tags in self.adds.items():
            out.extend("+" + h + ":" + t for t in tags)
        for h, tags in self.removes.items():
            out.extend("-" + h + ":" + t for t in tags)
        out.sort()
        return out

    def apply_dots(self, dots):
        for d in dots:
            sign, rest = d[0], d[1:]
            h, t = rest.rsplit(":", 1)
            target = self.adds if sign == "+" else self.removes
            target.setdefault(h, set()).add(t)

    @staticmethod
    def _in_range(d, lo, hi):
        return (lo is None or d >= lo) and (hi is None or d < hi)

    def range_dots(self, lo, hi):
        return [d for d in self.dots() if self._in_range(d, lo, hi)]

    def fp(self, lo, hi):
        """Order-independent fingerprint (XOR of per-dot hashes) and count over a range."""
        x = 0
        n = 0
        for d in self.range_dots(lo, hi):
            x ^= int.from_bytes(sha256(d.encode())[:8], "big")
            n += 1
        return x, n


class Node:
    def __init__(self, transport, gate: ContentGate,
                 difficulty: int = 16, k: int = K, replication: int = K):
        self.transport = transport
        self.difficulty = difficulty
        self.k = k
        self.replication = replication
        self.nonce, self.id = mine_node_id(transport.address, difficulty)
        self.me = Peer(self.id, transport.address, self.nonce)
        self.routing = RoutingTable(self.id, k)
        self.store = ContentStore(gate)
        self.catalog = Catalog()
        transport.serve(self._handle)

    # --- local publish from the crawler (already gated at ingest, re-gated here) ---
    def publish(self, content: bytes, media=None):
        cid = self.store.admit(content, media)
        if cid is None:
            return None
        self.catalog.add(cid)
        self._replicate(cid, content)
        return cid

    def _replicate(self, cid: bytes, content: bytes):
        for peer in self.routing.closest(cid, self.replication):
            try:
                self._rpc(peer, {"op": "store", "content": content.hex()})
            except Exception:
                continue

    # --- disjoint-path lookup, run in parallel ---
    def get(self, cid: bytes, paths: int = 3, max_hops: int = 8):
        """Query the `paths` closest seeds concurrently along node-disjoint paths.
        A node is claimed by at most one path, so a malicious cluster that captures
        one slice of the keyspace cannot starve the lookup: the other paths route
        around it. The first path to find the content wins and the rest stop. This
        is the insulated-queue property — no single path can hold the lookup up."""
        local = self.store.get(cid)
        if local is not None:
            return local
        seeds = self.routing.closest(cid, paths)
        if not seeds:
            return None

        found = threading.Event()
        result = {}
        claimed = set()
        lock = threading.Lock()

        def walk(seed):
            node = seed
            for _ in range(max_hops):
                if found.is_set():
                    return
                with lock:
                    if node.node_id in claimed:
                        return                 # owned by another path: stay disjoint
                    claimed.add(node.node_id)
                try:
                    r = self._rpc(node, {"op": "find", "cid": cid.hex()})
                except Exception:
                    return
                if r.get("content"):
                    with lock:
                        if not found.is_set():
                            result["content"] = bytes.fromhex(r["content"])
                            found.set()
                    return
                nxt = r.get("closer")
                if not nxt:
                    return
                peer = Peer(bytes.fromhex(nxt["node_id"]), nxt["destination"], nxt["nonce"])
                if not peer_valid(peer, self.difficulty):
                    return
                node = peer

        with ThreadPoolExecutor(max_workers=len(seeds)) as ex:
            for seed in seeds:
                ex.submit(walk, seed)
        return result.get("content")

    def repair(self):
        for h in self.catalog.present():
            cid = bytes.fromhex(h)
            c = self.store.get(cid)
            if c is not None:
                self._replicate(cid, c)

    # --- delta anti-entropy: reconcile catalogs by shipping only differing dots ---
    def anti_entropy(self, peer: Peer):
        self._ae_range(peer, None, None)

    def _ae_range(self, peer: Peer, lo, hi):
        my_fp, my_n = self.catalog.fp(lo, hi)
        r = self._rpc(peer, {"op": "ae_fp", "lo": lo, "hi": hi})
        if my_fp == r["fp"]:
            return                                  # ranges identical, ship nothing
        if max(my_n, r["n"]) <= AE_LEAF or my_n == 0 or r["n"] == 0:
            mine = self.catalog.range_dots(lo, hi)
            resp = self._rpc(peer, {"op": "ae_leaf", "lo": lo, "hi": hi, "dots": mine})
            self.catalog.apply_dots(resp["dots"])
            return
        mids = self.catalog.range_dots(lo, hi)
        mid = mids[len(mids) // 2]
        self._ae_range(peer, lo, mid)
        self._ae_range(peer, mid, hi)

    def learn(self, peer: Peer):
        if peer_valid(peer, self.difficulty):
            self.routing.add(peer, ping=self._ping)

    def _ping(self, peer: Peer) -> bool:
        try:
            return self._rpc(peer, {"op": "ping"}).get("pong", False)
        except Exception:
            return False

    # --- RPC ---
    def _rpc(self, peer: Peer, msg: dict) -> dict:
        raw = self.transport.send(peer.destination, json.dumps(msg).encode())
        return json.loads(raw)

    def _handle(self, src, raw: bytes) -> bytes:
        msg = json.loads(raw)
        op = msg.get("op")
        if op == "ping":
            return json.dumps({"pong": True}).encode()
        if op == "store":
            content = bytes.fromhex(msg["content"])
            cid = self.store.admit(content)          # gate on every received store
            if cid is None:
                return json.dumps({"ok": False, "reason": "gated"}).encode()
            self.catalog.add(cid)
            return json.dumps({"ok": True, "cid": cid.hex()}).encode()
        if op == "find":
            cid = bytes.fromhex(msg["cid"])
            content = self.store.get(cid)
            if content is not None:
                return json.dumps({"content": content.hex()}).encode()
            peers = self.routing.closest(cid, 1)
            if peers:
                p = peers[0]
                return json.dumps({"closer": {
                    "node_id": p.node_id.hex(),
                    "destination": p.destination,
                    "nonce": p.nonce}}).encode()
            return json.dumps({}).encode()
        if op == "ae_fp":
            fp, n = self.catalog.fp(msg["lo"], msg["hi"])
            return json.dumps({"fp": fp, "n": n}).encode()
        if op == "ae_leaf":
            self.catalog.apply_dots(msg["dots"])     # union their dots
            mine = self.catalog.range_dots(msg["lo"], msg["hi"])
            return json.dumps({"dots": mine}).encode()
        return json.dumps({"error": "unknown op"}).encode()
