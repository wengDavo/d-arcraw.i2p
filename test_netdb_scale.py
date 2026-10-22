from netdb import RoutingTable, Peer, Node
from transport import InMemoryNetwork, InMemoryTransport
from gate import ContentGate, sha256


def mk(first, name):
    return Peer(bytes(first) + b"\x00" * (32 - len(first)), name, 0)


# --- LRU bucket eviction ---
p1, p2, p3 = mk([1, 1], "p1"), mk([1, 2], "p2"), mk([1, 3], "p3")  # same bucket (top byte 0x01)

rt = RoutingTable(b"\x00" * 32, k=2)
rt.add(p1); rt.add(p2)
rt.add(p3, ping=lambda pr: True)       # oldest alive -> keep it, drop newcomer
b = rt.buckets[rt._bucket_index(p1.node_id)]
print("LRU keeps live oldest, drops newcomer:", p3 not in b and p1 in b and p2 in b)

rt2 = RoutingTable(b"\x00" * 32, k=2)
rt2.add(p1); rt2.add(p2)
rt2.add(p3, ping=lambda pr: False)     # oldest dead -> evict it, admit newcomer
b2 = rt2.buckets[rt2._bucket_index(p1.node_id)]
print("LRU evicts dead oldest, admits newcomer:", p1 not in b2 and p3 in b2)

# --- delta anti-entropy convergence ---
net = InMemoryNetwork()
gate = ContentGate(exact_hashes=set(), perceptual_hashes=[])
n1 = Node(InMemoryTransport(net, "n1"), gate, difficulty=8, replication=0)
n2 = Node(InMemoryTransport(net, "n2"), gate, difficulty=8, replication=0)

shared, onlyA, onlyB = sha256(b"shared"), sha256(b"onlyA"), sha256(b"onlyB")
n1.catalog.add(shared); n2.catalog.add(shared)   # same cid, different tags each
n1.catalog.add(onlyA)
n2.catalog.add(onlyB)

n1.anti_entropy(n2.me)
want = {shared.hex(), onlyA.hex(), onlyB.hex()}
print("anti-entropy converged both catalogs:",
      n1.catalog.present() == want and n2.catalog.present() == want)

# an already-synced pair reconciles in a single round trip (fp match short-circuits)
calls = {"n": 0}
real_send = n1.transport.send
def counting(dest, msg):
    calls["n"] += 1
    return real_send(dest, msg)
n1.transport.send = counting
n1.anti_entropy(n2.me)
print("already-synced reconcile ships no deltas (1 RPC):", calls["n"] == 1)
