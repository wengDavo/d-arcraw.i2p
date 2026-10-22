"""
Parallel, node-disjoint disjoint-path lookup (issue 2: XOR-routing insulated queues).

Two things are proven:
  - Network correctness: content published on one node is retrievable from every
    other node through the parallel lookup.
  - Insulation and disjointness: a captured/dead path does not stall the lookup, and
    no node is queried by more than one path (true node-disjoint S/Kademlia paths),
    including when two paths route toward the same closer node.
Run: python3 test_netdb_lookup.py   (stdlib only)
"""
from gate import ContentGate, sha256
from transport import InMemoryNetwork, InMemoryTransport
import netdb
from netdb import Node, Peer, mine_node_id

DIFFICULTY = 8


def test_network_correctness():
    net = InMemoryNetwork()
    gate = ContentGate(exact_hashes=set(), perceptual_hashes=[])
    nodes = [Node(InMemoryTransport(net, n), gate, difficulty=DIFFICULTY, replication=2)
             for n in ("a", "b", "c", "d", "e", "f")]
    for x in nodes:
        for y in nodes:
            if x is not y:
                x.learn(y.me)
    content = b"lawful eepsite snapshot"
    cid = nodes[0].publish(content)
    # every other node resolves it via parallel disjoint paths
    for n in nodes[1:]:
        assert n.get(cid, paths=3) == content, n.me.destination
    print("lookup: content resolvable from all 5 other nodes")


def test_disjoint_and_insulated():
    """Controlled seeds and a faked RPC: one dead path, two routing to one shared
    holder C. The lookup must still return C's content, and C must be queried once."""
    net = InMemoryNetwork()
    gate = ContentGate(exact_hashes=set(), perceptual_hashes=[])
    node = Node(InMemoryTransport(net, "req"), gate, difficulty=1)

    def mk(dest):
        nonce, nid = mine_node_id(dest, 1)
        return Peer(nid, dest, nonce)

    S0, S1, S2, C = mk("dead"), mk("s1"), mk("s2"), mk("holder")
    seeds = [S0, S1, S2]
    node.routing.closest = lambda key, n: seeds[:n]

    content = b"held-by-C"
    cid = sha256(content)
    queries = {}

    def fake_rpc(peer, msg):
        queries[peer.destination] = queries.get(peer.destination, 0) + 1
        d = peer.destination
        if d == "dead":
            return {}                                   # captured slice: no help
        if d in ("s1", "s2"):                           # both route to the same C
            return {"closer": {"node_id": C.node_id.hex(),
                               "destination": C.destination, "nonce": C.nonce}}
        if d == "holder":
            return {"content": content.hex()}
        return {}

    node._rpc = fake_rpc
    got = node.get(cid, paths=3)
    assert got == content, "lookup must route around the dead path"
    assert queries.get("holder", 0) == 1, ("holder queried once (disjoint)", queries)
    assert all(v <= 1 for v in queries.values()), ("no node queried twice", queries)
    print("lookup: dead path tolerated; shared holder queried exactly once", queries)


if __name__ == "__main__":
    test_network_correctness()
    test_disjoint_and_insulated()
    print("netdb lookup: all passed")
