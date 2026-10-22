"""
Orchestrator: dedup admission, rendezvous ownership, per-domain politeness, the gate
surviving the pump, and cross-peer seen reconciliation.
Run: python3 test_orchestrator.py   (stdlib only)
"""
from gate import ContentGate, sha256
from transport import InMemoryNetwork, InMemoryTransport
from netdb import Node
from dedup import SeenSet
from sketches import owner
from fetchpool import FetchBackend, FetchPool
from orchestrator import Orchestrator, host_of

DIFFICULTY = 8
GOOD = b"an intense but lawful shitpost"
BANNED = b"KNOWN-ILLEGAL-PAYLOAD"


def make_opener(table):
    def opener(url, proxy, headers):
        if url in table:
            return 200, table[url], {}
        return 404, b"", {}
    return opener


def make_node(name="alpha"):
    net = InMemoryNetwork()
    gate = ContentGate(exact_hashes={sha256(BANNED)}, perceptual_hashes=[])
    node = Node(InMemoryTransport(net, name), gate, difficulty=DIFFICULTY, replication=3)
    return net, gate, node


def test_dedup_admission():
    net, gate, node = make_node()
    pool = FetchPool(FetchBackend(make_opener({})))
    orc = Orchestrator(node, gate, pool, self_peer="alpha", peers=["alpha"], dim=3)
    assert orc.submit("i2p://a.i2p/1", "reg", [1, 0, 0]) == "admitted"
    assert orc.submit("i2p://a.i2p/1", "reg", [1, 0, 0]) == "dup"
    assert orc.stats["dup"] == 1
    print("orchestrator: duplicate URL rejected at admission")


def test_rendezvous_ownership_gates_submit():
    net, gate, node = make_node("alpha")
    peers = ["alpha", "beta", "gamma", "delta", "epsilon"]
    pool = FetchPool(FetchBackend(make_opener({})))
    orc = Orchestrator(node, gate, pool, self_peer="alpha", peers=peers, dim=3)

    mine = next(s for i in range(500)
                for s in ["s%d.i2p" % i] if owner(s, peers) == "alpha")
    not_mine = next(s for i in range(500)
                    for s in ["s%d.i2p" % i] if owner(s, peers) != "alpha")
    assert orc.submit("i2p://%s/x" % mine, "reg", [1, 0, 0]) == "admitted"
    assert orc.submit("i2p://%s/x" % not_mine, "reg", [1, 0, 0]) == "not-owned"
    assert orc.pending() == 1       # only the owned one is queued to scrape
    print("orchestrator: scrapes only rendezvous-owned sites (%s mine, %s not)"
          % (mine, not_mine))


def test_per_domain_politeness_releases_slowly():
    net, gate, node = make_node()
    urls = ["i2p://poll.i2p/%d" % i for i in range(3)]
    pool = FetchPool(FetchBackend(make_opener({u: GOOD for u in urls})))
    t = [0.0]
    orc = Orchestrator(node, gate, pool, self_peer="solo", peers=["solo"], dim=3,
                       per_domain_rate=1.0, per_domain_burst=1.0, clock=lambda: t[0])
    for u in urls:
        assert orc.submit(u, "reg", [1, 0, 0]) == "admitted"
    assert orc.pending() == 3
    released = orc.pump()
    assert released == 1 and orc.pending() == 2, (released, orc.pending())
    t[0] = 2.0                       # time passes, one more token for the domain
    released2 = orc.pump()
    assert released2 == 1 and orc.pending() == 1
    print("orchestrator: per-domain bucket paces releases (1 per interval)")


def test_gate_survives_the_pump():
    net, gate, node = make_node()
    good_url, bad_url = "i2p://g.i2p/x", "i2p://b.i2p/x"
    pool = FetchPool(FetchBackend(make_opener({good_url: GOOD, bad_url: BANNED})))
    orc = Orchestrator(node, gate, pool, self_peer="solo", peers=["solo"], dim=3,
                       per_domain_rate=100.0, per_domain_burst=100.0)
    orc.submit(good_url, "reg", [1, 0, 0])
    orc.submit(bad_url, "reg", [0, 1, 1])
    for _ in range(3):
        orc.pump()
    present = {h for h in node.catalog.present()}
    assert sha256(GOOD).hex() in present, "lawful content should be indexed"
    assert sha256(BANNED).hex() not in present, "gated content must never be indexed"
    assert node.store.get(sha256(GOOD)) == GOOD
    assert node.store.get(sha256(BANNED)) is None
    print("orchestrator: gate holds through the scrape pump (good in, banned out)")


def test_cross_peer_seen_reconcile():
    # two independent peers, overlapping seen-sets, reconcile via IBLT
    n1, g1, node1 = make_node("p1")
    n2, g2, node2 = make_node("p2")
    pool = FetchPool(FetchBackend(make_opener({})))
    o1 = Orchestrator(node1, g1, pool, "p1", ["p1"], dim=3, iblt_cells=512)
    o2 = Orchestrator(node2, g2, pool, "p2", ["p2"], dim=3, iblt_cells=512)

    for i in range(100):
        o1.submit("i2p://shared%d.i2p" % i, "reg", [1, 0, 0])
        o2.submit("i2p://shared%d.i2p" % i, "reg", [1, 0, 0])
    for i in range(5):
        o1.submit("i2p://only1-%d.i2p" % i, "reg", [1, 0, 0])
    for i in range(3):
        o2.submit("i2p://only2-%d.i2p" % i, "reg", [1, 0, 0])

    learned, we_had, ok = o1.reconcile_seen(o2.seen_iblt())
    assert ok, "reconcile should decode"
    assert learned == 3, learned     # p1 learns p2's 3 extra addresses
    assert we_had == 5, we_had       # p1 had 5 p2 lacked
    print("orchestrator: cross-peer seen reconcile learned %d, had %d extra" % (learned, we_had))


if __name__ == "__main__":
    test_dedup_admission()
    test_rendezvous_ownership_gates_submit()
    test_per_domain_politeness_releases_slowly()
    test_gate_survives_the_pump()
    test_cross_peer_seen_reconcile()
    print("orchestrator: all passed")
