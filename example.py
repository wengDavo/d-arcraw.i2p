"""
Smoke test: three in-memory nodes, a shared gate, publish and cross-node lookup,
and a demonstration that gated content never enters the netDb or replicates.

Run: python3 example.py
"""
from gate import ContentGate, sha256
from transport import InMemoryNetwork, InMemoryTransport
from netdb import Node
from crawler import Crawler, Candidate

DIFFICULTY = 8   # low for a fast local test; production uses far more


def build_net():
    net = InMemoryNetwork()
    # one known-bad payload goes in the blocklist by its exact hash
    banned = b"KNOWN-ILLEGAL-PAYLOAD"
    gate = ContentGate(exact_hashes={sha256(banned)}, perceptual_hashes=[])

    nodes = []
    for name in ("alpha", "beta", "gamma"):
        t = InMemoryTransport(net, name)
        nodes.append(Node(t, gate, difficulty=DIFFICULTY, replication=3))

    # bootstrap: everyone learns everyone (verified by PoW in learn())
    for a in nodes:
        for b in nodes:
            if a is not b:
                a.learn(b.me)
    return nodes, gate, banned


def main():
    nodes, gate, banned = build_net()
    alpha, beta, gamma = nodes

    # 1. publish lawful content on alpha, read it back from gamma
    good = b"an intense but lawful shitpost"
    cid = alpha.publish(good)
    assert cid is not None, "lawful content should publish"
    fetched = gamma.get(cid)
    print("cross-node lookup of lawful content:", fetched == good)

    # 2. gated content never gets a CID, never stored, never replicated
    blocked = alpha.publish(banned)
    print("gated content blocked at publish:", blocked is None)
    present_anywhere = any(bytes.fromhex(h) == sha256(banned)
                           for n in nodes for h in n.catalog.present())
    print("gated content absent from every catalog:", not present_anywhere)
    # even a direct store RPC to a peer is refused by its admission gate
    raw = beta._handle("attacker", b'{"op":"store","content":"%s"}' % banned.hex().encode())
    print("direct injection refused by store-admission gate:", b'"ok": false' in raw)

    # 3. crawler wires to the same gate; a fetch of banned content is dropped at ingestion
    def fetcher(url):
        table = {"i2p://good": (good, []), "i2p://bad": (banned, [])}
        return table.get(url)

    c = Crawler(alpha, gate, fetcher, dim=3, tick_budget=8)
    c.submit(Candidate("i2p://good", "registry", [1.0, 0.2, 0.0]))
    c.submit(Candidate("i2p://bad", "registry", [0.1, 0.9, 1.0]))
    c.tick()
    c.consolidate()
    print("policy weights after one tick:", [round(w, 3) for w in c.policy.w])
    bad_in_store = alpha.store.get(sha256(banned)) is not None
    print("crawler never stored gated content:", not bad_in_store)


if __name__ == "__main__":
    main()
