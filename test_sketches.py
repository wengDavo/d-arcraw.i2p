"""
Sketches: rendezvous stability, HyperLogLog accuracy and merge, IBLT reconciliation.
Run: python3 test_sketches.py   (stdlib only)
"""
from sketches import owner, owners, owns, HyperLogLog, IBLT


def test_rendezvous_stable_and_partitioning():
    peers = ["pA", "pB", "pC", "pD"]
    sites = ["s%d.i2p" % i for i in range(200)]
    assign = {s: owner(s, peers) for s in sites}

    # every peer gets a share (no degenerate all-to-one)
    counts = {p: sum(1 for s in sites if assign[s] == p) for p in peers}
    assert all(c > 0 for c in counts.values()), counts

    # dropping pA only moves sites that were pA's; others are untouched
    peers2 = ["pB", "pC", "pD"]
    for s in sites:
        new = owner(s, peers2)
        if assign[s] != "pA":
            assert new == assign[s], (s, assign[s], new)
        else:
            assert new in peers2
    print("rendezvous: balanced and churn-stable:", counts)


def test_rendezvous_redundancy():
    peers = ["pA", "pB", "pC", "pD", "pE"]
    top = owners("x.i2p", peers, 3)
    assert len(top) == 3 and len(set(top)) == 3
    assert top[0] == owner("x.i2p", peers)          # primary is the top-weighted
    assert owns(top[0], "x.i2p", peers, 1)          # primary owns at r=1
    assert owns(top[2], "x.i2p", peers, 3)          # third owns at r=3
    assert not owns(top[2], "x.i2p", peers, 1)      # but not at r=1
    print("rendezvous: r-way owners include the primary:", top)


def test_hll_accuracy_and_merge():
    a = HyperLogLog(12)
    for i in range(10000):
        a.add("u%d" % i)
    est = a.estimate()
    assert abs(est - 10000) / 10000 < 0.05, est          # within 5%

    b = HyperLogLog(12)
    for i in range(5000, 15000):
        b.add("u%d" % i)
    a.merge(b)                                           # union is 15000 distinct
    est_union = a.estimate()
    assert abs(est_union - 15000) / 15000 < 0.05, est_union
    print("HLL: est=%d (10000), union est=%d (15000)" % (round(est), round(est_union)))


def test_iblt_reconciles_difference_not_size():
    # 2000 shared keys, a handful unique to each side, small table
    A, B = IBLT(256), IBLT(256)
    for i in range(2000):
        A.insert(i)
        B.insert(i)
    for i in (90001, 90002, 90003, 90004):
        A.insert(i)
    for i in (80001, 80002):
        B.insert(i)
    only_a, only_b, ok = A.subtract(B).decode()
    assert ok, "should decode cleanly: difference << cells"
    assert only_a == {90001, 90002, 90003, 90004}, only_a
    assert only_b == {80001, 80002}, only_b
    print("IBLT: decoded 4 vs 2 diff over 2000 shared in 256 cells")


def test_iblt_overflow_reports_failure():
    # difference far larger than the table can carry -> decode reports not-ok
    A, B = IBLT(32), IBLT(32)
    for i in range(500):
        A.insert(i)
    _, _, ok = A.subtract(B).decode()
    assert ok is False
    print("IBLT: overflow correctly reported as undecodable")


if __name__ == "__main__":
    test_rendezvous_stable_and_partitioning()
    test_rendezvous_redundancy()
    test_hll_accuracy_and_merge()
    test_iblt_reconciles_difference_not_size()
    test_iblt_overflow_reports_failure()
    print("sketches: all passed")
