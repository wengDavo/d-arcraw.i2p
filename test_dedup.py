"""
Dedup: Bloom has no false negatives, SeenSet gates duplicates.
Run: python3 test_dedup.py   (stdlib only)
"""
from dedup import BloomFilter, SeenSet


def test_bloom_no_false_negatives():
    bf = BloomFilter(n=50000, p=0.001)
    for i in range(20000):
        bf.add("i2p://site%d.i2p/page" % i)
    missing = [i for i in range(20000) if "i2p://site%d.i2p/page" % i not in bf]
    assert missing == [], "a Bloom filter must never report a present item absent"
    print("bloom: 0 false negatives over 20000 inserts")


def test_bloom_false_positive_rate_in_budget():
    bf = BloomFilter(n=50000, p=0.01)
    for i in range(50000):
        bf.add("present%d" % i)
    fp = sum(1 for i in range(50000, 100000) if "present%d" % i in bf)
    rate = fp / 50000
    assert rate < 0.03, rate            # comfortably near the 1% target
    print("bloom: false-positive rate %.4f within budget" % rate)


def test_seenset_dedup():
    ss = SeenSet(n=10000)
    assert ss.check_and_mark("i2p://a.i2p") is True     # first sight: admitted
    assert ss.check_and_mark("i2p://a.i2p") is False    # duplicate: rejected
    assert ss.seen("i2p://a.i2p") is True
    assert ss.seen("i2p://b.i2p") is False
    print("seenset: admits new, rejects duplicate")


def test_seenset_exact_no_false_skips():
    ss = SeenSet(n=1000, exact=True)
    for i in range(5000):
        ss.mark("u%d" % i)
    # exact mode: a never-seen url is never wrongly reported seen
    wrongly_seen = [i for i in range(5000, 6000) if ss.seen("u%d" % i)]
    assert wrongly_seen == []
    print("seenset(exact): no false-positive skips")


if __name__ == "__main__":
    test_bloom_no_false_negatives()
    test_bloom_false_positive_rate_in_budget()
    test_seenset_dedup()
    test_seenset_exact_no_false_skips()
    print("dedup: all passed")
