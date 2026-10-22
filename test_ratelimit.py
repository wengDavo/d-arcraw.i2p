"""
Rate limiting: token-bucket burst/refill math and per-key isolation, on a fake clock.
Run: python3 test_ratelimit.py   (stdlib only)
"""
from ratelimit import TokenBucket, PerKeyRateLimiter


def test_bucket_burst_then_paced():
    t = [0.0]
    tb = TokenBucket(rate=2.0, capacity=2.0, clock=lambda: t[0])
    assert tb.take() and tb.take()          # burst of 2
    assert not tb.take()                    # empty
    t[0] = 0.5                              # half a second -> 1 token at rate 2/s
    assert tb.take()
    assert not tb.take()
    print("bucket: bursts to capacity then paces at rate")


def test_bucket_caps_at_capacity():
    t = [0.0]
    tb = TokenBucket(rate=1.0, capacity=3.0, clock=lambda: t[0])
    t[0] = 100.0                            # long idle must not overfill
    assert tb.take() and tb.take() and tb.take()
    assert not tb.take()
    print("bucket: idle refill capped at capacity")


def test_bucket_wait_time():
    t = [0.0]
    tb = TokenBucket(rate=4.0, capacity=4.0, clock=lambda: t[0])
    for _ in range(4):
        tb.take()
    # empty; need 1 token at 4/s -> 0.25s
    assert abs(tb.wait_time() - 0.25) < 1e-9, tb.wait_time()
    print("bucket: wait_time computed correctly")


def test_per_key_isolation():
    t = [0.0]
    rl = PerKeyRateLimiter(rate=1.0, capacity=1.0, clock=lambda: t[0])
    assert rl.allow("a.i2p")                # a spends its token
    assert not rl.allow("a.i2p")            # a is now empty
    assert rl.allow("b.i2p")                # b is independent
    print("per-key: buckets isolated by key")


def test_per_key_reap():
    t = [0.0]
    rl = PerKeyRateLimiter(rate=1.0, capacity=1.0, clock=lambda: t[0])
    rl.allow("a.i2p")                        # last activity at t=0
    rl.allow("b.i2p")
    t[0] = 100.0
    rl.allow("b.i2p")                        # b touched at t=100
    t[0] = 350.0                             # a idle 350s, b idle 250s
    rl.reap(max_idle=300.0)
    assert "a.i2p" not in rl._buckets        # idle past the window -> reaped
    assert "b.i2p" in rl._buckets            # still within the window -> kept
    print("per-key: idle buckets reaped, active ones kept")


if __name__ == "__main__":
    test_bucket_burst_then_paced()
    test_bucket_caps_at_capacity()
    test_bucket_wait_time()
    test_per_key_isolation()
    test_per_key_reap()
    print("ratelimit: all passed")
