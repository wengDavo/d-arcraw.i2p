"""
Signed records: signature verification, cryptographic expiry, TTL caps, per-origin
admission limiting, and republication.
Run: python3 test_records.py   (needs: pip install cryptography)
"""
import dataclasses
from cryptography.hazmat.primitives.asymmetric import ed25519

import records as R


def _key():
    return ed25519.Ed25519PrivateKey.generate()


def test_sign_and_verify():
    k = _key()
    rec = R.sign_record(k, "routerinfo", b"payload", ttl=3600, now=1000)
    ok, reason = R.verify_record(rec, now=1000)
    assert ok and reason == "ok"
    print("records: valid record verifies")


def test_tamper_breaks_signature():
    k = _key()
    rec = R.sign_record(k, "routerinfo", b"payload", ttl=3600, now=1000)
    for field, bad in [("payload", b"other"), ("expires", rec.expires + 1),
                       ("issued", rec.issued - 1), ("kind", "leaseset")]:
        t = dataclasses.replace(rec, **{field: bad})
        ok, reason = R.verify_record(t, now=1000)
        assert not ok, ("tamper of %s should fail" % field)
    print("records: any tampered field fails verification")


def test_wrong_key_rejected():
    k, other = _key(), _key()
    rec = R.sign_record(k, "routerinfo", b"p", ttl=3600, now=1000)
    forged = dataclasses.replace(rec, publisher=other.public_key().public_bytes_raw())
    ok, reason = R.verify_record(forged, now=1000)
    assert not ok and reason == "bad-signature"
    print("records: signature from a different key is rejected")


def test_expiry():
    k = _key()
    rec = R.sign_record(k, "leaseset", b"p", ttl=300, now=1000)
    assert R.verify_record(rec, now=1000)[0]
    assert R.verify_record(rec, now=1299)[0]
    assert R.verify_record(rec, now=1300) == (False, "expired")
    print("records: expires exactly at the signed timestamp")


def test_leaseset_ttl_capped_under_ten_minutes():
    k = _key()
    try:
        R.sign_record(k, "leaseset", b"p", ttl=601, now=1000)
        assert False, "ttl over cap should be refused at signing"
    except ValueError:
        pass
    # a forged over-cap lifetime is caught at verification too
    pub = k.public_key().public_bytes_raw()
    iss, exp = 1000, 1000 + 5000
    sig = k.sign(R.canonical("leaseset", pub, b"p", iss, exp))
    forged = R.SignedRecord("leaseset", pub, b"p", iss, exp, sig)
    assert R.verify_record(forged, now=1000) == (False, "ttl-too-long")
    print("records: leaseset lifetime capped under 10 min at sign and verify")


def test_future_dating_rejected():
    k = _key()
    rec = R.sign_record(k, "routerinfo", b"p", ttl=3600, now=5000)
    assert R.verify_record(rec, now=1000) == (False, "future-dated")
    print("records: far-future issued timestamp rejected")


def test_store_per_origin_rate_limit():
    # Each record is strictly newer (increasing issued) so none is rejected as stale;
    # the only thing that can cap admissions is the per-origin limiter. Its clock is
    # held fixed so no tokens refill mid-burst, while the store's freshness clock
    # advances with the issue times.
    now = [2000]
    st = R.RecordStore(per_origin_rate=1.0, per_origin_burst=3.0, clock=lambda: now[0])
    st._limiter.clock = lambda: 1000.0          # fixed: burst of 3, no refill
    k = _key()
    accepted = 0
    for i in range(5):
        now[0] = 2000 + i
        rec = R.sign_record(k, "announce", b"p", ttl=100, now=2000 + i)
        ok, reason = st.admit(rec)
        accepted += ok
    assert accepted == 3, accepted              # burst of 3, remaining 2 rate-limited
    print("records: per-origin admission capped to the burst (%d accepted)" % accepted)


def test_store_newer_replaces_older_and_expiry_reaps():
    t = [1000.0]
    st = R.RecordStore(per_origin_rate=100.0, per_origin_burst=100.0, clock=lambda: t[0])
    k = _key()
    r1 = R.sign_record(k, "leaseset", b"v1", ttl=300, now=1000)
    assert st.admit(r1)[0]
    # an older-or-equal issue is stale
    assert st.admit(r1) == (False, "stale")
    # a newer one replaces it (advance the clock so the newer issue is not future-dated)
    t[0] = 1100.0
    r2 = R.sign_record(k, "leaseset", b"v2", ttl=300, now=1100)
    assert st.admit(r2)[0]
    assert st.get("leaseset", k.public_key().public_bytes_raw()).payload == b"v2"
    # after expiry the store reaps it, forcing republication
    t[0] = 1500.0
    assert st.get("leaseset", k.public_key().public_bytes_raw()) is None
    print("records: newer replaces older; expired records reaped")


def test_due_for_republish():
    t = [1000.0]
    st = R.RecordStore(clock=lambda: t[0])
    k = _key()
    rec = R.sign_record(k, "leaseset", b"p", ttl=300, now=1000)  # expires 1300
    assert not st.due_for_republish(rec)        # fresh
    t[0] = 1250.0                                # within 20% of expiry (<=60s left)
    assert st.due_for_republish(rec)
    print("records: republication flagged before expiry")


def test_red25519_is_honest_stub():
    k = _key()
    rec = R.sign_record(k, "leaseset", b"p", ttl=300, now=1000)
    try:
        R.verify_blinded(rec)
        assert False, "blinded verify must not silently succeed"
    except NotImplementedError:
        pass
    print("records: Red25519 blinded path is an explicit NotImplementedError")


if __name__ == "__main__":
    test_sign_and_verify()
    test_tamper_breaks_signature()
    test_wrong_key_rejected()
    test_expiry()
    test_leaseset_ttl_capped_under_ten_minutes()
    test_future_dating_rejected()
    test_store_per_origin_rate_limit()
    test_store_newer_replaces_older_and_expiry_reaps()
    test_due_for_republish()
    test_red25519_is_honest_stub()
    print("records: all passed")
