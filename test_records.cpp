// Signed records: verification, cryptographic expiry, TTL caps, per-origin admission
// limiting, republication.
#include <cstdio>
#include <stdexcept>

#include "darcraw/records.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    // sign and verify
    Ed25519 k = Ed25519::generate();
    SignedRecord rec = sign_record(k, "routerinfo", to_bytes("payload"), 3600, 1000);
    REQUIRE(verify_record(rec, 1000).ok);

    // tamper breaks the signature
    {
        SignedRecord t = rec;
        t.payload = to_bytes("other");
        REQUIRE(!verify_record(t, 1000).ok);
        SignedRecord t2 = rec;
        t2.expires += 1;
        REQUIRE(!verify_record(t2, 1000).ok);
    }
    // wrong key
    {
        Ed25519 other = Ed25519::generate();
        SignedRecord f = rec;
        f.publisher = other.public_bytes();
        REQUIRE(verify_record(f, 1000).reason == "bad-signature");
    }
    std::printf("records: valid verifies, tamper and wrong key rejected\n");

    // expiry exactly at the signed timestamp
    {
        SignedRecord ls = sign_record(k, "leaseset", to_bytes("p"), 300, 1000);
        REQUIRE(verify_record(ls, 1000).ok);
        REQUIRE(verify_record(ls, 1299).ok);
        REQUIRE(verify_record(ls, 1300).reason == "expired");
    }
    std::printf("records: expires at the signed timestamp\n");

    // leaseset TTL capped under ten minutes, at sign and at verify
    {
        bool threw = false;
        try { sign_record(k, "leaseset", to_bytes("p"), 601, 1000); }
        catch (const std::invalid_argument&) { threw = true; }
        REQUIRE(threw);
        // forged over-cap lifetime caught at verification
        Bytes pub = k.public_bytes();
        int64_t iss = 1000, exp = 1000 + 5000;
        SignedRecord forged;
        forged.kind = "leaseset";
        forged.publisher = pub;
        forged.payload = to_bytes("p");
        forged.issued = iss;
        forged.expires = exp;
        forged.signature = k.sign(record_canonical("leaseset", pub, to_bytes("p"), iss, exp));
        REQUIRE(verify_record(forged, 1000).reason == "ttl-too-long");
    }
    std::printf("records: leaseset lifetime capped under 10 min\n");

    // future dating rejected
    {
        SignedRecord fut = sign_record(k, "routerinfo", to_bytes("p"), 3600, 5000);
        REQUIRE(verify_record(fut, 1000).reason == "future-dated");
    }
    std::printf("records: far-future issued rejected\n");

    // per-origin admission capped to the burst
    {
        double now = 2000;
        Clock store = [&now]() { return now; };
        Clock lim = []() { return 1000.0; };   // fixed: burst of 3, no refill
        RecordStore st(1.0, 3.0, store, lim);
        Ed25519 key = Ed25519::generate();
        int accepted = 0;
        for (int i = 0; i < 5; i++) {
            now = 2000 + i;
            SignedRecord r = sign_record(key, "announce", to_bytes("p"), 100, 2000 + i);
            if (st.admit(r).ok) accepted++;
        }
        REQUIRE(accepted == 3);
    }
    std::printf("records: per-origin admission capped to the burst\n");

    // newer replaces older, expired reaped
    {
        double t = 1000;
        Clock c = [&t]() { return t; };
        RecordStore st(100.0, 100.0, c, c);
        Ed25519 key = Ed25519::generate();
        SignedRecord r1 = sign_record(key, "leaseset", to_bytes("v1"), 300, 1000);
        REQUIRE(st.admit(r1).ok);
        REQUIRE(st.admit(r1).reason == "stale");
        t = 1100;
        SignedRecord r2 = sign_record(key, "leaseset", to_bytes("v2"), 300, 1100);
        REQUIRE(st.admit(r2).ok);
        SignedRecord out;
        REQUIRE(st.get("leaseset", key.public_bytes(), out));
        REQUIRE(to_string(out.payload) == "v2");
        t = 1500;
        REQUIRE(!st.get("leaseset", key.public_bytes(), out));
    }
    std::printf("records: newer replaces older, expired reaped\n");

    // due_for_republish
    {
        double t = 1000;
        Clock c = [&t]() { return t; };
        RecordStore st(100.0, 100.0, c, c);
        SignedRecord rec2 = sign_record(k, "leaseset", to_bytes("p"), 300, 1000);  // expires 1300
        REQUIRE(!st.due_for_republish(rec2));
        t = 1250;
        REQUIRE(st.due_for_republish(rec2));
    }
    std::printf("records: republication flagged before expiry\n");

    // Red25519 blinded path is an explicit not-implemented
    {
        bool threw = false;
        try { verify_blinded(rec); } catch (const std::runtime_error&) { threw = true; }
        REQUIRE(threw);
    }
    std::printf("records: Red25519 blinded path raises not-implemented\n");

    std::printf("records: all passed\n");
    return 0;
}
