// Blocklist: threshold signatures, tamper rejection, rollback protection, fail-closed.
#include <cstdio>

#include "darcraw/blocklist.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    Ed25519 k0 = Ed25519::generate(), k1 = Ed25519::generate(), k2 = Ed25519::generate();
    MaintainerSet mset;
    for (auto* k : {&k0, &k1, &k2}) mset.pubkeys[keyid(k->public_bytes())] = k->public_bytes();
    mset.threshold = 2;

    Bytes banned = to_bytes("KNOWN-ILLEGAL-PAYLOAD");
    Bytes bh = sha256(banned);

    // 2-of-3 verifies
    Bytes blob2 = make_blocklist(2, "t2", {bh}, {}, {k0, k1});
    Blocklist bl = verify_blocklist(blob2, mset);
    REQUIRE(bl.version == 2 && bl.exact.count(bh) == 1);

    // below threshold rejected
    {
        Bytes one = make_blocklist(3, "t3", {bh}, {}, {k0});
        bool threw = false;
        try { verify_blocklist(one, mset); } catch (...) { threw = true; }
        REQUIRE(threw);
    }
    // tamper rejected
    {
        Bytes t = blob2;
        t[t.size() / 2] ^= 1;
        bool threw = false;
        try { verify_blocklist(t, mset); } catch (...) { threw = true; }
        REQUIRE(threw);
    }
    std::printf("blocklist: threshold enforced, below-threshold and tampered rejected\n");

    // fail-closed until armed, then rollback protection
    ContentGate gate = ContentGate::unarmed();
    REQUIRE(!gate.check(to_bytes("anything")).allowed);     // fail closed
    BlocklistManager mgr(&gate, mset, 0);
    REQUIRE(mgr.apply(blob2));
    REQUIRE(gate.version() == 2);
    Bytes blob1 = make_blocklist(1, "t1", {bh}, {}, {k0, k1});
    REQUIRE(!mgr.apply(blob1));                             // older ignored
    REQUIRE(!mgr.apply(blob2));                             // equal ignored
    REQUIRE(!gate.check(banned).allowed);                  // armed: blocks banned
    REQUIRE(gate.check(to_bytes("lawful")).allowed);       // allows other
    std::printf("blocklist: fail-closed, armed, rollback ignored\n");

    std::printf("sec: all passed\n");
    return 0;
}
