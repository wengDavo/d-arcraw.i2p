// Governance: maintainer-set rotation and the hash-proposal lifecycle.
#include <cstdio>

#include "darcraw/governance.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    Ed25519 a = Ed25519::generate(), b = Ed25519::generate(),
            c = Ed25519::generate(), d = Ed25519::generate();
    Bytes ap = a.public_bytes(), bp = b.public_bytes(), cp = c.public_bytes(), dp = d.public_bytes();

    // genesis: 3 members, threshold 2
    MaintainerChain chain(make_maintainer_set_doc(1, {{ap, "m"}, {bp, "m"}, {cp, "m"}}, 2));

    // rotate to v2: add d, raise threshold to 3, signed by 2 of the current 3
    Bytes rot = sign_set_doc(make_maintainer_set_doc(2, {{ap, "m"}, {bp, "m"}, {cp, "m"}, {dp, "m"}}, 3), {a, b});
    REQUIRE(chain.apply_rotation(rot));
    REQUIRE(chain.current().version == 2 && chain.current().threshold == 3 &&
            chain.current().members.size() == 4);

    // a rotation signed by only one current member is rejected (need 3 now)
    {
        Bytes bad = sign_set_doc(make_maintainer_set_doc(3, {{ap, "m"}, {bp, "m"}, {cp, "m"}, {dp, "m"}}, 3), {a});
        bool threw = false;
        try { chain.apply_rotation(bad); } catch (...) { threw = true; }
        REQUIRE(threw);
    }
    std::printf("governance: maintainer-set rotation under current threshold\n");

    // proposal lifecycle: add a hash, co-sign to threshold, promote into a blocklist
    MaintainerSet mset = chain.maintainer_set();   // threshold 3
    Bytes h = sha256(to_bytes("known-bad-content"));
    SignedDoc prop = make_proposal("add", {h}, "csam", "ref#1", a);
    prop = cosign_proposal(prop, b);
    prop = cosign_proposal(prop, c);
    REQUIRE(proposal_support(prop, mset) == 3);
    REQUIRE(accepted(prop, mset));

    PromoteResult pr = promote({}, {}, {prop}, mset, {a, b, c}, 1);
    REQUIRE(pr.applied == 1 && pr.exact.count(h) == 1);
    REQUIRE(verify_blocklist(pr.blob, mset).exact.count(h) == 1);

    ContentGate gate = ContentGate::unarmed();
    BlocklistManager mgr(&gate, mset, 0);
    REQUIRE(mgr.apply(pr.blob));
    REQUIRE(!gate.check(to_bytes("known-bad-content")).allowed);
    std::printf("governance: proposal promoted, blocklist arms the gate\n");

    // removal lifts the hash
    SignedDoc rem = make_proposal("remove", {h}, "false-positive", "ref#2", a);
    rem = cosign_proposal(rem, b);
    rem = cosign_proposal(rem, c);
    PromoteResult pr2 = promote(pr.exact, pr.phash, {rem}, mset, {a, b, c}, 2);
    REQUIRE(pr2.exact.count(h) == 0);
    std::printf("governance: remove proposal lifts the hash\n");

    std::printf("governance: all passed\n");
    return 0;
}
