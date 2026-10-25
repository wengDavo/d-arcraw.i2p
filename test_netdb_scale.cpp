// LRU bucket eviction and delta anti-entropy convergence.
#include <cstdio>
#include <string>

#include "darcraw/netdb.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    // --- LRU eviction ---
    Bytes zero(32, 0);
    Peer A{Bytes(32, 0), "a", 0};
    A.node_id[0] = 0x80;                        // same top bit -> same bucket as B
    Peer B{Bytes(32, 0), "b", 0};
    B.node_id[0] = 0xC0;

    {   // live oldest: keep it, drop the newcomer
        RoutingTable rt(zero, 1);
        rt.add(A, [](const Peer&) { return true; });
        rt.add(B, [](const Peer&) { return true; });
        auto c = rt.closest(zero, 10);
        REQUIRE(c.size() == 1 && c[0].destination == "a");
    }
    {   // dead oldest: evict it, admit the newcomer
        RoutingTable rt(zero, 1);
        rt.add(A, [](const Peer&) { return false; });
        rt.add(B, [](const Peer&) { return false; });
        auto c = rt.closest(zero, 10);
        REQUIRE(c.size() == 1 && c[0].destination == "b");
    }
    std::printf("LRU: live oldest kept, dead oldest evicted\n");

    // --- delta anti-entropy convergence ---
    InMemoryNetwork net;
    ContentGate gate({}, {});                   // armed, empty blocklist
    InMemoryTransport ta(net, "alpha"), tb(net, "beta");
    Node alpha(ta, gate, 8), beta(tb, gate, 8);
    alpha.learn(beta.me());
    beta.learn(alpha.me());

    for (int i = 0; i < 3; i++) alpha.catalog().add(sha256(std::string("A") + std::to_string(i)));
    for (int i = 0; i < 2; i++) beta.catalog().add(sha256(std::string("B") + std::to_string(i)));

    alpha.anti_entropy(beta.me());
    REQUIRE(alpha.catalog().present() == beta.catalog().present());
    REQUIRE(alpha.catalog().present().size() == 5);
    std::printf("anti-entropy: catalogs converged to 5 entries both ways\n");

    // --- already synced: only the fingerprint query goes out ---
    net.reset_calls();
    alpha.anti_entropy(beta.me());
    REQUIRE(net.calls("beta") == 1);
    std::printf("anti-entropy: synced reconcile ships only the fp query\n");

    std::printf("netdb scale: all passed\n");
    return 0;
}
