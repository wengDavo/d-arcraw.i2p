// End-to-end: three in-memory nodes, a shared gate, publish and cross-node lookup,
// and proof that gated content never enters the netDb or replicates.
#include <cstdio>
#include <vector>

#include "darcraw/crawler.hpp"
#include "darcraw/netdb.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    InMemoryNetwork net;
    Bytes banned = to_bytes("KNOWN-ILLEGAL-PAYLOAD");
    ContentGate gate({sha256(banned)}, {});

    InMemoryTransport ta(net, "alpha"), tb(net, "beta"), tc(net, "gamma");
    Node alpha(ta, gate, 8, K, 3), beta(tb, gate, 8, K, 3), gamma(tc, gate, 8, K, 3);
    std::vector<Node*> nodes = {&alpha, &beta, &gamma};
    for (auto* x : nodes)
        for (auto* y : nodes)
            if (x != y) x->learn(y->me());

    // 1. publish lawful content on alpha, read it back from gamma
    Bytes good = to_bytes("an intense but lawful shitpost");
    auto cid = alpha.publish(good);
    REQUIRE(cid.has_value());
    auto fetched = gamma.get(*cid);
    REQUIRE(fetched && *fetched == good);
    std::printf("cross-node lookup of lawful content: ok\n");

    // 2. gated content never gets a CID, never stored, never replicated
    REQUIRE(!alpha.publish(banned).has_value());
    Bytes bcid = sha256(banned);
    for (auto* n : nodes) REQUIRE(n->catalog().present().count(to_hex(bcid)) == 0);
    std::printf("gated content absent from every catalog: ok\n");

    // even a direct store RPC is refused by the admission gate
    Writer w;
    w.u8(OP_STORE);
    w.bytes(banned);
    std::string resp = net.send("attacker", "beta", w.take());
    Reader r(resp);
    REQUIRE(r.u8() == 0);   // store refused
    REQUIRE(!beta.store().get(bcid).has_value());
    std::printf("direct injection refused by store-admission gate: ok\n");

    // 3. crawler wires to the same gate, a fetch of banned content is dropped at ingestion
    Fetcher fetcher = [&](const std::string& url) -> std::optional<std::pair<Bytes, std::vector<Bytes>>> {
        if (url == "i2p://good") return std::make_pair(good, std::vector<Bytes>{});
        if (url == "i2p://bad") return std::make_pair(banned, std::vector<Bytes>{});
        return std::nullopt;
    };
    Crawler c(&alpha, gate, fetcher, 3, 0.15, 8);
    c.submit(Candidate{"i2p://good", "registry", {1.0, 0.2, 0.0}});
    c.submit(Candidate{"i2p://bad", "registry", {0.1, 0.9, 1.0}});
    c.tick();
    REQUIRE(!alpha.store().get(sha256(banned)).has_value());
    std::printf("crawler never stored gated content: ok\n");

    std::printf("example: all passed\n");
    return 0;
}
