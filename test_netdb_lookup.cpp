// Parallel, node-disjoint lookup, giving XOR-routing insulated queues.
// Network correctness, plus: a dead node on the closest path does not stall a lookup,
// and no node is queried by more than one path.
#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "darcraw/netdb.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    InMemoryNetwork net;
    ContentGate gate({}, {});
    std::vector<std::string> names = {"a", "b", "c", "d", "e", "f"};
    std::vector<std::unique_ptr<InMemoryTransport>> tr;
    std::vector<std::unique_ptr<Node>> nodes;
    for (auto& n : names) tr.push_back(std::make_unique<InMemoryTransport>(net, n));
    for (auto& t : tr) nodes.push_back(std::make_unique<Node>(*t, gate, 8, K, 3));

    for (auto& x : nodes)
        for (auto& y : nodes)
            if (x != y) x->learn(y->me());

    Bytes content = to_bytes("lawful eepsite snapshot");
    Bytes cid = sha256(content);

    // sort nodes by XOR distance to cid: closest is a replica, farthest is a non-holder
    std::vector<std::pair<Bytes, std::string>> ids;
    for (auto& n : nodes) ids.push_back({n->me().node_id, n->me().destination});
    std::sort(ids.begin(), ids.end(),
              [&](const auto& x, const auto& y) { return xor_closer(x.first, y.first, cid); });
    std::string closest = ids.front().second, farthest = ids.back().second;

    auto nodeByDest = [&](const std::string& d) -> Node* {
        for (auto& n : nodes)
            if (n->me().destination == d) return n.get();
        return nullptr;
    };

    // publish on the node closest to cid, read it back from every other node
    Node* publisher = nodeByDest(closest);
    auto pub = publisher->publish(content);
    REQUIRE(pub && *pub == cid);
    for (auto& n : nodes)
        if (n->me().destination != closest) {
            auto got = n->get(cid);
            REQUIRE(got && *got == content);
        }
    std::printf("lookup: content resolvable from all other nodes\n");

    // insulation: kill the closest replica, read from the farthest (a non-holder)
    Node* requester = nodeByDest(farthest);
    net.disable(closest);
    net.reset_calls();
    auto got = requester->get(cid);
    REQUIRE(got && *got == content);                 // routed around the dead path
    for (auto& n : nodes)
        REQUIRE(net.calls(n->me().destination) <= 1);  // node-disjoint: each queried at most once
    std::printf("lookup: dead replica on the closest path tolerated, paths node-disjoint\n");

    std::printf("netdb lookup: all passed\n");
    return 0;
}
