// Orchestrator: dedup admission, rendezvous ownership, per-domain politeness, the gate
// surviving the pump, and cross-peer seen reconciliation.
#include <cstdio>
#include <map>
#include <optional>
#include <string>

#include "darcraw/orchestrator.hpp"
#include "check.hpp"

using namespace darcraw;

static const Bytes GOOD = to_bytes("an intense but lawful shitpost");
static const Bytes BANNED = to_bytes("KNOWN-ILLEGAL-PAYLOAD");

static Opener make_opener(std::map<std::string, Bytes> table) {
    return [table](const std::string& url, const std::string&,
                   const std::map<std::string, std::string>&) -> OpenerResult {
        auto it = table.find(url);
        OpenerResult r;
        if (it != table.end()) { r.status = 200; r.body = it->second; }
        else { r.status = 404; }
        return r;
    };
}

int main() {
    // --- dedup admission ---
    {
        InMemoryNetwork net;
        ContentGate gate({}, {});
        InMemoryTransport t(net, "alpha");
        Node node(t, gate, 8);
        FetchPool pool(FetchBackend(make_opener({})));
        Orchestrator orc(&node, gate, &pool, "alpha", {"alpha"}, 3);
        REQUIRE(orc.submit("i2p://a.i2p/1", "reg", {1, 0, 0}) == "admitted");
        REQUIRE(orc.submit("i2p://a.i2p/1", "reg", {1, 0, 0}) == "dup");
        REQUIRE(orc.stats().dup == 1);
        std::printf("orchestrator: duplicate URL rejected at admission\n");
    }

    // --- rendezvous ownership gates submit ---
    {
        InMemoryNetwork net;
        ContentGate gate({}, {});
        InMemoryTransport t(net, "alpha");
        Node node(t, gate, 8);
        FetchPool pool(FetchBackend(make_opener({})));
        std::vector<std::string> peers = {"alpha", "beta", "gamma", "delta", "epsilon"};
        Orchestrator orc(&node, gate, &pool, "alpha", peers, 3);

        std::string mine, not_mine;
        for (int i = 0; i < 500 && (mine.empty() || not_mine.empty()); i++) {
            std::string s = "s" + std::to_string(i) + ".i2p";
            std::string o = hrw_owner(s, peers);
            if (o == "alpha" && mine.empty()) mine = s;
            if (o != "alpha" && not_mine.empty()) not_mine = s;
        }
        REQUIRE(!mine.empty() && !not_mine.empty());
        REQUIRE(orc.submit("i2p://" + mine + "/x", "reg", {1, 0, 0}) == "admitted");
        REQUIRE(orc.submit("i2p://" + not_mine + "/x", "reg", {1, 0, 0}) == "not-owned");
        REQUIRE(orc.pending() == 1);
        std::printf("orchestrator: scrapes only rendezvous-owned sites\n");
    }

    // --- per-domain politeness releases slowly ---
    {
        InMemoryNetwork net;
        ContentGate gate({}, {});
        InMemoryTransport t(net, "solo");
        Node node(t, gate, 8);
        std::map<std::string, Bytes> table;
        std::vector<std::string> urls;
        for (int i = 0; i < 3; i++) {
            std::string u = "i2p://poll.i2p/" + std::to_string(i);
            urls.push_back(u);
            table[u] = GOOD;
        }
        FetchPool pool(FetchBackend(make_opener(table)));
        double tc = 0.0;
        Clock clk = [&tc]() { return tc; };
        Orchestrator orc(&node, gate, &pool, "solo", {"solo"}, 3, 1, 1.0, 1.0,
                         SeenSet(), nullptr, 1024, clk);
        for (auto& u : urls) REQUIRE(orc.submit(u, "reg", {1, 0, 0}) == "admitted");
        REQUIRE(orc.pending() == 3);
        REQUIRE(orc.pump() == 1);
        REQUIRE(orc.pending() == 2);
        tc = 2.0;
        REQUIRE(orc.pump() == 1);
        REQUIRE(orc.pending() == 1);
        std::printf("orchestrator: per-domain bucket paces releases\n");
    }

    // --- gate survives the pump ---
    {
        InMemoryNetwork net;
        ContentGate gate({sha256(BANNED)}, {});
        InMemoryTransport t(net, "solo");
        Node node(t, gate, 8);
        std::string gurl = "i2p://g.i2p/x", burl = "i2p://b.i2p/x";
        FetchPool pool(FetchBackend(make_opener({{gurl, GOOD}, {burl, BANNED}})));
        Orchestrator orc(&node, gate, &pool, "solo", {"solo"}, 3, 1, 100.0, 100.0);
        orc.submit(gurl, "reg", {1, 0, 0});
        orc.submit(burl, "reg", {0, 1, 1});
        for (int i = 0; i < 3; i++) orc.pump();
        auto present = node.catalog().present();
        REQUIRE(present.count(to_hex(sha256(GOOD))) == 1);
        REQUIRE(present.count(to_hex(sha256(BANNED))) == 0);
        REQUIRE(node.store().get(sha256(GOOD)).has_value());
        REQUIRE(!node.store().get(sha256(BANNED)).has_value());
        std::printf("orchestrator: gate holds through the pump (good in, banned out)\n");
    }

    // --- cross-peer seen reconcile ---
    {
        InMemoryNetwork n1, n2;
        ContentGate g1({}, {}), g2({}, {});
        InMemoryTransport t1(n1, "p1"), t2(n2, "p2");
        Node node1(t1, g1, 8), node2(t2, g2, 8);
        FetchPool pool1(FetchBackend(make_opener({}))), pool2(FetchBackend(make_opener({})));
        Orchestrator o1(&node1, g1, &pool1, "p1", {"p1"}, 3, 1, 0.5, 2.0, SeenSet(), nullptr, 512);
        Orchestrator o2(&node2, g2, &pool2, "p2", {"p2"}, 3, 1, 0.5, 2.0, SeenSet(), nullptr, 512);

        for (int i = 0; i < 100; i++) {
            std::string u = "i2p://shared" + std::to_string(i) + ".i2p";
            o1.submit(u, "reg", {1, 0, 0});
            o2.submit(u, "reg", {1, 0, 0});
        }
        for (int i = 0; i < 5; i++) o1.submit("i2p://only1-" + std::to_string(i) + ".i2p", "reg", {1, 0, 0});
        for (int i = 0; i < 3; i++) o2.submit("i2p://only2-" + std::to_string(i) + ".i2p", "reg", {1, 0, 0});

        ReconcileResult r = o1.reconcile_seen(o2.seen_iblt());
        REQUIRE(r.ok);
        REQUIRE(r.learned == 3);
        REQUIRE(r.we_had == 5);
        std::printf("orchestrator: cross-peer seen reconcile learned %d, had %d extra\n",
                    r.learned, r.we_had);
    }

    std::printf("orchestrator: all passed\n");
    return 0;
}
