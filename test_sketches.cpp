// Sketches: rendezvous stability, HyperLogLog accuracy and merge, IBLT reconciliation.
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "darcraw/sketches.hpp"
#include "check.hpp"

using namespace darcraw;

static std::string S(const char* fmt, int i) {
    char b[64];
    std::snprintf(b, sizeof b, fmt, i);
    return b;
}

int main() {
    // --- rendezvous: balanced and churn-stable ---
    std::vector<std::string> peers = {"pA", "pB", "pC", "pD"};
    std::vector<std::string> sites;
    for (int i = 0; i < 200; i++) sites.push_back(S("s%d.i2p", i));
    std::map<std::string, std::string> assign;
    std::map<std::string, int> counts;
    for (auto& s : sites) {
        assign[s] = hrw_owner(s, peers);
        counts[assign[s]]++;
    }
    for (auto& p : peers) REQUIRE(counts[p] > 0);

    std::vector<std::string> peers2 = {"pB", "pC", "pD"};
    for (auto& s : sites) {
        std::string nw = hrw_owner(s, peers2);
        if (assign[s] != "pA")
            REQUIRE(nw == assign[s]);     // untouched when their owner stays
        else
            REQUIRE(nw != "pA");          // pA's sites reassign within the survivors
    }
    std::printf("rendezvous: balanced and churn-stable\n");

    // --- rendezvous redundancy ---
    std::vector<std::string> p5 = {"pA", "pB", "pC", "pD", "pE"};
    auto top = hrw_owners("x.i2p", p5, 3);
    REQUIRE(top.size() == 3);
    REQUIRE(top[0] == hrw_owner("x.i2p", p5));
    REQUIRE(hrw_owns(top[0], "x.i2p", p5, 1));
    REQUIRE(hrw_owns(top[2], "x.i2p", p5, 3));
    REQUIRE(!hrw_owns(top[2], "x.i2p", p5, 1));
    std::printf("rendezvous: r-way owners include the primary\n");

    // --- HyperLogLog accuracy and merge ---
    HyperLogLog a(12), b(12);
    for (int i = 0; i < 10000; i++) a.add(S("u%d", i));
    double e1 = a.estimate();
    REQUIRE(std::abs(e1 - 10000) / 10000 < 0.05);
    for (int i = 5000; i < 15000; i++) b.add(S("u%d", i));
    a.merge(b);
    double e2 = a.estimate();
    REQUIRE(std::abs(e2 - 15000) / 15000 < 0.05);
    std::printf("HLL: est=%d (10000), union est=%d (15000)\n", (int)(e1 + 0.5), (int)(e2 + 0.5));

    // --- IBLT reconciles the difference, not the size ---
    IBLT A(256), B(256);
    for (uint64_t i = 0; i < 2000; i++) { A.insert(i); B.insert(i); }
    for (uint64_t k : {90001ULL, 90002ULL, 90003ULL, 90004ULL}) A.insert(k);
    for (uint64_t k : {80001ULL, 80002ULL}) B.insert(k);
    auto d = A.subtract(B).decode();
    REQUIRE(d.ok);
    REQUIRE((d.only_a == std::set<uint64_t>{90001, 90002, 90003, 90004}));
    REQUIRE((d.only_b == std::set<uint64_t>{80001, 80002}));
    std::printf("IBLT: decoded 4 vs 2 diff over 2000 shared in 256 cells\n");

    // --- IBLT overflow reports failure ---
    IBLT C(32), D(32);
    for (uint64_t i = 0; i < 500; i++) C.insert(i);
    REQUIRE(!C.subtract(D).decode().ok);
    std::printf("IBLT: overflow reported as undecodable\n");

    std::printf("sketches: all passed\n");
    return 0;
}
