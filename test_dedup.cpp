// Dedup: Bloom has no false negatives, SeenSet gates duplicates.
#include <cstdio>
#include <string>

#include "darcraw/dedup.hpp"
#include "check.hpp"

using namespace darcraw;

static std::string S(const char* fmt, int i) {
    char b[64];
    std::snprintf(b, sizeof b, fmt, i);
    return b;
}

int main() {
    // no false negatives
    BloomFilter bf(50000, 0.001);
    for (int i = 0; i < 20000; i++) bf.add(S("i2p://site%d.i2p/page", i));
    for (int i = 0; i < 20000; i++) REQUIRE(bf.contains(S("i2p://site%d.i2p/page", i)));
    std::printf("bloom: 0 false negatives over 20000 inserts\n");

    // false-positive rate within budget
    BloomFilter bf2(50000, 0.01);
    for (int i = 0; i < 50000; i++) bf2.add(S("present%d", i));
    int fp = 0;
    for (int i = 50000; i < 100000; i++) if (bf2.contains(S("present%d", i))) fp++;
    double rate = fp / 50000.0;
    REQUIRE(rate < 0.03);
    std::printf("bloom: false-positive rate %.4f within budget\n", rate);

    // SeenSet dedup
    SeenSet ss(10000);
    REQUIRE(ss.check_and_mark("i2p://a.i2p") == true);
    REQUIRE(ss.check_and_mark("i2p://a.i2p") == false);
    REQUIRE(ss.seen("i2p://a.i2p"));
    REQUIRE(!ss.seen("i2p://b.i2p"));
    std::printf("seenset: admits new, rejects duplicate\n");

    // exact mode: no false-positive skips
    SeenSet ex(1000, 0.001, true);
    for (int i = 0; i < 5000; i++) ex.mark(S("u%d", i));
    for (int i = 5000; i < 6000; i++) REQUIRE(!ex.seen(S("u%d", i)));
    std::printf("seenset(exact): no false-positive skips\n");

    std::printf("dedup: all passed\n");
    return 0;
}
