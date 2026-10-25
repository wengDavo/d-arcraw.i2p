// Fingerprint: SimHash near-duplicate distance and the banded LSH index.
#include <cstdio>
#include <string>

#include "darcraw/fingerprint.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    std::string base, far;
    for (int i = 0; i < 40; i++) base += "the quick brown fox jumps over the lazy dog ";
    for (int i = 0; i < 40; i++) far += "lorem ipsum dolor sit amet consectetur adipiscing elit ";
    std::string near = base + "and then the fox rested for a while";

    uint64_t hb = content_simhash(base), hn = content_simhash(near), hf = content_simhash(far);
    REQUIRE(fp_hamming(hb, hn) <= 3);        // a small edit moves only a few bits
    REQUIRE(fp_hamming(hb, hf) > 10);        // different content is far
    std::printf("simhash: near edit %d bits, different content %d bits\n",
                fp_hamming(hb, hn), fp_hamming(hb, hf));

    SimHashIndex idx;
    idx.add(hb, "base.i2p");
    auto q = idx.query(hn);
    REQUIRE(!q.empty() && q[0].first == "base.i2p");
    for (const auto& kd : idx.query(hf)) REQUIRE(kd.first != "base.i2p");
    std::printf("lsh index: near-dup found, far content not matched\n");

    std::printf("fingerprint: all passed\n");
    return 0;
}
