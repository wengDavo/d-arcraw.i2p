// SipHash-2-4 keyed 64-bit hash (Aumasson & Bernstein, CC0 reference logic).
// Reads message words little-endian explicitly, so the result is identical on any
// architecture. That matters here: peers must agree on rendezvous weights and IBLT
// cell positions, so the hash cannot depend on host endianness.
#pragma once
#include <cstddef>
#include <cstdint>

namespace darcraw {

inline uint64_t siphash24(const uint8_t* in, size_t inlen, uint64_t k0, uint64_t k1) {
    auto rotl = [](uint64_t x, int b) { return (x << b) | (x >> (64 - b)); };
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    auto round = [&]() {
        v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
        v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
    };
    const size_t full = inlen - (inlen % 8);
    uint64_t b = (uint64_t)inlen << 56;
    size_t i = 0;
    for (; i < full; i += 8) {
        uint64_t m = 0;
        for (int j = 0; j < 8; j++) m |= (uint64_t)in[i + j] << (8 * j);  // little-endian
        v3 ^= m; round(); round(); v0 ^= m;
    }
    for (int j = 0, left = (int)(inlen & 7); j < left; j++)
        b |= (uint64_t)in[full + j] << (8 * j);
    v3 ^= b; round(); round(); v0 ^= b;
    v2 ^= 0xff; round(); round(); round(); round();
    return v0 ^ v1 ^ v2 ^ v3;
}

// Convenience: seed a key from one 64-bit value. The second half is a fixed
// constant so distinct seeds give independent hash functions.
inline uint64_t siphash64(const uint8_t* in, size_t inlen, uint64_t seed) {
    return siphash24(in, inlen, seed, 0x9e3779b97f4a7c15ULL);
}

}  // namespace darcraw
