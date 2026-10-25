// Hashing and byte helpers. SHA-256 comes from OpenSSL. The keyed 64-bit hash used
// by the sketches and the Bloom filter is SipHash.
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>

#include "darcraw/siphash.hpp"

namespace darcraw {

using Bytes = std::vector<uint8_t>;

inline Bytes sha256(const uint8_t* data, size_t n) {
    Bytes out(32);
    unsigned len = 0;
    EVP_Digest(data, n, out.data(), &len, EVP_sha256(), nullptr);
    return out;
}
inline Bytes sha256(const std::string& s) {
    return sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
inline Bytes sha256(const Bytes& b) { return sha256(b.data(), b.size()); }

inline uint64_t siphash64(const std::string& s, uint64_t seed) {
    return siphash64(reinterpret_cast<const uint8_t*>(s.data()), s.size(), seed);
}

inline std::string to_hex(const uint8_t* d, size_t n) {
    static const char* hx = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        out.push_back(hx[d[i] >> 4]);
        out.push_back(hx[d[i] & 0xf]);
    }
    return out;
}
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }

inline Bytes from_hex(const std::string& h) {
    if (h.size() % 2) throw std::invalid_argument("odd hex length");
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument("bad hex digit");
    };
    Bytes out(h.size() / 2);
    for (size_t i = 0; i < out.size(); i++)
        out[i] = (uint8_t)((nib(h[2 * i]) << 4) | nib(h[2 * i + 1]));
    return out;
}

inline Bytes to_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}
inline std::string to_string(const Bytes& b) {
    return std::string(b.begin(), b.end());
}

}  // namespace darcraw
