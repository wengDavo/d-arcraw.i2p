// Content gate: fixed, non-learned, authoritative. Exact-hash and perceptual-hash
// blocklist, deny on match. It runs at crawler ingestion and at every store-admission,
// and fails closed until a verified blocklist arms it.
//
// Perceptual matching needs to turn encoded media into a dHash. That decode step is
// the one piece that needs an image codec, so it is an injectable hook: exact-hash
// matching is always active, and the perceptual path activates once a decoder is
// wired in. A production deployment must wire one. Until then media is matched by
// exact hash only, the same way the reference gate skips media it cannot decode.
#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "darcraw/hash.hpp"

namespace darcraw {

struct GateResult {
    bool allowed;
    std::string reason;
};

// Turns encoded media bytes into a 64-bit dHash, or nullopt if it is not a decodable
// image. Default is "no decoder compiled in" (always nullopt).
using PerceptualHasher = std::function<std::optional<uint64_t>(const Bytes&)>;

inline int hamming64(uint64_t a, uint64_t b) { return __builtin_popcountll(a ^ b); }

class ContentGate {
public:
    ContentGate(std::set<Bytes> exact, std::vector<uint64_t> phash,
                int phash_threshold = 6, PerceptualHasher hasher = nullptr)
        : exact_(std::move(exact)),
          phash_(std::move(phash)),
          threshold_(phash_threshold),
          armed_(true),
          hasher_(std::move(hasher)) {}

    // A gate with no verified blocklist yet. Fails closed, blocking everything until
    // update() arms it. A fresh node must arm from a signed blocklist first.
    static ContentGate unarmed(int phash_threshold = 6) {
        ContentGate g({}, {}, phash_threshold);
        g.armed_ = false;
        return g;
    }

    void update(std::set<Bytes> exact, std::vector<uint64_t> phash, int version) {
        exact_ = std::move(exact);
        phash_ = std::move(phash);
        version_ = version;
        armed_ = true;
    }

    int version() const { return version_; }

    GateResult check(const Bytes& content, const std::vector<Bytes>& media = {}) const {
        if (!armed_) return {false, "gate-unarmed"};
        if (exact_.count(sha256(content))) return {false, "exact-hash-match"};
        for (const auto& m : media) {
            if (exact_.count(sha256(m))) return {false, "media-exact-hash-match"};
            if (hasher_) {
                std::optional<uint64_t> ph = hasher_(m);
                if (ph) {
                    for (uint64_t bad : phash_)
                        if (hamming64(*ph, bad) <= threshold_)
                            return {false, "media-perceptual-match"};
                }
            }
        }
        return {true, ""};
    }

private:
    std::set<Bytes> exact_;       // sha256 digests
    std::vector<uint64_t> phash_; // dHash fingerprints
    int threshold_;
    int version_ = 0;
    bool armed_;
    PerceptualHasher hasher_;
};

}  // namespace darcraw
