// Content fingerprinting (Stage 2). SimHash over word shingles gives a 64-bit
// fingerprint where near-identical pages sit a few bits apart. A banded LSH index
// makes near-duplicate lookup sub-linear, which turns the same content served from two
// destinations into a mirror signal. Hashing is SipHash, so there is no extra dep.
#pragma once
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "darcraw/siphash.hpp"

namespace darcraw {

inline std::vector<std::string> shingles(const std::string& content, int k = 4) {
    std::string text;
    text.reserve(content.size());
    bool in_tag = false;
    for (char c : content) {
        if (c == '<') { in_tag = true; text.push_back(' '); continue; }
        if (c == '>') { in_tag = false; text.push_back(' '); continue; }
        if (in_tag) continue;
        text.push_back((char)std::tolower((unsigned char)c));
    }
    std::vector<std::string> words;
    std::string cur;
    for (char c : text) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            cur.push_back(c);
        } else if (!cur.empty()) {
            words.push_back(cur);
            cur.clear();
        }
    }
    if (!cur.empty()) words.push_back(cur);

    std::vector<std::string> out;
    auto join = [&](size_t start, size_t n) {
        std::string j;
        for (size_t i = 0; i < n; i++) {
            if (i) j += ' ';
            j += words[start + i];
        }
        return j;
    };
    if ((int)words.size() < k) {
        if (!words.empty()) out.push_back(join(0, words.size()));
        return out;
    }
    for (size_t i = 0; i + k <= words.size(); i++) out.push_back(join(i, k));
    return out;
}

inline uint64_t simhash(const std::vector<std::string>& tokens) {
    int v[64] = {0};
    for (const auto& t : tokens) {
        uint64_t x = siphash64(reinterpret_cast<const uint8_t*>(t.data()), t.size(), 7);
        for (int i = 0; i < 64; i++) v[i] += ((x >> i) & 1) ? 1 : -1;
    }
    uint64_t out = 0;
    for (int i = 0; i < 64; i++)
        if (v[i] > 0) out |= (1ULL << i);
    return out;
}

inline uint64_t content_simhash(const std::string& content) { return simhash(shingles(content)); }
inline int fp_hamming(uint64_t a, uint64_t b) { return __builtin_popcountll(a ^ b); }

// Banded LSH over 64-bit SimHashes. Pages matching on any band are candidates;
// candidates within `threshold` Hamming distance are reported as near-duplicates.
class SimHashIndex {
public:
    SimHashIndex(int bands = 4, int threshold = 3)
        : bands_(bands), width_(64 / bands), threshold_(threshold), buckets_(bands) {
        if (64 % bands) throw std::invalid_argument("bands must divide 64");
    }

    void add(uint64_t h, const std::string& key) {
        items_[key] = h;
        auto bv = band_vals(h);
        for (int i = 0; i < bands_; i++) buckets_[i][bv[i]].insert(key);
    }

    std::vector<std::pair<std::string, int>> query(uint64_t h) const {
        std::set<std::string> cand;
        auto bv = band_vals(h);
        for (int i = 0; i < bands_; i++) {
            auto it = buckets_[i].find(bv[i]);
            if (it != buckets_[i].end()) cand.insert(it->second.begin(), it->second.end());
        }
        std::vector<std::pair<std::string, int>> out;
        for (const auto& k : cand) {
            int d = fp_hamming(h, items_.at(k));
            if (d <= threshold_) out.push_back({k, d});
        }
        std::sort(out.begin(), out.end(),
                  [](const auto& a, const auto& b) { return a.second < b.second; });
        return out;
    }

private:
    std::vector<uint64_t> band_vals(uint64_t h) const {
        uint64_t mask = width_ >= 64 ? ~0ULL : ((1ULL << width_) - 1);
        std::vector<uint64_t> o;
        for (int i = 0; i < bands_; i++) o.push_back((h >> (i * width_)) & mask);
        return o;
    }
    int bands_, width_, threshold_;
    std::vector<std::map<uint64_t, std::set<std::string>>> buckets_;
    std::map<std::string, uint64_t> items_;
};

}  // namespace darcraw
