// Coordination sketches: rendezvous (HRW) hashing, HyperLogLog, and an IBLT.
// Rendezvous assigns each site one owner peer with no coordinator. HyperLogLog
// estimates distinct-count with register-wise mergeable state. The IBLT reconciles
// two peers' sets in traffic proportional to their difference.
#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "darcraw/siphash.hpp"

namespace darcraw {

// --- rendezvous / highest-random-weight ------------------------------------

inline uint64_t hrw_weight(const std::string& peer, const std::string& site) {
    std::string s = peer;
    s.push_back('\0');
    s += site;
    return siphash64(reinterpret_cast<const uint8_t*>(s.data()), s.size(), 0);
}

inline std::string hrw_owner(const std::string& site, const std::vector<std::string>& peers) {
    const std::string* best = nullptr;
    uint64_t bw = 0;
    for (const auto& p : peers) {
        uint64_t w = hrw_weight(p, site);
        if (best == nullptr || w > bw) {
            bw = w;
            best = &p;
        }
    }
    return best ? *best : std::string();
}

inline std::vector<std::string> hrw_owners(const std::string& site,
                                           std::vector<std::string> peers, int r) {
    std::sort(peers.begin(), peers.end(), [&](const std::string& a, const std::string& b) {
        return hrw_weight(a, site) > hrw_weight(b, site);
    });
    if ((int)peers.size() > r) peers.resize(r);
    return peers;
}

inline bool hrw_owns(const std::string& peer, const std::string& site,
                     const std::vector<std::string>& peers, int r = 1) {
    auto o = hrw_owners(site, peers, r);
    return std::find(o.begin(), o.end(), peer) != o.end();
}

// --- HyperLogLog ------------------------------------------------------------

class HyperLogLog {
public:
    explicit HyperLogLog(int p = 10) : p_(p), m_(1u << p), reg_(m_, 0) {}

    void add(const std::string& item) {
        uint64_t h = siphash64(reinterpret_cast<const uint8_t*>(item.data()), item.size(), 1);
        uint64_t idx = h >> (64 - p_);
        uint64_t rest = h << p_;                 // remaining bits, left-justified
        int rank = 1;
        while (rank <= 64 - p_ && !((rest >> (64 - rank)) & 1ULL)) rank++;
        if ((uint8_t)rank > reg_[idx]) reg_[idx] = (uint8_t)rank;
    }

    void merge(const HyperLogLog& o) {
        if (o.p_ != p_) throw std::runtime_error("HLL precision mismatch");
        for (uint32_t i = 0; i < m_; i++)
            if (o.reg_[i] > reg_[i]) reg_[i] = o.reg_[i];
    }

    double estimate() const {
        double m = (double)m_;
        double alpha = m_ >= 128 ? 0.7213 / (1 + 1.079 / m) : 0.709;
        double s = 0;
        for (uint8_t r : reg_) s += std::pow(2.0, -(double)r);
        double raw = alpha * m * m / s;
        if (raw <= 2.5 * m) {
            size_t z = std::count(reg_.begin(), reg_.end(), (uint8_t)0);
            if (z) return m * std::log(m / (double)z);
        }
        return raw;
    }

private:
    int p_;
    uint32_t m_;
    std::vector<uint8_t> reg_;
};

// --- Invertible Bloom Lookup Table ------------------------------------------

class IBLT {
public:
    struct Diff {
        std::set<uint64_t> only_a;   // keys present here but not in the other table
        std::set<uint64_t> only_b;   // keys present in the other table but not here
        bool ok;                     // false if the difference overran the cells
    };

    explicit IBLT(int cells = 256, int k = 4)
        : cells_(cells), k_(k), count_(cells, 0), keysum_(cells, 0), hashsum_(cells, 0) {}

    void insert(uint64_t key) { apply(key, +1); }

    IBLT subtract(const IBLT& o) const {
        if (cells_ != o.cells_ || k_ != o.k_) throw std::runtime_error("IBLT geometry mismatch");
        IBLT d(cells_, k_);
        for (int j = 0; j < cells_; j++) {
            d.count_[j] = count_[j] - o.count_[j];
            d.keysum_[j] = keysum_[j] ^ o.keysum_[j];
            d.hashsum_[j] = hashsum_[j] ^ o.hashsum_[j];
        }
        return d;
    }

    Diff decode() const {
        std::vector<int64_t> count = count_;
        std::vector<uint64_t> keysum = keysum_, hashsum = hashsum_;
        Diff out;
        out.ok = false;
        bool changed = true;
        while (changed) {
            changed = false;
            for (int j = 0; j < cells_; j++) {
                if ((count[j] == 1 || count[j] == -1) && hashsum[j] == hkey(keysum[j], 99)) {
                    uint64_t key = keysum[j];
                    int sign = (int)count[j];
                    (sign == 1 ? out.only_a : out.only_b).insert(key);
                    for (int p : positions(key)) {
                        count[p] -= sign;
                        keysum[p] ^= key;
                        hashsum[p] ^= hkey(key, 99);
                    }
                    changed = true;
                }
            }
        }
        bool clean = true;
        for (auto c : count) if (c != 0) clean = false;
        for (auto h : hashsum) if (h != 0) clean = false;
        out.ok = clean;
        return out;
    }

private:
    static uint64_t hkey(uint64_t key, uint64_t seed) {
        uint8_t b[8];
        for (int i = 0; i < 8; i++) b[7 - i] = (uint8_t)(key >> (8 * i));  // big-endian
        return siphash64(b, 8, seed);
    }

    std::vector<int> positions(uint64_t key) const {
        std::set<int> pos;
        uint64_t i = 0;
        while ((int)pos.size() < k_) {
            pos.insert((int)(hkey(key, 10 + i) % cells_));
            i++;
        }
        return std::vector<int>(pos.begin(), pos.end());
    }

    void apply(uint64_t key, int sign) {
        uint64_t kh = hkey(key, 99);
        for (int j : positions(key)) {
            count_[j] += sign;
            keysum_[j] ^= key;
            hashsum_[j] ^= kh;
        }
    }

    int cells_, k_;
    std::vector<int64_t> count_;
    std::vector<uint64_t> keysum_, hashsum_;
};

}  // namespace darcraw
