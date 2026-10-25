// URL deduplication before queuing. Local Bloom filter per peer, with an optional
// shared backend hook for a single operator's worker fleet. Cross-peer dedup is the
// IBLT in sketches.hpp, so no central store is required for the network as a whole.
#pragma once
#include <cmath>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "darcraw/siphash.hpp"

namespace darcraw {

class BloomFilter {
public:
    BloomFilter(size_t n = 1000000, double p = 0.001) {
        m_ = std::max<size_t>(8, (size_t)(-((double)n * std::log(p)) / (std::log(2) * std::log(2))));
        k_ = std::max<size_t>(1, (size_t)std::lround(((double)m_ / n) * std::log(2)));
        bits_.assign((m_ + 7) / 8, 0);
    }

    void add(const std::string& item) {
        for (size_t pos : positions(item)) bits_[pos >> 3] |= (uint8_t)(1u << (pos & 7));
    }

    bool contains(const std::string& item) const {
        for (size_t pos : positions(item))
            if (!(bits_[pos >> 3] & (1u << (pos & 7)))) return false;
        return true;
    }

private:
    std::vector<size_t> positions(const std::string& item) const {
        // Two base hashes combined (Kirsch-Mitzenmacher) give k positions cheaply.
        uint64_t h1 = siphash64(reinterpret_cast<const uint8_t*>(item.data()), item.size(), 1000);
        uint64_t h2 = siphash64(reinterpret_cast<const uint8_t*>(item.data()), item.size(), 2000) | 1ULL;
        std::vector<size_t> out(k_);
        for (size_t i = 0; i < k_; i++) out[i] = (size_t)((h1 + i * h2) % m_);
        return out;
    }
    size_t m_, k_;
    std::vector<uint8_t> bits_;
};

// Optional shared seen-set for one operator's worker fleet (e.g. a Redis adapter).
// The network-wide path does not use this. It reconciles with the IBLT.
struct SeenBackend {
    virtual ~SeenBackend() = default;
    virtual bool seen(const std::string& url) = 0;
    virtual void mark(const std::string& url) = 0;
};

class SeenSet {
public:
    SeenSet(size_t n = 1000000, double p = 0.001, bool exact = false,
            std::shared_ptr<SeenBackend> backend = nullptr)
        : bloom_(n, p), use_exact_(exact), backend_(std::move(backend)) {}

    bool seen(const std::string& url) const {
        if (backend_ && backend_->seen(url)) return true;
        if (use_exact_) return exact_.count(url) != 0;
        return bloom_.contains(url);
    }

    void mark(const std::string& url) {
        bloom_.add(url);
        if (use_exact_) exact_.insert(url);
        if (backend_) backend_->mark(url);
    }

    // True if newly admitted (was unseen), false if a duplicate to skip.
    bool check_and_mark(const std::string& url) {
        if (seen(url)) return false;
        mark(url);
        return true;
    }

private:
    BloomFilter bloom_;
    bool use_exact_;
    std::set<std::string> exact_;
    std::shared_ptr<SeenBackend> backend_;
};

}  // namespace darcraw
