// Distributed scrape orchestrator. Every peer runs this same object. The coordination
// comes from rendezvous hashing, not a coordinator. There is no central orchestrator
// process.
//
// A tick: admit a URL only if unseen (Bloom dedup) and this peer is a rendezvous owner
// of its site. Release admitted candidates into the learned frontier as each site's
// per-domain token bucket allows. Let the bandit order, fetch, gate, and publish.
// Anti-entropy spreads the catalog so every peer's index tracks the network.
// Network-wide dedup is reconcile_seen via an IBLT. The gate is untouched.
#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "darcraw/crawler.hpp"
#include "darcraw/dedup.hpp"
#include "darcraw/fetchpool.hpp"
#include "darcraw/gate.hpp"
#include "darcraw/netdb.hpp"
#include "darcraw/ratelimit.hpp"
#include "darcraw/sketches.hpp"

namespace darcraw {

inline std::string orch_host_of(const std::string& url) {
    std::string rest = url;
    auto p = rest.find("://");
    if (p != std::string::npos) rest = rest.substr(p + 3);
    return rest.substr(0, rest.find('/'));
}

inline uint64_t url_key(const std::string& url) {
    return siphash64(reinterpret_cast<const uint8_t*>(url.data()), url.size(), 0xD4);
}

struct OrchStats {
    int admitted = 0, dup = 0, not_owned = 0, released = 0;
};

struct ReconcileResult {
    int learned;   // addresses this peer learned the other had covered
    int we_had;    // addresses this peer had that the other lacked
    bool ok;       // whether the IBLT decoded
};

class Orchestrator {
public:
    Orchestrator(Node* node, const ContentGate& gate, FetchPool* fetch_pool,
                 std::string self_peer, std::vector<std::string> peers, size_t dim,
                 int redundancy = 1, double per_domain_rate = 0.5, double per_domain_burst = 2.0,
                 SeenSet seen = SeenSet(), Classifier classifier = nullptr,
                 int iblt_cells = 1024, Clock clock = steady_now)
        : node_(node),
          fetch_pool_(fetch_pool),
          self_peer_(std::move(self_peer)),
          peers_(peers.empty() ? std::vector<std::string>{self_peer_} : std::move(peers)),
          redundancy_(redundancy),
          seen_(std::move(seen)),
          clock_(std::move(clock)),
          domain_limiter_(per_domain_rate, per_domain_burst, clock_),
          crawler_(node, gate, fetch_pool->as_fetcher(), dim, 0.15, 32, 4.0, 256, 1.5,
                   std::move(classifier), clock_),
          coverage_(12),
          seen_iblt_(iblt_cells) {}

    void set_peers(std::vector<std::string> peers) { peers_ = std::move(peers); }
    bool owns(const std::string& site) const {
        return hrw_owns(self_peer_, site, peers_, redundancy_);
    }

    // Returns "dup", "not-owned", or "admitted". Dedup first, so a URL this peer does
    // not own still counts as seen and is not reconsidered every round.
    std::string submit(const std::string& url, const std::string& source,
                       const std::vector<double>& features) {
        std::string site = orch_host_of(url);
        if (seen_.seen(url)) { stats_.dup++; return "dup"; }
        seen_.mark(url);
        seen_iblt_.insert(url_key(url));
        coverage_.add(site);
        if (!owns(site)) { stats_.not_owned++; return "not-owned"; }
        pending_.push_back(Candidate{url, source, features});
        stats_.admitted++;
        return "admitted";
    }

    // Release politeness-ready candidates into the frontier, then run one crawl tick.
    int pump(int consolidate_every = 10) {
        int released = 0;
        std::vector<Candidate> still;
        for (auto& cand : pending_) {
            if (released >= crawler_.tick_budget()) { still.push_back(cand); continue; }
            std::string site = orch_host_of(cand.url);
            if (domain_limiter_.allow(site)) {
                crawler_.submit(cand);
                released++;
            } else {
                still.push_back(cand);   // not yet polite to fetch, hold it
            }
        }
        pending_ = std::move(still);
        stats_.released += released;
        crawler_.tick();
        ticks_++;
        if (ticks_ % consolidate_every == 0) crawler_.consolidate();
        return released;
    }

    int pending() const { return (int)pending_.size(); }
    const OrchStats& stats() const { return stats_; }
    double coverage_estimate() const { return coverage_.estimate(); }

    // Network-wide dedup: hand a peer this IBLT. They subtract to find exactly which
    // addresses each side is missing, in difference-sized traffic.
    IBLT seen_iblt() const { return seen_iblt_; }

    ReconcileResult reconcile_seen(const IBLT& other) {
        auto d = seen_iblt_.subtract(other).decode();
        if (d.ok)
            for (uint64_t key : d.only_b) seen_iblt_.insert(key);
        return {(int)d.only_b.size(), (int)d.only_a.size(), d.ok};
    }

    void reconcile_index(const Peer& peer) { node_->anti_entropy(peer); }

private:
    Node* node_;
    FetchPool* fetch_pool_;
    std::string self_peer_;
    std::vector<std::string> peers_;
    int redundancy_;
    SeenSet seen_;
    Clock clock_;
    PerKeyRateLimiter domain_limiter_;
    Crawler crawler_;
    HyperLogLog coverage_;
    std::vector<Candidate> pending_;
    IBLT seen_iblt_;
    OrchStats stats_;
    long ticks_ = 0;
};

}  // namespace darcraw
