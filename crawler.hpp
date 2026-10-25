// Self-updating crawl loop. A linear contextual bandit orders the frontier. Each
// fetch produces a self-supervised reward and the policy updates online. Compute is
// bounded per tick, so the loop runs in real time and stays within that budget
// instead of stalling.
//
// The content gate runs at ingestion, before anything is published, and is the same
// fixed gate the netDb enforces at store-admission. It is never part of the policy.
// Per-source influence is capped per window, and a frozen holdout rolls the policy
// back if it drifts, for poisoning resistance.
#pragma once
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <random>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "darcraw/gate.hpp"
#include "darcraw/hash.hpp"
#include "darcraw/netdb.hpp"
#include "darcraw/ratelimit.hpp"

namespace darcraw {

// fetch(url) -> (content, media) or nothing
using Fetcher = std::function<std::optional<std::pair<Bytes, std::vector<Bytes>>>(const std::string&)>;
// classify(content, url) -> origin type ("native" / "multi-homed" / "unknown"), or empty
using Classifier = std::function<std::string(const Bytes&, const std::string&)>;

struct Candidate {
    std::string url;
    std::string source;        // which discovery source proposed this address
    std::vector<double> features;
};

struct Outcome {
    std::vector<double> features;
    double reward;
    std::string source;
};

inline double dot(const std::vector<double>& w, const std::vector<double>& x) {
    double s = 0;
    size_t n = std::min(w.size(), x.size());
    for (size_t i = 0; i < n; i++) s += w[i] * x[i];
    return s;
}

class LinearPolicy {
public:
    explicit LinearPolicy(size_t dim, double lr = 0.05) : w_(dim, 0.0), lr_(lr) {}
    double score(const std::vector<double>& x) const { return dot(w_, x); }
    double update(const std::vector<double>& x, double reward, double scale = 1.0) {
        double err = reward - score(x);
        for (size_t i = 0; i < w_.size() && i < x.size(); i++) w_[i] += lr_ * err * x[i] * scale;
        return err;
    }
    std::vector<double>& weights() { return w_; }
    const std::vector<double>& weights() const { return w_; }

private:
    std::vector<double> w_;
    double lr_;
};

class Crawler {
public:
    Crawler(Node* node, const ContentGate& gate, Fetcher fetcher, size_t dim,
            double epsilon = 0.15, int tick_budget = 32, double per_source_cap = 4.0,
            size_t holdout_size = 256, double drift_margin = 1.5,
            Classifier classifier = nullptr, Clock clock = steady_now)
        : node_(node), gate_(gate), fetcher_(std::move(fetcher)), classifier_(std::move(classifier)),
          policy_(dim), epsilon_(epsilon), tick_budget_(tick_budget),
          per_source_cap_(per_source_cap), holdout_size_(holdout_size),
          drift_margin_(drift_margin), clock_(std::move(clock)),
          best_w_(policy_.weights()), rng_(std::random_device{}()) {}

    void submit(const Candidate& c) { frontier_.push_back(c); }
    int tick_budget() const { return tick_budget_; }
    const LinearPolicy& policy() const { return policy_; }

    void tick() {
        for (int i = 0; i < tick_budget_; i++) {
            std::optional<Candidate> cand = pick();
            if (!cand) break;
            auto fetched = fetcher_(cand->url);
            Bytes content;
            std::vector<Bytes> media;
            if (fetched) { content = fetched->first; media = fetched->second; }
            bool has_content = fetched && !content.empty();
            std::string origin;
            if (has_content) {
                if (!gate_.check(content, media).allowed) continue;  // gated at ingestion
                if (classifier_) origin = classifier_(content, cand->url);
                node_->publish(content, media);
            }
            double reward = compute_reward((bool)fetched, has_content, origin);
            policy_.update(cand->features, reward, source_scale(cand->source));
            Outcome o{cand->features, reward, cand->source};
            replay_.push_back(o);
            if (replay_.size() > 5000) replay_.pop_front();
            if (uniform() < 0.1) {
                holdout_.push_back(o);
                if (holdout_.size() > holdout_size_) holdout_.pop_front();
            }
        }
    }

    double holdout_loss() const {
        if (holdout_.empty()) return 0.0;
        double s = 0;
        for (const auto& o : holdout_) {
            double d = o.reward - policy_.score(o.features);
            s += d * d;
        }
        return s / holdout_.size();
    }

    // Checkpoint good weights, roll back drift. Call periodically between ticks.
    void consolidate() {
        double loss = holdout_loss();
        if (loss < best_loss_) {
            best_loss_ = loss;
            best_w_ = policy_.weights();
        } else if (loss > best_loss_ * drift_margin_) {
            policy_.weights() = best_w_;    // revert a drifting / poisoned policy
        }
    }

private:
    double uniform() { return std::uniform_real_distribution<double>(0, 1)(rng_); }

    std::optional<Candidate> pick() {
        if (frontier_.empty()) return std::nullopt;
        size_t idx;
        if (uniform() < epsilon_) {
            idx = (size_t)(uniform() * frontier_.size());
            if (idx >= frontier_.size()) idx = frontier_.size() - 1;
        } else {
            idx = 0;
            double best = policy_.score(frontier_[0].features);
            for (size_t j = 1; j < frontier_.size(); j++) {
                double s = policy_.score(frontier_[j].features);
                if (s > best) { best = s; idx = j; }
            }
        }
        Candidate c = frontier_[idx];
        frontier_.erase(frontier_.begin() + idx);
        return c;
    }

    static double compute_reward(bool fetched, bool has_content, const std::string& origin) {
        if (!fetched) return 0.0;        // did not resolve
        double r = 1.0;                  // alive
        if (has_content) r += 0.5;       // carried content
        if (!origin.empty()) {           // prefer native, derivatives redundant with clearnet
            if (origin == "native") r += 1.0;
            else if (origin == "multi-homed") r += 0.5;
            else if (origin == "unknown") r += 0.2;
        }
        return r;
    }

    double source_scale(const std::string& source) {
        double now = clock_();
        if (now - window_ > 60) { spend_.clear(); window_ = now; }
        if (spend_[source] >= per_source_cap_) return 0.0;  // out of influence this window
        spend_[source] += 1.0;
        return 1.0;
    }

    Node* node_;
    const ContentGate& gate_;
    Fetcher fetcher_;
    Classifier classifier_;
    LinearPolicy policy_;
    double epsilon_;
    int tick_budget_;
    double per_source_cap_;
    size_t holdout_size_;
    double drift_margin_;
    Clock clock_;
    std::vector<Candidate> frontier_;
    std::deque<Outcome> replay_, holdout_;
    std::vector<double> best_w_;
    double best_loss_ = 1e300;
    std::unordered_map<std::string, double> spend_;
    double window_ = steady_now();
    std::mt19937_64 rng_;
};

}  // namespace darcraw
