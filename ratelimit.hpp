// Token-bucket rate limiting. One primitive at two keys: per-domain politeness on a
// site's owner peer, and per-origin netDb admission. The clock is injectable so the
// behavior is deterministic under test.
#pragma once
#include <chrono>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace darcraw {

using Clock = std::function<double()>;

inline double steady_now() {
    using namespace std::chrono;
    return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

class TokenBucket {
public:
    TokenBucket(double rate, double capacity, Clock clock = steady_now)
        : rate_(rate), capacity_(capacity), clock_(std::move(clock)) {
        tokens_ = capacity_;
        last_ = clock_();
    }

    bool take(double n = 1.0) {
        refill();
        if (tokens_ >= n) {
            tokens_ -= n;
            return true;
        }
        return false;
    }

    double wait_time(double n = 1.0) {
        refill();
        if (tokens_ >= n) return 0.0;
        return (n - tokens_) / rate_;
    }

    double last_touch() const { return last_; }

private:
    void refill() {
        double now = clock_();
        if (now > last_) {
            tokens_ = std::min(capacity_, tokens_ + (now - last_) * rate_);
            last_ = now;
        }
    }
    double rate_, capacity_, tokens_, last_;
    Clock clock_;
};

class PerKeyRateLimiter {
public:
    PerKeyRateLimiter(double rate, double capacity, Clock clock = steady_now)
        : rate_(rate), capacity_(capacity), clock_(std::move(clock)) {}

    bool allow(const std::string& key, double n = 1.0) { return bucket(key).take(n); }
    double wait_time(const std::string& key, double n = 1.0) { return bucket(key).wait_time(n); }

    // Drop buckets untouched for longer than max_idle. A bucket idle that long would
    // have refilled to full, so recreating it fresh on next use is identical.
    void reap(double max_idle = 300.0) {
        double now = clock_();
        std::vector<std::string> dead;
        for (auto& kv : buckets_)
            if (now - kv.second.last_touch() > max_idle) dead.push_back(kv.first);
        for (auto& k : dead) buckets_.erase(k);
    }

    size_t size() const { return buckets_.size(); }

private:
    TokenBucket& bucket(const std::string& key) {
        auto it = buckets_.find(key);
        if (it == buckets_.end())
            it = buckets_.emplace(key, TokenBucket(rate_, capacity_, clock_)).first;
        return it->second;
    }
    double rate_, capacity_;
    Clock clock_;
    std::unordered_map<std::string, TokenBucket> buckets_;
};

}  // namespace darcraw
