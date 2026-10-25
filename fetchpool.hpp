// Proxy and session management for the fetch layer.
//
// The classic clearnet approach is a pool of residential or datacenter IPs to rotate
// through, backoff when one gets blocked, and cookie sessions. Most of that does not
// translate to I2P, where the target sees an I2P destination rather than an IP, so
// the layer is split by where the target lives:
//   - I2P targets go through the I2P HTTP proxy. The rotation knob is the outbound
//     client tunnel / destination, not an IP. Cookie sessions still matter.
//   - Clearnet targets (mirrors) use proxy rotation, backoff, and cookies as usual.
//
// The network call is an injectable opener, so the pacing logic is testable with no
// live proxy and a production opener (HTTP over the I2P proxy, or a clearnet proxy)
// drops in behind the same interface.
#pragma once
#include <algorithm>
#include <cmath>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "darcraw/crawler.hpp"   // Fetcher
#include "darcraw/hash.hpp"
#include "darcraw/ratelimit.hpp"

namespace darcraw {

class Session {
public:
    explicit Session(std::map<std::string, std::string> headers = {}) : headers_(std::move(headers)) {}

    void absorb(const std::vector<std::string>& set_cookie) {
        for (const auto& sc : set_cookie) {
            std::string first = sc.substr(0, sc.find(';'));
            auto eq = first.find('=');
            if (eq != std::string::npos) {
                std::string name = trim(first.substr(0, eq));
                std::string value = trim(first.substr(eq + 1));
                cookies_[name] = value;
            }
        }
    }

    std::map<std::string, std::string> request_headers() const {
        std::map<std::string, std::string> h = headers_;
        if (!cookies_.empty()) {
            std::string c;
            for (const auto& kv : cookies_) {
                if (!c.empty()) c += "; ";
                c += kv.first + "=" + kv.second;
            }
            h["Cookie"] = c;
        }
        return h;
    }

    const std::map<std::string, std::string>& cookies() const { return cookies_; }

private:
    static std::string trim(const std::string& s) {
        size_t a = s.find_first_not_of(" \t");
        size_t b = s.find_last_not_of(" \t");
        return a == std::string::npos ? "" : s.substr(a, b - a + 1);
    }
    std::map<std::string, std::string> headers_, cookies_;
};

class ProxyPool {
public:
    ProxyPool(std::vector<std::string> proxies = {""}, double base_backoff = 2.0,
              double max_backoff = 300.0, Clock clock = steady_now)
        : clock_(std::move(clock)), base_(base_backoff), max_(max_backoff) {
        if (proxies.empty()) proxies = {""};   // "" means direct
        for (auto& p : proxies) entries_.push_back({p, 0, 0.0});
    }

    // Round-robin, skipping any in backoff. nullopt when every proxy is cooling down.
    std::optional<std::string> pick() {
        double now = clock_();
        size_t n = entries_.size();
        for (size_t i = 0; i < n; i++) {
            Entry& e = entries_[rr_ % n];
            rr_++;
            if (e.blocked_until <= now) return e.proxy;
        }
        return std::nullopt;
    }

    void report_failure(const std::string& proxy) {
        Entry* e = find(proxy);
        if (!e) return;
        e->failures++;
        double cd = base_ * std::pow(2.0, e->failures - 1);
        e->blocked_until = clock_() + std::min(max_, cd);
    }
    void report_success(const std::string& proxy) {
        Entry* e = find(proxy);
        if (e) { e->failures = 0; e->blocked_until = 0.0; }
    }
    bool is_direct_only() const { return entries_.size() == 1 && entries_[0].proxy.empty(); }

private:
    struct Entry {
        std::string proxy;
        int failures;
        double blocked_until;
    };
    Entry* find(const std::string& proxy) {
        for (auto& e : entries_)
            if (e.proxy == proxy) return &e;
        return nullptr;
    }
    Clock clock_;
    double base_, max_;
    std::vector<Entry> entries_;
    size_t rr_ = 0;
};

struct OpenerResult {
    int status = 0;
    Bytes body;
    std::vector<std::string> set_cookie;
};

// opener(url, proxy, headers) -> OpenerResult. Default returns status 0 (no network);
// a production opener performs the HTTP request over the appropriate proxy.
using Opener = std::function<OpenerResult(const std::string&, const std::string&,
                                          const std::map<std::string, std::string>&)>;

struct FetchResult {
    bool ok = false;
    int status = 0;
    Bytes content;
    std::vector<Bytes> media;
    std::vector<std::string> set_cookie;
};

class FetchBackend {
public:
    explicit FetchBackend(Opener opener) : opener_(std::move(opener)) {}
    virtual ~FetchBackend() = default;

    FetchResult fetch(const std::string& url, const Session& session, const std::string& proxy) {
        OpenerResult o = opener_(url, proxy, session.request_headers());
        FetchResult r;
        r.status = o.status;
        r.content = o.body;
        r.set_cookie = o.set_cookie;
        r.ok = o.status >= 200 && o.status < 300;
        return r;
    }

private:
    Opener opener_;
};

// Tag subclasses. The I2P backend's proxy argument names the outbound tunnel/
// destination to rotate. The clearnet backend's is a real IP proxy.
class I2PFetchBackend : public FetchBackend {
public:
    using FetchBackend::FetchBackend;
};
class ClearnetFetchBackend : public FetchBackend {
public:
    using FetchBackend::FetchBackend;
};

class FetchPool {
public:
    FetchPool(FetchBackend backend, ProxyPool proxies = ProxyPool(), int max_retries = 3,
              std::map<std::string, std::string> default_headers = {{"User-Agent", "darcraw/0"}})
        : backend_(std::move(backend)), proxies_(std::move(proxies)),
          max_retries_(max_retries), default_headers_(std::move(default_headers)) {}

    static std::string host_of(const std::string& url) {
        std::string rest = url;
        auto p = rest.find("://");
        if (p != std::string::npos) rest = rest.substr(p + 3);
        return rest.substr(0, rest.find('/'));
    }

    std::optional<std::pair<Bytes, std::vector<Bytes>>> fetch(const std::string& url) {
        std::string host = host_of(url);
        Session& session = session_for(host);
        for (int i = 0; i < max_retries_; i++) {
            std::optional<std::string> proxy = proxies_.pick();
            if (!proxy) return std::nullopt;         // all proxies cooling down
            FetchResult res;
            try {
                res = backend_.fetch(url, session, *proxy);
            } catch (...) {
                proxies_.report_failure(*proxy);
                continue;
            }
            if (res.ok) {
                proxies_.report_success(*proxy);
                session.absorb(res.set_cookie);
                return std::make_pair(res.content, res.media);
            }
            proxies_.report_failure(*proxy);
        }
        return std::nullopt;
    }

    // Returns the callable the crawler expects: fetch(url) -> (content, media) | none.
    Fetcher as_fetcher() {
        return [this](const std::string& url) { return this->fetch(url); };
    }

private:
    Session& session_for(const std::string& host) {
        auto it = sessions_.find(host);
        if (it == sessions_.end())
            it = sessions_.emplace(host, Session(default_headers_)).first;
        return it->second;
    }
    FetchBackend backend_;
    ProxyPool proxies_;
    int max_retries_;
    std::map<std::string, std::string> default_headers_;
    std::map<std::string, Session> sessions_;
};

}  // namespace darcraw
