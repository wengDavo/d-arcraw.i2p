// Origin classifier. Stage 1 is cheap page signals (regex) classifying a page as
// native, multi-homed, mirror, instance, proxy, or unknown. Stage 2 adds SimHash
// near-duplicate detection: a page that near-duplicates content first seen at an
// earlier address is a mirror, so the original keeps its label and later copies are
// flagged. Feeds the crawler's reward so it prefers native content.
#pragma once
#include <functional>
#include <map>
#include <regex>
#include <string>
#include <vector>

#include "darcraw/fingerprint.hpp"
#include "darcraw/hash.hpp"

namespace darcraw {

struct Origin {
    std::string type;
    double confidence;
    std::vector<std::string> signals;
};

inline bool url_is_i2p(const std::string& u) { return u.find(".i2p") != std::string::npos; }
inline bool url_is_onion(const std::string& u) { return u.find(".onion") != std::string::npos; }
inline bool url_is_clearnet(const std::string& u) {
    if (u.size() < 4) return false;
    std::string p = u.substr(0, 4);
    for (auto& c : p) c = (char)std::tolower((unsigned char)c);
    return p == "http" && !url_is_i2p(u) && !url_is_onion(u);
}

inline Origin classify(const std::string& content, const std::string& = "") {
    using std::regex;
    static const regex GENERATOR(R"(<meta[^>]+name=["']?generator["']?[^>]+content=["']([^"']+))", regex::icase);
    static const regex CANON_A(R"(<link[^>]+rel=["']?(?:canonical|alternate)["']?[^>]+href=["']([^"']+))", regex::icase);
    static const regex CANON_B(R"(<link[^>]+href=["']([^"']+)["'][^>]+rel=["']?(?:canonical|alternate))", regex::icase);
    static const regex HREF(R"(href=["']([^"']+))", regex::icase);
    static const regex ASSET(R"((?:src|href)=["'](https?://[^"']+\.(?:png|jpe?g|gif|webp|css|js|svg|woff2?)))", regex::icase);
    static const regex MIRROR(R"(mirror of\s+[a-z0-9.-]+\.[a-z]{2,})", regex::icase);
    static const char* SOFTWARE[] = {"searxng", "mediawiki", "lemmy", "wordpress", "gitea"};

    std::smatch m;
    if (std::regex_search(content, m, GENERATOR)) {
        std::string g = m[1].str();
        for (auto& c : g) c = (char)std::tolower((unsigned char)c);
        for (const char* name : SOFTWARE)
            if (g.find(name) != std::string::npos)
                return {"instance", 0.8, {std::string("generator:") + name}};
    }
    if (std::regex_search(content, m, MIRROR)) return {"mirror", 0.75, {"mirror-banner"}};

    std::smatch cm;
    if (std::regex_search(content, cm, CANON_A) || std::regex_search(content, cm, CANON_B)) {
        std::string href = cm[1].str();
        if (url_is_clearnet(href) || url_is_onion(href))
            return {"mirror", 0.7, {"canonical-offnetwork"}};
    }

    int clear = 0, i2p = 0;
    for (auto it = std::sregex_iterator(content.begin(), content.end(), HREF);
         it != std::sregex_iterator(); ++it) {
        std::string h = (*it)[1].str();
        if (url_is_clearnet(h)) clear++;
        else if (url_is_i2p(h)) i2p++;
    }
    int total = clear + i2p;
    double ratio = total ? (double)clear / total : 0.0;
    int assets_clear = (int)std::distance(
        std::sregex_iterator(content.begin(), content.end(), ASSET), std::sregex_iterator());
    if (total) {
        if (ratio > 0.6 && assets_clear > 0)
            return {"proxy", 0.6, {"clearnet-link-ratio", "clearnet-assets"}};
        if (i2p > 0 && ratio < 0.2 && assets_clear == 0)
            return {"native", 0.7, {"i2p-link-ratio"}};
    }
    return {"unknown", 0.3, {}};
}

inline std::string address_of(const std::string& url) {
    if (url.empty()) return "";
    static const std::regex HOST(R"([a-z0-9.-]+\.(?:b32\.i2p|i2p|onion))", std::regex::icase);
    std::smatch m;
    if (std::regex_search(url, m, HOST)) {
        std::string a = m[0].str();
        for (auto& c : a) c = (char)std::tolower((unsigned char)c);
        return a;
    }
    return url;
}

class TwoStageClassifier {
public:
    explicit TwoStageClassifier(SimHashIndex index = SimHashIndex()) : index_(std::move(index)) {}

    Origin operator()(const Bytes& content, const std::string& url = "") {
        std::string text = to_string(content);
        std::string addr = address_of(url);
        if (addr.empty()) return classify(text, url);        // no address: Stage 1 only
        uint64_t h = content_simhash(text);
        long long age = first_seen_.count(addr) ? first_seen_[addr] : seq_;
        std::vector<std::pair<std::string, int>> near;
        for (const auto& kd : index_.query(h)) {
            long long fk = first_seen_.count(kd.first) ? first_seen_[kd.first] : (1LL << 62);
            if (kd.first != addr && fk < age) near.push_back(kd);
        }
        if (!first_seen_.count(addr)) first_seen_[addr] = seq_++;
        index_.add(h, addr);
        if (!near.empty()) {
            Origin base = classify(text, url);
            base.type = "mirror";
            base.confidence = 0.65;
            base.signals.push_back("near-dup:" + near[0].first + ":" + std::to_string(near[0].second));
            return base;
        }
        return classify(text, url);
    }

    // Adapter for the crawler: fetch(content,url) -> origin type string.
    std::function<std::string(const Bytes&, const std::string&)> as_type_classifier() {
        return [this](const Bytes& c, const std::string& u) { return (*this)(c, u).type; };
    }

private:
    SimHashIndex index_;
    std::map<std::string, long long> first_seen_;
    long long seq_ = 0;
};

}  // namespace darcraw
