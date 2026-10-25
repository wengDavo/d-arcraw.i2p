// Signed, expiring netDb records. A record is trustworthy only if it is signed by
// the identity it claims and only while it is fresh. Three properties come together:
// Ed25519 verification before storage, cryptographic-timestamp expiry with LeaseSets
// capped under ten minutes, and a per-origin admission rate cap.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <utility>

#include "darcraw/ed25519.hpp"
#include "darcraw/hash.hpp"
#include "darcraw/ratelimit.hpp"
#include "darcraw/wire.hpp"

namespace darcraw {

// Max lifetime per kind, in seconds. LeaseSets expire fast to force republication.
// The 600-second cap keeps them under ten minutes.
inline const std::map<std::string, int64_t>& max_ttl() {
    static const std::map<std::string, int64_t> m = {
        {"leaseset", 600}, {"routerinfo", 7200}, {"announce", 86400}};
    return m;
}
constexpr int64_t CLOCK_SKEW = 60;

inline Bytes record_canonical(const std::string& kind, const Bytes& publisher,
                              const Bytes& payload, int64_t issued, int64_t expires) {
    Writer w;
    w.str(kind);
    w.bytes(publisher);
    w.bytes(payload);
    w.i64(issued);
    w.i64(expires);
    return to_bytes(w.take());
}

struct SignedRecord {
    std::string kind;
    Bytes publisher;   // Ed25519 public key, 32 bytes
    Bytes payload;
    int64_t issued = 0;
    int64_t expires = 0;
    Bytes signature;

    std::string origin() const { return to_hex(sha256(publisher)); }
    std::string storage_key() const { return kind + ":" + origin(); }
};

struct VResult {
    bool ok;
    std::string reason;
};

inline SignedRecord sign_record(const Ed25519& key, const std::string& kind,
                                const Bytes& payload, int64_t ttl, int64_t now) {
    auto it = max_ttl().find(kind);
    if (it == max_ttl().end()) throw std::invalid_argument("unknown record kind: " + kind);
    if (ttl > it->second) throw std::invalid_argument("ttl exceeds max for " + kind);
    SignedRecord r;
    r.kind = kind;
    r.publisher = key.public_bytes();
    r.payload = payload;
    r.issued = now;
    r.expires = now + ttl;
    r.signature = key.sign(record_canonical(kind, r.publisher, payload, r.issued, r.expires));
    return r;
}

inline VResult verify_record(const SignedRecord& rec, int64_t now, int64_t skew = CLOCK_SKEW) {
    auto it = max_ttl().find(rec.kind);
    if (it == max_ttl().end()) return {false, "unknown-kind"};
    if (rec.expires <= now) return {false, "expired"};
    if (rec.issued > now + skew) return {false, "future-dated"};
    if (rec.expires - rec.issued > it->second) return {false, "ttl-too-long"};
    Bytes msg = record_canonical(rec.kind, rec.publisher, rec.payload, rec.issued, rec.expires);
    if (!ed25519_verify(rec.publisher, msg, rec.signature)) return {false, "bad-signature"};
    return {true, "ok"};
}

// Red25519 blinded verification is not implemented. See ed25519.hpp.
[[noreturn]] inline void verify_blinded(const SignedRecord&) {
    throw std::runtime_error(
        "Red25519 blinded verification must be ported from an I2P router; "
        "unblinded LeaseSets verify via verify_record");
}

class RecordStore {
public:
    RecordStore(double per_origin_rate = 1.0, double per_origin_burst = 5.0,
                Clock store_clock = steady_now, Clock limiter_clock = steady_now)
        : clock_(std::move(store_clock)),
          limiter_(per_origin_rate, per_origin_burst, std::move(limiter_clock)) {}

    VResult admit(const SignedRecord& rec) {
        int64_t now = (int64_t)clock_();
        if (!limiter_.allow(rec.origin())) return {false, "rate-limited"};
        VResult v = verify_record(rec, now);
        if (!v.ok) return v;
        std::string key = rec.storage_key();
        auto it = records_.find(key);
        if (it != records_.end() && it->second.issued >= rec.issued) return {false, "stale"};
        records_[key] = rec;
        return {true, "ok"};
    }

    bool get(const std::string& kind, const Bytes& publisher, SignedRecord& out) {
        reap();
        auto it = records_.find(kind + ":" + to_hex(sha256(publisher)));
        if (it == records_.end()) return false;
        out = it->second;
        return true;
    }

    std::map<std::string, SignedRecord> present() {
        reap();
        return records_;
    }

    bool due_for_republish(const SignedRecord& rec, double margin = 0.2) const {
        int64_t now = (int64_t)clock_();
        int64_t life = rec.expires - rec.issued;
        return now >= rec.expires - (int64_t)(life * margin);
    }

    PerKeyRateLimiter& limiter() { return limiter_; }

private:
    void reap() {
        int64_t now = (int64_t)clock_();
        for (auto it = records_.begin(); it != records_.end();) {
            if (it->second.expires <= now)
                it = records_.erase(it);
            else
                ++it;
        }
    }
    Clock clock_;
    PerKeyRateLimiter limiter_;
    std::map<std::string, SignedRecord> records_;
};

}  // namespace darcraw
