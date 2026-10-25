// Signed blocklist: the content gate's trust and update path. A maintainer-signed,
// versioned document of exact and perceptual hashes under an M-of-N threshold, so no
// single key is a single point of failure. Nodes move forward in version only, which
// blocks rollback, and a node with no verified list fails closed.
//
// A blob verifies by signature, not by the content gate, so a fresh node can fetch and
// verify the list before its gate is armed. Signatures are Ed25519. The canonical
// payload and the blob are the deterministic binary wire format.
#pragma once
#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "darcraw/ed25519.hpp"
#include "darcraw/gate.hpp"
#include "darcraw/hash.hpp"
#include "darcraw/wire.hpp"

namespace darcraw {

inline std::string keyid(const Bytes& pub) {
    return to_hex(Bytes(pub.begin(), pub.begin() + 8));
}

// A signed document is a payload plus a list of (keyid, signature) pairs.
struct SignedDoc {
    Bytes payload;
    std::vector<std::pair<std::string, Bytes>> sigs;
};

inline Bytes sign_doc(const Bytes& payload, const std::vector<Ed25519>& keys) {
    Writer w;
    w.bytes(payload);
    w.u64(keys.size());
    for (const auto& k : keys) {
        w.str(keyid(k.public_bytes()));
        w.bytes(k.sign(payload));
    }
    return to_bytes(w.take());
}

inline SignedDoc parse_signed(const Bytes& blob) {
    Reader r(to_string(blob));
    SignedDoc d;
    d.payload = r.bytes();
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) {
        std::string kid = r.str();
        Bytes sig = r.bytes();
        d.sigs.push_back({kid, sig});
    }
    return d;
}

// Count distinct member signatures that verify over payload.
inline int count_good(const Bytes& payload,
                      const std::vector<std::pair<std::string, Bytes>>& sigs,
                      const std::map<std::string, Bytes>& members) {
    std::set<std::string> good;
    for (const auto& ks : sigs) {
        auto it = members.find(ks.first);
        if (it == members.end() || good.count(ks.first)) continue;
        if (ed25519_verify(it->second, payload, ks.second)) good.insert(ks.first);
    }
    return (int)good.size();
}

inline Bytes blocklist_payload(uint64_t version, const std::string& created,
                               const std::set<Bytes>& exact, const std::vector<uint64_t>& phash) {
    std::vector<std::string> ex;
    for (const auto& h : exact) ex.push_back(to_hex(h));
    std::sort(ex.begin(), ex.end());
    std::vector<uint64_t> ph = phash;
    std::sort(ph.begin(), ph.end());
    Writer w;
    w.u64(version);
    w.str(created);
    w.u64(ex.size());
    for (const auto& h : ex) w.str(h);
    w.u64(ph.size());
    for (auto v : ph) w.u64(v);
    return to_bytes(w.take());
}

inline Bytes make_blocklist(uint64_t version, const std::string& created,
                            const std::set<Bytes>& exact, const std::vector<uint64_t>& phash,
                            const std::vector<Ed25519>& signing_keys) {
    return sign_doc(blocklist_payload(version, created, exact, phash), signing_keys);
}

struct MaintainerSet {
    std::map<std::string, Bytes> pubkeys;   // keyid -> raw public key
    int threshold;
};

struct Blocklist {
    uint64_t version;
    std::string created;
    std::set<Bytes> exact;
    std::vector<uint64_t> phash;
};

// Throws unless at least threshold distinct maintainer signatures verify.
inline Blocklist verify_blocklist(const Bytes& blob, const MaintainerSet& mset) {
    SignedDoc d = parse_signed(blob);
    if (count_good(d.payload, d.sigs, mset.pubkeys) < mset.threshold)
        throw std::runtime_error("blocklist below signature threshold");
    Reader r(to_string(d.payload));
    Blocklist b;
    b.version = r.u64();
    b.created = r.str();
    uint64_t ne = r.u64();
    for (uint64_t i = 0; i < ne; i++) b.exact.insert(from_hex(r.str()));
    uint64_t np = r.u64();
    for (uint64_t i = 0; i < np; i++) b.phash.push_back(r.u64());
    return b;
}

// Owns version state and arms/updates the gate from verified blobs. Version
// persistence across restarts is a deployment hook, kept in memory here.
class BlocklistManager {
public:
    BlocklistManager(ContentGate* gate, MaintainerSet mset, uint64_t version = 0)
        : gate_(gate), mset_(std::move(mset)), version_(version) {}

    // Verify, and if strictly newer, arm/update the gate. Throws on an unverifiable
    // blob. A verified but older-or-equal blob is ignored (rollback protection).
    bool apply(const Bytes& blob) {
        Blocklist b = verify_blocklist(blob, mset_);
        if (b.version <= version_) return false;
        gate_->update(b.exact, b.phash, (int)b.version);
        version_ = b.version;
        return true;
    }
    uint64_t version() const { return version_; }

private:
    ContentGate* gate_;
    MaintainerSet mset_;
    uint64_t version_;
};

}  // namespace darcraw
