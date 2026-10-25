// Maintainer-set governance for the blocklist. Two signed, versioned artifacts carry
// the trust: the maintainer set (version N+1 signed by a threshold of version N, so it
// rotates with no central authority) and hash proposals (signed, co-signed to a
// threshold, then promoted into a new signed blocklist). Removal runs the same path,
// which is how a false-positive block is lifted. Signatures are Ed25519.
#pragma once
#include <algorithm>
#include <ctime>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "darcraw/blocklist.hpp"
#include "darcraw/ed25519.hpp"
#include "darcraw/hash.hpp"
#include "darcraw/wire.hpp"

namespace darcraw {

inline std::string gov_now() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// ---------- maintainer set, versioned and signed ----------

struct Member {
    std::string keyid;
    Bytes pub;
    std::string role;
};

struct MaintainerSetDoc {
    uint64_t version;
    std::string created;
    int threshold;
    std::vector<Member> members;   // sorted by keyid
};

inline Bytes maintainer_set_payload(const MaintainerSetDoc& d) {
    Writer w;
    w.u64(d.version);
    w.str(d.created);
    w.u64((uint64_t)d.threshold);
    w.u64(d.members.size());
    for (const auto& m : d.members) {
        w.str(m.keyid);
        w.bytes(m.pub);
        w.str(m.role);
    }
    return to_bytes(w.take());
}

inline MaintainerSetDoc parse_maintainer_set(const Bytes& payload) {
    Reader r(to_string(payload));
    MaintainerSetDoc d;
    d.version = r.u64();
    d.created = r.str();
    d.threshold = (int)r.u64();
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) {
        Member m;
        m.keyid = r.str();
        m.pub = r.bytes();
        m.role = r.str();
        d.members.push_back(m);
    }
    return d;
}

inline MaintainerSetDoc make_maintainer_set_doc(
    uint64_t version, const std::vector<std::pair<Bytes, std::string>>& members,
    int threshold, const std::string& created = "") {
    MaintainerSetDoc d;
    d.version = version;
    d.created = created.empty() ? gov_now() : created;
    d.threshold = threshold;
    for (const auto& pr : members) d.members.push_back({keyid(pr.first), pr.first, pr.second});
    std::sort(d.members.begin(), d.members.end(),
              [](const Member& a, const Member& b) { return a.keyid < b.keyid; });
    return d;
}

inline Bytes sign_set_doc(const MaintainerSetDoc& d, const std::vector<Ed25519>& keys) {
    return sign_doc(maintainer_set_payload(d), keys);
}

inline MaintainerSet load_set(const MaintainerSetDoc& d) {
    MaintainerSet s;
    s.threshold = d.threshold;
    for (const auto& m : d.members) s.pubkeys[m.keyid] = m.pub;
    return s;
}

class MaintainerChain {
public:
    explicit MaintainerChain(MaintainerSetDoc genesis) : current_(std::move(genesis)) {}

    std::map<std::string, Bytes> members_by_id() const {
        std::map<std::string, Bytes> m;
        for (const auto& mem : current_.members) m[mem.keyid] = mem.pub;
        return m;
    }

    // Accept a new set version signed by a threshold of the CURRENT set.
    bool apply_rotation(const Bytes& blob) {
        SignedDoc d = parse_signed(blob);
        MaintainerSetDoc nd = parse_maintainer_set(d.payload);
        if (nd.version <= current_.version) return false;
        int got = count_good(d.payload, d.sigs, members_by_id());
        if (got < current_.threshold)
            throw std::runtime_error("rotation below current-set threshold");
        current_ = nd;
        return true;
    }

    const MaintainerSetDoc& current() const { return current_; }
    MaintainerSet maintainer_set() const { return load_set(current_); }

private:
    MaintainerSetDoc current_;
};

// ---------- hash proposals ----------

struct ProposalFields {
    std::string action;              // "add" or "remove"
    std::vector<std::string> hashes; // hex, sorted
    std::string category;
    std::string evidence_ref;
    std::string created;
    std::string proposer;            // keyid
};

inline Bytes proposal_payload(const ProposalFields& p) {
    Writer w;
    w.str(p.action);
    w.u64(p.hashes.size());
    for (const auto& h : p.hashes) w.str(h);
    w.str(p.category);
    w.str(p.evidence_ref);
    w.str(p.created);
    w.str(p.proposer);
    return to_bytes(w.take());
}

inline ProposalFields parse_proposal(const Bytes& payload) {
    Reader r(to_string(payload));
    ProposalFields p;
    p.action = r.str();
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) p.hashes.push_back(r.str());
    p.category = r.str();
    p.evidence_ref = r.str();
    p.created = r.str();
    p.proposer = r.str();
    return p;
}

inline SignedDoc make_proposal(const std::string& action, const std::set<Bytes>& hashes,
                               const std::string& category, const std::string& evidence_ref,
                               const Ed25519& proposer, const std::string& created = "") {
    if (action != "add" && action != "remove") throw std::invalid_argument("action must be add or remove");
    ProposalFields p;
    p.action = action;
    for (const auto& h : hashes) p.hashes.push_back(to_hex(h));
    std::sort(p.hashes.begin(), p.hashes.end());
    p.category = category;
    p.evidence_ref = evidence_ref;
    p.created = created.empty() ? gov_now() : created;
    p.proposer = keyid(proposer.public_bytes());
    SignedDoc d;
    d.payload = proposal_payload(p);
    d.sigs.push_back({p.proposer, proposer.sign(d.payload)});
    return d;
}

inline SignedDoc cosign_proposal(SignedDoc prop, const Ed25519& key) {
    std::string kid = keyid(key.public_bytes());
    for (const auto& s : prop.sigs)
        if (s.first == kid) return prop;    // already signed
    prop.sigs.push_back({kid, key.sign(prop.payload)});
    return prop;
}

inline int proposal_support(const SignedDoc& prop, const MaintainerSet& mset) {
    return count_good(prop.payload, prop.sigs, mset.pubkeys);
}
inline bool accepted(const SignedDoc& prop, const MaintainerSet& mset) {
    return proposal_support(prop, mset) >= mset.threshold;
}

struct PromoteResult {
    Bytes blob;
    std::set<Bytes> exact;
    std::vector<uint64_t> phash;
    int applied;
};

// Apply threshold-supported proposals to the hash sets and emit a new signed blocklist.
// Only exact (sha256) hashes are handled here. Perceptual proposals are analogous.
inline PromoteResult promote(const std::set<Bytes>& current_exact,
                             const std::vector<uint64_t>& current_phash,
                             const std::vector<SignedDoc>& proposals, const MaintainerSet& mset,
                             const std::vector<Ed25519>& signing_keys, uint64_t next_version) {
    std::set<Bytes> exact = current_exact;
    std::vector<uint64_t> phash = current_phash;
    int applied = 0;
    for (const auto& p : proposals) {
        if (!accepted(p, mset)) continue;
        ProposalFields pf = parse_proposal(p.payload);
        for (const auto& h : pf.hashes) {
            if (h.size() != 64) continue;   // exact sha256 hex only
            Bytes b = from_hex(h);
            if (pf.action == "add") exact.insert(b);
            else exact.erase(b);
        }
        applied++;
    }
    PromoteResult r;
    r.exact = exact;
    r.phash = phash;
    r.applied = applied;
    r.blob = make_blocklist(next_version, gov_now(), exact, phash, signing_keys);
    return r;
}

}  // namespace darcraw
