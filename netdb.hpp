// Decentralized, content-addressed netDb over a Kademlia-style DHT.
//
// Placement is deterministic (the k closest node IDs to a key hold it), so there is
// no consensus to run. Node IDs are bound to the I2P destination and carry a proof of
// work, the Sybil cost. Lookups run parallel, node-disjoint paths. Routing buckets use
// LRU eviction with liveness pings. The catalog of what exists is an OR-Set CRDT
// reconciled by range-based (delta) anti-entropy.
//
// The content gate runs at every store-admission: local publish, received store, and
// replication. Gated content never acquires a CID and therefore never spreads.
#pragma once
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "darcraw/gate.hpp"
#include "darcraw/hash.hpp"
#include "darcraw/transport.hpp"
#include "darcraw/wire.hpp"

namespace darcraw {

constexpr int K = 20;         // bucket size and default replication factor
constexpr int AE_LEAF = 16;   // anti-entropy: exchange elements once a range is this small

enum OpCode : uint8_t { OP_PING = 1, OP_STORE = 2, OP_FIND = 3, OP_AE_FP = 4, OP_AE_LEAF = 5 };

// --- optional-string and string-list helpers over the wire ------------------
inline void put_opt(Writer& w, const std::optional<std::string>& o) {
    w.u8(o ? 1 : 0);
    if (o) w.str(*o);
}
inline std::optional<std::string> get_opt(Reader& r) {
    if (r.u8()) return r.str();
    return std::nullopt;
}
inline void put_list(Writer& w, const std::vector<std::string>& v) {
    w.u64(v.size());
    for (const auto& s : v) w.str(s);
}
inline std::vector<std::string> get_list(Reader& r) {
    uint64_t n = r.u64();
    std::vector<std::string> v;
    v.reserve(n);
    for (uint64_t i = 0; i < n; i++) v.push_back(r.str());
    return v;
}

// --- node identity: bound to destination, gated by proof of work ------------
inline Bytes node_id(const std::string& destination, uint64_t nonce) {
    std::string s = destination;
    for (int i = 7; i >= 0; i--) s.push_back((char)((nonce >> (8 * i)) & 0xff));
    return sha256(s);
}
inline bool leading_zero_bits(const Bytes& b, int bits) {
    int full = bits / 8, rem = bits % 8;
    for (int i = 0; i < full; i++)
        if (b[i] != 0) return false;
    if (rem) {
        uint8_t mask = (uint8_t)(0xFF << (8 - rem));
        if (b[full] & mask) return false;
    }
    return true;
}
inline bool pow_valid(const std::string& dest, uint64_t nonce, int difficulty) {
    return leading_zero_bits(node_id(dest, nonce), difficulty);
}
inline std::pair<uint64_t, Bytes> mine_node_id(const std::string& dest, int difficulty) {
    uint64_t nonce = 0;
    while (!pow_valid(dest, nonce, difficulty)) nonce++;
    return {nonce, node_id(dest, nonce)};
}

struct Peer {
    Bytes node_id;
    std::string destination;
    uint64_t nonce;
};

inline bool peer_valid(const Peer& p, int difficulty) {
    return p.node_id == node_id(p.destination, p.nonce) && pow_valid(p.destination, p.nonce, difficulty);
}

// xor(a,key) < xor(b,key) as 256-bit integers (lexicographic over big-endian bytes)
inline bool xor_closer(const Bytes& a, const Bytes& b, const Bytes& key) {
    for (size_t i = 0; i < key.size(); i++) {
        uint8_t da = a[i] ^ key[i], db = b[i] ^ key[i];
        if (da != db) return da < db;
    }
    return false;
}

class RoutingTable {
public:
    RoutingTable(Bytes self, int k) : self_(std::move(self)), k_(k), buckets_(256) {}

    int bucket_index(const Bytes& nid) const {
        int lz = 0;
        for (size_t i = 0; i < self_.size(); i++) {
            uint8_t x = self_[i] ^ nid[i];
            if (x == 0) { lz += 8; continue; }
            lz += __builtin_clz((unsigned)x) - 24;
            break;
        }
        int bitlen = 256 - lz;
        return bitlen > 0 ? bitlen - 1 : 0;
    }

    void add(const Peer& peer, const std::function<bool(const Peer&)>& ping) {
        auto& b = buckets_[bucket_index(peer.node_id)];
        for (size_t i = 0; i < b.size(); i++) {
            if (b[i].node_id == peer.node_id) {       // seen: move to most-recent end
                Peer p = b[i];
                b.erase(b.begin() + i);
                b.push_back(p);
                return;
            }
        }
        if ((int)b.size() < k_) { b.push_back(peer); return; }
        Peer oldest = b.front();
        if (ping && ping(oldest)) {                   // alive: keep it, drop newcomer
            b.erase(b.begin());
            b.push_back(oldest);
        } else {                                      // dead: evict, admit newcomer
            b.erase(b.begin());
            b.push_back(peer);
        }
    }

    std::vector<Peer> closest(const Bytes& key, int n) const {
        std::vector<Peer> all;
        for (const auto& bk : buckets_)
            for (const auto& p : bk) all.push_back(p);
        std::sort(all.begin(), all.end(), [&](const Peer& a, const Peer& b) {
            return xor_closer(a.node_id, b.node_id, key);
        });
        if ((int)all.size() > n) all.resize(n);
        return all;
    }

private:
    Bytes self_;
    int k_;
    std::vector<std::vector<Peer>> buckets_;
};

class ContentStore {
public:
    explicit ContentStore(const ContentGate& gate) : gate_(gate) {}

    static Bytes cid(const Bytes& content) { return sha256(content); }

    std::optional<Bytes> admit(const Bytes& content, const std::vector<Bytes>& media = {}) {
        if (!gate_.check(content, media).allowed) return std::nullopt;
        Bytes c = cid(content);
        data_[c] = content;
        return c;
    }
    std::optional<Bytes> get(const Bytes& cid) const {
        auto it = data_.find(cid);
        if (it == data_.end()) return std::nullopt;
        return it->second;
    }
    void purge(const Bytes& cid) { data_.erase(cid); }

private:
    const ContentGate& gate_;
    std::map<Bytes, Bytes> data_;
};

// Observed-Remove Set of CID hexes. Adds carry unique tags, removes tombstone them.
// Join is union of adds and removes: commutative, idempotent, leaderless.
class Catalog {
public:
    void add(const Bytes& cid) { adds_[to_hex(cid)].insert(rand_tag()); }
    void remove(const Bytes& cid) {
        std::string h = to_hex(cid);
        auto it = adds_.find(h);
        if (it != adds_.end()) removes_[h].insert(it->second.begin(), it->second.end());
    }
    std::set<std::string> present() const {
        std::set<std::string> out;
        for (const auto& kv : adds_) {
            const std::set<std::string>* rem = nullptr;
            auto it = removes_.find(kv.first);
            if (it != removes_.end()) rem = &it->second;
            for (const auto& t : kv.second)
                if (!rem || !rem->count(t)) { out.insert(kv.first); break; }
        }
        return out;
    }
    void merge(const Catalog& o) {
        for (const auto& kv : o.adds_) adds_[kv.first].insert(kv.second.begin(), kv.second.end());
        for (const auto& kv : o.removes_) removes_[kv.first].insert(kv.second.begin(), kv.second.end());
    }

    std::vector<std::string> dots() const {
        std::vector<std::string> out;
        for (const auto& kv : adds_)
            for (const auto& t : kv.second) out.push_back("+" + kv.first + ":" + t);
        for (const auto& kv : removes_)
            for (const auto& t : kv.second) out.push_back("-" + kv.first + ":" + t);
        std::sort(out.begin(), out.end());
        return out;
    }
    void apply_dots(const std::vector<std::string>& dots) {
        for (const auto& d : dots) {
            char sign = d[0];
            std::string rest = d.substr(1);
            auto pos = rest.rfind(':');
            std::string h = rest.substr(0, pos), t = rest.substr(pos + 1);
            (sign == '+' ? adds_ : removes_)[h].insert(t);
        }
    }
    std::vector<std::string> range_dots(const std::optional<std::string>& lo,
                                        const std::optional<std::string>& hi) const {
        std::vector<std::string> out;
        for (const auto& d : dots())
            if ((!lo || d >= *lo) && (!hi || d < *hi)) out.push_back(d);
        return out;
    }
    // Order-independent fingerprint (XOR of per-dot hashes) and count over a range.
    std::pair<uint64_t, uint64_t> fp(const std::optional<std::string>& lo,
                                     const std::optional<std::string>& hi) const {
        uint64_t x = 0, n = 0;
        for (const auto& d : range_dots(lo, hi)) {
            Bytes h = sha256(d);
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | h[i];
            x ^= v;
            n++;
        }
        return {x, n};
    }

private:
    static std::string rand_tag() {
        static thread_local std::mt19937_64 rng(std::random_device{}());
        uint64_t a = rng(), b = rng();
        Bytes t(16);
        for (int i = 0; i < 8; i++) {
            t[i] = (uint8_t)(a >> (8 * i));
            t[8 + i] = (uint8_t)(b >> (8 * i));
        }
        return to_hex(t);
    }
    std::map<std::string, std::set<std::string>> adds_, removes_;
};

class Node {
public:
    Node(Transport& transport, const ContentGate& gate, int difficulty = 16,
         int k = K, int replication = K)
        : transport_(transport),
          difficulty_(difficulty),
          k_(k),
          replication_(replication),
          mined_(mine_node_id(transport.address(), difficulty)),
          nonce_(mined_.first),
          id_(mined_.second),
          me_{id_, transport.address(), nonce_},
          routing_(id_, k),
          store_(gate) {
        transport_.serve([this](const std::string& s, const std::string& m) { return handle(s, m); });
    }

    const Peer& me() const { return me_; }
    Catalog& catalog() { return catalog_; }
    ContentStore& store() { return store_; }

    std::optional<Bytes> publish(const Bytes& content, const std::vector<Bytes>& media = {}) {
        auto cid = store_.admit(content, media);
        if (!cid) return std::nullopt;
        catalog_.add(*cid);
        replicate(*cid, content);
        return cid;
    }

    // Parallel, node-disjoint disjoint-path lookup.
    std::optional<Bytes> get(const Bytes& cid, int paths = 3, int max_hops = 8) {
        auto local = store_.get(cid);
        if (local) return local;
        auto seeds = routing_.closest(cid, paths);
        if (seeds.empty()) return std::nullopt;

        std::atomic<bool> found{false};
        Bytes result;
        bool have = false;
        std::set<Bytes> claimed;
        std::mutex mu;

        auto walk = [&](Peer node) {
            for (int h = 0; h < max_hops; h++) {
                if (found.load()) return;
                {
                    std::lock_guard<std::mutex> lk(mu);
                    if (claimed.count(node.node_id)) return;  // owned by another path
                    claimed.insert(node.node_id);
                }
                std::string resp;
                try {
                    Writer q;
                    q.u8(OP_FIND);
                    q.bytes(cid);
                    resp = rpc(node, q.take());
                } catch (...) {
                    return;
                }
                Reader r(resp);
                uint8_t tag = r.u8();
                if (tag == 1) {
                    Bytes content = r.bytes();
                    std::lock_guard<std::mutex> lk(mu);
                    if (!found.load()) { result = content; have = true; found.store(true); }
                    return;
                }
                if (tag == 2) {
                    Bytes nid = r.bytes();
                    std::string dest = r.str();
                    uint64_t nonce = r.u64();
                    Peer p{nid, dest, nonce};
                    if (!peer_valid(p, difficulty_)) return;
                    node = p;
                    continue;
                }
                return;  // empty
            }
        };

        std::vector<std::thread> ts;
        for (auto& s : seeds) ts.emplace_back(walk, s);
        for (auto& t : ts) t.join();
        if (have) return result;
        return std::nullopt;
    }

    void repair() {
        for (const auto& h : catalog_.present()) {
            Bytes cid = from_hex(h);
            auto c = store_.get(cid);
            if (c) replicate(cid, *c);
        }
    }

    void anti_entropy(const Peer& peer) { ae_range(peer, std::nullopt, std::nullopt); }

    void learn(const Peer& peer) {
        if (peer_valid(peer, difficulty_))
            routing_.add(peer, [this](const Peer& p) { return ping(p); });
    }

private:
    void replicate(const Bytes& cid, const Bytes& content) {
        for (const auto& peer : routing_.closest(cid, replication_)) {
            try {
                Writer q;
                q.u8(OP_STORE);
                q.bytes(content);
                rpc(peer, q.take());
            } catch (...) {
                continue;
            }
        }
    }

    void ae_range(const Peer& peer, std::optional<std::string> lo, std::optional<std::string> hi) {
        auto mine = catalog_.fp(lo, hi);
        Writer q;
        q.u8(OP_AE_FP);
        put_opt(q, lo);
        put_opt(q, hi);
        Reader rr(rpc(peer, q.take()));
        uint64_t pfp = rr.u64(), pn = rr.u64();
        if (mine.first == pfp) return;  // identical, ship nothing
        if (std::max(mine.second, pn) <= (uint64_t)AE_LEAF || mine.second == 0 || pn == 0) {
            auto dots = catalog_.range_dots(lo, hi);
            Writer lw;
            lw.u8(OP_AE_LEAF);
            put_opt(lw, lo);
            put_opt(lw, hi);
            put_list(lw, dots);
            Reader lr(rpc(peer, lw.take()));
            catalog_.apply_dots(get_list(lr));
            return;
        }
        auto mids = catalog_.range_dots(lo, hi);
        std::string mid = mids[mids.size() / 2];
        ae_range(peer, lo, mid);
        ae_range(peer, mid, hi);
    }

    bool ping(const Peer& peer) {
        try {
            Writer q;
            q.u8(OP_PING);
            Reader r(rpc(peer, q.take()));
            return r.u8() == 1;
        } catch (...) {
            return false;
        }
    }

    std::string rpc(const Peer& peer, const std::string& msg) {
        return transport_.send(peer.destination, msg);
    }

    std::string handle(const std::string&, const std::string& raw) {
        Reader r(raw);
        uint8_t op = r.u8();
        Writer w;
        if (op == OP_PING) {
            w.u8(1);
        } else if (op == OP_STORE) {
            Bytes content = r.bytes();
            auto cid = store_.admit(content);  // gate on every received store
            if (!cid) {
                w.u8(0);
            } else {
                catalog_.add(*cid);
                w.u8(1);
            }
        } else if (op == OP_FIND) {
            Bytes cid = r.bytes();
            auto c = store_.get(cid);
            if (c) {
                w.u8(1);
                w.bytes(*c);
            } else {
                auto peers = routing_.closest(cid, 1);
                if (!peers.empty()) {
                    w.u8(2);
                    w.bytes(peers[0].node_id);
                    w.str(peers[0].destination);
                    w.u64(peers[0].nonce);
                } else {
                    w.u8(0);
                }
            }
        } else if (op == OP_AE_FP) {
            auto lo = get_opt(r), hi = get_opt(r);
            auto f = catalog_.fp(lo, hi);
            w.u64(f.first);
            w.u64(f.second);
        } else if (op == OP_AE_LEAF) {
            auto lo = get_opt(r), hi = get_opt(r);
            auto theirs = get_list(r);
            catalog_.apply_dots(theirs);        // union their dots
            put_list(w, catalog_.range_dots(lo, hi));
        }
        return w.take();
    }

    Transport& transport_;
    int difficulty_, k_, replication_;
    std::pair<uint64_t, Bytes> mined_;
    uint64_t nonce_;
    Bytes id_;
    Peer me_;
    RoutingTable routing_;
    ContentStore store_;
    Catalog catalog_;
};

}  // namespace darcraw
