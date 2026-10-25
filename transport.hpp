// Transport abstraction. Production transport speaks I2P SAM v3, so every node is an
// I2P destination and all RPC rides inside I2P. This defines the interface plus an
// in-memory transport for local testing. Swapping to I2P means implementing Transport
// against a SAM session. Nothing above this layer changes.
#pragma once
#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace darcraw {

using RpcHandler = std::function<std::string(const std::string& src, const std::string& msg)>;

class Transport {
public:
    virtual ~Transport() = default;
    virtual const std::string& address() const = 0;
    virtual std::string send(const std::string& dest, const std::string& msg) = 0;
    virtual void serve(RpcHandler handler) = 0;
};

// A local message bus so several nodes can talk in one process, for tests.
// calls_ counts requests per destination and disable() drops a node, so a test can
// simulate an offline peer and observe how many times each node was queried.
class InMemoryNetwork {
public:
    void registerNode(const std::string& addr, RpcHandler handler) {
        nodes_[addr] = std::move(handler);
    }
    void disable(const std::string& addr) { nodes_.erase(addr); }

    std::string send(const std::string& src, const std::string& dest, const std::string& msg) {
        calls_[dest]++;
        auto it = nodes_.find(dest);
        if (it == nodes_.end()) throw std::runtime_error("unreachable: " + dest);
        return it->second(src, msg);
    }

    int calls(const std::string& addr) const {
        auto it = calls_.find(addr);
        return it == calls_.end() ? 0 : it->second;
    }
    void reset_calls() { calls_.clear(); }

private:
    std::unordered_map<std::string, RpcHandler> nodes_;
    std::unordered_map<std::string, int> calls_;
};

class InMemoryTransport : public Transport {
public:
    InMemoryTransport(InMemoryNetwork& net, std::string address)
        : net_(net), addr_(std::move(address)) {}

    const std::string& address() const override { return addr_; }
    std::string send(const std::string& dest, const std::string& msg) override {
        return net_.send(addr_, dest, msg);
    }
    void serve(RpcHandler handler) override { net_.registerNode(addr_, std::move(handler)); }

private:
    InMemoryNetwork& net_;
    std::string addr_;
};

}  // namespace darcraw
