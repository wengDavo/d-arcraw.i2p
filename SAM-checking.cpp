// Validation harness for the SAM transport against a LIVE I2P router.
//
// Enable the SAM bridge first (Java I2P: router console, Clients, SAM application
// bridge, Start. i2pd: sam.enabled=true), default 127.0.0.1:7656. A pass is: two nodes
// get distinct b32 destinations, lawful content published on one is fetched from the
// other over I2P, and the gate still refuses blocked content. The first cross-node
// call can take 30 to 60 seconds while tunnels build.
#include <cstdio>
#include <stdexcept>

#include "darcraw/netdb.hpp"
#include "darcraw/sam_transport.hpp"

using namespace darcraw;

int main() {
    try {
        Bytes banned = to_bytes("KNOWN-ILLEGAL-PAYLOAD");
        ContentGate gate({sha256(banned)}, {});

        SAMTransport ta("darcraw-a"), tb("darcraw-b");
        std::printf("node A b32: %s\n", ta.b32().c_str());
        std::printf("node B b32: %s\n", tb.b32().c_str());

        Node a(ta, gate, 12, K, 2), b(tb, gate, 12, K, 2);
        a.learn(b.me());
        b.learn(a.me());

        Bytes good = to_bytes("an intense but lawful shitpost");
        auto cid = a.publish(good);
        if (!cid) { std::printf("FAIL: lawful content did not publish\n"); return 1; }
        auto got = b.get(*cid);
        std::printf("cross-node fetch over I2P: %s\n", (got && *got == good) ? "ok" : "FAILED");
        std::printf("gate still refuses blocked content: %s\n",
                    a.publish(banned).has_value() ? "FAILED" : "ok");
        return 0;
    } catch (const std::exception& e) {
        std::printf("SAM check could not run: %s\n", e.what());
        std::printf("Enable the SAM bridge at 127.0.0.1:7656 and retry.\n");
        return 2;
    }
}
