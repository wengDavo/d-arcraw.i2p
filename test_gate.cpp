// Gate: exact-hash deny, allow otherwise, fail-closed when unarmed, perceptual match
// through an injected decoder.
#include <cstdio>
#include <optional>

#include "darcraw/gate.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    Bytes banned = to_bytes("KNOWN-ILLEGAL-PAYLOAD");
    Bytes good = to_bytes("an intense but lawful shitpost");

    ContentGate gate({sha256(banned)}, {});
    REQUIRE(gate.check(banned).allowed == false);
    REQUIRE(gate.check(banned).reason == "exact-hash-match");
    REQUIRE(gate.check(good).allowed == true);
    std::printf("gate: exact-hash deny, allow otherwise\n");

    // media exact-hash match
    Bytes badmedia = to_bytes("bad-image-bytes");
    ContentGate mg({sha256(badmedia)}, {});
    REQUIRE(mg.check(good, {badmedia}).reason == "media-exact-hash-match");
    std::printf("gate: media exact-hash deny\n");

    // unarmed fails closed
    ContentGate u = ContentGate::unarmed();
    REQUIRE(u.check(good).allowed == false);
    REQUIRE(u.check(good).reason == "gate-unarmed");
    std::printf("gate: unarmed fails closed\n");

    // perceptual match via an injected decoder
    PerceptualHasher hasher = [](const Bytes& m) -> std::optional<uint64_t> {
        if (m == to_bytes("img-bad")) return (uint64_t)0xFFFF0000FFFF0000ULL;
        if (m == to_bytes("img-ok")) return (uint64_t)0x0ULL;
        return std::nullopt;  // not a decodable image
    };
    ContentGate pg({}, {0xFFFF0000FFFF0001ULL}, 6, hasher);  // 1 bit from img-bad
    REQUIRE(pg.check(good, {to_bytes("img-bad")}).reason == "media-perceptual-match");
    REQUIRE(pg.check(good, {to_bytes("img-ok")}).allowed == true);
    REQUIRE(pg.check(good, {to_bytes("not-an-image")}).allowed == true);
    std::printf("gate: perceptual match within threshold, allow beyond\n");

    std::printf("gate: all passed\n");
    return 0;
}
