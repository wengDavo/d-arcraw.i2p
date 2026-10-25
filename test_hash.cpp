// Foundation: SHA-256 vectors, SipHash determinism, wire round-trip, hex helpers.
#include <cstdio>
#include <string>

#include "darcraw/hash.hpp"
#include "darcraw/wire.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    // SHA-256 known vector for "abc"
    REQUIRE(to_hex(sha256(std::string("abc"))) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // hex round-trip
    Bytes r = sha256(std::string("darcraw"));
    REQUIRE(from_hex(to_hex(r)) == r);

    // SipHash: deterministic, seed-dependent, length-sensitive
    std::string a = "b32address.i2p";
    REQUIRE(siphash64(a, 1) == siphash64(a, 1));
    REQUIRE(siphash64(a, 1) != siphash64(a, 2));
    REQUIRE(siphash64(a, 1) != siphash64(a + "x", 1));

    // wire round-trip
    Writer w;
    w.u8(7);
    w.u64(0x0123456789abcdefULL);
    w.str("op:find");
    w.bytes(r);
    std::string buf = w.take();
    Reader rd(buf);
    REQUIRE(rd.u8() == 7);
    REQUIRE(rd.u64() == 0x0123456789abcdefULL);
    REQUIRE(rd.str() == "op:find");
    REQUIRE(rd.bytes() == r);
    REQUIRE(rd.eof());

    std::printf("hash/wire: sha256 vector, siphash determinism, wire round-trip ok\n");
    return 0;
}
