# D'Arcraw back-end (C++17)

D'Arcraw's back-end: a decentralized, content-addressed netDb, a self-updating crawl
loop, and the distributed scrape orchestrator that ties peers into one real-time
index. Every part is built around one fixed, non-learned content gate. The
orchestrator is per-peer, not a central server. `ORCHESTRATOR.md` documents the design
and the reasoning behind each subsystem.

The core is header-only under `include/darcraw`. The only dependency is OpenSSL, used
for SHA-256 and Ed25519. SipHash (for the sketches and the Bloom filter) and the RPC
wire format are vendored, so there is nothing else to fetch.

## Prerequisites

The only dependency beyond the compiler is OpenSSL, for SHA-256 and Ed25519. SipHash
and the RPC wire format are vendored into the headers, so there is nothing else to
fetch and no third-party C++ libraries to install.

To build, you need:

- A C++17 compiler. g++ 8 or newer, or clang 7 or newer. The project was built with
  g++ 13, but it does not require 13.
- CMake 3.16 or newer, plus a backend. make is standard, and ninja also works.
- OpenSSL development headers and library, for SHA-256 and Ed25519. The runtime ships
  on nearly every Linux already, but compiling needs the `-dev` / `-devel` package.

Install one-liners:

- Debian/Ubuntu: `sudo apt install build-essential cmake libssl-dev`
- Fedora/RHEL: `sudo dnf install gcc-c++ cmake openssl-devel`
- macOS: `xcode-select --install`, then `brew install cmake openssl@3`, and point CMake
  at the brew OpenSSL with `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)`.

If you already build C++ projects, the only likely missing piece is `libssl-dev`, which
is the one-line install above.

## Build and test

```
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

`sam_check` is built but not run by ctest, because it needs a live I2P SAM bridge:

```
./build/sam_check          # validates the SAM transport against a router on 127.0.0.1:7656
```

## Running a node

A built binary needs only the OpenSSL shared library (libcrypto), which ships with the
OS. No compiler or CMake is needed on the running nodes, so you build once on a dev box
and ship the binary to the network. The toolchain is a build-time requirement, not a
per-node one.

## Portability

The core is standard C++17 and builds on Linux and macOS. The SAM transport
(`sam_transport.hpp`) uses POSIX sockets, so on Windows it needs a winsock shim or WSL.
The rest of the code is portable as written.

## Files

Core, under `include/darcraw`:

- `gate.hpp`: the content gate. Exact-hash and perceptual-hash blocklist, deny on match. Runs at crawler ingestion and at every store-admission. Never learned. Fails closed until armed.
- `blocklist.hpp`: the signed, versioned blocklist the gate enforces. M-of-N maintainer signatures, forward-only versions for rollback protection, fail-closed arming.
- `governance.hpp`: the maintainer-set chain (versioned, rotatable) and the hash-proposal lifecycle: propose, review, co-sign, promote.
- `netdb.hpp`: Kademlia-style content-addressed DHT. Proof-of-work node IDs bound to the I2P destination, k-bucket routing with LRU eviction and liveness pings, replication to the k closest, parallel node-disjoint lookup, and an OR-Set CRDT catalog reconciled by range-based anti-entropy. The gate runs on every store.
- `crawler.hpp`: online contextual-bandit crawl loop with bounded ticks, per-source influence caps, and holdout-gated rollback for poisoning resistance.
- `orchestrator.hpp`: the per-peer distributed scrape loop. Dedup and rendezvous-ownership admission, per-domain politeness release, the learned crawl tick, real-time index spread, and cross-peer seen reconciliation.
- `sketches.hpp`: rendezvous (HRW) hashing for coordinator-free work assignment, HyperLogLog for network-wide coverage, and IBLT for difference-sized set reconciliation.
- `dedup.hpp`: Bloom-filter `SeenSet` for URL dedup before queuing, plus an optional shared backend hook for one operator's worker fleet.
- `ratelimit.hpp`: token bucket and per-key limiter, shared by per-origin netDb admission and per-domain scrape politeness.
- `records.hpp`: signed, expiring RouterInfo and LeaseSet-style records. Ed25519 verified before storage, cryptographic-timestamp expiry with LeaseSets capped under ten minutes, per-origin admission limiting. Red25519 blinding is an explicit unimplemented hook.
- `fetchpool.hpp`: proxy and session pool with backoff and cookie sessions, split into an I2P backend (tunnel and destination rotation through the I2P HTTP proxy) and a clearnet backend (IP proxy rotation for mirror fetches).
- `origin.hpp`: origin classifier. Stage 1 cheap page signals, and `TwoStageClassifier` adds Stage 2 SimHash near-duplicate detection to flag mirrors. Feeds the crawler's reward so it prefers native content.
- `fingerprint.hpp`: SimHash over word shingles plus a banded LSH index for sub-linear near-duplicate lookup.
- `transport.hpp`: the transport interface plus an in-memory transport for the offline tests.
- `sam_transport.hpp`: the production I2P SAM v3 transport (STREAM style, length-framed). Validate against a live router.
- `ed25519.hpp`, `hash.hpp`, `siphash.hpp`, `wire.hpp`: crypto, hashing, and the binary RPC framing the rest builds on.

Tools and tests:

- `tools/sam_check.cpp`: the validation harness for the SAM transport against a live router.
- `tests/`: one executable per subsystem, run by ctest.

## The gate is the invariant

Gate first, then store, then replicate. Never another order. The gate runs at three
points so there is no path into the replicated layer that skips it: crawler ingestion,
local publish, and every received store from a peer. Gated content never acquires a
CID, so it cannot propagate. A malicious fork that strips the gate is outside the
project's control. The network refuses gated content at every hop by construction.

## What runs now, and what needs a live network

The coordination logic, the signed-record lifecycle, the gate through the pump, the
parallel lookup, the blocklist and its governance, and both classifier stages are
implemented and covered by ctest against the in-memory transport. That exercises the
logic in one process. It does not mean the system has run on a live I2P network or
under load. `STATUS.md` lists the gates between this state and a test deployment.

## For the developer picking this up

The back-end is yours to extend: add crawl features, discovery sources, and policy on
top of these headers. The front-end is described in `ORCHESTRATOR.md` and the per-
eepsite statistics format, and is yours to build. Standing up the network, wiring the
real fetch openers, and the live routing and load testing run through the SAM
transport once `sam_check` passes against your router. `STATUS.md` is the ordered list
of what stands between here and a running deployment.
