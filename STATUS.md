# Status and path to a test deployment

This is the current state of D'Arcraw's C++ back-end and what a contributor needs to do
to stand up a test deployment. It states what has and has not been exercised.

## Where it stands

The netDb, the content gate, the blocklist and its governance, the crawl loop, both
stages of the origin classifier, and the distributed scrape orchestrator are
implemented and covered by ctest:

- `test_hash`: SHA-256 vectors, SipHash determinism, the RPC wire format
- `test_sketches`: rendezvous hashing, HyperLogLog coverage, IBLT reconciliation
- `test_dedup`: Bloom no-false-negatives and SeenSet dedup
- `test_ratelimit`: token-bucket burst and refill, per-key isolation
- `test_records`: signed-record verification, cryptographic expiry, TTL caps, per-origin admission limiting
- `test_gate`: exact-hash deny, fail-closed when unarmed, perceptual match through an injected decoder
- `test_netdb_scale`: LRU bucket eviction and delta anti-entropy convergence
- `test_netdb_lookup`: parallel node-disjoint lookups and insulation under a dead path
- `test_fingerprint`: SimHash near-duplicate distance and the banded LSH index
- `test_origin`: Stage 1 signals and Stage 2 mirror detection with first-seen ordering
- `test_sec`: blocklist threshold signatures, rollback protection, fail-closed arming
- `test_governance`: maintainer-set rotation and the hash-proposal lifecycle
- `test_example`: end-to-end publish, replicate, cross-node lookup, and the gate refusing content at every path

These run against the in-memory transport. That means the logic is exercised and the
invariants hold in a single process. It does not mean the system has run on a live I2P
network or under load. Three things stand between this state and a test deployment, and
all are external to the logic above.

The orchestrator (`orchestrator.hpp`) is the per-peer scrape loop. `ORCHESTRATOR.md`
documents its design and the reasoning behind each subsystem, including the three
places where the usual clearnet approach does not fit an I2P overlay and what takes its
place (IP-subnet Sybil limiting, a central Redis dedup, and a centrally enforced rate
limit).

## The three gates to a test deployment

### 1. Validate the SAM transport on a live router

`sam_transport.hpp` is written to I2P SAM v3 but has only been exercised through the
in-memory transport. The SAM dialogue itself has to run against a real router.

Path:
1. Enable the SAM application bridge. Java I2P: router console, Clients, SAM
   application bridge, Start. i2pd: set `sam.enabled=true`. Default is `127.0.0.1:7656`.
2. Run `./build/sam_check`. A pass is: the bridge is reachable, two nodes get distinct
   b32 destinations, lawful content published on one is fetched from the other over
   I2P, and the gate still refuses blocked content. The first cross-node call can take
   30 to 60 seconds while tunnels build.
3. If it hangs or fails, the SAM dialogue in `sam_transport.hpp` is where to look. One
   known hardening item: the accept loop handles one inbound stream at a time, so a
   production node should keep several accepts outstanding to avoid dropping concurrent
   inbound connections.
4. Once two nodes work on one machine, stand up a few across machines and confirm
   publish, replication, disjoint-path lookup, and anti-entropy over real I2P.

### 2. Decide the hash-source posture

The gate fails closed until a signed blocklist arms it, so a node cannot run until it
has a list. `HASH_SOURCE.md` lays out the options.

Path:
1. For a closed test among trusted operators, a maintainer-signed community blocklist
   plus perceptual hashing is enough to exercise the full pipeline, with media kept out
   of the archive until the hash gate is live. Generate a maintainer set and a signed
   blocklist with `governance.hpp` and `blocklist.hpp`, arm the gate, and run.
2. For anything beyond a closed test, the authoritative-source question in
   `HASH_SOURCE.md` has to be answered, and legal counsel on reporting obligations has
   to be in place first. Those are not test-deployment blockers, but they are hard
   blockers for a public one, so decide early which kind of deployment the test is a
   step toward.

### 3. Validate the fetch layer against a live I2P proxy

`fetchpool.hpp` is written to two injectable openers, one through the I2P HTTP proxy
and one through a clearnet proxy, and has only been exercised with a fake opener. The
real fetch dialogue has to run against a live I2P HTTP proxy and real eepsites.

Path:
1. Wire the I2P backend's opener to the router's HTTP proxy (127.0.0.1:4444 by default)
   and fetch a known-up eepsite. Confirm content comes back and the per-host cookie
   session persists across requests.
2. Tune the per-domain politeness rate in the orchestrator to what eepsites actually
   tolerate. The test default is set low.
3. For the clearnet backend used on mirrors, confirm proxy rotation and backoff against
   a target that rate-limits, so a blocked proxy cools down instead of being hammered.

This gate is independent of the two above and can be worked in parallel.

## What a contributor can pick up now

These harden toward a finalized deployment and do not block the test, so they are good
first contributions. Each maps to a header:

- A stronger multiset fingerprint than XOR in the anti-entropy path, for very large
  catalogs (`netdb.hpp`, the `Catalog::fp` method).
- Several outstanding accepts for inbound concurrency (`sam_transport.hpp`).
- Persistence for the content store and catalog across restarts (`netdb.hpp`).
- The Red25519 blinding transform so encrypted LeaseSet2 records verify, ported from a
  router implementation (`records.hpp`, `verify_blinded`).
- The real I2P-proxy and clearnet openers behind the fetch pool, replacing the
  injectable fakes (`fetchpool.hpp`).
- An image decoder wired to the gate's perceptual hook so media perceptual matching is
  active, not exact-hash only (`gate.hpp`, the `PerceptualHasher`).
- HyperLogLog coverage novelty fed into the crawl feature vector, so the policy reads
  how much new content a frontier is still surfacing (`orchestrator.hpp` into
  `crawler.hpp`).

## Before a finalized, public deployment

Beyond the three gates above, a public deployment also needs four things. Legal counsel
on reporting obligations and on who may lawfully hold or query a matcher. An
authoritative hash source, or an explicitly documented best-effort posture and its
limits. Load and scale testing on a real network. And an adversarial review of the SAM
path and of the gate invariant under malicious nodes. None of these is optional for a
public launch, and `HASH_SOURCE.md` is the starting point for the hash and legal
questions.
