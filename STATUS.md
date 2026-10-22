# Status and path to a test deployment

This is the current state of D'Arcraw and what a contributor needs to do to stand up
a test deployment. It is honest about what has and has not been exercised.

## Where it stands

The netDb, the content gate, the blocklist and its governance, the crawl loop, both
stages of the origin classifier, and the distributed scrape orchestrator are
implemented and covered by tests:

- `test_netdb_scale.py`: LRU bucket eviction and delta anti-entropy convergence
- `test_netdb_lookup.py`: parallel node-disjoint lookups and insulation under a dead path
- `test_fingerprint.py`: Stage 2 SimHash near-duplicate and mirror detection
- `test_origin.py`: Stage 1 origin signals and the crawler reward wiring
- `test_sketches.py`: rendezvous hashing, HyperLogLog coverage, IBLT reconciliation
- `test_dedup.py`: Bloom no-false-negatives and SeenSet dedup
- `test_ratelimit.py`: token-bucket burst/refill math and per-key isolation
- `test_orchestrator.py`: admission, rendezvous ownership, per-domain politeness, the gate surviving the pump, and cross-peer seen reconciliation
- `test_sec.py`: blocklist threshold signatures, rollback protection, fail-closed arming
- `test_governance.py`: maintainer-set rotation and the hash-proposal lifecycle
- `test_records.py`: signed-record verification, cryptographic expiry, TTL caps, per-origin admission limiting
- `example.py`: end-to-end: publish, replicate, cross-node lookup, and the gate refusing content at every path

The orchestrator (`orchestrator.py`) is the per-peer scrape loop. `ORCHESTRATOR.md`
documents its design and the reasoning behind each subsystem, including the three
places where the usual clearnet approach does not fit an I2P overlay and what takes
its place (IP-subnet Sybil limiting, a central Redis dedup, and a centrally enforced
rate limit).

These run against the in-memory transport. That means the logic is exercised and the
invariants hold in a single process. It does not mean the system has run on a live
I2P network or under load. Three things stand between this state and a test
deployment, and all are external to the logic above.

## The three gates to a test deployment

### 1. Validate the SAM transport on a live router

`sam_transport.py` is written to I2P SAM v3 but has only been exercised through the
in-memory transport. The SAM dialogue itself has to run against a real router.

Path:
1. Enable the SAM application bridge. Java I2P: router console, Clients, SAM
   application bridge, Start. i2pd: set `sam.enabled=true`. Default is `127.0.0.1:7656`.
2. Run `python3 sam_check.py`. A pass is: the bridge is reachable, two nodes get
   distinct b32 destinations, lawful content published on one is fetched from the
   other over I2P, and the gate still refuses blocked content. The first cross-node
   call can take 30 to 60 seconds while tunnels build; that is expected.
3. If it hangs or fails, the SAM dialogue in `sam_transport.py` is where to look.
   One known hardening item: the accept loop issues one `STREAM ACCEPT` at a time,
   so a production node should keep several accepts outstanding to avoid dropping
   concurrent inbound connections.
4. Once two nodes work on one machine, stand up a few across machines and confirm
   publish, replication, disjoint-path lookup, and anti-entropy over real I2P.

### 2. Decide the hash-source posture

The gate fails closed until a signed blocklist arms it, so a node cannot run until it
has a list. `HASH_SOURCE.md` lays out the options.

Path:
1. For a closed test among trusted operators, a maintainer-signed community blocklist
   plus perceptual hashing is enough to exercise the full pipeline, with media kept
   out of the archive until the hash gate is live. Generate a maintainer set and a
   signed blocklist with `governance.py` and `blocklist.py`, arm the gate, and run.
2. For anything beyond a closed test, the authoritative-source question in
   `HASH_SOURCE.md` has to be answered, and legal counsel on reporting obligations
   has to be in place first. Those are not test-deployment blockers, but they are
   hard blockers for a public one, so decide early which kind of deployment the test
   is a step toward.

### 3. Validate the fetch layer against a live I2P proxy

`fetchpool.py` is written to two injectable openers, one through the I2P HTTP proxy
and one through a clearnet proxy, and has only been exercised with a fake opener. The
real fetch dialogue has to run against a live I2P HTTP proxy and real eepsites.

Path:
1. Point the I2P backend at the router's HTTP proxy (127.0.0.1:4444 by default) and
   fetch a known-up eepsite. Confirm content comes back and the per-host cookie
   session persists across requests.
2. Tune the per-domain politeness rate in the orchestrator to what eepsites actually
   tolerate; the test default is deliberately conservative.
3. For the clearnet backend used on mirrors, confirm proxy rotation and backoff
   against a target that rate-limits, so a blocked proxy cools down instead of being
   hammered.

This gate is independent of the two above and can be worked in parallel.

## What a contributor can pick up now

These harden toward a finalized deployment and do not block the test, so they are
good first contributions. Each maps to a file:

- A stronger multiset fingerprint than XOR in the anti-entropy path, for very large
  catalogs (`netdb.py`, the `Catalog.fp` method).
- Several outstanding `STREAM ACCEPT`s for inbound concurrency (`sam_transport.py`).
- Persistence for the content store and catalog across restarts (`netdb.py`).
- Richer crawl features from the sketch structures feeding the bandit (`crawler.py`).
- Perceptual-hash proposals in the governance promote path, currently exact-only
  (`governance.py`).
- The Red25519 blinding transform so encrypted LeaseSet2 records verify, ported from
  a router implementation (`records.py`, `verify_blinded`).
- The real I2P-proxy and clearnet openers behind the fetch pool, replacing the
  injectable fakes (`fetchpool.py`).
- HyperLogLog coverage novelty fed into the crawl feature vector, so the policy reads
  how much new content a frontier is still surfacing (`orchestrator.py` coverage into
  `crawler.py` features).
- The single-operator Redis seen backend wired for a multi-worker owner peer
  (`dedup.py`, `RedisSeenBackend`).

## Before a finalized, public deployment

Beyond the three gates above, a public deployment also needs: legal counsel on
reporting obligations and on who may lawfully hold or query a matcher; an authoritative
hash source or an explicitly documented best-effort posture and its limits; load and
scale testing on a real network; and an adversarial review of the SAM path and of the
gate invariant under malicious nodes. None of these is optional for a public launch,
and `HASH_SOURCE.md` is the starting point for the hash and legal questions.
