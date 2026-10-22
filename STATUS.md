# Status and path to a test deployment

This is the current state of D'Arcraw and what a contributor needs to do to stand up
a test deployment. It is honest about what has and has not been exercised.

## Where it stands

The netDb, the content gate, the blocklist and its governance, the crawl loop, and
both stages of the origin classifier are implemented and covered by tests:

- `test_netdb_scale.py` — LRU bucket eviction and delta anti-entropy convergence
- `test_fingerprint.py` — Stage 2 SimHash near-duplicate and mirror detection
- `test_origin.py` — Stage 1 origin signals and the crawler reward wiring
- `test_sec.py` — blocklist threshold signatures, rollback protection, fail-closed arming
- `test_governance.py` — maintainer-set rotation and the hash-proposal lifecycle
- `example.py` — end-to-end: publish, replicate, cross-node lookup, and the gate refusing content at every path

These run against the in-memory transport. That means the logic is exercised and the
invariants hold in a single process. It does not mean the system has run on a live
I2P network or under load. Two things stand between this state and a test deployment,
and both are external to the logic above.

## The two gates to a test deployment

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

## Before a finalized, public deployment

Beyond the two gates above, a public deployment also needs: legal counsel on
reporting obligations and on who may lawfully hold or query a matcher; an authoritative
hash source or an explicitly documented best-effort posture and its limits; load and
scale testing on a real network; and an adversarial review of the SAM path and of the
gate invariant under malicious nodes. None of these is optional for a public launch,
and `HASH_SOURCE.md` is the starting point for the hash and legal questions.
