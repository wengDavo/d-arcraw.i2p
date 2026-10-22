# The distributed scrape orchestrator

D'Arcraw's back-end is a distributed scraping orchestrator. Every peer runs the same
loop: it pulls from the discovery sources, scrapes the eepsites it is responsible
for, gates and publishes what it finds, and the catalog of what exists converges
across the network continuously. The deep-learning crawl policy decides where to
point the scrape. The demoscene coordination structures decide who scrapes what and
how peers agree on what they have already seen. There is no central orchestrator
process. The word "orchestrator" is the loop each peer runs, not a server they all
report to.

The design problem this back-end solves is that most of the standard
distributed-scraping toolkit assumes a central coordinator and a clearnet target, and
D'Arcraw has neither. It runs on an anonymity overlay where peers never see each
other's IP addresses and no node is in charge. The sections below document how each
hard part works under those constraints, and call out the places where the usual
clearnet answer is wrong for I2P and what replaces it.

## How one tick works

A peer's loop, in `orchestrator.py`:

1. **Admission.** `submit(url, source, features)` admits a URL only if it is unseen
   (Bloom dedup) and this peer is a rendezvous owner of its site. Duplicates and
   sites owned by other peers are dropped before any fetch.
2. **Release under politeness.** `pump()` moves admitted candidates into the learned
   frontier only as each site's per-domain token bucket allows. Everything else waits
   in the pending queue.
3. **Learned ordering, fetch, gate, publish.** The contextual bandit in `crawler.py`
   orders the released frontier, fetches through the proxy/session pool, runs the
   content gate at ingestion, publishes survivors to the netDb, and updates online
   from the outcome.
4. **Real-time indexing.** Each published item enters the OR-Set catalog, which
   range-based anti-entropy spreads to the k closest peers, so an index tracks the
   network continuously instead of in batch rebuilds.

The gate is the invariant and is not touched here. It runs at ingestion and at every
store-admission in `netdb.py`, so nothing in the orchestrator can publish or replicate
past it.

## Design decisions under I2P constraints

### Sybil resistance without visible IP addresses

The usual DHT defense caps netDb entries per IPv4/IPv6 subnet. That cannot work on
this layer. A netDb riding on I2P sees destinations, not IP addresses, because a peer
never learns another peer's IP, so it has nothing to count per subnet. The IP-subnet
form of the defense belongs to the I2P router underneath, where i2pd and Java I2P
already limit how many routers they will trust from one IP range when they select
peers and build their own netDb. That limit is worth setting in the router config.

At D'Arcraw's own layer the same goal is met with what the layer can actually see:

- **PoW-bound node IDs** (`netdb.py`): a node ID is a proof of work over the
  destination, so minting many identities is expensive.
- **Per-origin admission rate limiting** (`records.py`, `RecordStore`, backed by
  `ratelimit.py`): a token bucket keyed by the publishing identity caps how fast any
  one origin can land records. Signing a thousand records buys no extra catalog share.
- **Node-disjoint lookups** (below) so a cluster of Sybils on one slice of the
  keyspace cannot own a lookup.

### Lookup resilience against a captured keyspace slice

`netdb.py`'s `get` runs its disjoint paths concurrently and strictly node-disjoint. A
node is claimed by at most one path, so two paths never collapse onto the same route,
and a captured or dead slice of the keyspace does not stall the lookup because the
other paths route around it. The first path to find the content wins and the rest
stop. `test_netdb_lookup.py` covers this, including the case where two paths route
toward one shared holder and it is still queried exactly once.

### Record authenticity: self-signed, verified before storage

`records.py` carries the publisher's Ed25519 public key and a signature over the
record's canonical bytes. `verify_record` checks it before `RecordStore` will hold the
record, and any tampered field breaks the signature, so a peer cannot inject a
RouterInfo or LeaseSet it does not hold the key for. Ed25519 is fully implemented and
tested.

Red25519, I2P's blinded signature for encrypted LeaseSet2, is a deliberate
`NotImplementedError` rather than a stub that returns "valid". The blinding-factor
derivation is I2P-specific and has to come from a router implementation before blinded
records can be trusted. Until that is in place, LeaseSets verify on the unblinded
Ed25519 path.

### Record expiry and forced republication

Records carry signed `issued` and `expires` timestamps inside the canonical bytes, so
a relay cannot extend a lifetime without breaking the signature. `RecordStore` refuses
anything already expired or dated further out than its kind allows, and reaps expired
records. LeaseSet-style records are capped under ten minutes
(`MAX_TTL["leaseset"] = 600`), enforced both at signing and at verification, so they
fall out of every store on their own and the publisher must re-sign to stay present.
`due_for_republish` tells a publisher to re-sign before expiry rather than after.
`test_records.py` covers the lifecycle.

### Deduplication without a central store

The clearnet pattern for this is a shared Bloom filter in Redis. Redis is a single
central store, and making the whole network depend on one would recentralize exactly
what a decentralized netDb exists to avoid. The dedup is split so the decentralized
case needs no central store:

- **Local Bloom per peer** (`dedup.py`): the cheap, bounded-memory gate before a URL
  is queued. It has no false negatives, so a "seen" answer is always safe to skip.
- **Cross-peer reconciliation by IBLT** (`sketches.py`, `orchestrator.reconcile_seen`):
  two peers exchange an Invertible Bloom Lookup Table of their seen-sets and learn
  exactly the addresses the other already covered, in traffic proportional to the
  difference rather than to the set. This is the network-wide dedup, and it is
  coordinator-free.
- **Optional Redis backend** (`dedup.RedisSeenBackend`): for the one case where a
  central store is correct, a single operator running many worker processes behind one
  owner peer who wants them to share a seen-set. That is one operator's own fleet, not
  the network. It is optional and guarded, and without redis everything runs on the
  local Bloom.

### Fetching: proxy and session management scoped to where the target lives

Residential and datacenter proxy rotation is a clearnet technique, and most of it does
not translate to I2P, where the target sees an I2P destination rather than an IP. So
`fetchpool.py` splits the fetch by where the target lives:

- **I2P targets** go through the I2P HTTP proxy, 127.0.0.1:4444 by default. There is
  no IP to rotate, so the rotation knob is the outbound client tunnel and destination.
  Cookie sessions still matter for stateful eepsites.
- **Clearnet targets**, the mirrors D'Arcraw indexes to mark a site multi-homed, are
  where proxy rotation, exponential backoff, and cookie sessions apply in the ordinary
  way.

Both share the pool, backoff, and session machinery (`ProxyPool`, `Session`,
`FetchPool`). The network call is an injectable opener, so the real I2P-proxy and
clearnet-proxy openers drop in behind one interface and the pacing logic is testable
with no live proxy.

### Politeness enforced structurally, not centrally

Enforcing a per-domain rate across many peers would need a coordinator. Rendezvous
ownership removes the need. Each site has exactly one owner peer, so only that peer
scrapes it and two peers never hit a site at once. Politeness is then a single local
token bucket per domain on the owner (`ratelimit.py`, `orchestrator.pump`), with no
cross-peer coordination because there is no second scraper to coordinate with. r-way
ownership keeps a site covered when its primary owner is down. `test_orchestrator.py`
covers the pacing.

## Files

Added for the orchestrator:

- `orchestrator.py`: the per-peer loop. Admission, politeness release, the learned
  crawl tick, real-time index spread, and cross-peer seen reconciliation.
- `sketches.py`: rendezvous (HRW) hashing, HyperLogLog coverage, and IBLT
  reconciliation. Stdlib only.
- `dedup.py`: Bloom `SeenSet` and the optional single-operator Redis backend.
- `ratelimit.py`: token bucket and per-key limiter, shared by Sybil admission and
  per-domain politeness.
- `records.py`: signed, expiring records with per-origin admission limiting.
- `fetchpool.py`: proxy/session pool with the I2P and clearnet backends.

Changed:

- `netdb.py`: `get` now runs parallel, node-disjoint lookups.

Tests: `test_sketches.py`, `test_dedup.py`, `test_ratelimit.py`, `test_records.py`,
`test_orchestrator.py`, `test_netdb_lookup.py`.

## What is exercised, and what is not

The coordination logic, the signed-record lifecycle, the gate through the pump, and
the parallel lookup are all exercised in-process by the tests above. What they do not
prove is the same as the rest of the project: none of this has run on a live I2P
network or under load. Three external gates stand between this state and a test
deployment, all documented in `STATUS.md`: validating the SAM transport on a live
router, deciding the hash-source posture, and running the real I2P-proxy and clearnet
openers against a live I2P HTTP proxy and real targets with the politeness rates tuned
to what eepsites tolerate.
