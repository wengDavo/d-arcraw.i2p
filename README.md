# D'Arcraw netDb, crawler, and scrape orchestrator

A reference skeleton for D'Arcraw's back-end: a decentralized, content-addressed
netDb, a self-updating crawl loop, and the distributed scrape orchestrator that ties
peers into one real-time index. Every part is built around one fixed, non-learned
content gate. The orchestrator is per-peer, not a central server. `ORCHESTRATOR.md`
documents its design and the reasoning behind each subsystem.

## Files

- `gate.py`: the content gate. Exact-hash and perceptual-hash blocklist, deny on match. Runs at crawler ingestion and at every store-admission. Never learned. Fails closed until armed.
- `blocklist.py`: the signed, versioned blocklist the gate enforces: M-of-N maintainer signatures, forward-only versions for rollback protection, and fail-closed arming. The gate's trust and update path.
- `governance.py`: the maintainer-set chain (versioned, rotatable) and the hash-proposal lifecycle: propose, review, co-sign, promote.
- `GOVERNANCE.md`: the human process around it: key-holding, roles, the illegal-not-offensive review bar, rotation, and the unsolved hash-source dependency.
- `HASH_SOURCE.md`: the approach to an authoritative hash source: the oracle/verdict model, candidate partners, the obstacles, and a concrete sequence.
- `STATUS.md`: current state, the two gates to a test deployment, and what a contributor can pick up.
- `netdb.py`: Kademlia-style content-addressed DHT: proof-of-work node IDs bound to the I2P destination, k-bucket routing with LRU eviction and liveness pings, replication to the k closest, disjoint-path lookup, and an OR-Set CRDT catalog reconciled by range-based (delta) anti-entropy. The gate is enforced on every store.
- `crawler.py`: online contextual-bandit crawl loop with bounded ticks, per-source influence caps, and holdout-gated rollback for poisoning resistance.
- `orchestrator.py`: the per-peer distributed scrape loop: dedup + rendezvous-ownership admission, per-domain politeness release, the learned crawl tick, real-time index spread, and cross-peer seen reconciliation. Ties the pieces below to the netDb and crawler. See `ORCHESTRATOR.md`.
- `sketches.py`: the demoscene coordination structures, stdlib only: rendezvous (HRW) hashing for coordinator-free work assignment, HyperLogLog for network-wide coverage, and IBLT for difference-sized set reconciliation.
- `dedup.py`: Bloom-filter `SeenSet` for URL dedup before queuing; cross-peer reconciliation via IBLT, with an optional Redis backend scoped to a single operator's worker fleet rather than the network.
- `ratelimit.py`: token bucket and per-key limiter, shared by per-origin netDb admission (Sybil) and per-domain scrape politeness.
- `records.py`: signed, expiring RouterInfo/LeaseSet-style records: Ed25519 verified before storage, cryptographic-timestamp expiry with LeaseSets capped under ten minutes, and per-origin admission rate limiting. Red25519 blinding is an explicit unimplemented hook.
- `fetchpool.py`: proxy/session pool with backoff and cookie sessions, split into an I2P backend (tunnel/destination rotation through the I2P HTTP proxy) and a clearnet backend (IP proxy rotation for mirror fetches).
- `origin.py`: origin classifier. Stage 1 cheap page signals, and `TwoStageClassifier` adds Stage 2 SimHash near-duplicate detection to flag mirrors. Feeds the crawler's reward so it prefers native content.
- `fingerprint.py`: SimHash over word shingles plus a banded LSH index for sub-linear near-duplicate lookup. Stdlib only.
- `transport.py`: transport interface plus an in-memory transport for tests.
- `sam_transport.py`: the production I2P SAM v3 transport (STREAM style, length-framed). Validate against a live router.
- `sam_check.py`: validation harness that exercises the SAM transport against a live router: two nodes, publish and cross-node fetch over I2P.
- `example.py`: three-node smoke test, including proof that gated content never enters the netDb.

## The gate is the invariant

Gate first, then store, then replicate. Never another order. The gate runs at
three points so there is no path into the replicated layer that skips it:
crawler ingestion, local publish, and every received store from a peer. Gated
content never acquires a CID, so it cannot propagate. A malicious fork that strips
the gate is outside the project's control; the reference network refuses gated
content at every hop by construction.

## What is a skeleton here, and must be filled in

- **I2P SAM transport** is implemented in `sam_transport.py` with a validation harness in `sam_check.py`. Run the harness against a live router to confirm the SAM dialogue, which cannot be exercised without one. The in-memory transport stays for the offline tests.
- **Blocklist trust, update, and governance** are implemented: `blocklist.py` (threshold-signed, versioned, fail-closed), `governance.py` (rotatable maintainer chain and the proposal lifecycle), and `GOVERNANCE.md` (the process). The one piece still unsolved, and the weakest point in the project, is the authoritative hash source: licensed CSAM sets generally cannot be redistributed to untrusted nodes, so the floor relies on what the maintainers can lawfully obtain and attest to. Secure that before any real deployment.
Implemented since the first skeleton: LRU bucket eviction with liveness pings, delta (range-based) anti-entropy, the origin classifier wired into the crawler's reward, and Stage 2 SimHash near-duplicate and mirror detection. The remaining netDb hardening for very large scale is a stronger multiset fingerprint than XOR in the anti-entropy path.

## Run the tests

```
python3 example.py            # netDb, crawler, and gate smoke test, no extra deps
python3 test_netdb_scale.py   # LRU eviction and delta anti-entropy convergence, no extra deps
python3 test_netdb_lookup.py  # parallel node-disjoint lookups, insulation under a dead path, no extra deps
python3 test_origin.py        # origin classifier and reward wiring, no extra deps
python3 test_fingerprint.py   # Stage 2 SimHash near-dup and mirror flagging, no extra deps
python3 test_sketches.py      # rendezvous, HyperLogLog, IBLT reconciliation, no extra deps
python3 test_dedup.py         # Bloom no-false-negatives and SeenSet dedup, no extra deps
python3 test_ratelimit.py     # token-bucket burst/refill and per-key isolation, no extra deps
python3 test_orchestrator.py  # admission, ownership, politeness, gate-through-pump, reconcile, no extra deps
python3 test_sec.py           # blocklist signatures, rollback, fail-closed; needs: pip install cryptography
python3 test_governance.py    # maintainer rotation and the proposal lifecycle; needs cryptography
python3 test_records.py       # signed-record verify, expiry, TTL caps, per-origin limiting; needs cryptography
python3 sam_check.py          # SAM transport against a LIVE I2P router (enable the SAM bridge first)
```
