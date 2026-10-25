# Blocklist governance

The content gate is only as strong as the list it enforces, and in a decentralized
network with no central authority, who controls that list is the hardest question.
`governance.hpp` is the trust machinery. This document is how people operate it.

## Trust model

Trust is spread across a maintainer set under an M-of-N threshold. No single key can
change the list. The genesis set is pinned in the client, the way a browser ships root
certificates, and every later version of the set is signed by a threshold of the
previous version. Nodes follow that signed chain forward, so the set can rotate without
anyone being a permanent authority.

Two things are signed and versioned: the maintainer set itself, and the blocklist. A
node accepts a new set version only if a threshold of the current members signed it,
and accepts a new blocklist version only if a threshold of the current set signed it
and the version number went up. Versions never go backward, which is what stops a
rollback attack that serves an old list missing recent hashes.

## Roles

- **Maintainers** hold signing keys. They review proposals and sign set rotations and
  blocklist versions. The threshold is a number of maintainers, not a number of
  signatures from one person.
- **Reporters** can submit proposals but cannot sign them in. Anyone can be a reporter.
  A proposal only takes effect when a threshold of maintainers co-signs.

Keep maintainers independent: different people, ideally different jurisdictions and
organizations, keys on hardware tokens and offline where possible. The point of M-of-N
is defeated if one person holds several keys or they all sit on one machine.

## What qualifies for the list

The floor is provably illegal content, and the anchor case is CSAM. This is not an
editorial board. Shocking, offensive, tasteless, and otherwise lawful-but-awful content
does not go on the list, because carrying that content is the point of the project. A
proposal that amounts to "this is gross" is rejected. A proposal is in scope only when
the content is illegal, and the review looks for that, with an evidence reference
attached to the proposal.

## The lifecycle of a hash

1. **Propose.** A reporter or maintainer builds a proposal (`make_proposal`) with the
   action (add or remove), the hashes, a category, and an evidence reference. The
   proposal is signed by its proposer.
2. **Review.** Maintainers examine the evidence against the illegal-not-offensive bar.
   This step is manual.
3. **Co-sign.** A maintainer who agrees co-signs (`cosign_proposal`). When a threshold
   of distinct maintainers has signed, the proposal is accepted (`accepted`).
4. **Promote.** Accepted proposals are folded into a new blocklist version (`promote`),
   signed by a threshold of maintainers. This is the artifact nodes enforce.
5. **Distribute.** The signed blocklist rides the netDb. Nodes verify the signatures
   and the forward version, then arm or update their gate. Verification is by signature,
   not by the gate, so a fresh node can fetch and verify the list before it is armed and
   before it can store anything.

Removal runs the identical path with action "remove", which is how a false positive (a
lawful item wrongly blocked) is lifted. Treat false-positive removals with the same
seriousness as additions, because an over-broad list silently censors the exact speech
the project exists to carry.

## Key rotation

Routine rotation and compromise response use the same mechanism: publish a new
maintainer-set version, signed by a threshold of the current set, that adds or removes
member keys (`make_maintainer_set_doc` then `sign_set_doc`, applied with
`MaintainerChain::apply_rotation`).

- **Routine:** rotate keys on a schedule, add new maintainers, retire old ones.
- **Compromise:** if a key is exposed, the remaining maintainers immediately publish a
  new set version removing it. As long as a threshold of uncompromised keys remains,
  control is retained.

The hard limit: if a threshold of keys is lost or compromised at once, the chain cannot
advance and the set cannot heal itself. Mitigate by making N large enough that a
threshold is hard to capture, holding keys independently, and keeping some maintainers
cold. There is no central party to fall back on. That is the cost of being
decentralized.

## The unsolved dependency

The machinery above is only as good as the hashes that enter it, and this is the
weakest point in the entire project. Authoritative CSAM hash sets (PhotoDNA, NCMEC,
IWF) generally cannot be redistributed to arbitrary anonymous nodes, which is exactly
what a decentralized netDb is. So the realistic floor is a community blocklist
maintained by this set, seeded from whatever authoritative or open sources the
maintainers can lawfully obtain and attest to. That is less complete than a licensed
set, and it depends on the integrity and diligence of the maintainers.

Two consequences. First, no blocklist catches everything, so the gate reduces but does
not eliminate the presence of illegal content. The design goal is that the network
never knowingly stores or serves it, not that detection is perfect. Second, if the
project can partner with an organization able to hold a licensed set and attest to
hashes without redistributing the set itself, that materially strengthens the floor and
is worth pursuing before any real deployment.

## Transparency

Set versions, proposals, and blocklist versions are public and auditable. Anyone can
verify the signature chain and see what is blocked at the level of hashes and
categories, without the blocked content itself being exposed. A node operator can
inspect exactly which signed list their gate is enforcing and who signed it.
