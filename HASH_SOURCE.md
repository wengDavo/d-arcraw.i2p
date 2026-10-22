# Approaching an authoritative hash source

The gate's floor is only as strong as the hashes behind it, and the authoritative
CSAM hash sets are deliberately not open. An open set would let abusers test their
material against it to find what evades detection, so the sets are held by a few
organizations and licensed under strict terms that forbid redistribution. A
decentralized netDb that shipped the raw list to every anonymous node is exactly
what those terms prohibit, and rightly so. This document is how to get a real floor
anyway, and what it will cost.

## The reframe: you need verdicts, not the set

The mistake is assuming the gate on each node needs the list. It does not. It needs
to know, for a specific piece of content, whether that content is known-illegal.
That is a verdict, and a verdict about one hash reveals one hash, not the corpus.

So the model is an oracle, not a download. A holder of an authoritative matcher
answers "is this hash in your set" without exposing the set. Confirmed-bad hashes
then become ordinary signed entries on the community blocklist that `blocklist.py`
already distributes and `governance.py` already governs. The licensed set never
leaves the holder. What propagates across the netDb is the list of hashes that have
been confirmed bad, which grows organically as the crawler encounters them. This
fits the architecture you already have: the oracle is just a maintainer whose
co-signature on a blocklist addition carries the weight of an authoritative match.

The cost of the oracle model is that it reintroduces a trusted party at the
attestation layer, and that querying it leaks which hashes you are checking.
Mitigate with a threshold of independent oracles, by submitting only hashes and
never content, by caching signed verdicts so you query once per hash, and by
batching. It is not perfectly decentralized, and pretending otherwise would be
dishonest. It is the price of a real floor.

## Candidate holders

These are the organizations that actually hold authoritative sets or run matching
services. Terms change, so treat this as where to start, not as settled fact, and
confirm current terms with each directly.

- **Project Arachnid, Canadian Centre for Child Protection.** The most accessible
  for a platform. It runs a detection service and exposes an API for services to
  match and remove CSAM, with published best practices for reducing availability.
  Start here. https://projectarachnid.ca/ and https://projectarachnid.ca/en/best-practices/
- **Internet Watch Foundation Hash List (UK).** A hash list offered to members
  under membership terms. https://iwf.org.uk/our-services/hash-list
- **NCMEC (US).** Operates the CyberTipline and industry hash sharing for registered
  electronic service providers. Being a provider also brings US reporting duties,
  noted below.
- **The Tech Coalition's Lantern.** Cross-platform signal sharing among member
  companies. Membership-gated. https://technologycoalition.org/
- **Thorn (Safer) and Microsoft PhotoDNA.** Commercial and licensed matching
  products. PhotoDNA vetting was already the blocker you hit on Jaysden.

## The obstacles, stated plainly

The technical path is the easy part. The hard parts are human and legal, and they
may be fatal to a partnership, so go in clear-eyed.

Association risk is the big one. These are child-protection organizations. A project
branded as "free speech absolutist," that crawls and stores shocking content on an
anonymity network, is close to the opposite of the counterparties they usually work
with. Many will decline on sight, regardless of the floor you have built. To have
any chance, the floor and the governance have to be the first thing they see, not a
footnote, and you should expect to rethink the public framing. The honest version of
the pitch is that D'Arcraw's purpose includes keeping this specific content off a
network where it otherwise spreads unchecked, and that the hard floor is
deterministic, non-negotiable, and already built. That is true, and it is the only
framing that has a chance.

Legal exposure is the other. In the US, once a provider has knowledge of CSAM it has
mandatory CyberTipline reporting obligations, and an I2P netDb operator may acquire
exactly that knowledge by running the gate. Handling these hashes, running a matcher,
and operating nodes all sit in regulated territory that varies by jurisdiction and
by who the node operators are. This needs counsel before any public node runs, not
after. The maintainers who would hold a matcher almost certainly need to be an
organization with standing to possess it, not anonymous individuals.

## A concrete sequence

1. Make the floor and governance non-negotiable and visible, which is done:
   deterministic gate, threshold-signed versioned blocklist, a published governance
   process with an illegal-not-offensive review bar.
2. Get counsel on reporting obligations and on who may lawfully hold or query a
   matcher in the operators' jurisdictions. Do this before step 3.
3. Approach Project Arachnid first, then IWF, about the verdict model: the holder
   matches, the project receives signed per-hash verdicts, the set never leaves the
   holder. Lead with the floor, not the network.
4. If a holder agrees, seat them on the maintainer set as an attestation maintainer
   whose co-signature promotes a confirmed hash. The oracle becomes governance.
5. If no holder will engage, operate with the community blocklist plus perceptual
   hashing plus fail-closed media, and say so explicitly in the project docs: the
   CSAM floor is best-effort without an authoritative source, which materially
   limits what the project can responsibly deploy and how widely.

## The honest bottom line

Without a partner, the floor relies on a community list and perceptual matching,
which catches known and near-known material but cannot be as complete as a licensed
set, by the deliberate design of the whole field. That is a real limit on what a
purely decentralized, no-partner D'Arcraw can responsibly be. The oracle-via-partner
model is the path to a strong floor, and it trades a little decentralization at the
attestation layer for a real one. Whether a child-protection organization will work
with a project like this is the open question that decides how far D'Arcraw can go,
and it is a question for those organizations and for counsel, not one the code can
answer.
