import governance as g
from blocklist import verify_blocklist
from gate import sha256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ks = [Ed25519PrivateKey.generate() for _ in range(4)]
pub = [k.public_key() for k in ks]

genesis = g.make_maintainer_set_doc(
    1, [(pub[0], "maintainer"), (pub[1], "maintainer"), (pub[2], "maintainer")], threshold=2)
chain = g.MaintainerChain(genesis)
print("genesis pinned at version 1:", chain.current["version"] == 1)

# rotate to v2, add member 4, raise threshold to 3; signed by 2 of the current 3
v2 = g.make_maintainer_set_doc(
    2, [(pub[0], "m"), (pub[1], "m"), (pub[2], "m"), (pub[3], "m")], threshold=3)
print("rotation signed by 2-of-3 current accepted:",
      chain.apply_rotation(g.sign_doc(v2, [ks[0], ks[1]])) and chain.current["version"] == 2)

# next rotation needs threshold of the CURRENT set (now 3); 2 sigs must fail
v3 = g.make_maintainer_set_doc(3, [(pub[0], "m"), (pub[1], "m"), (pub[3], "m")], threshold=2)
try:
    chain.apply_rotation(g.sign_doc(v3, [ks[0], ks[1]]))
    print("under-signed rotation accepted: FAIL")
except ValueError:
    print("under-signed rotation rejected:", True)

# proposal lifecycle against current set (v2, threshold 3)
mset = chain.maintainer_set()
bad = sha256(b"provably-illegal-item")
prop = g.make_proposal("add", [bad], "csam", "evidence#123", ks[0])
prop = g.cosign_proposal(prop, ks[1])
print("proposal below threshold not accepted:", not g.accepted(prop, mset))
prop = g.cosign_proposal(prop, ks[2])
print("proposal at threshold accepted:", g.accepted(prop, mset))

blob, exact, phash, applied = g.promote(set(), [], [prop], mset, [ks[0], ks[1], ks[2]], next_version=5)
ver, _, ex2, _ = verify_blocklist(blob, mset)
print("promoted blocklist carries the hash:", bad in ex2 and ver == 5)

# remove proposal lifts a false positive
rem = g.make_proposal("remove", [bad], "false-positive", "evidence#124", ks[0])
rem = g.cosign_proposal(rem, ks[1])
rem = g.cosign_proposal(rem, ks[2])
_, exact2, _, _ = g.promote(exact, phash, [rem], mset, [ks[0], ks[1], ks[2]], next_version=6)
print("remove proposal lifts the hash:", bad not in exact2)
