import base64, json, socket, datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from gate import ContentGate, sha256
from blocklist import make_blocklist, MaintainerSet, verify_blocklist, BlocklistManager, _keyid
import sam_transport as sam

ks = [Ed25519PrivateKey.generate() for _ in range(3)]
mset = MaintainerSet({_keyid(k.public_key()): k.public_key() for k in ks}, threshold=2)
bad = sha256(b"KNOWN-ILLEGAL")
now = datetime.datetime.utcnow().isoformat()

blob1 = make_blocklist(1, now, [bad], [], ks[:2])
v, _, exact, ph = verify_blocklist(blob1, mset)
print("verify 2-of-3 threshold:", v == 1 and bad in exact)

try:
    verify_blocklist(make_blocklist(2, now, [bad], [], ks[:1]), mset)
    print("1-of-3 accepted: FAIL")
except ValueError:
    print("1-of-3 below threshold rejected:", True)

d = json.loads(blob1); d["payload_b64"] = base64.b64encode(b"tampered").decode()
try:
    verify_blocklist(json.dumps(d).encode(), mset)
    print("tamper accepted: FAIL")
except ValueError:
    print("tampered payload rejected:", True)

g = ContentGate.unarmed()
print("unarmed gate fails closed:", not g.check(b"anything").allowed)
mgr = BlocklistManager(g, mset)
print("apply v1 arms gate:", mgr.apply(blob1) and g.version == 1)
print("armed blocks listed hash:", not g.check(b"KNOWN-ILLEGAL").allowed)
print("armed allows unlisted:", g.check(b"a lawful shitpost").allowed)

blob2 = make_blocklist(2, now, [bad, sha256(b"another")], [], ks[1:3])
print("apply newer v2:", mgr.apply(blob2) and g.version == 2)
print("replay older v1 ignored:", mgr.apply(blob1) is False and g.version == 2)

raw = bytes(range(256)) + bytes(131)                       # a 387-byte fake destination
i2pb64 = base64.b64encode(raw).decode().replace("+", "-").replace("/", "~")
b32 = sam.dest_to_b32(i2pb64)
part = b32[:-len(".b32.i2p")]
print("b32 well-formed (52 chars + .b32.i2p):", b32.endswith(".b32.i2p") and len(part) == 52)

a, b = socket.socketpair()
sam._write_framed(a, b"hello frame payload")
print("framing round-trip:", sam._read_framed(b) == b"hello frame payload")
a.close(); b.close()
