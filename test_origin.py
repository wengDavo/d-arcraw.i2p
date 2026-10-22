from origin import classify
from crawler import Crawler

native = b'<html><a href="http://abcd.b32.i2p/x">x</a> <a href="http://ee.i2p">y</a></html>'
inst = b'<html><head><meta name="generator" content="SearXNG 2024.1"></head></html>'
mirror_c = b'<html><head><link rel="canonical" href="https://example.com/p"></head></html>'
mirror_b = b'<html>this is a mirror of example.com, enjoy</html>'
proxy = (b'<html><a href="https://a.com">a</a><a href="https://b.com">b</a>'
         b'<a href="https://c.com">c</a><img src="https://cdn.com/x.png"></html>')

print("native page -> native:", classify(native).type == "native")
print("searxng generator -> instance:", classify(inst).type == "instance")
print("canonical off-network -> mirror:", classify(mirror_c).type == "mirror")
print("mirror banner -> mirror:", classify(mirror_b).type == "mirror")
print("clearnet links + assets -> proxy:", classify(proxy).type == "proxy")


class O:
    def __init__(self, t):
        self.type = t


print("reward prefers native over mirror:",
      Crawler._reward(("x", []), b"x", O("native")) > Crawler._reward(("x", []), b"x", O("mirror")))
print("reward prefers native over unknown:",
      Crawler._reward(("x", []), b"x", O("native")) > Crawler._reward(("x", []), b"x", O("unknown")))
