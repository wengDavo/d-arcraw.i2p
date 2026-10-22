from fingerprint import content_simhash, hamming, SimHashIndex
from origin import TwoStageClassifier

page = b"<html><body>" + b" ".join(b"word%d" % (i % 50) for i in range(400)) + b"</body></html>"
page_edit = page.replace(b"word1 ", b"word1x ", 3)                       # a few tokens changed
page_diff = b"<html>" + b" ".join(b"other%d" % i for i in range(200)) + b"</html>"

h1, h2, h3 = content_simhash(page), content_simhash(page_edit), content_simhash(page_diff)
print("near-dup small hamming:", hamming(h1, h2) <= 3)
print("unrelated large hamming:", hamming(h1, h3) > 10)

idx = SimHashIndex(threshold=3)
idx.add(h1, "a.b32.i2p")
print("index finds near-dup:", any(k == "a.b32.i2p" for k, d in idx.query(h2)))
print("index ignores unrelated:", idx.query(h3) == [])

clf = TwoStageClassifier()
o1 = clf(page, "i2p://a.b32.i2p/")          # first sighting
o2 = clf(page_edit, "i2p://b.b32.i2p/")     # same content, different address
print("first sighting not a mirror:", o1.type != "mirror")
print("second address flagged mirror:", o2.type == "mirror")
print("re-crawl of same address not self-flagged:", clf(page, "i2p://a.b32.i2p/").type != "mirror")
