"""
Origin classifier (Stage 1, cheap signals) for D'Arcraw.

Classifies a fetched page as native, multi-homed, mirror, instance, proxy, or
unknown from signals already in the page. Regex-based and cheap so it runs in the
crawl tick budget on small hardware. Stage 2 content fingerprinting (SimHash) is a
heavier, separate pass and is not done here.

Privacy: a cross-network link is only a signal. Whether a clearnet identity is
recorded is governed by the netDb's disclosure rule, not by this classifier.
"""
import re
from dataclasses import dataclass, field

from fingerprint import content_simhash, SimHashIndex


@dataclass
class Origin:
    type: str
    confidence: float
    signals: list = field(default_factory=list)


_GENERATOR = re.compile(rb'<meta[^>]+name=["\']?generator["\']?[^>]+content=["\']([^"\']+)', re.I)
_CANON_A = re.compile(rb'<link[^>]+rel=["\']?(?:canonical|alternate)["\']?[^>]+href=["\']([^"\']+)', re.I)
_CANON_B = re.compile(rb'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']?(?:canonical|alternate)', re.I)
_HREF = re.compile(rb'href=["\']([^"\']+)', re.I)
_ASSET = re.compile(rb'(?:src|href)=["\'](https?://[^"\']+\.(?:png|jpe?g|gif|webp|css|js|svg|woff2?))', re.I)
_MIRROR = re.compile(rb'mirror of\s+[a-z0-9.-]+\.[a-z]{2,}', re.I)

_SOFTWARE = (b"searxng", b"mediawiki", b"lemmy", b"wordpress", b"gitea")


def _is_i2p(url: bytes) -> bool:
    return b".i2p" in url


def _is_onion(url: bytes) -> bool:
    return b".onion" in url


def _is_clearnet(url: bytes) -> bool:
    return url[:4].lower() == b"http" and not _is_i2p(url) and not _is_onion(url)


def classify(content: bytes, url: str = None) -> Origin:
    # software fingerprint -> instance
    gen = _GENERATOR.search(content)
    if gen:
        g = gen.group(1).lower()
        for name in _SOFTWARE:
            if name in g:
                return Origin("instance", 0.8, ["generator:" + name.decode()])

    # explicit "mirror of X" banner
    if _MIRROR.search(content):
        return Origin("mirror", 0.75, ["mirror-banner"])

    # canonical / alternate pointing off-network -> mirror
    canon = _CANON_A.search(content) or _CANON_B.search(content)
    if canon and (_is_clearnet(canon.group(1)) or _is_onion(canon.group(1))):
        return Origin("mirror", 0.7, ["canonical-offnetwork"])

    # outbound link ratio and clearnet assets
    hrefs = _HREF.findall(content)
    if hrefs:
        clear = sum(1 for h in hrefs if _is_clearnet(h))
        i2p = sum(1 for h in hrefs if _is_i2p(h))
        total = clear + i2p
        ratio = clear / total if total else 0.0
        assets_clear = len(_ASSET.findall(content))
        if ratio > 0.6 and assets_clear > 0:
            return Origin("proxy", 0.6, [f"clearnet-link-ratio:{ratio:.2f}",
                                         f"clearnet-assets:{assets_clear}"])
        if i2p > 0 and ratio < 0.2 and assets_clear == 0:
            return Origin("native", 0.7, [f"i2p-link-ratio:{1 - ratio:.2f}"])

    return Origin("unknown", 0.3, [])


_HOST = re.compile(r"[a-z0-9.-]+\.(?:b32\.i2p|i2p|onion)", re.I)


def _address_of(url):
    if not url:
        return None
    m = _HOST.search(url)
    return m.group(0).lower() if m else url


class TwoStageClassifier:
    """Stage 1 cheap signals, then Stage 2 SimHash near-duplicate detection. A page
    whose content near-duplicates one already seen at a different address is a mirror.
    The first sighting keeps its Stage 1 label and is indexed; later copies at other
    addresses are flagged. Call as classifier(content, url)."""

    def __init__(self, index=None):
        self.index = index or SimHashIndex()
        self.first_seen = {}      # addr -> sequence number of first sighting
        self._seq = 0

    def __call__(self, content: bytes, url: str = None) -> Origin:
        addr = _address_of(url)
        if addr is None:
            return classify(content)           # no address: Stage 1 only
        h = content_simhash(content)
        age = self.first_seen.get(addr, self._seq)
        # a mirror is a near-dup of content first seen at an EARLIER address, so the
        # original keeps its label and only the later copies are flagged
        near = [(k, d) for (k, d) in self.index.query(h)
                if k != addr and self.first_seen.get(k, 1 << 62) < age]
        if addr not in self.first_seen:
            self.first_seen[addr] = self._seq
            self._seq += 1
        self.index.add(h, addr)
        if near:
            base = classify(content)
            return Origin("mirror", 0.65, base.signals + [f"near-dup:{near[0][0]}:{near[0][1]}"])
        return classify(content)
