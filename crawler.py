"""
Self-updating crawl loop for D'Arcraw.

A linear contextual bandit orders the crawl frontier. Each fetch produces a
self-supervised reward (did it resolve, did it carry content, plus whatever
origin or content signals you wire in), and the policy updates online from that
reward. Compute is bounded per tick, so the loop runs in real time on small
hardware and degrades gracefully instead of stalling.

The content gate runs at ingestion, before anything is published to the netDb,
and is the same fixed gate the netDb enforces at store-admission. It is never
part of the learned policy.

Poisoning resistance has two parts: per-source influence is capped per time
window, so no single source can shove the policy, and a frozen holdout
checkpoints the best known weights and rolls the policy back if it drifts past a
margin. Seed the holdout from trusted examples; a holdout fed only by the live
stream can itself be poisoned.
"""
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class Candidate:
    url: str
    source: str          # which discovery source proposed this address
    features: list        # feature vector (sketch features, link stats, uptime, ...)


@dataclass
class Outcome:
    features: list
    reward: float
    source: str


def dot(w, x):
    return sum(wi * xi for wi, xi in zip(w, x))


class LinearPolicy:
    def __init__(self, dim, lr=0.05):
        self.w = [0.0] * dim
        self.lr = lr

    def score(self, x):
        return dot(self.w, x)

    def update(self, x, reward, scale=1.0):
        err = reward - self.score(x)
        for i in range(len(self.w)):
            self.w[i] += self.lr * err * x[i] * scale
        return err


class Crawler:
    def __init__(self, node, gate, fetcher, dim,
                 epsilon=0.15, tick_budget=32,
                 per_source_cap=4.0, holdout_size=256, drift_margin=1.5,
                 classifier=None):
        self.node = node
        self.gate = gate              # SAME fixed gate instance the netDb uses
        self.fetcher = fetcher        # fetch(url) -> (content:bytes, media:list[bytes]) or None
        self.classifier = classifier  # classify(content) -> Origin, or None
        self.policy = LinearPolicy(dim)
        self.epsilon = epsilon
        self.tick_budget = tick_budget
        self.per_source_cap = per_source_cap
        self.drift_margin = drift_margin
        self.frontier = []
        self.replay = deque(maxlen=5000)
        self.holdout = deque(maxlen=holdout_size)
        self.best_w = list(self.policy.w)
        self.best_loss = float("inf")
        self._spend = defaultdict(float)
        self._window = time.time()

    def submit(self, cand: Candidate):
        self.frontier.append(cand)

    def _pick(self):
        if not self.frontier:
            return None
        if random.random() < self.epsilon:                 # explore
            i = random.randrange(len(self.frontier))
        else:                                               # exploit
            i = max(range(len(self.frontier)),
                    key=lambda j: self.policy.score(self.frontier[j].features))
        return self.frontier.pop(i)

    @staticmethod
    def _reward(fetched, content, origin=None):
        if fetched is None:
            return 0.0            # did not resolve
        r = 1.0                   # alive
        if content:
            r += 0.5              # carried content
        if origin is not None:   # prefer native; derivatives are redundant with clearnet
            r += {"native": 1.0, "multi-homed": 0.5, "unknown": 0.2}.get(origin.type, 0.0)
        return r

    def _source_scale(self, source):
        now = time.time()
        if now - self._window > 60:
            self._spend.clear()
            self._window = now
        if self._spend[source] >= self.per_source_cap:
            return 0.0            # this source is out of influence this window
        self._spend[source] += 1.0
        return 1.0

    def tick(self):
        for _ in range(self.tick_budget):
            cand = self._pick()
            if cand is None:
                break
            fetched = self.fetcher(cand.url)
            content, media = fetched if fetched else (b"", [])
            origin = None
            if content:
                if not self.gate.check(content, media).allowed:
                    continue       # gated at ingestion: not published, not learned from
                if self.classifier is not None:
                    origin = self.classifier(content, cand.url)
                self.node.publish(content, media)
            reward = self._reward(fetched, content, origin)
            self.policy.update(cand.features, reward, self._source_scale(cand.source))
            out = Outcome(cand.features, reward, cand.source)
            self.replay.append(out)
            if random.random() < 0.1:
                self.holdout.append(out)

    def holdout_loss(self, policy=None):
        p = policy or self.policy
        if not self.holdout:
            return 0.0
        return sum((o.reward - p.score(o.features)) ** 2 for o in self.holdout) / len(self.holdout)

    def consolidate(self):
        """Checkpoint good weights, roll back drift. Call periodically between ticks."""
        loss = self.holdout_loss()
        if loss < self.best_loss:
            self.best_loss = loss
            self.best_w = list(self.policy.w)
        elif loss > self.best_loss * self.drift_margin:
            self.policy.w = list(self.best_w)      # revert a drifting / poisoned policy
