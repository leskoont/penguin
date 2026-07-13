"""penguin - self-learning wordlist manager.

Implements the guide's principle that every discovered artifact is fed back
into the pipeline. Nouns extracted from endpoints / subdomains / params are
accumulated into ``wordlists/learned.txt`` and re-used on the next run for
brute-forcing, permutations and parameter fuzzing.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from .config import Config

logger = logging.getLogger("penguin.wordlists")

_NOUN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")
_STOP = {
    "http", "https", "www", "api", "the", "and", "com", "html", "php", "json",
    "admin", "user", "users", "index", "page", "data", "src", "static", "assets",
    "app", "main", "login", "logout", "get", "post", "the", "for", "with", "this",
}


class WordlistManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.learned_file = cfg.path(cfg.general.wordlists_dir, "learned.txt")
        self.learned_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.learned_file.exists():
            self.learned_file.write_text("", encoding="utf-8")

    def extract_nouns(self, text: str) -> set[str]:
        out = set()
        for tok in _NOUN_RE.findall(text):
            t = tok.lower().strip("-_")
            if len(t) >= 3 and t not in _STOP:
                out.add(t)
        return out

    def learn_from_endpoints(self, endpoints: list[str]) -> int:
        words: set[str] = set()
        for ep in endpoints:
            # strip scheme/host, keep path segments
            path = re.sub(r"^https?://[^/]+", "", ep)
            for seg in path.split("/"):
                seg = seg.split("?")[0]
                if seg:
                    words |= self.extract_nouns(seg)
            # also look at query param names
            if "?" in ep:
                for kv in ep.split("?")[1].split("&"):
                    if "=" in kv:
                        words |= self.extract_nouns(kv.split("=")[0])
        return self.add(words)

    def add(self, words: set[str]) -> int:
        existing = self._read()
        new = {w for w in words if w not in existing}
        if new:
            with open(self.learned_file, "a", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(new)) + "\n")
            logger.info("[wordlists] learned %d new tokens -> %s", len(new), self.learned_file)
        return len(new)

    def learned(self) -> list[str]:
        return self._read()

    def _read(self) -> set[str]:
        if not self.learned_file.exists():
            return set()
        return {x.strip() for x in self.learned_file.read_text(encoding="utf-8").splitlines() if x.strip()}
