"""penguin - self-learning wordlist manager.

Implements the guide's principle that every discovered artifact is fed back
into the pipeline. Nouns extracted from endpoints / subdomains / params are
accumulated into ``wordlists/learned.txt`` and re-used on the next run for
brute-forcing, permutations and parameter fuzzing.
"""
from __future__ import annotations

import logging
import re
import tempfile
from pathlib import Path

from .config import Config

logger = logging.getLogger("penguin.wordlists")

_NOUN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")
# #84: removed duplicate "the" entry
_STOP = {
    "http", "https", "www", "api", "the", "and", "com", "html", "php", "json",
    "admin", "user", "users", "index", "page", "data", "src", "static", "assets",
    "app", "main", "login", "logout", "get", "post", "for", "with", "this",
}


class WordlistManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.learned_file = cfg.path(cfg.general.wordlists_dir, "learned.txt")
        self.learned_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.learned_file.exists():
            self.learned_file.write_text("", encoding="utf-8")
        # #84: cache learned words in memory to avoid O(n) re-read on every add()
        self._learned_cache = self._read()

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
        # #84: use cached learned words instead of re-reading on every add()
        new = {w for w in words if w not in self._learned_cache}
        if new:
            # Atomic write: read-dedupe-temp-rename to avoid RMW race
            all_words = self._learned_cache | new
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self.learned_file.parent,
                encoding="utf-8",
                delete=False,
                suffix=".tmp"
            ) as tmp:
                tmp.write("\n".join(sorted(all_words)) + "\n")
                tmp_path = Path(tmp.name)
            # Atomic rename on Windows and POSIX
            tmp_path.replace(self.learned_file)
            # Flush cache after successful write
            self._learned_cache = all_words
            logger.info("[wordlists] learned %d new tokens -> %s", len(new), self.learned_file)
        return len(new)

    def learned(self) -> list[str]:
        # #84: return from cache instead of re-reading
        return list(self._learned_cache)

    def _read(self) -> set[str]:
        if not self.learned_file.exists():
            return set()
        return {x.strip() for x in self.learned_file.read_text(encoding="utf-8").splitlines() if x.strip()}
