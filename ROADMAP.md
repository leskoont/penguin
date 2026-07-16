# 🐧 penguin — Development Roadmap

A prioritized, detailed plan for hardening, improving and extending the
codebase. Derived from a full read of `penguin/` (config, runner, state,
proxies, wordlists, notify, venv, `tools/*`, `pipelines/*`, `ui/*`) on
2026-07-14.

The plan is organized into **workstreams** (WS), each with concrete tasks,
rationale, the files touched, and a rough effort tag (S/M/L). Priorities:

- **P0** — foundational; unblocks everything else and stops silent regressions.
- **P1** — high-value correctness/perf/feature work.
- **P2** — expansion and polish.

Every task is scoped to land as its **own commit** (per project convention),
each leaving the tree in a working state (`python -m penguin --help` +
`self-test` green).

---

## 0. Current-state assessment

**Strengths (keep and build on):**

- Clean, single-responsibility modules; pipelines mirror the recon "blocks".
- `runner.run` is genuinely resilient: retries, exponential backoff,
  `is_permanent()` fail-fast, missing-binary skips, ANSI-stripped errors.
- `state.py` gives file-based state + anew-style dedup + a real diff engine.
- Proxy pool with concurrent validation, protocol preference and rotation.
- Self-bootstrapping venv + toolchain; recently modernized Typer/Rich UI.

**Structural gaps (the roadmap targets these):**

| # | Gap | Impact |
|---|-----|--------|
| 1 | No tests, no CI, no packaging | Every tool-CLI-drift fix risks silent regression; history shows this is the dominant failure mode |
| 2 | Fully sequential execution | Wall-clock dominated by serial I/O waits; largest untapped speedup |
| 3 | Self-learning loop half-wired | `learned.txt` written but never read back into brute/perms |
| 4 | No per-run tool-outcome ledger | "Why did results drop?" needs manual tmp-log reading (the degradation saga) |
| 5 | Counts-only reports, no findings model | No typed, triage-ready output of *what* was found |
| 6 | Free-proxy churn re-validated every run | ~3 min startup tax; proxies die mid-run anyway |
| 7 | `notify.py` bugs | Telegram payload malformed; `critical_findings` never fires |
| 8 | No takeover detection / resume / retention pruning | Missing high-value recon signal; disk growth; no crash recovery |

---

## WS1 — Reliability foundation: tests, CI, packaging  **(P0)**

The single highest-leverage investment. The git log is a sequence of
"fix: correct <tool> flags/output parsing" commits — exactly the class of bug
a test suite prevents from recurring.

- **1.1 (M) Add `pyproject.toml`** — PEP 621 metadata, `console_scripts`
  entry point (`penguin = "penguin.cli:main"`), pinned dep ranges, dev extras
  (`pytest`, `pytest-cov`, `ruff`, `mypy`). Keeps `requirements.txt` working;
  adds `pip install -e .[dev]`. *Files:* new `pyproject.toml`.
- **1.2 (M) Unit tests for pure logic** (no network, no binaries):
  - `state.py` — dedup/anew, diff (new/removed), archive round-trip.
  - `config.py` — YAML overlay, env-key gating, `load_targets` parsing of
    every type prefix + bare domain + comment lines.
  - `wordlists.py` — noun extraction, stop-word filter, `learn_from_endpoints`.
  - `runner.is_permanent` — the whole `_PERMANENT_ERR_SUBSTRINGS` matrix +
    curl-exit-6 special case.
  - `block1_infra._scope_regex` / `_extract_scoped` — the amass graph-noise
    filter, incl. the `relay.hantik.ru`-buried-in-graph recovery case and
    out-of-scope rejection (these were literal production bugs; lock them in).
  - `proxies._parse` — `ip:port:proto` vs `ip:port`, protocol upgrade rule.
  *Files:* new `tests/`.
- **1.3 (M) Wrapper contract tests via a fake runner** — monkeypatch
  `tools._base.run` to return canned `RunResult`s and assert each wrapper
  builds the *correct argv* and parses output correctly. This is the real
  regression net for tool-flag drift (e.g. would have caught `amass -src`,
  `katana -js`, `nuclei technologies/`, `gotator` no-`-o`). *Files:*
  `tests/test_tools_*.py`.
- **1.4 (S) GitHub Actions CI** — matrix on py3.11/3.12, run `ruff check`,
  `mypy penguin`, `pytest --cov`, and a smoke `python -m penguin --no-venv
  install-check`. *Files:* new `.github/workflows/ci.yml`.
- **1.5 (S) Pre-commit config** — ruff + ruff-format + a check that every new
  `tools/*` wrapper has a matching test. *Files:* `.pre-commit-config.yaml`.

**Exit criteria:** `pytest` green in CI; a deliberately-broken wrapper argv
fails a test.

---

## WS2 — Observability & run diagnostics  **(P0/P1)**

Directly addresses gap #4 and the recorded degradation memory: make "why did
this run produce N results" answerable from a machine-readable artifact, not
by grepping raw tool logs.

- **2.1 (M) Per-run tool-outcome ledger** — have `ToolContext.execute` record
  every invocation `{tool, argv_redacted, returncode, attempts, duration,
  outcome: ok|timeout|permanent|skipped|empty, bytes_out}` into a
  `run_dir/_tool_ledger.jsonl`. One append per call; zero behavior change to
  the tools themselves. *Files:* `tools/_base.py`, `state.py` (ledger sink).
- **2.2 (S) Run manifest** — `run_dir/_manifest.json` capturing config
  snapshot (redacted), enabled stages, proxy pool size at start, tool
  presence map, penguin git SHA, start/end timestamps, and rolled-up ledger
  stats (n_ok / n_timeout / n_skipped per tool). *Files:* `master.py`,
  `report.py`.
- **2.3 (S) "Empty-output" signal** — several wrappers already special-case
  suspiciously-empty httpx output; generalize a `expected_output` check so a
  tool that exits 0 but writes nothing is logged as `outcome: empty` in the
  ledger (this is how crt.sh/subfinder silently contributed zero). *Files:*
  `tools/_base.py`.
- **2.4 (S) `penguin diagnose <run_dir>`** — new subcommand that reads the
  ledger + manifest and prints a Rich table: per-source subdomain
  contribution, tools that produced zero, tools that timed out, proxy death
  rate. Turns the degradation-investigation workflow into one command.
  *Files:* `cli.py`, new `penguin/diagnostics.py`.
- **2.5 (S) Structured run summary log line** — emit a single machine-parseable
  `RUN_SUMMARY {json}` line at end so continuous-mode logs are greppable.

**Exit criteria:** after a run, `penguin diagnose <run_dir>` explains the
subdomain count by source with no manual log reading.

---

## WS3 — Concurrency & performance  **(P1)**

Gap #2. The workload is almost entirely network-I/O wait; serial execution is
the dominant wall-clock cost.

- **3.1 (M) Bounded concurrency primitive** — add a `runner.run_many(specs,
  max_workers)` thread-pool helper (mirrors the proven pattern already in
  `proxies.validate`: `ThreadPoolExecutor` + short-poll `wait()` so Ctrl+C
  works on Windows). Central, tested, reused everywhere below. *Files:*
  `runner.py`, tests.
- **3.2 (M) Parallelize per-host loops** — block2's JS-download loop, ffuf/
  ferox/arjun/x8 per-host loop, block4's per-subdomain git-dump loop, block3's
  per-candidate bucket probes. Convert `for h in hosts:` to `run_many` with a
  configurable `general.max_parallel` (default e.g. 10). Biggest single win
  (block2 JS download was observed at 30+ min serially). *Files:*
  `block2_web.py`, `block3_cloud_db.py`, `block4_elite.py`, `config.py`.
- **3.3 (M) Parallelize independent passive sources** — block1 stage-1 fires
  7 independent passive tools per domain serially; run them concurrently.
  *Files:* `block1_infra.py`.
- **3.4 (S) Optional inter-block parallelism** — blocks 3 (cloud/db) and 4
  (git/origin) don't strictly depend on block 2 completing; allow an
  opt-in DAG so they overlap. Guard behind config; keep default sequential
  for reproducibility. *Files:* `master.py`.
- **3.5 (S) Global rate-limit awareness** — `general.rate_limit` exists in
  config but is only passed to nuclei. With new parallelism, thread it into a
  shared token bucket so concurrency doesn't blow past program-defined caps.
  *Files:* `runner.py`, `_base.py`.

**Exit criteria:** a representative single-domain run's wall-clock drops
materially (target: block2 no longer dominated by serial JS fetches), with
identical result sets vs the serial baseline (verified by diff).

---

## WS4 — Findings model & richer reporting  **(P1)**

Gap #5. Today `summary` is counts and `report.md` restates them. Triage needs
the actual artifacts, typed and severity-ranked.

- **4.1 (M) `Finding` dataclass + `findings.jsonl`** — `{type, severity,
  target, asset, evidence, source_tool, first_seen_run, url}`. Blocks emit
  Findings (exposed .git, open DB port, live secret, public bucket, takeover,
  new subdomain) instead of only bumping counts. *Files:* new
  `penguin/findings.py`, all four blocks, `master.py`.
- **4.2 (M) Rich Markdown + HTML report** — group findings by severity, list
  actual assets (new subdomains, secret hits w/ file+line, bucket URLs,
  open-DB host:port), embed the ledger-based "recon coverage" section from
  WS2. HTML variant self-contained for sharing. *Files:* `report.py`.
- **4.3 (S) Severity + dedup across runs** — `findings.jsonl` accumulates per
  target with `first_seen_run`, so reports can show "new this run" for *all*
  finding types, not just subdomains. *Files:* `findings.py`, `state.py`.
- **4.4 (S) Secret false-positive suppression** — an allowlist +
  entropy/format sanity gate before a secretfinder/gitleaks hit becomes a
  `critical` Finding (these tools are noisy; unverified hits erode trust).
  *Files:* `tools/secrets.py`, `findings.py`.

**Exit criteria:** report lists concrete, severity-ranked findings and a
coverage section; `findings.jsonl` is diffable across runs.

---

## WS5 — Close the self-learning loop  **(P1, small, high-value)**

Gap #3 — a genuine functional bug: the framework's headline "self-learning"
feature learns tokens it never reuses.

- **5.1 (S) Feed `learned.txt` into brute/permutations** — in `block1_infra`,
  union `WordlistManager.learned()` into the brute wordlist and the
  permutation-word seed before puredns/gotator. *Files:*
  `block1_infra.py`, `wordlists.py`.
- **5.2 (S) Feed learned tokens into param fuzzing** — same tokens seed
  arjun/x8 param discovery in block2. *Files:* `block2_web.py`.
- **5.3 (S) Cap + age learned wordlist** — prevent unbounded growth; keep
  most-recently-useful tokens (LRU or frequency-capped). *Files:*
  `wordlists.py`.

**Exit criteria:** a second run against the same target measurably reuses
tokens discovered in the first (assert via the ledger/wordlist size).

---

## WS6 — Proxy subsystem overhaul  **(P1)**

Gap #6 and the root of the whole degradation saga. Free proxies are
fundamentally unreliable; the goal is to stop paying full validation cost
every run and to survive mid-run death.

- **6.1 (M) Cross-run proxy cache with TTL** — persist validated proxies with
  a timestamp; on next run, re-test only the cached survivors first and top up
  from source, instead of re-validating thousands cold. Cuts the ~3 min
  startup tax to seconds on warm cache. *Files:* `proxies.py`, `config.py`.
- **6.2 (M) Live health tracking + eviction** — record per-proxy success/fail
  as tools use `pick()`; evict a proxy after N consecutive failures so a dead
  proxy isn't handed out repeatedly. *Files:* `proxies.py`, `_base.py`.
- **6.3 (S) Authenticated/paid proxy support** — allow a static upstream
  (env-provided `PENGUIN_PROXY_URL`, incl. user:pass) as an alternative to the
  free pool, for users who have a real proxy. *Files:* `config.py`,
  `proxies.py`.
- **6.4 (S) Per-run proxy opt-out & scope rule codified** — make "passive
  OSINT against public aggregators never proxies" a declared property per
  wrapper (not ad-hoc `proxy=False` at call sites), so it can't regress.
  *Files:* `_base.py`, `tools/*`.

**Exit criteria:** warm-cache run starts in seconds; a dead proxy is evicted
rather than re-handed; passive-source proxy policy is declarative + tested.

---

## WS7 — Resume, checkpointing & retention  **(P2)**

- **7.1 (M) Idempotent resume** — mark each block/stage complete in the run
  dir; `penguin run --resume <run_dir>` skips finished stages. Avoids
  re-running a 4-block pipeline from scratch after a crash. *Files:*
  `master.py`, `state.py`, `cli.py`.
- **7.2 (S) `results/` retention policy** — `state.archive()` copytree's the
  full run into `history/` every run; add `general.keep_runs` pruning of old
  history + optional compression. *Files:* `state.py`, `config.py`.
- **7.3 (S) Run locking** — a per-target lockfile so continuous mode + a manual
  run don't clobber each other. *Files:* `state.py`.

---

## WS8 — Functional expansion  **(P1/P2)**

New recon capability, ordered by signal-to-effort.

- **8.1 (S, P1) Subdomain-takeover detection** — a dedicated pass (nuclei
  `http/takeovers/` or `subzy`) over resolved subdomains with dangling
  CNAMEs; emit `takeover` Findings. High-value, currently absent. *Files:*
  new `tools/takeover.py`, `block1_infra.py`.
- **8.2 (S, P1) Fix + extend notifications** (gap #7): correct the Telegram
  payload (`chat_id` + `text`), and actually fire `critical_findings` for
  secrets/open-DB/exposed-git/takeover — currently only `new_subdomains`
  notifies despite config. Add per-severity routing. *Files:* `notify.py`,
  `master.py`, `findings.py`.
- **8.3 (M, P2) CORS / security-header / takeover-adjacent web checks** — a
  lightweight block2 pass for CORS misconfig and missing security headers off
  the httpx data already collected. *Files:* `block2_web.py`, new wrapper.
- **8.4 (M, P2) Optional active vuln tools** — opt-in `dalfox` (XSS on
  discovered params) and nuclei DAST profiles, gated by an explicit
  `--active` flag + config (never on by default; respect scope). *Files:*
  `block2_web.py`, config.
- **8.5 (S, P2) Paid-source enrichment wiring** — `config.paid` defines 8
  services but only a few are used; wire Shodan/Censys/SecurityTrails/Netlas
  passive enrichment behind their existing enable+key gates. *Files:*
  `tools/*`, blocks.

---

## WS9 — Config, UX & cross-platform hardening  **(P2)**

- **9.1 (S) Config schema validation** — validate `config.yaml` on load
  (unknown keys warn, wrong types error) so silent typos don't no-op. Add
  `Config.save()` for the wizard to persist choices (currently in-memory
  only). *Files:* `config.py`.
- **9.2 (S) `penguin run --dry-run`** — print the planned block/tool graph and
  target list without executing. Pairs with WS2 manifest. *Files:* `cli.py`,
  `master.py`.
- **9.3 (S) Windows-native story** — document + test what actually works on
  native Windows vs WSL; make `install-check` flag WSL-only tools (masscan,
  many Go tools) explicitly rather than just "MISSING". *Files:*
  `install.ps1`, `cli.py`, README.
- **9.4 (S) `--target` accepts multiple / file / stdin** — quality-of-life for
  ad-hoc lists without editing `targets.txt`. *Files:* `cli.py`, `ui/targets`.

---

## Suggested phasing (milestones)

**M1 — "Can't silently regress" (P0):** WS1 (tests+CI+packaging) + WS2.1–2.2
(ledger+manifest). Foundation everything else leans on.

**M2 — "Know what happened & why":** WS2.3–2.5 (diagnose command) + WS4.1–4.2
(findings model + real report) + WS5 (close learning loop) + WS8.2 (notify
fixes). Highest user-visible value per unit effort.

**M3 — "Fast & robust":** WS3 (concurrency) + WS6 (proxy overhaul) + WS7.1
(resume).

**M4 — "More signal":** WS8.1/8.3/8.4/8.5 (takeover, web checks, active/paid)
+ WS9 (config/UX/Windows) + WS7.2–7.3 (retention/locking).

---

## Cross-cutting risks & guardrails

- **Concurrency vs. rate/scope (WS3):** parallelism must respect
  `rate_limit` and program scope — land WS3.5 (shared rate limiter) alongside,
  not after, the parallel loops.
- **Behavioral parity:** WS3/WS6 changes must be validated by diffing result
  sets against the current serial/free-proxy baseline before default-on.
- **Test the bugs we already fixed:** WS1.3 must pin the exact wrappers whose
  flags drifted (amass, katana, nuclei templates, gotator/subjs/hakrawler
  stdout-only, crt.sh direct) so the recon-degradation history can't repeat.
- **Never-on-by-default for active/intrusive:** WS8.4 active scanning stays
  behind an explicit flag; scope/authorization posture unchanged.
