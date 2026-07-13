# 🐧 penguin — Recon Automation Framework

A modular, opinionated recon automation layer implementing a layered pipeline
`passive → resolve → probe → enrich → content discovery → diff/alert`. It
stores all state as files, diffs every run against the previous one, and
feeds discoveries back into the pipeline (self-learning wordlists). Proxies
are refreshed and applied on **every run**.

> ⚠️ Only target assets you are **authorized** to test. Respect scope, laws and
> program rules.

## Architecture

```
config/            config.yaml · targets.txt · templates/ (custom nuclei)
scripts/           install.sh (WSL) · install.ps1 · recon.sh/.ps1 · cron.example
wordlists/         learned.txt (self-learning) + downloaded lists
results/<target>/<run_id>/   per-run artifacts + history/ for diffs
results/proxies/   proxies_raw.txt · proxies_valid.txt
reports/<target>/  <date>_report.md + .json
penguin/           python package (config, runner, state, proxies, notify,
                   wordlists, tools/*, pipelines/*, cli)
```

Pipeline blocks (mirror the guide):

| Block | Module | Covers |
|---|---|---|
| 0 | `pipelines/master.py` | orchestration, accumulation, diff, notify, report |
| 1 | `pipelines/block1_infra.py` | ASN/BGP, 3-stage subdomain enum, resolve, IPv6 |
| 2 | `pipelines/block2_web.py` | tech fingerprint, JS analysis, fuzzing, API recon |
| 3 | `pipelines/block3_cloud_db.py` | open DB scan, bucket discovery |
| 4 | `pipelines/block4_elite.py` | origin IP / Cloudflare bypass, CI/CD+Git, custom Nuclei |

## Install

penguin manages its own Python virtualenv automatically: the **first** `run`
creates `.venv/`, installs `requirements.txt` into it, and re-executes inside
that venv. Every later run re-enters the same venv (deps are not reinstalled
unless the marker is missing). No manual `pip install` / `venv` steps needed.

```bash
# WSL / Linux (installs Go + all tools + wordlists)
bash scripts/install.sh

# Windows (best-effort: wordlists + pip deps; run Go tools under WSL)
pwsh scripts/install.ps1

# verify what's present
python -m penguin install-check
```

Virtualenv control:

```bash
python -m penguin run --no-venv          # skip .venv, use current interpreter
python -m penguin run --reinstall-venv   # force reinstall deps into .venv
PENGUIN_NO_VENV=1 python -m penguin run  # same as --no-venv
```

## Usage

Use the root launcher (it `cd`s to the project root so the venv bootstrap and
package import work from any directory):

```bash
# single target
./penguin run --target example.com        # WSL/Linux
pwsh ./penguin.ps1 run --target example.com   # Windows PowerShell
penguin.bat run --target example.com          # Windows cmd

# all targets from config/targets.txt
./penguin run

# continuous recon (diff + notify every 6h)
./penguin continuous --interval 6h

# refresh proxy pool only
./penguin proxies

# validate config + diff engine + proxies
./penguin self-test
```

(You can also run `python -m penguin` directly from the project root.)

## Proxies (automatic every run)

On every invocation penguin fetches both free proxy lists, dedups, validates
them against a benign endpoint, and applies a working proxy to every
proxy-capable tool (`httpx`, `nuclei`, `puredns`, `subfinder`, `amass`, `dnsx`,
`katana`, `gau`, `ffuf`). Configure in `config.yaml → proxies`:

```yaml
proxies:
  enabled: true
  proxifly: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt"
  iplocate: "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt"
  validate: true
  protocol_preference: "http"   # http | socks5 | any
  rotate: "roundrobin"          # roundrobin | random | fastest
```

## Paid / OSINT tools — opt-in

All paid integrations are **disabled by default**. Enable per service and
supply the API key via environment variable (never stored in config):

```bash
export SHODAN_KEY=... CENSYS_ID=... CENSYS_SECRET=... SECURITYTRAILS_KEY=... CHAOS_KEY=...
```

| Service | Config key | Env |
|---|---|---|
| Shodan | `paid.shodan` | `SHODAN_KEY` |
| Censys | `paid.censys` | `CENSYS_ID` / `CENSYS_SECRET` |
| SecurityTrails | `paid.securitytrails` | `SECURITYTRAILS_KEY` |
| Chaos (PD) | `paid.chaos` | `CHAOS_KEY` |
| GrayhatWarfare | `paid.grayhat` | `GRAYHAT_KEY` |
| Netlas | `paid.netlas` | `NETLAS_KEY` |
| FOFA | `paid.fofa` | `FOFA_KEY` |

Free equivalents (crt.sh, BGPView, viewdns, public passive DNS) are always used
when the paid path is off.

## Notifications (optional)

```yaml
notify:
  enabled: true
  provider: slack            # slack | discord | telegram
  webhook_env: PENGUIN_NOTIFY_WEBHOOK
  notify_on: ["new_subdomains", "critical_findings"]
```

## Resilience & state

- `runner.py` wraps every tool with exponential-backoff retries; missing
  binaries are skipped non-fatally so partially-installed setups still run.
- `state.py` dedups (anew-style) into per-target accumulators and diffs each
  run against `history/` — new assets trigger alerts.
- `wordlists.py` extracts nouns from discovered endpoints/subdomains and feeds
  them back into the next run's brute/permutation/param fuzzing.

## Custom Nuclei templates

`config/templates/` ships the four templates from guide §4.4 (exposed-git,
authenticated-idor-check, custom-debug-endpoint, dsl-sqli). Add your own and
they are picked up automatically.

## License

MIT — see [LICENSE](LICENSE). For authorized security testing and learning
only; see [SECURITY.md](SECURITY.md) for scope/legal notes and how to report
vulnerabilities in penguin itself. See [CONTRIBUTING.md](CONTRIBUTING.md) to
contribute.
