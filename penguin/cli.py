"""penguin CLI: run / continuous / self-test / install-check / proxies."""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from .config import load, load_targets
from .proxies import get_pool
from .pipelines.master import run_target
from .pipelines.report import build_report

LOG = logging.getLogger("penguin")


def _setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _parse_interval(interval: str) -> int:
    interval = interval.strip()
    if interval.endswith("h"):
        return int(interval[:-1]) * 3600
    if interval.endswith("m"):
        return int(interval[:-1]) * 60
    if interval.endswith("d"):
        return int(interval[:-1]) * 86400
    return int(interval)


def cmd_run(args):
    cfg = load(args.config)
    pool = get_pool(cfg)
    if cfg.proxies.enabled:
        valid = pool.refresh(force=args.refresh_proxies)
        LOG.info("[proxies] %d valid proxies in pool", len(valid))
    targets = load_targets(args.targets)
    if args.target:
        targets = [{"type": "domain", "value": args.target}]
    if not targets:
        LOG.error("no targets; pass --target or populate config/targets.txt")
        return 1
    for t in targets:
        summary = run_target(cfg, t)
        build_report(cfg, t, summary)
    return 0


def cmd_continuous(args):
    cfg = load(args.config)
    targets = load_targets(args.targets)
    if not targets:
        LOG.error("no targets for continuous mode")
        return 1
    interval = _parse_interval(cfg.continuous.interval if not args.interval else args.interval)
    LOG.info("[continuous] every %ds across %d targets", interval, len(targets))
    while True:
        pool = get_pool(cfg)
        if cfg.proxies.enabled:
            pool.refresh(force=True)
        for t in targets:
            try:
                summary = run_target(cfg, t)
                build_report(cfg, t, summary)
            except Exception as exc:  # noqa
                LOG.exception("target %s failed: %s", t["value"], exc)
        LOG.info("[continuous] sleeping %ds", interval)
        time.sleep(interval)


def cmd_self_test(args):
    cfg = load(args.config)
    ok = True
    LOG.info("[selftest] config loaded: stages=%s", cfg.stages)
    LOG.info("[selftest] proxies.enabled=%s", cfg.proxies.enabled)
    # proxies refresh (best effort)
    pool = get_pool(cfg)
    if cfg.proxies.enabled:
        try:
            valid = pool.refresh(force=True)
            LOG.info("[selftest] proxies: %d valid", len(valid))
        except Exception as exc:  # noqa
            LOG.warning("[selftest] proxies fetch failed (network?): %s", exc)
    # diff engine smoke test
    from .state import RunState

    st = RunState(cfg, "__selftest__")
    st.add_lines("all_subdomains.txt", ["a.target.com", "b.target.com"])
    st.archive()
    st2 = RunState(cfg, "__selftest__")
    st2.add_lines("all_subdomains.txt", ["a.target.com", "b.target.com", "c.target.com"])
    diff = st2.write_diff_files("all_subdomains.txt")
    assert "c.target.com" in diff["new"], "diff engine broken"
    LOG.info("[selftest] diff engine OK: new=%s", diff["new"])
    # tool availability
    from .runner import run

    for b in ["subfinder", "httpx", "nuclei", "puredns", "dnsx", "ffuf", "amass"]:
        r = run([b, "--help"], retries=1, timeout=10)
        LOG.info("[selftest] %-12s %s", b, "present" if r.returncode != -1 else "MISSING (will skip)")
    LOG.info("[selftest] complete")
    return 0 if ok else 1


def cmd_install_check(args):
    cfg = load(args.config)
    from .runner import run

    tools = ["subfinder", "httpx", "nuclei", "amass", "puredns", "dnsx", "ffuf",
             "feroxbuster", "katana", "gau", "waybackurls", "subjs", "arjun",
             "masscan", "nmap", "naabu", "cloud_enum", "trufflehog", "gitleaks",
             "gitdumper", "github-subdomains", "kr", "grpcurl", "trivy", "dnsgen",
             "altdns", "gotator", "massdns", "rustscan", "redis-cli", "aws", "dig"]
    missing = []
    for b in tools:
        r = run([b, "--help"], retries=1, timeout=10)
        if r.returncode == -1:
            missing.append(b)
            LOG.warning("[install-check] MISSING: %s", b)
        else:
            LOG.info("[install-check] ok: %s", b)
    LOG.info("[install-check] %d/%d present, %d missing", len(tools) - len(missing), len(tools), len(missing))
    if missing:
        LOG.info("[install-check] run scripts/install.sh to install missing tools")
    return 0


def cmd_proxies(args):
    cfg = load(args.config)
    pool = get_pool(cfg)
    valid = pool.refresh(force=True)
    LOG.info("[proxies] %d valid (http/socks5) -> %s", len(valid), cfg.proxies.pool_file)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="penguin", description="penguin recon automation framework")
    p.add_argument("-c", "--config", default=None, help="path to config.yaml")
    p.add_argument("-t", "--targets", default=None, help="path to targets.txt")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-venv", action="store_true", help="do not use/create .venv")
    p.add_argument("--reinstall-venv", action="store_true", help="force reinstall venv deps")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("run", help="run full pipeline")
    r.add_argument("--target", default=None, help="single domain to scan")
    r.add_argument("--refresh-proxies", action="store_true")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("continuous", help="continuous recon loop")
    c.add_argument("--interval", default=None, help="override interval e.g. 6h")
    c.set_defaults(func=cmd_continuous)

    s = sub.add_parser("self-test", help="validate config + diff engine + proxies")
    s.set_defaults(func=cmd_self_test)

    i = sub.add_parser("install-check", help="list missing recon tools")
    i.set_defaults(func=cmd_install_check)

    pr = sub.add_parser("proxies", help="refresh proxy pool now")
    pr.set_defaults(func=cmd_proxies)
    return p


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "verbose", False))
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
