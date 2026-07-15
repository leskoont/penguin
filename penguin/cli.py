"""penguin CLI: run / continuous / self-test / install-check / proxies."""
from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass
from typing import Optional

import typer

from .config import load, load_targets
from .proxies import get_pool
from .pipelines.master import run_target
from .pipelines.report import build_report
from .ui.console import console, setup_logging
from .ui.progress import RichBlockProgress, refresh_proxy_pool
from .ui.tables import install_check_table, summary_table, url_check_table
from .ui.targets import resolve_targets

LOG = logging.getLogger("penguin")

app = typer.Typer(add_completion=False, no_args_is_help=False,
                   context_settings={"help_option_names": ["-h", "--help"]})


@dataclass
class GlobalOpts:
    verbose: bool = False
    config: Optional[str] = None
    targets: Optional[str] = None


def _parse_interval(interval: str) -> int:
    interval = interval.strip()
    if interval.endswith("h"):
        return int(interval[:-1]) * 3600
    if interval.endswith("m"):
        return int(interval[:-1]) * 60
    if interval.endswith("d"):
        return int(interval[:-1]) * 86400
    return int(interval)


def _merge(ctx: typer.Context, verbose: bool, config: Optional[str], targets: Optional[str]):
    """Fold a subcommand's own -v/-c/-t onto the top-level GlobalOpts, so the
    flags work whether they appear before or after the subcommand name."""
    g: GlobalOpts = ctx.obj
    if verbose and not g.verbose:
        g.verbose = True
        setup_logging(True)
    return (config or g.config), (targets or g.targets)


@app.callback(invoke_without_command=True)
def _top(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "-v", "--verbose", help="verbose logging"),
    config: Optional[str] = typer.Option(None, "-c", "--config", help="path to config.yaml"),
    targets: Optional[str] = typer.Option(None, "-t", "--targets", help="path to targets.txt"),
    no_venv: bool = typer.Option(False, "--no-venv", help="do not use/create .venv"),
    reinstall_venv: bool = typer.Option(False, "--reinstall-venv", help="force reinstall venv deps"),
) -> None:
    """penguin recon automation framework"""
    ctx.obj = GlobalOpts(verbose=verbose, config=config, targets=targets)
    setup_logging(ctx.obj.verbose)
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit(0)


@app.command("run", help="run full pipeline (drops into an interactive wizard if no target resolves and stdin is a TTY)")
def cmd_run(
    ctx: typer.Context,
    target: Optional[str] = typer.Option(None, "--target", help="single domain to scan"),
    refresh_proxies: bool = typer.Option(False, "--refresh-proxies"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="verbose logging"),
    config: Optional[str] = typer.Option(None, "-c", "--config", help="path to config.yaml"),
    targets: Optional[str] = typer.Option(None, "-t", "--targets", help="path to targets.txt"),
    no_venv: bool = typer.Option(False, "--no-venv", hidden=True),
    reinstall_venv: bool = typer.Option(False, "--reinstall-venv", hidden=True),
) -> int:
    cfg_path, targets_path = _merge(ctx, verbose, config, targets)
    cfg = load(cfg_path)
    pool = get_pool(cfg)
    if cfg.proxies.enabled:
        valid = refresh_proxy_pool(pool, console, force=refresh_proxies)
        LOG.info("[proxies] %d valid proxies in pool", len(valid))
    resolved = resolve_targets(cfg, targets_path, target)
    if not resolved:
        LOG.error("no targets; pass --target or populate config/targets.txt")
        return 1
    had_failure = False
    for t in resolved:
        try:
            with RichBlockProgress(console) as bp:
                summary = run_target(cfg, t, progress_cb=bp.callback)
            console.print(summary_table(t["value"], summary))
            build_report(cfg, t, summary)
        except Exception as exc:  # noqa - one target's failure must not abort the batch
            LOG.exception("target %s failed: %s", t["value"], exc)
            had_failure = True
    return 1 if had_failure else 0


@app.command("continuous", help="continuous recon loop")
def cmd_continuous(
    ctx: typer.Context,
    interval: Optional[str] = typer.Option(None, "--interval", help="override interval e.g. 6h"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="verbose logging"),
    config: Optional[str] = typer.Option(None, "-c", "--config", help="path to config.yaml"),
    targets: Optional[str] = typer.Option(None, "-t", "--targets", help="path to targets.txt"),
    no_venv: bool = typer.Option(False, "--no-venv", hidden=True),
    reinstall_venv: bool = typer.Option(False, "--reinstall-venv", hidden=True),
) -> int:
    cfg_path, targets_path = _merge(ctx, verbose, config, targets)
    cfg = load(cfg_path)
    resolved = load_targets(targets_path)
    if not resolved:
        LOG.error("no targets for continuous mode")
        return 1
    interval_s = _parse_interval(cfg.continuous.interval if not interval else interval)
    LOG.info("[continuous] every %ds across %d targets", interval_s, len(resolved))
    while True:
        pool = get_pool(cfg)
        if cfg.proxies.enabled:
            refresh_proxy_pool(pool, console, force=True)
        for t in resolved:
            try:
                summary = run_target(cfg, t)
                build_report(cfg, t, summary)
            except Exception as exc:  # noqa
                LOG.exception("target %s failed: %s", t["value"], exc)
        LOG.info("[continuous] sleeping %ds", interval_s)
        time.sleep(interval_s)


@app.command("self-test", help="validate config + diff engine + proxies")
def cmd_self_test(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "-v", "--verbose", help="verbose logging"),
    config: Optional[str] = typer.Option(None, "-c", "--config", help="path to config.yaml"),
    targets: Optional[str] = typer.Option(None, "-t", "--targets", help="path to targets.txt"),
    no_venv: bool = typer.Option(False, "--no-venv", hidden=True),
    reinstall_venv: bool = typer.Option(False, "--reinstall-venv", hidden=True),
) -> int:
    cfg_path, _ = _merge(ctx, verbose, config, targets)
    cfg = load(cfg_path)
    ok = True
    LOG.info("[selftest] config loaded: stages=%s", cfg.stages)
    LOG.info("[selftest] proxies.enabled=%s", cfg.proxies.enabled)
    pool = get_pool(cfg)
    if cfg.proxies.enabled:
        try:
            valid = refresh_proxy_pool(pool, console, force=True)
            LOG.info("[selftest] proxies: %d valid", len(valid))
        except Exception as exc:  # noqa
            LOG.warning("[selftest] proxies fetch failed (network?): %s", exc)
    from .state import RunState

    st = RunState(cfg, "__selftest__")
    st.add_lines("all_subdomains.txt", ["a.target.com", "b.target.com"])
    st.archive()
    st2 = RunState(cfg, "__selftest__")
    st2.add_lines("all_subdomains.txt", ["a.target.com", "b.target.com", "c.target.com"])
    diff = st2.write_diff_files("all_subdomains.txt")
    assert "c.target.com" in diff["new"], "diff engine broken"
    LOG.info("[selftest] diff engine OK: new=%s", diff["new"])
    import shutil

    for b in ["subfinder", "httpx", "nuclei", "puredns", "dnsx", "ffuf", "amass"]:
        present = shutil.which(b) is not None
        LOG.info("[selftest] %-12s %s", b, "present" if present else "MISSING (will skip)")

    # Check download-URL liveness (issue #51)
    from .install_check import check_critical_urls
    LOG.info("[selftest] checking critical download-URL liveness...")
    url_results = check_critical_urls()
    console.print(url_check_table(url_results))
    dead_urls = [label for label, is_alive, _ in url_results if not is_alive]
    if dead_urls:
        LOG.warning("[selftest] %d/%d download URLs are dead; wordlist fetches may fail", len(dead_urls), len(url_results))
    else:
        LOG.info("[selftest] all download URLs OK")

    LOG.info("[selftest] complete")
    return 0 if ok else 1


@app.command("install-check", help="list missing recon tools")
def cmd_install_check(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "-v", "--verbose", help="verbose logging"),
    config: Optional[str] = typer.Option(None, "-c", "--config", help="path to config.yaml"),
    targets: Optional[str] = typer.Option(None, "-t", "--targets", help="path to targets.txt"),
    no_venv: bool = typer.Option(False, "--no-venv", hidden=True),
    reinstall_venv: bool = typer.Option(False, "--reinstall-venv", hidden=True),
) -> int:
    cfg_path, _ = _merge(ctx, verbose, config, targets)
    cfg = load(cfg_path)
    import shutil

    tools = ["subfinder", "httpx", "nuclei", "amass", "puredns", "dnsx", "ffuf",
             "feroxbuster", "katana", "gau", "waybackurls", "subjs", "arjun",
             "findomain", "masscan", "nmap", "cloud_enum", "trufflehog", "gitleaks",
             "gitdumper", "github-subdomains", "kr", "grpcurl", "trivy", "dnsgen",
             "gotator", "redis-cli", "aws", "dig", "dnsvalidator",
             "hakrawler", "paramspider", "x8", "s3scanner", "bucketloot", "jsluice",
             "SecretFinder", "gcpbucketbrute"]
    # Presence is a plain PATH lookup, not a "--help" probe: many of these
    # tools (dig, masscan, amass with its own postinstall quirks, ...) exit
    # nonzero or need root/subcommands for --help, and runner.run() collapses
    # "not found" and "found but every retry failed" into the same
    # returncode=-1 -- so a --help probe reported installed tools as MISSING.
    results: list[tuple[str, bool]] = [(b, shutil.which(b) is not None) for b in tools]
    console.print(install_check_table(results))
    missing = [name for name, present in results if not present]
    LOG.info("[install-check] %d/%d present, %d missing", len(tools) - len(missing), len(tools), len(missing))
    if missing:
        LOG.info("[install-check] run scripts/install.sh to install missing tools")

    # Check download-URL liveness (issue #51)
    from .install_check import check_critical_urls
    LOG.info("[install-check] checking critical download-URL liveness...")
    url_results = check_critical_urls()
    console.print(url_check_table(url_results))
    dead_urls = [label for label, is_alive, _ in url_results if not is_alive]
    if dead_urls:
        LOG.warning("[install-check] %d/%d download URLs are dead; wordlist fetches may fail", len(dead_urls), len(url_results))
    else:
        LOG.info("[install-check] all download URLs OK")

    return 0


@app.command("tui", help="run a single target with a live textual dashboard")
def cmd_tui(
    ctx: typer.Context,
    target: Optional[str] = typer.Option(None, "--target", help="single domain to scan"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="verbose logging"),
    config: Optional[str] = typer.Option(None, "-c", "--config", help="path to config.yaml"),
    targets: Optional[str] = typer.Option(None, "-t", "--targets", help="path to targets.txt"),
    no_venv: bool = typer.Option(False, "--no-venv", hidden=True),
    reinstall_venv: bool = typer.Option(False, "--reinstall-venv", hidden=True),
) -> int:
    cfg_path, targets_path = _merge(ctx, verbose, config, targets)
    cfg = load(cfg_path)
    resolved = resolve_targets(cfg, targets_path, target)
    if not resolved:
        LOG.error("no targets; pass --target or populate config/targets.txt")
        return 1
    picked = resolved[0]
    if len(resolved) > 1:
        import questionary

        value = questionary.select(
            "Multiple targets resolved; pick one for the TUI:",
            choices=[t["value"] for t in resolved],
        ).ask()
        if value is None:
            return 1
        picked = next(t for t in resolved if t["value"] == value)

    from .ui.tui import PenguinTUI

    PenguinTUI(cfg, picked).run()
    return 0


@app.command("proxies", help="refresh proxy pool now")
def cmd_proxies(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "-v", "--verbose", help="verbose logging"),
    config: Optional[str] = typer.Option(None, "-c", "--config", help="path to config.yaml"),
    targets: Optional[str] = typer.Option(None, "-t", "--targets", help="path to targets.txt"),
    no_venv: bool = typer.Option(False, "--no-venv", hidden=True),
    reinstall_venv: bool = typer.Option(False, "--reinstall-venv", hidden=True),
) -> int:
    cfg_path, _ = _merge(ctx, verbose, config, targets)
    cfg = load(cfg_path)
    pool = get_pool(cfg)
    valid = refresh_proxy_pool(pool, console, force=True)
    LOG.info("[proxies] %d valid (http/socks5) -> %s", len(valid), cfg.proxies.pool_file)
    return 0


def main(argv=None) -> int:
    """Invoke the Typer app in non-standalone mode so command return values
    (0/1) flow back as our own exit code, per __main__.py's
    `raise SystemExit(main())` contract. Typer >=0.16 vendors its own
    click-compatible exception hierarchy internally rather than depending on
    the external `click` package, so usage errors are recognized by duck
    typing (`.show()` + `.exit_code`) instead of importing a private module.
    """
    argv = list(argv) if argv is not None else sys.argv[1:]
    try:
        result = app(args=argv, prog_name="penguin", standalone_mode=False)
    except typer.Exit as exc:
        return int(exc.exit_code)
    except typer.Abort:
        return 130
    except Exception as exc:
        show = getattr(exc, "show", None)
        exit_code = getattr(exc, "exit_code", None)
        if callable(show) and exit_code is not None:
            show()
            return int(exit_code)
        raise
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
