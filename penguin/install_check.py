"""URL-liveness checking for install-check command."""
from __future__ import annotations

import logging
from typing import Optional

import requests

LOG = logging.getLogger("penguin")

# Critical download URLs referenced in scripts/install.sh and config.yaml
# that lack liveness checks. Grouped by source for clarity.
CRITICAL_URLS = {
    # Binary releases (x8, kr, findomain) - install.sh lines 79-126
    "x8 (prebuilt release)": "https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-linux-x8.gz",
    "kiterunner (prebuilt release)": "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz",
    "findomain (prebuilt release)": "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip",

    # Wordlist/corpus URLs - install.sh lines 266-296
    "kiterunner routes-large.kite": "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz",
    "resolvers (trickest)": "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
    "subdomains-large (SecLists)": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    "directory-list (dirbuster)": "https://raw.githubusercontent.com/3ndG4me/KaliLists/master/dirbuster/directory-list-2.3-medium.txt",
    "permutation words (altdns)": "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt",
    "param names (SecLists)": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",

    # Proxy list URLs - config.yaml lines 67-68
    "proxifly proxy list": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
    "iplocate proxy list": "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt",
}


def check_url_liveness(url: str, timeout: int = 5) -> tuple[bool, Optional[str]]:
    """
    Probe a URL via HEAD request to check if it's alive/accessible.

    Returns:
        (is_alive, error_message) where is_alive is True if HEAD returned 2xx,
        and error_message is None on success or a description of the failure.
    """
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        if response.status_code >= 200 and response.status_code < 300:
            return True, None
        else:
            return False, f"HTTP {response.status_code}"
    except requests.Timeout:
        return False, "timeout"
    except requests.ConnectionError:
        return False, "connection error"
    except requests.RequestException as e:
        return False, f"request error: {type(e).__name__}"
    except Exception as e:
        return False, f"unexpected error: {type(e).__name__}"


def check_critical_urls() -> list[tuple[str, bool, Optional[str]]]:
    """
    Check all critical download URLs for liveness.

    Returns:
        List of (label, is_alive, error_message) tuples.
    """
    results = []
    for label, url in CRITICAL_URLS.items():
        is_alive, error = check_url_liveness(url)
        results.append((label, is_alive, error))
        status_str = "[green]OK[/]" if is_alive else f"[red]DEAD[/] ({error})"
        LOG.info("[url-check] %-45s %s", label, "OK" if is_alive else f"DEAD ({error})")
    return results
