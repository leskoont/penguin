# penguin installer (Windows, best-effort)
# Downloads prebuilt Windows binaries for recon tools and wordlists.
# Run in PowerShell: .\scripts\install.ps1
$ErrorActionPreference = "Continue"
$PENGUIN = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $PENGUIN

function Fetch($url, $out) {
    Write-Host "[penguin] $url -> $out"
    # A stale sub-1 KB file (a 404 body or truncated download from an earlier
    # run) would otherwise linger and poison the pipeline; every wordlist here
    # is >100 KB, so re-fetch anything suspiciously small.
    if ((Test-Path $out) -and ((Get-Item $out).Length -ge 1024)) { return }
    try { Invoke-WebRequest -Uri $url -OutFile $out -ErrorAction Stop } catch { Write-Warning "  ! failed: $url"; return }
    if ((Test-Path $out) -and ((Get-Item $out).Length -lt 1024)) { Write-Warning "  ! too small, discarding: $out"; Remove-Item $out -Force }
}

New-Item -ItemType Directory -Force -Path wordlists, results/proxies, reports | Out-Null

# resolvers + wordlists (upstream URLs refreshed 2026-07 after wholesale rot:
# the assetnote us_subdomains/kite CDN paths and the httprobe resolvers.txt all
# 404'd, which starved puredns/ffuf and fed massdns a bogus resolvers file).
Fetch "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" "wordlists/resolvers.txt"
# 20k (not 110k): puredns bruteforce ran past its 1200s timeout on the full
# 110k list and contributed nothing; the 20k list resolves ~5x faster and
# completes within the timeout while still covering the high-value names.
# One-time migration: Fetch skips any file >=1 KB, so an already-cached 2 MB
# 110k copy under this same filename would survive forever and silently defeat
# the shrink -- drop any oversized (>512 KB) legacy copy to force the 20k list.
if ((Test-Path "wordlists/subdomains-large.txt") -and ((Get-Item "wordlists/subdomains-large.txt").Length -gt 512000)) {
    Write-Warning "  ! subdomains-large.txt: dropping oversized legacy 110k list, refetching 20k"
    Remove-Item "wordlists/subdomains-large.txt" -Force
}
Fetch "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt" "wordlists/subdomains-large.txt"
Fetch "https://raw.githubusercontent.com/3ndG4me/KaliLists/master/dirbuster/directory-list-2.3-medium.txt" "wordlists/directory-list-2.3-medium.txt"
Fetch "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt" "wordlists/permutation-words.txt"
Fetch "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" "wordlists/params.txt"
# kiterunner routes now ship as a gzipped tarball; download + extract.
if (-not ((Test-Path wordlists/routes-large.kite) -and ((Get-Item wordlists/routes-large.kite).Length -ge 1024))) {
    try {
        Invoke-WebRequest -Uri "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz" -OutFile "wordlists/routes-large.kite.tar.gz" -ErrorAction Stop
        tar -xzf wordlists/routes-large.kite.tar.gz -C wordlists
    } catch { Write-Warning "  ! kiterunner routes fetch/extract failed" }
    if (Test-Path wordlists/routes-large.kite.tar.gz) { Remove-Item wordlists/routes-large.kite.tar.gz -Force }
}
if (-not (Test-Path wordlists/learned.txt)) { New-Item -ItemType File -Path wordlists/learned.txt | Out-Null }

Write-Host "[penguin] Windows: most recon Go binaries are cross-platform. Download per-tool releases from GitHub and add to PATH, or run under WSL with scripts/install.sh for full automation."
Write-Host "[penguin] pip deps:"; python -m pip install -r requirements.txt
Write-Host "[penguin] done. Run: python -m penguin install-check"
