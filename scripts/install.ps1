# penguin installer (Windows, best-effort)
# Downloads prebuilt Windows binaries for recon tools and wordlists.
# Run in PowerShell: .\scripts\install.ps1
$ErrorActionPreference = "Continue"
$PENGUIN = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $PENGUIN

function Fetch($url, $out) {
    Write-Host "[penguin] $url -> $out"
    try { Invoke-WebRequest -Uri $url -OutFile $out -ErrorAction Stop } catch { Write-Warning "  ! failed: $url" }
}

New-Item -ItemType Directory -Force -Path wordlists, results/proxies, reports | Out-Null

# resolvers + wordlists
Fetch "https://raw.githubusercontent.com/tomnomnom/httprobe/master/resolvers.txt" "wordlists/resolvers.txt"
Fetch "https://wordlists-cdn.assetnote.io/data/us_subdomains.txt" "wordlists/subdomains-large.txt"
Fetch "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt" "wordlists/directory-list-2.3-medium.txt"
Fetch "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite" "wordlists/routes-large.kite"
if (-not (Test-Path wordlists/learned.txt)) { New-Item -ItemType File -Path wordlists/learned.txt | Out-Null }

Write-Host "[penguin] Windows: most recon Go binaries are cross-platform. Download per-tool releases from GitHub and add to PATH, or run under WSL with scripts/install.sh for full automation."
Write-Host "[penguin] pip deps:"; python -m pip install -r requirements.txt
Write-Host "[penguin] done. Run: python -m penguin install-check"
