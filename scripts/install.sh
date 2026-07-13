#!/usr/bin/env bash
# penguin installer (WSL / Linux)
# Installs recon tooling + wordlists, then runs install-check.
# Usage: bash scripts/install.sh
set -euo pipefail

PENGUIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PENGUIN_DIR"

log(){ echo -e "\033[1;34m[penguin]\033[0m $*"; }

# ---- Go toolchain ----
install_go(){
  if command -v go >/dev/null 2>&1; then
    log "go present: $(go version | awk '{print $3}')"
    return
  fi
  log "installing go..."
  ARCH=$(uname -m); case "$ARCH" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; esac
  VER=1.22.5
  curl -sL "https://go.dev/dl/go${VER}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.bashrc"
}

# ---- Go-based tools (go install) ----
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/puredns/v2/cmd/puredns@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
  "github.com/owasp-amass/amass/v4/...@master"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/tomnomnom/gau@latest"
  "github.com/lc/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/lc/subjs@latest"
  "github.com/ffuf/ffuf@latest"
  "github.com/epi052/feroxbuster@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/tomnomnom/httprobe@latest"
  "github.com/Emoe/kiterunner/cmd/kr@latest"
)
install_go
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
for t in "${GO_TOOLS[@]}"; do
  log "go install $t"
  go install "$t" || log "  ! failed: $t"
done

# ---- pip python tools ----
PY_TOOLS=(trufflehog gitleaks gitdumper github-subdomains dnsgen altdns gotator linkfinder SecretFinder jsluice jsretk arjun paramspider x8 cloud_enum S3Scanner bucketloot gcpbucketbrute)
log "pip install core python deps"
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt || true
for m in trufflehog gitleaks; do
  command -v "$m" >/dev/null 2>&1 || { log "  installing $m via pipx"; pipx install "$m" 2>/dev/null || log "  ! $m not installed"; }
done

# ---- system packages ----
for b in masscan nmap rustscan redis-tools dnsutils awscli docker.io trivy; do
  command -v "$b" >/dev/null 2>&1 || log "  note: $b not auto-installed (apt/brew as needed)"
done

# ---- wordlists ----
mkdir -p wordlists results/proxies reports
[ -f wordlists/resolvers.txt ] || { log "fetching resolvers"; curl -sL https://raw.githubusercontent.com/tomnomnom/httprobe/master/resolvers.txt -o wordlists/resolvers.txt 2>/dev/null || log "  ! resolvers fetch failed"; }
[ -f wordlists/subdomains-large.txt ] || { log "fetching subdomains-large (assetnote)"; curl -sL https://wordlists-cdn.assetnote.io/data/us_subdomains.txt -o wordlists/subdomains-large.txt 2>/dev/null || log "  ! subdomain list fetch failed"; }
[ -f wordlists/directory-list-2.3-medium.txt ] || { log "fetching directory wordlist (SecLists)"; curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -o wordlists/directory-list-2.3-medium.txt 2>/dev/null || log "  ! dir list fetch failed"; }
[ -f wordlists/routes-large.kite ] || { log "fetching kiterunner routes-large.kite"; curl -sL https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite -o wordlists/routes-large.kite 2>/dev/null || log "  ! kite fetch failed"; }
[ -f wordlists/learned.txt ] || touch wordlists/learned.txt

log "done. Run: python3 -m penguin install-check"
