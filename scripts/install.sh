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
  "github.com/d3mondev/puredns/v2@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
  "github.com/owasp-amass/amass/v4/...@master"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/lc/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/lc/subjs@latest"
  "github.com/ffuf/ffuf@latest"
  "github.com/tomnomnom/httprobe@latest"
  "github.com/assetnote/kiterunner/cmd/kr@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
)
install_go
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
for t in "${GO_TOOLS[@]}"; do
  log "go install $t"
  go install "$t" || log "  ! failed: $t"
done

# feroxbuster is Rust, not Go -- not go-installable. Use apt/cargo/prebuilt release.
command -v feroxbuster >/dev/null 2>&1 || {
  log "feroxbuster not found; installing via apt (falls back to a note if unavailable)"
  sudo apt-get install -y feroxbuster 2>/dev/null || log "  ! feroxbuster: install manually (cargo install feroxbuster, or https://github.com/epi052/feroxbuster/releases)"
}

# ---- pip python tools ----
PY_TOOLS=(trufflehog gitleaks gitdumper github-subdomains dnsgen altdns gotator linkfinder SecretFinder jsluice jsretk arjun paramspider x8 cloud_enum S3Scanner bucketloot gcpbucketbrute dnsvalidator)
log "pip install core python deps"
# Both guarded with || true: modern Debian/Kali enforce PEP 668
# (externally-managed-environment) and refuse a bare global pip install, and
# under set -e an unguarded failure here would abort the rest of the script
# (pipx tools + wordlists below) -- penguin's own deps are installed
# separately into .venv/ by penguin/venv.py, so this system-wide install is
# best-effort only.
python3 -m pip install --upgrade pip || true
python3 -m pip install -r requirements.txt || true
for m in trufflehog gitleaks; do
  command -v "$m" >/dev/null 2>&1 || { log "  installing $m via pipx"; pipx install "$m" 2>/dev/null || log "  ! $m not installed"; }
done

# ---- system packages ----
for b in masscan nmap redis-tools dnsutils awscli docker.io trivy; do
  command -v "$b" >/dev/null 2>&1 || log "  note: $b not auto-installed (apt/brew as needed)"
done

# ---- wordlists ----
mkdir -p wordlists results/proxies reports
[ -f wordlists/resolvers.txt ] || { log "fetching resolvers"; curl -sL https://raw.githubusercontent.com/tomnomnom/httprobe/master/resolvers.txt -o wordlists/resolvers.txt 2>/dev/null || log "  ! resolvers fetch failed"; }
[ -f wordlists/subdomains-large.txt ] || { log "fetching subdomains-large (assetnote)"; curl -sL https://wordlists-cdn.assetnote.io/data/us_subdomains.txt -o wordlists/subdomains-large.txt 2>/dev/null || log "  ! subdomain list fetch failed"; }
[ -f wordlists/directory-list-2.3-medium.txt ] || { log "fetching directory wordlist (SecLists)"; curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -o wordlists/directory-list-2.3-medium.txt 2>/dev/null || log "  ! dir list fetch failed"; }
[ -f wordlists/routes-large.kite ] || { log "fetching kiterunner routes-large.kite"; curl -sL https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite -o wordlists/routes-large.kite 2>/dev/null || log "  ! kite fetch failed"; }
[ -f wordlists/permutation-words.txt ] || { log "fetching permutation words (OneListForAll)"; curl -sL https://raw.githubusercontent.com/six2dez/OneListForAll/main/permutations_list.txt -o wordlists/permutation-words.txt 2>/dev/null || log "  ! permutation words fetch failed"; }
[ -f wordlists/params.txt ] || { log "fetching param names (SecLists)"; curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt -o wordlists/params.txt 2>/dev/null || log "  ! param wordlist fetch failed"; }
[ -f wordlists/learned.txt ] || touch wordlists/learned.txt

log "done. Run: python3 -m penguin install-check"
