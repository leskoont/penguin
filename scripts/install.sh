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
  "github.com/hakluke/hakrawler@latest"
  "github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
  "github.com/gwen001/github-subdomains@latest"
  "github.com/Josue87/gotator@latest"
  "github.com/BishopFox/jsluice/cmd/jsluice@latest"
  "github.com/redhuntlabs/bucketloot/cmd/bucketloot@latest"
  "github.com/sa7mon/s3scanner@latest"
  "github.com/gitleaks/gitleaks/v8@latest"
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

# x8 is Rust too. Prefer cargo; fall back to the prebuilt release binary
# (upstream ships no arm64 build, so that fallback is amd64-only).
command -v x8 >/dev/null 2>&1 || {
  if command -v cargo >/dev/null 2>&1; then
    log "installing x8 via cargo"
    cargo install x8 2>/dev/null || log "  ! x8: cargo install failed"
  elif [ "$(uname -m)" = "x86_64" ]; then
    log "installing x8 (prebuilt release, no cargo found)"
    mkdir -p "$HOME/go/bin"
    curl -sL https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-linux-x8.gz -o /tmp/x8.gz \
      && gunzip -f /tmp/x8.gz \
      && install -m 0755 /tmp/x8 "$HOME/go/bin/x8" \
      || log "  ! x8: prebuilt download failed"
    rm -f /tmp/x8.gz /tmp/x8
  else
    log "  ! x8: needs Rust/cargo (not installed) -- see https://github.com/Sh1Yo/x8#installation"
  fi
}

# kiterunner ships no go-installable target at all -- upstream's own README
# only documents `make build` or downloading a prebuilt release binary, so
# `go install .../cmd/kr@latest` (the previous approach here) could never
# succeed. Grab the release tarball directly instead.
command -v kr >/dev/null 2>&1 || {
  KR_ARCH=$(uname -m); case "$KR_ARCH" in x86_64) KR_ARCH=amd64;; aarch64) KR_ARCH=arm64;; esac
  case "$KR_ARCH" in
    amd64|arm64)
      log "installing kr (kiterunner prebuilt release, linux_$KR_ARCH)"
      mkdir -p "$HOME/go/bin"
      curl -sL "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_${KR_ARCH}.tar.gz" -o /tmp/kr.tar.gz \
        && tar -xzf /tmp/kr.tar.gz -C /tmp kr \
        && install -m 0755 /tmp/kr "$HOME/go/bin/kr" \
        || log "  ! kr: download/extract failed"
      rm -f /tmp/kr.tar.gz /tmp/kr
      ;;
    *) log "  ! kr: unsupported arch $(uname -m), skipping" ;;
  esac
}

# findomain is Rust, not Go -- ships no go-installable target either.
# Grab the prebuilt release zip directly (both amd64 and arm64 are published).
command -v findomain >/dev/null 2>&1 || {
  FD_ARCH=$(uname -m); FD_ASSET=""
  case "$FD_ARCH" in x86_64) FD_ASSET=findomain-linux.zip;; aarch64) FD_ASSET=findomain-aarch64.zip;; esac
  if [ -n "$FD_ASSET" ]; then
    log "installing findomain (prebuilt release, $FD_ASSET)"
    mkdir -p "$HOME/go/bin"
    curl -sL "https://github.com/Findomain/Findomain/releases/latest/download/$FD_ASSET" -o /tmp/findomain.zip \
      && unzip -oq /tmp/findomain.zip -d /tmp \
      && install -m 0755 /tmp/findomain "$HOME/go/bin/findomain" \
      || log "  ! findomain: download/extract failed"
    rm -f /tmp/findomain.zip /tmp/findomain
  else
    log "  ! findomain: unsupported arch $(uname -m), skipping"
  fi
}

# ---- pip/pipx python tools (real PyPI packages) ----
log "pip install core python deps"
# Both guarded with || true: modern Debian/Kali enforce PEP 668
# (externally-managed-environment) and refuse a bare global pip install, and
# under set -e an unguarded failure here would abort the rest of the script
# (pipx tools + wordlists below) -- penguin's own deps are installed
# separately into .venv/ by penguin/venv.py, so this system-wide install is
# best-effort only.
python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
python3 -m pip install -r requirements.txt >/dev/null 2>&1 || log "  (skipped: PEP 668 externally-managed-environment or offline)"
for m in trufflehog dnsgen arjun; do
  command -v "$m" >/dev/null 2>&1 || { log "  installing $m via pipx"; pipx install "$m" 2>/dev/null || log "  ! $m not installed"; }
done
# py-altdns publishes under a different PyPI name than its binary. It also
# hasn't been updated since ~2019 and imports the `imp` module, removed in
# Python 3.12 -- if the system's default python3 is 3.12+, retry pinned to
# whatever older interpreter happens to be on PATH before giving up.
command -v altdns >/dev/null 2>&1 || {
  log "  installing altdns via pipx (py-altdns)"
  if ! pipx install py-altdns 2>/dev/null; then
    altdns_ok=false
    for py in python3.11 python3.10 python3.9; do
      command -v "$py" >/dev/null 2>&1 || continue
      pipx install --python "$py" py-altdns 2>/dev/null && { altdns_ok=true; break; }
    done
    $altdns_ok || log "  ! altdns: incompatible with Python 3.12+ (removed 'imp' module) and no older python3.x found on PATH -- see https://github.com/infosec-au/altdns/issues"
  fi
}
# no PyPI release, but both have proper setup.py packaging -> pipx can install straight from git
command -v paramspider >/dev/null 2>&1 || { log "  installing paramspider via pipx (from git)"; pipx install "git+https://github.com/devanshbatham/paramspider" 2>/dev/null || log "  ! paramspider not installed"; }
command -v dnsvalidator >/dev/null 2>&1 || { log "  installing dnsvalidator via pipx (from git)"; pipx install "git+https://github.com/vortexau/dnsvalidator" 2>/dev/null || log "  ! dnsvalidator not installed"; }

# ---- script-only tools with no packaging at all: clone + dedicated venv/wrapper ----
# These ship as a single script meant to be run with `python3 script.py`, with
# no setup.py/entry_points -- pip/pipx can't produce a binary for them, so each
# gets its own throwaway venv (sidesteps PEP 668 too) and a thin wrapper on PATH.
TOOLS_DIR="$HOME/.penguin-tools"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$TOOLS_DIR" "$BIN_DIR"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) export PATH="$BIN_DIR:$PATH"; echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc" ;;
esac

install_py_script_tool() {
  local bin_name="$1" repo_url="$2" entry_script="$3"
  command -v "$bin_name" >/dev/null 2>&1 && return
  local dest="$TOOLS_DIR/$(basename "$repo_url" .git)"
  log "  installing $bin_name (clone + venv: $repo_url)"
  [ -d "$dest" ] || git clone --depth 1 "$repo_url" "$dest" 2>/dev/null || { log "  ! $bin_name: clone failed"; return; }
  python3 -m venv "$dest/.venv" 2>/dev/null || { log "  ! $bin_name: venv create failed"; return; }
  [ -f "$dest/requirements.txt" ] && "$dest/.venv/bin/pip" install -q -r "$dest/requirements.txt" 2>/dev/null
  printf '#!/usr/bin/env bash\nexec "%s" "%s" "$@"\n' "$dest/.venv/bin/python" "$dest/$entry_script" > "$BIN_DIR/$bin_name"
  chmod +x "$BIN_DIR/$bin_name"
}

install_py_script_tool linkfinder     "https://github.com/GerbenJavado/LinkFinder"        "linkfinder.py"
install_py_script_tool SecretFinder   "https://github.com/m4ll0k/SecretFinder"            "SecretFinder.py"
install_py_script_tool cloud_enum     "https://github.com/initstring/cloud_enum"          "cloud_enum.py"
install_py_script_tool gcpbucketbrute "https://github.com/RhinoSecurityLabs/GCPBucketBrute" "gcpbucketbrute.py"

# puredns (installed above via go install) shells out to a separate massdns
# binary at runtime -- go install can't produce it (massdns is a C project,
# not a Go module), and it wasn't installed anywhere else either, so every
# puredns call failed with "unable to execute massdns: exec: massdns:
# executable file not found in $PATH" (permanent failure, zero DNS-bruteforce
# resolution, on every single run). Try apt first, else build from source.
command -v massdns >/dev/null 2>&1 || {
  log "installing massdns (puredns dependency)"
  sudo apt-get install -y massdns 2>/dev/null || {
    log "  massdns not in apt; building from source"
    dest="$TOOLS_DIR/massdns"
    [ -d "$dest" ] || git clone --depth 1 https://github.com/blechschmidt/massdns "$dest" 2>/dev/null
    if [ -d "$dest" ]; then
      make -C "$dest" 2>/dev/null && install -m 0755 "$dest/bin/massdns" "$BIN_DIR/massdns" || log "  ! massdns: build failed"
    else
      log "  ! massdns: clone failed"
    fi
  }
}

# gitdumper: bash script (GitTools), not Python -- same clone pattern, no venv needed
command -v gitdumper >/dev/null 2>&1 || {
  log "  installing gitdumper (git clone)"
  dest="$TOOLS_DIR/GitTools"
  [ -d "$dest" ] || git clone --depth 1 https://github.com/internetwache/GitTools "$dest" 2>/dev/null || log "  ! gitdumper: clone failed"
  if [ -f "$dest/Dumper/gitdumper.sh" ]; then
    chmod +x "$dest/Dumper/gitdumper.sh"
    printf '#!/usr/bin/env bash\nexec "%s" "$@"\n' "$dest/Dumper/gitdumper.sh" > "$BIN_DIR/gitdumper"
    chmod +x "$BIN_DIR/gitdumper"
  else
    log "  ! gitdumper.sh not found after clone"
  fi
}

# jsretk (SeanPesce/JSRETK) is Node.js-based with no documented install/PATH
# story (run directly as `node jsretk-strings.js`, not a packaged CLI) --
# left as a manual step rather than guessing at a wrapper.
command -v jsretk-strings >/dev/null 2>&1 || log "  note: jsretk not auto-installed (Node.js tool, no CLI package -- see https://github.com/SeanPesce/JSRETK)"

# ---- system packages ----
for b in masscan nmap redis-tools dnsutils awscli docker.io trivy; do
  command -v "$b" >/dev/null 2>&1 || log "  note: $b not auto-installed (apt/brew as needed)"
done

# ---- wordlists ----
mkdir -p wordlists results/proxies reports

# plain `curl -sL -o file` exits 0 even on a 404/CDN error page, so a single
# network hiccup silently writes garbage into `file`; the old `[ -f file ] ||`
# guard then treated that garbage as "already fetched" forever, on every
# future run. -f makes curl actually fail on HTTP errors, `-s "$path"` (non-
# empty, not just exists) is the re-fetch guard, and a failed attempt is
# removed instead of left behind half-written.
fetch_wordlist() {
  local path="$1" url="$2" label="$3"
  [ -s "$path" ] && return 0
  log "fetching $label"
  curl -fsL "$url" -o "$path" 2>/dev/null || { rm -f "$path"; log "  ! $label fetch failed"; }
}

fetch_wordlist wordlists/resolvers.txt https://raw.githubusercontent.com/tomnomnom/httprobe/master/resolvers.txt "resolvers"
fetch_wordlist wordlists/subdomains-large.txt https://wordlists-cdn.assetnote.io/data/us_subdomains.txt "subdomains-large (assetnote)"
fetch_wordlist wordlists/directory-list-2.3-medium.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt "directory wordlist (SecLists)"
fetch_wordlist wordlists/routes-large.kite https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite "kiterunner routes-large.kite"
fetch_wordlist wordlists/permutation-words.txt https://raw.githubusercontent.com/six2dez/OneListForAll/main/permutations_list.txt "permutation words (OneListForAll)"
fetch_wordlist wordlists/params.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt "param names (SecLists)"
[ -f wordlists/learned.txt ] || touch wordlists/learned.txt

log "done. Run: python3 -m penguin install-check"
