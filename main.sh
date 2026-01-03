#!/bin/bash

# ==============================================================================
# Supply Chain Security Scanner (External Tool Mode)
# Scans for: Dependency Confusion, Namespace Takeovers, Secrets, Broken Links
# Supported: NPM, PyPI, RubyGems, Go, Maven, Docker, Rust, Composer, NuGet, Actions
# ==============================================================================

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
crit()   { printf '\e[1;31m[CRITICAL]\e[0m %s\n' "$*"; }

echo
echo -e "[ERROR] World \e[31mOFF\e[0m,Terminal \e[32mON \e[0m"
echo -e " █████                             █████           █████
░░███                             ░░███           ░░███
 ░███████  █████ ████  ███████  ███████   ██████  ███████    ██████  █████ █████  ██████
 ░███░░███░░███ ░███  ███░░███ ███░░███  ███░░███░░░███░    ███░░███░░███ ░░███  ███░░███
 ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███    ░███████  ░░░█████░  ░███████
 ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███ ███░███░░░    ███░░░███ ░███░░░
 ████████  ░░████████░░███████░░████████░░██████   ░░█████ ░░██████  █████ █████░░██████
░░░░░░░░    ░░░░░░░░  ░░░░░███ ░░░░░░░░  ░░░░░░     ░░░░░   ░░░░░░  ░░░░░ ░░░░░  ░░░░░░
                      ███ ░███
                     ░░██████
                      ░░░░░░                                                             "
echo -e "[WARN] Make \e[31mCritical\e[0m great again"

# ------------------------------
# Parse arguments
# ------------------------------
USER=""
ORG=""
FOLDER=""
GITLAB=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -u|--user)   USER=$2; shift 2 ;;
    -o|--org)    ORG=$2; shift 2 ;;
    -f|--folder) FOLDER=$2; shift 2 ;;
    -g|--gitlab) GITLAB=$2; shift 2 ;;
    *) warn "Usage: bash scan.sh -u <USER> | -o <ORG> | -f <FOLDER> | -g <GROUP>"; exit 1 ;;
  esac
done

# ------------------------------
# Validation
# ------------------------------
if [[ -z "$USER" && -z "$ORG" && -z "$FOLDER" && -z "$GITLAB" ]]; then
  err "[-] You must specify a target with -u, -o, -g, or -f"
  exit 1
fi

# ------------------------------
# Environment Setup
# ------------------------------
TARGET=${ORG:-${USER:-${GITLAB:-$(basename "$FOLDER")}}}
OUTPUT="/tmp/${TARGET}"
mkdir -p "$OUTPUT"
echo "$TARGET" | anew githubTargets.txt

# ------------------------------
# Clone or Use Local Folder
# ------------------------------
cloneOrg() {
  notice "[-] Cloning GitHub Organization Repositories: $ORG"
  ghorg clone "$ORG" --fetch-all --quiet -p "$OUTPUT" -t "$GITHUB_TOKEN" \
    --color enabled --skip-forks --skip-archived
}

cloneUser() {
  notice "[-] Cloning GitHub User Repositories: $USER"
  ghorg clone "$USER" --clone-type=user --fetch-all --quiet -p "$OUTPUT" -t "$GITHUB_TOKEN" \
    --color enabled --skip-archived --skip-forks
}

useLocalFolder() {
  notice "[-] Using local folder as source: $FOLDER"
  cp -r "$FOLDER"/* "$OUTPUT/" 2>/dev/null
}

cloneGitlabGroup() {
  notice "[-] Cloning Gitlab Group Repositories: $GITLAB"
  ghorg clone $GITLAB --scm=gitlab --path=$OUTPUT
}

# ------------------------------
# Fallback Functions (Only for ecosystems without external tools)
# ------------------------------

# 1. PHP/Composer
php-name() {
  local pkg=$1
  if [[ "$pkg" == */* ]]; then
     local vendor=$(echo "$pkg" | cut -d'/' -f1)
     local code=$(curl -s -o /dev/null -w "%{http_code}" "https://packagist.org/packages/$vendor/")
     if [[ -n "$code" && "$code" -eq 200 ]]; then return 0; fi
     crit "PHP Vendor $vendor is available (found in $pkg)"
  else
     local code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://packagist.org/packages/$pkg.json")
     if [[ -n "$code" && "$code" -eq 404 ]]; then warn "PHP Package $pkg is available"; fi
  fi
}

# 2. Maven
maven-name() {
  local pkg=$1
  local group_path=$(echo "$pkg" | cut -d':' -f1 | tr '.' '/')
  local code=$(curl -s -o /dev/null -w "%{http_code}" "https://repo1.maven.org/maven2/${group_path}/")
  if [[ -n "$code" && "$code" -eq 200 ]]; then return 0; fi
  crit "Maven GroupID $(echo $pkg | cut -d':' -f1) is available (found in $pkg)"
}

# 3. Go
go-name() {
  local pkg=$1
  local code=$(curl -s -o /dev/null -w "%{http_code}" "https://proxy.golang.org/${pkg}/@v/list")
  if [[ -n "$code" && "$code" -eq 200 ]]; then return 0; fi
  
  if [[ "$pkg" == github.com/* ]]; then
     local owner=$(echo "$pkg" | cut -d'/' -f2)
     local gh_code=$(curl -s -o /dev/null -w "%{http_code}" "https://github.com/$owner")
     if [[ -n "$gh_code" && "$gh_code" -eq 404 ]]; then crit "Go Namespace github.com/$owner is available (found in $pkg)"; return; fi
  fi
}

# 4. GitHub Actions
action-name() {
  local action=$1
  local owner=$(echo "$action" | cut -d'/' -f1)
  local code=$(curl -s -o /dev/null -w "%{http_code}" "https://github.com/$owner")
  if [[ -n "$code" && "$code" -eq 404 ]]; then crit "GitHub Action Owner $owner is available (found in $action)"; fi
}

# 5. Standard Fallbacks
gem-name() {
  local pkg=$1
  local code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://rubygems.org/gems/$pkg")
  if [[ -n "$code" && "$code" -eq 404 ]]; then warn "Ruby Gem $pkg is available"; fi
}

nuget-name() {
  local pkg=$1
  local code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://www.nuget.org/packages/$pkg")
  if [[ -n "$code" && "$code" -eq 404 ]]; then warn "NuGet Package $pkg is available"; fi
}

docker-name() {
  local pkg=$1
  [[ "$pkg" =~ \{\{.*\}\} || "$pkg" =~ \} || "$pkg" == *" "* ]] && return 0
  local url="https://hub.docker.com/v2/repositories/$pkg/"
  [[ "$pkg" != */* ]] && url="https://hub.docker.com/v2/repositories/library/$pkg/"
  local code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  if [[ -n "$code" && "$code" -eq 404 ]]; then warn "Docker Image $pkg is available"; fi
}

rust-name() {
  local pkg=$1
  local code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://crates.io/api/v1/crates/$pkg")
  if [[ -n "$code" && "$code" -eq 404 ]]; then warn "Rust Crate $pkg is available"; fi
}

broken-github() {
  local url=$1
  local code=$(curl -Ls -o /dev/null -w "%{http_code}" "$url")
  if [[ -n "$code" && "$code" -eq 404 ]]; then warn "|-BROKEN-| $url => $code"; fi
}

# ------------------------------
# Extraction Logic
# ------------------------------
getDependencies() {
  mkdir -p "$OUTPUT/DEP"
  
  notice "Fetching NPM dependencies..."
  find "$OUTPUT" -name package.json | xargs -I {} get-dependencies {} | sort -u | anew "$OUTPUT/DEP/npm.deps"

notice "Fetching Python dependencies..."
  # Clean up paths to avoid checking local files
  find "$OUTPUT" -type f \( -name "*requirements*.txt" -o -name "*.pip" \) | xargs -I {} cat {} | \
  sed 's/#.*//' | \
  grep -vE '^\s*-|^\s*$' | \
  grep -vE 'git\+|http:|https:|://' | \
  sed -E 's/([<>=!~;]).*/\1/' | \
  tr -d '[<>=!~;]' | \
  tr -d '[]' | \
  awk '{print $1}' | \
  sort -u | anew "$OUTPUT/DEP/pip.deps"

  notice "Fetching Ruby dependencies..."
  find "$OUTPUT" -name "Gemfile" | \
  xargs -I {} grep "^[[:space:]]*gem" {} | \
  sed -E "s/^[[:space:]]*gem[[:space:]]+['\"]([^'\"]+)['\"].*/\1/" | \
  sort -u | anew "$OUTPUT/DEP/ruby.deps"

  find "$OUTPUT" -name "*.gemspec" | \
    xargs -I {} grep -E "\.add_(runtime_|development_)?dependency" {} | \
    sed -E "s/.*['\"]([^'\"]+)['\"].*/\1/" | \
    sort -u | anew "$OUTPUT/DEP/ruby.deps"

  notice "Fetching Go dependencies..."
  find "$OUTPUT" -name "go.mod" | while read -r file; do
    awk '/^require/ { if ($2 != "(") print $2 } /^\)/ {in_block=0} /^require \(/ {in_block=1} in_block && $1 != "require" {print $1}' "$file"
  done | sort -u | anew "$OUTPUT/DEP/go.deps"

  notice "Fetching Maven dependencies..."
  find "$OUTPUT" -name "pom.xml" | while read -r file; do
    awk -F'[<>]' '/<groupId>/ {g=$3} /<artifactId>/ {a=$3; if(g) print g":"a}' "$file"
  done | sort -u | anew "$OUTPUT/DEP/maven.deps"

  notice "Fetching Docker dependencies..."
  find "$OUTPUT" -type f \( -name "Dockerfile" -o -name "*.yml" \) | \
    grep -Eho "image:[[:space:]]*[\"']?([a-zA-Z0-9._/:-]+)" | cut -d: -f2 | tr -d '"' | sort -u | anew "$OUTPUT/DEP/docker.deps"

  notice "Fetching Rust dependencies..."
  find "$OUTPUT" -name "Cargo.toml" | while read -r file; do
    awk '/^\[.*dependencies\]/ {in_sec=1; next} /^\[/ {in_sec=0} in_sec && /^[a-zA-Z0-9_-]+/ {print $1}' "$file" | cut -d= -f1 | tr -d ' '
  done | sort -u | anew "$OUTPUT/DEP/rust.deps"

  notice "Fetching PHP (Composer) dependencies..."
  find "$OUTPUT" -name "composer.json" | while read -r file; do
    jq -r '(.require // {}), (.require-dev // {}) | keys[]' "$file" 2>/dev/null
  done | sort -u | grep "/" | anew "$OUTPUT/DEP/php.deps"

  notice "Fetching NuGet dependencies..."
  find "$OUTPUT" -type f \( -name "*.csproj" -o -name "packages.config" \) | while read -r file; do
    grep -o 'Include="[^"]*"' "$file" | cut -d'"' -f2
    grep -o 'package.*id="[^"]*"' "$file" | cut -d'"' -f2
  done | sort -u | grep -v "\." | anew "$OUTPUT/DEP/nuget.deps"

  notice "Fetching GitHub Actions..."
  find "$OUTPUT" -name ".github" -type d 2>/dev/null | xargs -I {} find {} -name "*.yml" -o -name "*.yaml" | \
    xargs -I {} grep -Eho "uses: [a-zA-Z0-9-]+/[a-zA-Z0-9_.-]+" {} | awk '{print $2}' | sort -u | anew "$OUTPUT/DEP/actions.deps"
}

# ------------------------------
# Check Execution
# ------------------------------
checkDependencies() {
  
  # -----------------------------------------------
  # 1. NPM: Pure External Tool Check
  # -----------------------------------------------
  
    notice "[-] Scanning NPM dependencies "
    cat "$OUTPUT/DEP/npm.deps" | xargs -I {} npm-name {} | anew "$OUTPUT/DEP/npm.checked"
    cat "$OUTPUT/DEP/npm.checked" | grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/npm.potential"
    
   notice "[-] Scanning PyPI dependencies using external"
   cat "$OUTPUT/DEP/pip.deps" | xargs -I {} pip-name {} | anew "$OUTPUT/DEP/pip.checked"
   cat "$OUTPUT/DEP/pip.checked" | grep "is available" | awk '{print $1}' | anew "$OUTPUT/DEP/pip.potential"
  # -----------------------------------------------
  # 3. Other Checks (Using Bash Functions)
  # -----------------------------------------------
  
  export -f gem-name go-name maven-name docker-name rust-name php-name nuget-name action-name crit warn notice err

  notice "Checking Ruby..."
  cat "$OUTPUT/DEP/ruby.deps" | xargs -P 10 -I {} bash -c 'gem-name "$@"' _ {} | anew "$OUTPUT/DEP/gem.potential"

  notice "Checking Go..."
  cat "$OUTPUT/DEP/go.deps" | xargs -P 10 -I {} bash -c 'go-name "$@"' _ {} | anew "$OUTPUT/DEP/go.potential"

  notice "Checking Maven..."
  cat "$OUTPUT/DEP/maven.deps" | xargs -P 10 -I {} bash -c 'maven-name "$@"' _ {} | anew "$OUTPUT/DEP/maven.potential"

  notice "Checking Docker..."
  cat "$OUTPUT/DEP/docker.deps" | xargs -P 10 -I {} bash -c 'docker-name "$@"' _ {} | anew "$OUTPUT/DEP/docker.potential"

  notice "Checking Rust..."
  cat "$OUTPUT/DEP/rust.deps" | xargs -P 10 -I {} bash -c 'rust-name "$@"' _ {} | anew "$OUTPUT/DEP/rust.potential"

  notice "Checking PHP..."
  cat "$OUTPUT/DEP/php.deps" | xargs -P 10 -I {} bash -c 'php-name "$@"' _ {} | anew "$OUTPUT/DEP/php.potential"

  notice "Checking NuGet..."
  cat "$OUTPUT/DEP/nuget.deps" | xargs -P 10 -I {} bash -c 'nuget-name "$@"' _ {} | anew "$OUTPUT/DEP/nuget.potential"

  notice "Checking GitHub Actions..."
  cat "$OUTPUT/DEP/actions.deps" | xargs -P 10 -I {} bash -c 'action-name "$@"' _ {} | anew "$OUTPUT/DEP/actions.potential"
}

brokenSupplychain() {
  export -f broken-github
  notice "[-] Finding broken GitHub references..."
  grep -rohE 'https?://github\.com/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?' "$OUTPUT" 2>/dev/null | sort -u | anew "$OUTPUT/DEP/github.url"
  
  notice "[-] Checking broken GitHub references..."
  cat "$OUTPUT/DEP/github.url" | xargs -P 10 -I {} bash -c 'broken-github "$@"' _ {} | anew "$OUTPUT/DEP/github.potential"
}

secretFinding() {
  notice "[-] Scanning for secrets with TruffleHog..."
  trufflehog filesystem --only-verified "$OUTPUT" --no-update 2>/dev/null
}

report() {
  warn "[+] Scan completed for $TARGET — results in $OUTPUT/DEP"
  echo
  notice "=== POTENTIAL FINDINGS SUMMARY ==="
  for dep_file in "$OUTPUT/DEP"/*.potential; do
    if [[ -f "$dep_file" ]]; then
      count=$(wc -l < "$dep_file" 2>/dev/null || echo "0")
      type=$(basename "$dep_file" .potential)
      if [[ "$count" -gt 0 ]]; then
        crit "$type: $count potential vulnerabilities"
        cat "$dep_file"
        echo "------------------------------------------------"
      fi
    fi
  done
}

# ------------------------------
# Main Execution
# ------------------------------
main() {
  if [[ -n "$ORG" ]]; then cloneOrg
  elif [[ -n "$USER" ]]; then cloneUser
  elif [[ -n "$FOLDER" ]]; then useLocalFolder
  elif [[ -n "$GITLAB" ]]; then cloneGitlabGroup
  fi

  getDependencies
  checkDependencies
  brokenSupplychain
  secretFinding
  report
}

main
