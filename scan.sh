#!/bin/bash

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }

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
    -u|--user)
      USER=$2
      shift 2
      ;;
    -o|--org)
      ORG=$2
      shift 2
      ;;
    -f|--folder)
      FOLDER=$2
      shift 2
      ;;
    -g|--gitlab)
      GITLAB=$2
      shift 2
      ;;
     *)
      warn "Usage: bash scan.sh -u <USER> | -o <ORG> | -f <FOLDER>"
      exit 1
      ;;
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
}

cloneGitlabGroup() {
  notice "[-] Cloning Gitlab Group Repositories: $GITLAB"
  ghorg clone $GITLAB --scm=gitlab --path=$OUTPUT
}

# ------------------------------
# Dependency & Security Functions
# ------------------------------

gem-name() {
  local pkg=$1
  local code
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://rubygems.org/gems/$pkg")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"
  fi
}

go-name() {
  local pkg=$1
  local code
  code=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" "https://proxy.golang.org/${pkg}/@v/list")
  if [ "$code" -eq 404 ]; then printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"; fi
}

maven-name() {
  local pkg=$1
  local group=$(echo "$pkg" | cut -d':' -f1 | tr '.' '/')
  local artifact=$(echo "$pkg" | cut -d':' -f2)
  local code
  code=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" "https://repo1.maven.org/maven2/${group}/${artifact}/")
  if [ "$code" -eq 404 ]; then printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"; fi
}

docker-name() {
  local pkg=$1
  if [[ "$pkg" =~ \{\{.*\}\} ]] || [[ "$pkg" =~ \} ]] || [[ "$pkg" =~ ^[[:space:]]*$ ]] || [[ "$pkg" == *" "* ]]; then
    return 0
  fi

  local url="https://hub.docker.com/v2/repositories/$pkg/"
  if [[ "$pkg" != */* ]]; then
    url="https://hub.docker.com/v2/repositories/library/$pkg/"
  fi

  local code
  code=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" "$url")
  if [ "$code" -eq 404 ]; then printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"; fi
}

rust-name() {
  local pkg=$1
  local code
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://crates.io/api/v1/crates/$pkg")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"
  fi
}

github-takeover() {
  local url=$1
  local code
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "$url")
  if [ "$code" -eq 302 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "|-Potential Takeover-| $url => $code"
  fi
}

broken-github() {
  local url=$1
  local code
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "$url")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "|-BROKEN-| $url => $code"
  fi
}

getDependencies() {
  mkdir -p "$OUTPUT/DEP"
  notice "Fetching NPM dependencies..."
  find "$OUTPUT" -name package.json | xargs -I {} get-dependencies {} | sort -u | anew "$OUTPUT/DEP/npm.deps"

  notice "Fetching Python dependencies..."
  find "$OUTPUT" -name "requirements*.txt" | \
    xargs -I {} awk '{print}' {} | grep -v "git:\|https\:\|http\:\|\#\|\""  | awk -F '=' '{print $1}' | awk -F ';' '{print $1}' | awk -F '(' '{print $1}' | awk -F '<' '{print $1}' | awk -F '>' '{print $1}' | awk -F '~' '{print $1}' | awk -F '[' '{print $1}' | awk NF | sed 's/ //g' | grep -v "^-" | sort | uniq | anew $OUTPUT/DEP/pip.deps

  notice "Fetching Ruby dependencies..."
  find "$OUTPUT" -name Gemfile | \
    xargs -I {} awk '{print}' {} | grep "^gem" | grep -v gemspec | sed "s/\"/\'/g" | awk -F "\'" '{print $2}' | awk NF | sort | uniq | anew "$OUTPUT/DEP/ruby.deps"

  notice "Fetching Go dependencies..."
find "$OUTPUT" -name "go.mod" | while read -r file; do
  awk '
    /^require[[:space:]]+\(/ { in_block=1; next }
    /^\)/ { in_block=0 }
    in_block && /^[[:space:]]*[a-zA-Z0-9._\/-]+/ { print $1; next }
    /^require[[:space:]]+[a-zA-Z0-9._\/-]+/ { print $2 }
  ' "$file"
done | sort -u | anew "$OUTPUT/DEP/go.deps"

notice "Fetching Maven dependencies..."
find "$OUTPUT" -name "pom.xml" | while read -r file; do
  awk -F'[<>]' '
    /<dependency>/ { in_dep=1; gid=""; aid="" }
    /<\/dependency>/ {
      if (in_dep && gid != "" && aid != "") print gid ":" aid;
      in_dep=0
    }
    in_dep && /<groupId>/ { gid=$3 }
    in_dep && /<artifactId>/ { aid=$3 }
  ' "$file"
done | sort -u | anew "$OUTPUT/DEP/maven.deps"

notice "Fetching Docker dependencies..."

find "$OUTPUT" -type f \( -iname "Dockerfile" -o -iname "docker-compose*.yml" -o -iname "*.yaml" -o -iname "*.yml" \) | \
xargs -I {} grep -Eho "image:[[:space:]]*[\"']?([a-zA-Z0-9._/:-]+)" {} | \
sed -E 's/^image:[[:space:]]*[\"'\'']//; s/[\"'\'']$//' | \
cut -d: -f1 | grep -vE '^{{|^\.\.?/|^[[:space:]]*$' | sort -u | anew "$OUTPUT/DEP/docker.deps"


  notice "Fetching Rust dependencies..."
find "$OUTPUT" -name "Cargo.toml" | while read -r file; do
  awk '
    { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0) }
    /^(#|$)/ { next }
    /^\[(dev-|build-)?dependencies\]/ { in_dep = 1; next }
    /^\[target\..*\.(dev-|build-)?dependencies\]/ { in_dep = 1; next }
    /^\[/ { in_dep = 0 }
    (in_dep == 1) {
      if (match($0, /^[a-zA-Z0-9._-]+/)) {
        pkg = substr($0, RSTART, RLENGTH)
        print pkg
      }
    }
  ' "$file"
done | sort -u | anew "$OUTPUT/DEP/rust.deps"

  }
  
brokenSupplychain() {
  export -f broken-github
 notice "[-] Finding broken GitHub references: Github Url"
 GH_URL_REGEX='https?://github\.com/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?'
  grep -roh '(http.)?://(raw.githubusercontent.com)\b([-a-zA-Z0-9@:%_\+.~#?&\/=]*)' $OUTPUT | sort | uniq | anew "$OUTPUT/DEP/github.account"
  grep -roh '(http.)?://(raw.github.com)\b([-a-zA-Z0-9@:%_\+.~#?&\/=]*)' $OUTPUT | sort | uniq | anew "$OUTPUT/DEP/github.account"
  grep -rhoE "$GH_URL_REGEX" "$OUTPUT" 2>/dev/null | sort -u | anew "$OUTPUT/DEP/github.account"
  grep -roh '(http.)?://(media.githubusercontent.com)\b([-a-zA-Z0-9@:%_\+.~#?&\/=]*)' $OUTPUT | sort | uniq | anew "$OUTPUT/DEP/github.account"
 notice "[-] Finding broken GitHub references: Github Action"
  grep -roh -E "uses: [-a-zA-Z0-9\.]+/[-a-zA-Z0-9.]+\@[-a-zA-Z0-9\.]+" $OUTPUT | awk -F ": " '{print $2}' | awk -F "/" '{print "https://github.com/"$1}' | sort | uniq | grep -v "github.com/actions$" | anew "$OUTPUT/DEP/github.action"

 notice "[-] Checking broken GitHub references: Github Url"
 cat "$OUTPUT/DEP/github.account" | sort -u | xargs -I {} bash -c 'broken-github "$@"' _ {} | anew "$OUTPUT/DEP/github.potential"
 notice "[-] Checking broken GitHub references: Github Action"
 cat "$OUTPUT/DEP/github.action" | sort -u | xargs -I {} bash -c 'broken-github "$@"' _ {} | anew "$OUTPUT/DEP/github.potential"
}

checkDependencies() {
  export -f gem-name go-name maven-name docker-name rust-name
  notice "Checking npm..."
  cat "$OUTPUT/DEP/npm.deps" | xargs -I {} npm-name {} | anew "$OUTPUT/DEP/npm.checked"
  cat "$OUTPUT/DEP/npm.checked" | grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/npm.potential"

  notice "Checking pip..."
  cat "$OUTPUT/DEP/pip.deps" | xargs -I {} pip-name {} | anew "$OUTPUT/DEP/pip.checked"
  cat "$OUTPUT/DEP/pip.checked" | grep "is available" | awk '{print $1}' | anew "$OUTPUT/DEP/pip.potential"

  notice "Checking Ruby Gems..."
  cat "$OUTPUT/DEP/ruby.deps" | xargs -I {} bash -c 'gem-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/gem.potential"

  notice "Checking Go modules..."
  export -f github-takeover
  cat "$OUTPUT/DEP/go.deps" | xargs -I {} bash -c 'go-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/go.potential"
  warn "Checking Go modules: Available..."
   cat "$OUTPUT/DEP/go.potential" | grep "github.com" | sort -u | xargs -I {} bash -c 'github-takeover "$@"' _ {} | anew "$OUTPUT/DEP/go.takeover"

  notice "Checking Maven artifacts..."
  cat "$OUTPUT/DEP/maven.deps" | xargs -I {} bash -c 'maven-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/maven.potential"

  notice "Checking Docker images..."
  cat "$OUTPUT/DEP/docker.deps" | grep -v "^{{" | grep -v "^\." | grep -v "^[[:space:]]*$" | \
    xargs -I {} bash -c 'docker-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/docker.potential"

  notice "Checking Rust crates..."
  cat "$OUTPUT/DEP/rust.deps" | xargs -I {} bash -c 'rust-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/rust.potential"
}

secretFinding() {
  if [[ -n "$ORG" ]]; then
    trufflehog github --only-verified --token="$GITHUB_TOKEN" \
      --issue-comments --pr-comments --gist-comments --include-members \
      --archive-max-depth=50 --org="$ORG"
  elif [[ -n "$USER" ]]; then
    trufflehog filesystem --only-verified $OUTPUT
  elif [[ -n "$FOLDER" ]]; then
    trufflehog filesystem --only-verified $OUTPUT
  elif [[ -n "$GITLAB" ]]; then
    trufflehog filesystem --only-verified $OUTPUT
  fi
}

report() {
  warn "[+] Scan completed for $TARGET — results in $OUTPUT"
  echo
  notice "=== POTENTIAL FINDINGS SUMMARY ==="
  for dep_file in "$OUTPUT/DEP"/*.potential; do
    if [[ -f "$dep_file" ]]; then
      count=$(wc -l < "$dep_file" 2>/dev/null || echo "0")
      type=$(basename "$dep_file" .potential)
      if [[ "$count" -gt 0 ]]; then
        warn "$type: $count potential vulnerabilities"
      else
        notice "$type: $count potential vulnerabilities"
      fi
    fi
  done
}

# ------------------------------
# Main Execution
# ---------------------------

main() {
  if [[ -n "$ORG" ]]; then
    cloneOrg
  elif [[ -n "$USER" ]]; then
    cloneUser
  elif [[ -n "$FOLDER" ]]; then
    useLocalFolder
  elif [[ -n "$GITLAB" ]]; then
    cloneGitlabGroup
  fi

  node main.js "$OUTPUT" "$OUTPUT/extracted-npm.potential"
  getDependencies
  checkDependencies
  brokenSupplychain
  secretFinding
  report
}

main
