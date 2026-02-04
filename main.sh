#!/bin/bash

# ==============================================================================
# Depende Audit - v3.5 (Source Tracing Edition)
# Features: File-level attribution, GitHub False Positive elimination
# ==============================================================================

# Colors
notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
crit()   { printf '\e[1;31m[CRITICAL]\e[0m %s\n' "$*"; }

# 1. Pre-flight Checks
check_requirements() {
    local tools=("ghorg" "trufflehog" "anew" "jq" "node" "curl")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            err "Required tool '$tool' is missing."
            exit 1
        fi
    done
}

ensure_path() {
    # Ensure Go-installed tools (like ghorg) are discoverable in WSL.
    export PATH="$HOME/go/bin:$PATH"
}

# ==============================================================================
# Ignore Rules (Enterprise Noise Reduction)
# - Default ignores remove test fixtures/examples/vendor dirs.
# - You can extend with .dependeauditignore (one pattern per line, glob-like)
# ==============================================================================

DEFAULT_IGNORE_REGEX='/(node_modules|\.git|dist|build|target|vendor|\.venv|venv|__pycache__|coverage|\.cache|\.next|\.nuxt|\.tox|\.idea|\.vscode|test|tests|__tests__|spec|specs|example|examples|mock|mocks|fixture|fixtures|testdata|test_resources)(/|$)'

# If a finding is ONLY present inside ignored paths, we still want to show a source.
# So we log sources before applying ignore in some extractors.

load_ignore_regex() {
    IGNORE_REGEX="$DEFAULT_IGNORE_REGEX"
    if [[ -f ".dependeauditignore" ]]; then
        # Convert simple glob-ish patterns into a regex OR list
        # Supported lines:
        #   **/path/**   -> path segment match
        #   test_resources -> segment match
        # Comments (#) and blank lines ignored.
        local extra=""
        while IFS= read -r line; do
            line=$(echo "$line" | sed 's/#.*$//' | xargs)
            [[ -z "$line" ]] && continue
            line=$(echo "$line" | sed 's|\.|\\.|g; s|\*\*|.*|g; s|\*|[^/]*|g; s|\?|.|g')
            extra+="|$line"
        done < ".dependeauditignore"
        if [[ -n "$extra" ]]; then
            IGNORE_REGEX="$IGNORE_REGEX$extra"
        fi
    fi
}

should_ignore_path() {
    local p="$1"
    echo "$p" | grep -Eq "$IGNORE_REGEX"
}

# 2. Arguments
USER=""; ORG=""; FOLDER=""; GITLAB=""; PRODUCTION_ONLY=0; TOKEN=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -u|--user)   USER=$2; shift 2 ;;
    -o|--org)    ORG=$2; shift 2 ;;
    -f|--folder) FOLDER=$2; shift 2 ;;
    -g|--gitlab) GITLAB=$2; shift 2 ;;
    --production-only) PRODUCTION_ONLY=1; shift 1 ;;
    --token) TOKEN=$2; shift 2 ;;
    *) warn "Usage: bash main.sh -u <USER> | -o <ORG> | -f <FOLDER>"; exit 1 ;;
  esac
done

# Prefer env tokens (do not print them). Support GHORG_GITHUB_TOKEN as well.
if [[ -z "$TOKEN" ]]; then
  TOKEN="${GHORG_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
fi

TARGET=${ORG:-${USER:-${GITLAB:-$(basename "$FOLDER")}}}
OUTPUT="/tmp/${TARGET}"
mkdir -p "$OUTPUT/DEP"
SOURCES_LOG="$OUTPUT/DEP/sources.log"
: > "$SOURCES_LOG" # Clear log

load_ignore_regex

# 3. Source Acquisition
acquire_source() {
    notice "Acquiring source for $TARGET..."
    if [[ -n "$ORG" ]]; then
        if [[ -z "$TOKEN" ]]; then
            warn "No GitHub token available; skipping acquisition. Set GITHUB_TOKEN/GHORG_GITHUB_TOKEN or pass --token."
            return 0
        fi
        ghorg clone "$ORG" --quiet -p "$OUTPUT" -t "$TOKEN" --skip-forks --skip-archived
    elif [[ -n "$USER" ]]; then
        if [[ -z "$TOKEN" ]]; then
            warn "No GitHub token available; skipping acquisition. Set GITHUB_TOKEN/GHORG_GITHUB_TOKEN or pass --token."
            return 0
        fi
        ghorg clone "$USER" --clone-type=user --quiet -p "$OUTPUT" -t "$TOKEN" --skip-archived
    elif [[ -n "$FOLDER" ]]; then
        cp -r "$FOLDER"/* "$OUTPUT/" 2>/dev/null
    elif [[ -n "$GITLAB" ]]; then
        ghorg clone "$GITLAB" --scm=gitlab --path="$OUTPUT"
    fi
}

should_verify_path() {
    # In production-only mode we do not verify deps from ignored paths.
    local p="$1"
    if [[ "$PRODUCTION_ONLY" -eq 1 ]] && should_ignore_path "$p"; then
        return 0
    fi
    return 1
}

filter_deps_by_sources() {
    # Reads deps from stdin and only outputs those that have at least one source
    # outside ignored paths when --production-only is enabled.
    local dep
    while read -r dep; do
        [[ -z "$dep" ]] && continue
        if [[ "$PRODUCTION_ONLY" -eq 1 ]]; then
            # If there exists a source line for this dep where the path is NOT ignored, keep it.
            if grep -F "$dep " "$SOURCES_LOG" | awk '{print $2}' | grep -Ev "$DEFAULT_IGNORE_REGEX" | head -n 1 | grep -q .; then
                echo "$dep"
            fi
        else
            echo "$dep"
        fi
    done
}

# 4. Check Functions (Smart GitHub Check)
check_pypi() {
    local code=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$1/json")
    [[ "$code" -eq 404 ]] && echo "$1"
}

check_ruby() {
    local code=$(curl -s -o /dev/null -w "%{http_code}" "https://rubygems.org/api/v1/gems/$1.json")
    [[ "$code" -eq 404 ]] && echo "$1"
}

check_go() {
    local pkg=$1
    
    # 1. Smart GitHub Check: If it lives on GitHub, check if the REPO exists.
    # If the repo exists (200), it's NOT a dependency confusion risk.
    if [[ "$pkg" == github.com/* ]]; then
        # Extract Owner/Repo (e.g., github.com/DataDog/datadog-agent)
        local repo_root=$(echo "$pkg" | cut -d/ -f1-3)
        local gh_code=$(curl -s -o /dev/null -w "%{http_code}" -L "https://$repo_root")
        
        # If GitHub says 200 OK, the repo belongs to someone. Safe.
        if [[ "$gh_code" -eq 200 ]]; then
            return
        fi
        # If 404, the user/repo is missing => VULNERABLE to takeover.
        echo "$pkg"
        return
    fi

    # 2. Standard Proxy Check for non-GitHub packages (gopkg.in, etc.)
    local code=$(curl -s -o /dev/null -w "%{http_code}" "https://proxy.golang.org/$1/@v/list")
    [[ "$code" -eq 404 ]] && echo "$1"
}

check_gopkg_in() {
    # gopkg.in/<user>/<repo>.vN maps to github.com/<user>/<repo>
    # If GitHub repo does not exist, takeover risk can exist.
    local pkg="$1"
    # example: gopkg.in/yaml.v3 (special case) or gopkg.in/DataDog/dd-trace-go.v1
    if [[ "$pkg" =~ ^gopkg\.in\/([^\/]+)\/([^\/]+)\.v[0-9]+$ ]]; then
        local owner="${BASH_REMATCH[1]}"
        local repo="${BASH_REMATCH[2]}"
        local code=$(curl -s -o /dev/null -w "%{http_code}" "https://github.com/$owner/$repo")
        [[ "$code" -eq 404 ]] && echo "$pkg"
        return
    fi
    # example: gopkg.in/yaml.v3 => maps to github.com/go-yaml/yaml
    if [[ "$pkg" =~ ^gopkg\.in\/yaml\.v[0-9]+$ ]]; then
        local code=$(curl -s -o /dev/null -w "%{http_code}" "https://github.com/go-yaml/yaml")
        [[ "$code" -eq 404 ]] && echo "$pkg"
        return
    fi
}

check_action() {
    local repo=$(echo "$1" | cut -d'@' -f1)
    local code=$(curl -s -o /dev/null -w "%{http_code}" "https://github.com/$repo")
    [[ "$code" -eq 404 ]] && echo "$repo"
}

check_maven() {
    # Input format: groupId:artifactId
    # Maven Central search returns HTTP 200 even when not found, so we parse numFound.
    local ga="$1"
    local g="${ga%%:*}"
    local a="${ga##*:}"
    [[ -z "$g" || -z "$a" || "$g" == "$a" ]] && return
    local q="g:%22${g}%22+AND+a:%22${a}%22"
    local url="https://search.maven.org/solrsearch/select?q=${q}&rows=0&wt=json"
    local num=$(curl -s "$url" | jq -r '.response.numFound // 0' 2>/dev/null)
    [[ "$num" == "0" ]] && echo "$ga"
}

check_nuget() {
    # NuGet v3 flat container
    local name=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    local code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.nuget.org/v3-flatcontainer/${name}/index.json")
    [[ "$code" -eq 404 ]] && echo "$1"
}

check_packagist() {
    # composer package: vendor/name
    local code=$(curl -s -o /dev/null -w "%{http_code}" "https://repo.packagist.org/p2/$1.json")
    [[ "$code" -eq 404 ]] && echo "$1"
}

check_crates() {
    # crates.io returns 200 with JSON for existing crates, 404 for missing
    local code=$(curl -s -o /dev/null -w "%{http_code}" "https://crates.io/api/v1/crates/$1")
    [[ "$code" -eq 404 ]] && echo "$1"
}

export -f check_pypi check_ruby check_go check_gopkg_in check_action check_crates check_maven check_nuget check_packagist

# Helper to trace source
# Usage: echo "pkg_name source_file" | trace_add
trace_add() {
    # Appends to the source log
    cat >> "$SOURCES_LOG"
}

# 5. Organized Extraction (With Source Logging)
getDependencies() {
    echo ""
    notice "=== EXTRACTING DEPENDENCIES ==="
    
    # JS/NPM (via main.js)
    if [[ -f "./main.js" ]]; then
        notice "[-] Scanning JavaScript (AST & SourceMaps)..."
        # Assuming main.js outputs "Available: <pkg>"
        node main.js "$OUTPUT" > "$OUTPUT/DEP/js_scan.log"
        grep "Available:" "$OUTPUT/DEP/js_scan.log" | awk '{print $2}' | anew "$OUTPUT/DEP/npm.potential"
    fi

    # NPM (package.json)
    notice "[-] Scanning NPM (package.json)..."
    find "$OUTPUT" -name "package.json" -not -path "*/node_modules/*" | while read -r file; do
        should_ignore_path "$file" && continue
        # Extract deps and prepend filename
        jq -r '(.dependencies // {}), (.devDependencies // {}) | keys[]' "$file" 2>/dev/null | \
        while read -r dep; do
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/npm.deps"

    # Python (requirements.txt)
    notice "[-] Scanning Python (requirements.txt)..."
    find "$OUTPUT" -type f \( -name "*requirements*.txt" -o -name "*.pip" \) | while read -r file; do
        # Always log sources, even if ignored (for transparency)
        # Better PEP508-ish cleanup:
        # - strip comments
        # - ignore options (-r, -e, --index-url, etc)
        # - extract package name before extras/specifiers
        grep -vE '^\s*#' "$file" | \
          grep -vE '^\s*(-r|-e|--|git\+|https?://)' | \
          sed 's/#.*$//' | \
          sed 's/\\s\+//g' | \
          sed -E 's/^([A-Za-z0-9_.-]+).*/\1/' | \
        while read -r dep; do
            [ -z "$dep" ] && continue
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/pip.deps"

    # Ruby (Gemfile)
    notice "[-] Scanning Ruby (Gemfile)..."
    find "$OUTPUT" -name "Gemfile" | while read -r file; do
        should_ignore_path "$file" && continue
        grep -E "^[[:space:]]*gem" "$file" | sed -E "s/^[[:space:]]*gem[[:space:]]+['\"]([^'\"]+)['\"].*/\1/" | \
        while read -r dep; do
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/ruby.deps"

    # Go (go.mod)
    notice "[-] Scanning Go (go.mod)..."
    find "$OUTPUT" -name "go.mod" | while read -r file; do
        # Always log sources, even if ignored (for transparency)
        awk '/^require/ { if ($2 != "(") print $2 } /^\)/ {in_block=0} /^require \(/ {in_block=1} in_block && $1 != "require" {print $1}' "$file" | \
        while read -r dep; do
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/go.deps"

    # GitHub Actions
    notice "[-] Scanning GitHub Actions..."
    find "$OUTPUT" -path "*/.github/workflows/*" \( -name "*.yml" -o -name "*.yaml" \) | while read -r file; do
        should_ignore_path "$file" && continue
        grep -Eho "uses: [a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+" "$file" | awk '{print $2}' | \
        while read -r dep; do
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/actions.deps"

    # Maven (pom.xml, gradle)
    notice "[-] Scanning Maven/Gradle (pom.xml/build.gradle)..."
    # pom.xml: groupId/artifactId pairs (best-effort)
    find "$OUTPUT" -name "pom.xml" | while read -r file; do
        # Extract <groupId> and <artifactId> in dependencies blocks; best-effort regex.
        # This will not be perfect but captures many real-world cases.
        awk 'BEGIN{g="";a=""}
             /<groupId>[^<]+<\/groupId>/ {g=$0; sub(/.*<groupId>/,"",g); sub(/<\/.*/,"",g)}
             /<artifactId>[^<]+<\/artifactId>/ {a=$0; sub(/.*<artifactId>/,"",a); sub(/<\/.*/,"",a);
                if(g!="" && a!=""){print g ":" a; g=""; a=""}
             }' "$file" | while read -r dep; do
                [ -z "$dep" ] && continue
                echo "$dep $file" >> "$SOURCES_LOG"
                echo "$dep"
             done
    done | sort -u | anew "$OUTPUT/DEP/maven.deps"

    # Gradle: implementation 'group:artifact:version' or "group:artifact:version"
    find "$OUTPUT" -name "build.gradle" -o -name "build.gradle.kts" | while read -r file; do
        grep -Eho "['\"][A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[^'\"]+['\"]" "$file" | sed -E "s/^['\"]|['\"]$//g" | awk -F: '{print $1":"$2}' | while read -r dep; do
            [ -z "$dep" ] && continue
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/maven.deps"

    # NuGet (.csproj, packages.config)
    notice "[-] Scanning NuGet (.csproj/packages.config)..."
    find "$OUTPUT" -name "*.csproj" -o -name "packages.config" -o -name "packages.lock.json" | while read -r file; do
        # csproj: <PackageReference Include="X" ...>
        grep -Eho 'PackageReference[^>]+Include="[^"]+"' "$file" 2>/dev/null | sed -E 's/.*Include="([^"]+)".*/\1/' | while read -r dep; do
            [ -z "$dep" ] && continue
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
        # packages.config: id="X"
        grep -Eho 'id="[^"]+"' "$file" 2>/dev/null | sed -E 's/id="([^"]+)"/\1/' | while read -r dep; do
            [ -z "$dep" ] && continue
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/nuget.deps"

    # Composer
    notice "[-] Scanning Composer (composer.json)..."
    find "$OUTPUT" -name "composer.json" | while read -r file; do
        jq -r '(.require // {}), (."require-dev" // {}) | keys[]' "$file" 2>/dev/null | while read -r dep; do
            [ -z "$dep" ] && continue
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/composer.deps"

    # URL / download-source extraction (supply chain takeover)
    notice "[-] Scanning URL download sources (GitHub/S3/GCS/Azure/CDN)..."
    if command -v node &>/dev/null && [[ -f "./url-audit.js" ]]; then
        # Includes takeover feasibility checks in output
        node ./url-audit.js --root "$OUTPUT" --out "$OUTPUT/DEP/url-findings.json" --github-check >/dev/null 2>&1 || true
    fi

    # Rust (Cargo)
    notice "[-] Scanning Rust (Cargo.toml/Cargo.lock)..."
    # Cargo.toml: parse dependency tables (best-effort)
    find "$OUTPUT" -name "Cargo.toml" | while read -r file; do
        should_ignore_path "$file" && continue
        # capture lines like: name = "1.2" or name = { ... }
        # ignore section headers and local path/git deps are still names (can be confusion if resolved via registry elsewhere)
        awk '
            BEGIN{in_deps=0}
            /^\[dependencies\]/ {in_deps=1; next}
            /^\[dev-dependencies\]/ {in_deps=1; next}
            /^\[build-dependencies\]/ {in_deps=1; next}
            /^\[/ {in_deps=0}
            in_deps && $0 ~ /^[A-Za-z0-9_-]+[[:space:]]*=/ {print $1}
        ' "$file" | while read -r dep; do
            [ -z "$dep" ] && continue
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/crates.deps"

    # Cargo.lock: authoritative list (names appear as `name = "crate"`)
    find "$OUTPUT" -name "Cargo.lock" | while read -r file; do
        should_ignore_path "$file" && continue
        grep -E '^name = "[A-Za-z0-9_-]+"' "$file" | sed -E 's/^name = "([A-Za-z0-9_-]+)"/\1/' | while read -r dep; do
            [ -z "$dep" ] && continue
            echo "$dep $file" >> "$SOURCES_LOG"
            echo "$dep"
        done
    done | sort -u | anew "$OUTPUT/DEP/crates.deps"
}

# 6. Verification
verify() {
    echo ""
    notice "=== VERIFYING REGISTRIES ==="
    
    # Run in parallel
    [[ -s "$OUTPUT/DEP/pip.deps" ]] && cat "$OUTPUT/DEP/pip.deps" | filter_deps_by_sources | xargs -P 15 -I {} bash -c 'check_pypi "$@"' _ {} | anew "$OUTPUT/DEP/pip.potential"
    [[ -s "$OUTPUT/DEP/ruby.deps" ]] && cat "$OUTPUT/DEP/ruby.deps" | xargs -P 15 -I {} bash -c 'check_ruby "$@"' _ {} | anew "$OUTPUT/DEP/ruby.potential"
    # Go: split out gopkg.in to a smarter GitHub existence check
    if [[ -s "$OUTPUT/DEP/go.deps" ]]; then
        cat "$OUTPUT/DEP/go.deps" | filter_deps_by_sources | grep -vE '^gopkg\.in/' | xargs -P 15 -I {} bash -c 'check_go "$@"' _ {} | anew "$OUTPUT/DEP/go.potential"
        cat "$OUTPUT/DEP/go.deps" | filter_deps_by_sources | grep -E '^gopkg\.in/' | xargs -P 15 -I {} bash -c 'check_gopkg_in "$@"' _ {} | anew "$OUTPUT/DEP/go.potential"
    fi
    [[ -s "$OUTPUT/DEP/actions.deps" ]] && cat "$OUTPUT/DEP/actions.deps" | xargs -P 15 -I {} bash -c 'check_action "$@"' _ {} | anew "$OUTPUT/DEP/actions.potential"
    [[ -s "$OUTPUT/DEP/crates.deps" ]] && cat "$OUTPUT/DEP/crates.deps" | xargs -P 15 -I {} bash -c 'check_crates "$@"' _ {} | anew "$OUTPUT/DEP/crates.potential"
    [[ -s "$OUTPUT/DEP/maven.deps" ]] && cat "$OUTPUT/DEP/maven.deps" | xargs -P 15 -I {} bash -c 'check_maven "$@"' _ {} | anew "$OUTPUT/DEP/maven.potential"
    [[ -s "$OUTPUT/DEP/nuget.deps" ]] && cat "$OUTPUT/DEP/nuget.deps" | xargs -P 15 -I {} bash -c 'check_nuget "$@"' _ {} | anew "$OUTPUT/DEP/nuget.potential"
    [[ -s "$OUTPUT/DEP/composer.deps" ]] && cat "$OUTPUT/DEP/composer.deps" | xargs -P 15 -I {} bash -c 'check_packagist "$@"' _ {} | anew "$OUTPUT/DEP/composer.potential"
}

# 7. Reporting with Sources
report() {
    echo ""
    notice "=== FINAL FINDINGS ==="
    found=0
    for dep_file in "$OUTPUT/DEP"/*.potential; do
        if [[ -s "$dep_file" ]]; then
            type=$(basename "$dep_file" .potential)
            crit "VULNERABILITY ($type):"
            
            while read -r pkg; do
                # Grep the source file from our log
                # We use 'head -1' because a popular package might be in many files; showing one source is usually enough to start
                source_file=$(grep -F "$pkg " "$SOURCES_LOG" | head -n 1 | awk '{print $2}')
                
                if [[ -n "$source_file" ]]; then
                    # Clean up path for display (remove /tmp/Target)
                    clean_path=$(echo "$source_file" | sed "s|$OUTPUT/||")
                    echo "  ↳ $pkg (Found in: $clean_path)"
                else
                    echo "  ↳ $pkg"
                fi
            done < "$dep_file"
            
            found=1
        fi
    done
    
    if [[ "$found" -eq 0 ]]; then
        echo -e "\n\e[1;32m[+] No dependency confusion vulnerabilities found.\e[0m"
    fi

    if [[ -s "$OUTPUT/DEP/url-findings.json" ]]; then
        echo ""
        notice "=== URL / DOWNLOAD SOURCE FINDINGS (see $OUTPUT/DEP/url-findings.json) ==="
        python3 - <<PY 2>/dev/null || true
import json
p = "$OUTPUT/DEP/url-findings.json"
try:
    d=json.load(open(p))
except Exception:
    raise SystemExit(0)
risky=[f for f in d.get('findings',[]) if f.get('category')=='download' and f.get('risks')]
print('Total URLs:', d.get('count',0))
print('Risky download URLs:', len(risky))
for f in risky[:10]:
    print('  -', f.get('url'))
PY
    fi
}

ensure_path
check_requirements
acquire_source
getDependencies
verify
report

