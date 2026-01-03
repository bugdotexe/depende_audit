#!/bin/bash

sourcemaps=$1

# 1. Check if input file exists
if [ -z "$sourcemaps" ]; then
    echo "Usage: $0 <list_of_js_map_urls>"
    exit 1
fi

success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

while IFS= read -r map; do
    [ -z "$map" ] && continue
    debug "Extracting : $map"

    # 2. Optimized Extraction Pipeline
    curl -s "$map" | \
    jq -r '.sources[]?' 2>/dev/null | \
    grep "node_modules" | \
    # Regex explanation: Match node_modules/, then capture either (@scope/pkg) OR (pkg)
    sed -E 's/.*node_modules\/((@[^/]+\/[^/]+)|([^/]+)).*/\1/' | \
    # 3. Filter out invalid names (starts with dot or underscore)
    grep -vE "^(\.|_)" | \
    sort -u | \
    while read -r pkg; do
        # 4. Check Registry
        status=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
        if [ "$status" -eq 404 ]; then
            success "Available: $pkg"
        elif [ "$status" -eq 200 ]; then
            # Optional: Comment this out to reduce noise
            echo "Example public pkg: $pkg" > /dev/null
        fi
    done

done < "$sourcemaps"#!/bin/bash

sourcemaps=$1

# 1. Check if input file exists
if [ -z "$sourcemaps" ]; then
    echo "Usage: $0 <list_of_js_map_urls>"
    exit 1
fi

success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

while IFS= read -r map; do
    [ -z "$map" ] && continue
    debug "Extracting : $map"

    # 2. Optimized Extraction Pipeline
    curl -s "$map" | \
    jq -r '.sources[]?' 2>/dev/null | \
    grep "node_modules" | \
    # Regex explanation: Match node_modules/, then capture either (@scope/pkg) OR (pkg)
    sed -E 's/.*node_modules\/((@[^/]+\/[^/]+)|([^/]+)).*/\1/' | \
    # 3. Filter out invalid names (starts with dot or underscore)
    grep -vE "^(\.|_)" | \
    sort -u | \
    while read -r pkg; do
        # 4. Check Registry
        status=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
        if [ "$status" -eq 404 ]; then
            success "Available: $pkg"
        elif [ "$status" -eq 200 ]; then
            # Optional: Comment this out to reduce noise
            echo "Example public pkg: $pkg" > /dev/null
        fi
    done

done < "$sourcemaps"
