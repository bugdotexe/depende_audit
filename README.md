# Depende Audit (Enterprise Workflow)

This repo contains a **multi-signal dependency confusion + supply-chain download audit** toolkit.

It is designed for **bug bounty** and **enterprise AppSec** workflows:

- **Repo/org scans**: clone many repos, extract dependencies across ecosystems, verify registries, and print file-level attribution.
- **HAR/web scans**: extract JavaScript/NPM dependency hints from captured traffic (HAR) and verify claimable NPM names.
- **URL/download source scans**: find risky download sources (GitHub releases, S3/GCS/Azure/CDN, HTTP/IP) and attach **takeover feasibility signals**.

## Contents

- `main.sh` — org/user/folder scanner (multi-ecosystem) + URL audit integration
- `audit.js` — HAR supply-chain scanner (JS/NPM)
- `url-audit.js` — URL extraction + download source risk + takeover feasibility signals
- `.dependeauditignore` — optional repo-specific ignore rules

---

## 1) Setup

### 1.1 System dependencies

You need:

- **bash**
- **nodejs** (>= 18 recommended)
- **jq**
- **curl**
- **git**

For `main.sh` you also need:

- `ghorg` (clones org/user repos)
- `anew` (de-duplicates output; part of `anew` / `github.com/tomnomnom/anew`)

If you don’t have `ghorg`, you can still scan a local folder using `-f`.

### 1.2 Install Node dependencies

From this repo root:

```bash
npm install
```

### 1.3 Install ghorg (WSL/Linux)

```bash
sudo apt-get update
sudo apt-get install -y golang-go
go install github.com/gabrie30/ghorg@latest
export PATH="$HOME/go/bin:$PATH"
```

`main.sh` also calls `ensure_path()` to include `$HOME/go/bin`, so you usually don’t need to export PATH manually after install.

### 1.4 GitHub token (IMPORTANT)

To clone org/user repos via `ghorg`, you need a GitHub Personal Access Token (PAT).

Set it **as an environment variable** (recommended):

```bash
export GITHUB_TOKEN="<YOUR_PAT>"
```

or

```bash
export GHORG_GITHUB_TOKEN="<YOUR_PAT>"
```

You can also pass a token explicitly:

```bash
./main.sh -o replit --token "<YOUR_PAT>"
```

### Do NOT paste tokens in chat / logs
If a token leaks, **revoke/rotate it immediately**.

---

## 2) Repo / Org / Folder scan (`main.sh`)

### 2.1 Scan an org

```bash
./main.sh -o replit
```

Outputs are stored under:

```text
/tmp/<target>/DEP/
```

Key files:

- `sources.log` — dependency → file attribution
- `*.deps` — extracted dependency lists per ecosystem
- `*.potential` — registry-missing candidates (possible confusion)
- `url-findings.json` — URL findings + takeover signals

### 2.2 Production-only mode

This reduces noise from fixtures/tests by filtering verification to dependencies that appear outside default ignored paths:

```bash
./main.sh -o replit --production-only
```

### 2.3 Scan a local folder

```bash
./main.sh -f /path/to/source
```

### 2.4 Ignore rules

Default ignores include common noise:

`test/`, `tests/`, `__tests__/`, `spec/`, `examples/`, `fixtures/`, `test_resources/`, `node_modules/`, `dist/`, `build/`, etc.

Add repo-specific patterns in `.dependeauditignore`.

---

## 3) URL audit (`url-audit.js`)

You can run URL extraction directly:

```bash
node url-audit.js --root /tmp/replit --out /tmp/replit/DEP/url-findings.json --github-check
```

### What “takeover feasibility” means
`url-audit.js` attaches **best-effort, non-invasive** signals:

- `takeover.github`: owner/repo exists vs missing (404)
- `takeover.bucket`: bucket/container root probe (exists-private / exists-public / missing-ish)
- `takeover.domain`: host reachability (reachable/unreachable)

These checks do **not** prove you can take over a bucket or org; they identify **obvious missing/unreachable** candidates.

---

## 4) HAR audit (`audit.js`)

Scan a directory of HAR files:

```bash
node audit.js ./test --mode default --out findings.json --concurrency 15
```

Modes:

- `default`: verifies high-confidence sources by default (low noise)
- `strict`: higher minScore
- `paranoid`: includes string-literal + webpack comment sources (higher recall, higher noise)

Useful flags:

- `--verify-sources ast,sourcemap,...`
- `--concurrency 15`

---

## 5) Interpreting results (Important)

### Dependency confusion findings
If a package name is **missing** from the public registry, it *might* be claimable.
However, many false positives can occur from:

- test fixtures (`test_resources/`)
- telemetry keys
- random string literals

Always validate:
- whether the name is actually used as a dependency (lockfile, import graph)
- whether the target installs from a private registry/scope

### URL/download findings
“Risky downloads” are **supply-chain** risks:

- third-party binaries/configs
- buckets and CDNs

Mitigations are usually:
- checksum pinning (sha256)
- signature verification (GPG/cosign)
- allowlists

---

## 6) Recommended enterprise workflow

1) **Org scan** (production-only)
```bash
./main.sh -o <org> --production-only
```

2) Review:
- `/tmp/<org>/DEP/*.potential`
- `/tmp/<org>/DEP/sources.log`
- `/tmp/<org>/DEP/url-findings.json`

3) For web apps, capture HAR(s) and run:
```bash
node audit.js <har_dir> --mode default --concurrency 15
```

---

## Troubleshooting

- If `ghorg` says token missing: set `GITHUB_TOKEN` or pass `--token`.
- If URL scanning outputs too many files: use `--max-files`.
