#!/usr/bin/env node
/**
 * url-audit.js - Repo URL + Download Source Takeover Analyzer
 *
 * Goals:
 * - Extract URLs / repo references from all repo files (high recall)
 * - Flag risky download sources (GitHub personal namespace, raw IP/HTTP, S3 buckets, etc.)
 * - Optionally check GitHub namespace/repo existence (takeover feasibility)
 *
 * Usage:
 *   node url-audit.js --root <dir> [--out out.json] [--github-check] [--max-files 200000]
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const fg = require('fast-glob');

function parseArgs(argv) {
  const out = {
    root: process.cwd(),
    outFile: 'url-findings.json',
    githubCheck: false,
    maxFiles: 200000,
  };
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--root' && args[i + 1]) out.root = args[++i];
    else if (a === '--out' && args[i + 1]) out.outFile = args[++i];
    else if (a === '--github-check') out.githubCheck = true;
    else if (a === '--max-files' && args[i + 1]) out.maxFiles = Number(args[++i]);
    else if (a === '-h' || a === '--help') out.help = true;
  }
  return out;
}

function isProbablyBinary(buf) {
  // If it contains many NUL bytes early, treat as binary.
  const sample = buf.subarray(0, Math.min(buf.length, 8000));
  let nul = 0;
  for (const b of sample) if (b === 0) nul++;
  return nul > 0;
}

function extractUrlsFromLine(line) {
  const out = [];
  // http(s) URLs
  const urlRe = /https?:\/\/[^\s"'<>\)\]]+/g;
  let m;
  while ((m = urlRe.exec(line)) !== null) out.push(m[0]);

  // github.com/org/repo without scheme
  const ghBare = /\bgithub\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\b/g;
  while ((m = ghBare.exec(line)) !== null) out.push('https://' + m[0]);

  // git@host:org/repo(.git)
  const gitSsh = /\bgit@([A-Za-z0-9.-]+):([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\b/g;
  while ((m = gitSsh.exec(line)) !== null) out.push(`ssh://git@${m[1]}/${m[2]}/${m[3]}`);

  return out;
}

function normalizeUrl(u) {
  try {
    // Remove trailing punctuation common in docs
    u = u.replace(/[),.;]+$/, '');
    const x = new URL(u);
    // Drop fragment (keep query)
    x.hash = '';
    // Canonicalize path to reduce duplicates like /foo/// and trailing slash on files
    x.pathname = x.pathname.replace(/\/+/g, '/');
    if (x.pathname.length > 1) x.pathname = x.pathname.replace(/\/+$/, '');
    return x.toString();
  } catch {
    return null;
  }
}

function classifyUrl(url) {
  let u;
  try { u = new URL(url); } catch { return { category: 'unknown', risks: [] }; }
  const host = u.hostname.toLowerCase();
  const risks = [];

  const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  if (u.protocol === 'http:') risks.push({ id: 'insecure-http', severity: 'high', note: 'HTTP URL (MITM risk)' });
  if (isIp) risks.push({ id: 'ip-host', severity: 'high', note: 'Direct IP host (hard to verify ownership; MITM/BGP risk)' });

  // GitHub releases/download patterns
  if (host === 'github.com') {
    const parts = u.pathname.split('/').filter(Boolean);
    const owner = parts[0];
    const repo = parts[1];
    const isReleaseDownload = parts[2] === 'releases' && parts[3] === 'download';
    if (owner && repo) {
      if (isReleaseDownload) {
        risks.push({ id: 'github-release-download', severity: 'medium', note: 'Downloads binaries/configs from GitHub releases' });
      }
      // Heuristic: personal namespace (not org) is hard to know; flag as info for review
      // A better enterprise rule is to compare against an expected allowlist.
      if (!/[A-Z]/.test(owner) && owner.includes('-')) {
        // keep low, avoid noise
      }
    }
  }

  // AWS S3
  // - virtual-hosted-style: bucket.s3.amazonaws.com/key
  // - path-style: s3.amazonaws.com/bucket/key
  // - regional: bucket.s3.<region>.amazonaws.com
  const s3Virtual = /^(?<bucket>[a-z0-9.-]{3,63})\.s3[.-][a-z0-9-]+\.amazonaws\.com$|^(?<bucket2>[a-z0-9.-]{3,63})\.s3\.amazonaws\.com$/.exec(host);
  if (s3Virtual) {
    risks.push({ id: 's3-bucket-download', severity: 'medium', note: 'Downloads from S3 bucket; ensure bucket ownership + integrity checks' });
  }
  if (host === 's3.amazonaws.com' || host.endsWith('.s3.amazonaws.com')) {
    risks.push({ id: 's3-bucket-download', severity: 'medium', note: 'Downloads from S3 bucket; ensure bucket ownership + integrity checks' });
  }

  // Generic cloud storage/CDN hints
  if (host.endsWith('storage.googleapis.com')) risks.push({ id: 'gcs-download', severity: 'medium', note: 'Downloads from GCS bucket; validate ownership + integrity' });
  if (host.endsWith('blob.core.windows.net')) risks.push({ id: 'azure-blob-download', severity: 'medium', note: 'Downloads from Azure Blob; validate ownership + integrity' });
  if (host.endsWith('cloudfront.net')) risks.push({ id: 'cdn-download', severity: 'low', note: 'Downloads from CDN; ensure origin + integrity' });

  // Classify category (rough)
  let category = 'url';
  if (host === 'github.com' && u.pathname.includes('/releases/download/')) category = 'download';
  else if (s3Virtual || host === 's3.amazonaws.com') category = 'download';
  else if (u.pathname.match(/\.(zip|tar\.gz|tgz|gz|bz2|xz|exe|msi|dmg|pkg|deb|rpm|jar|war)$/i)) category = 'download';
  else if (host.includes('api.')) category = 'api';
  return { category, risks };
}

function detectAutoExecutionHints(line) {
  const hints = [];
  const l = line.toLowerCase();
  if (l.includes('chmod') && l.includes('+x')) hints.push('chmod+x');
  if (l.includes('subprocess') || l.includes('os.system') || l.includes('exec(') || l.includes('spawn(') || l.includes('popen')) hints.push('exec');
  if (l.includes('wget ') || l.includes('curl ') || l.includes('requests.get') || l.includes('urllib')) hints.push('download');
  if (l.includes('tar ') || l.includes('zipfile') || l.includes('tarfile') || l.includes('unzip')) hints.push('extract');
  return hints;
}

function requestStatus(url) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.request(url, { method: 'HEAD' }, (res) => {
      resolve({ status: res.statusCode || 0 });
      res.resume();
    });
    req.on('error', () => resolve({ status: 0 }));
    req.setTimeout(8000, () => {
      req.destroy();
      resolve({ status: 0 });
    });
    req.end();
  });
}

function requestStatusDetailed(url) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.request(url, { method: 'HEAD' }, (res) => {
      const headers = res.headers || {};
      resolve({ status: res.statusCode || 0, headers });
      res.resume();
    });
    req.on('error', (e) => resolve({ status: 0, error: String(e && e.message ? e.message : e) }));
    req.setTimeout(8000, () => {
      req.destroy();
      resolve({ status: 0, error: 'timeout' });
    });
    req.end();
  });
}

function isLikelyGcs(url) {
  try { return new URL(url).hostname.toLowerCase() === 'storage.googleapis.com'; } catch { return false; }
}
function isLikelyS3(url) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return h === 's3.amazonaws.com' || h.endsWith('.s3.amazonaws.com') || /\.s3[.-][a-z0-9-]+\.amazonaws\.com$/.test(h);
  } catch { return false; }
}
function isLikelyAzureBlob(url) {
  try { return new URL(url).hostname.toLowerCase().endsWith('.blob.core.windows.net'); } catch { return false; }
}

function extractBucketInfo(url) {
  // Returns { provider, bucket, extra } if recognized.
  const u = new URL(url);
  const host = u.hostname.toLowerCase();
  if (host === 'storage.googleapis.com') {
    const parts = u.pathname.split('/').filter(Boolean);
    if (parts.length >= 1) return { provider: 'gcs', bucket: parts[0] };
  }
  if (host === 's3.amazonaws.com') {
    const parts = u.pathname.split('/').filter(Boolean);
    if (parts.length >= 1) return { provider: 's3', bucket: parts[0] };
  }
  // virtual hosted S3: bucket.s3.amazonaws.com or bucket.s3.region.amazonaws.com
  const m = /^(?<bucket>[a-z0-9.-]{3,63})\.s3[.-][a-z0-9-]+\.amazonaws\.com$|^(?<bucket2>[a-z0-9.-]{3,63})\.s3\.amazonaws\.com$/.exec(host);
  if (m) return { provider: 's3', bucket: m.groups.bucket || m.groups.bucket2 };

  // Azure blob: <account>.blob.core.windows.net/<container>/...
  if (host.endsWith('.blob.core.windows.net')) {
    const account = host.split('.blob.core.windows.net')[0];
    const parts = u.pathname.split('/').filter(Boolean);
    const container = parts[0];
    if (account && container) return { provider: 'azure', bucket: `${account}/${container}` };
  }

  return null;
}

async function checkBucketMissing(url) {
  // This does not “prove takeover”, but detects obvious missing buckets/accounts.
  try {
    const info = extractBucketInfo(url);
    if (!info) return null;

    if (info.provider === 'gcs') {
      const res = await requestStatusDetailed(`https://storage.googleapis.com/${info.bucket}`);
      // Common: 200 (public), 403 (exists but private), 404 (missing)
      if (res.status === 404) return { provider: 'gcs', bucket: info.bucket, status: 'missing', evidence: 'HTTP 404 at bucket root' };
      if (res.status === 403) return { provider: 'gcs', bucket: info.bucket, status: 'exists-private', evidence: 'HTTP 403 at bucket root' };
      if (res.status === 200) return { provider: 'gcs', bucket: info.bucket, status: 'exists-public', evidence: 'HTTP 200 at bucket root' };
      return { provider: 'gcs', bucket: info.bucket, status: 'unknown', evidence: `HTTP ${res.status}` };
    }

    if (info.provider === 's3') {
      const res = await requestStatusDetailed(`https://${info.bucket}.s3.amazonaws.com/`);
      // S3 missing often returns 404 with NoSuchBucket in body, but HEAD may still show 404.
      if (res.status === 404) return { provider: 's3', bucket: info.bucket, status: 'missing-or-private', evidence: 'HTTP 404 at bucket root (HEAD)' };
      if (res.status === 403) return { provider: 's3', bucket: info.bucket, status: 'exists-private', evidence: 'HTTP 403 at bucket root' };
      if (res.status === 200) return { provider: 's3', bucket: info.bucket, status: 'exists-public', evidence: 'HTTP 200 at bucket root' };
      return { provider: 's3', bucket: info.bucket, status: 'unknown', evidence: `HTTP ${res.status}` };
    }

    if (info.provider === 'azure') {
      const [account, container] = info.bucket.split('/');
      const res = await requestStatusDetailed(`https://${account}.blob.core.windows.net/${container}`);
      // 404 could be missing container or account; 403 exists private; 200 exists public
      if (res.status === 404) return { provider: 'azure', bucket: info.bucket, status: 'missing-or-private', evidence: 'HTTP 404 at container root (HEAD)' };
      if (res.status === 403) return { provider: 'azure', bucket: info.bucket, status: 'exists-private', evidence: 'HTTP 403 at container root' };
      if (res.status === 200) return { provider: 'azure', bucket: info.bucket, status: 'exists-public', evidence: 'HTTP 200 at container root' };
      return { provider: 'azure', bucket: info.bucket, status: 'unknown', evidence: `HTTP ${res.status}` };
    }
    return null;
  } catch {
    return null;
  }
}

async function checkDomainTakeoverSignals(url) {
  // Checks only for obvious “domain not resolving” signals.
  try {
    const u = new URL(url);
    const host = u.hostname;
    const res = await requestStatusDetailed(`${u.protocol}//${host}/`);
    if (res.status === 0) {
      return { status: 'unreachable', evidence: res.error || 'request failed' };
    }
    // Some CDNs return 404/403 even when alive; that's not takeover.
    return { status: 'reachable', evidence: `HTTP ${res.status}` };
  } catch {
    return null;
  }
}

async function githubExistenceCheck(url) {
  // Checks owner and repo existence for https://github.com/<owner>/<repo>/...
  try {
    const u = new URL(url);
    if (u.hostname.toLowerCase() !== 'github.com') return null;
    const parts = u.pathname.split('/').filter(Boolean);
    const owner = parts[0];
    const repo = parts[1];
    if (!owner || !repo) return null;
    const ownerUrl = `https://github.com/${owner}`;
    const repoUrl = `https://github.com/${owner}/${repo}`;
    const [o, r] = await Promise.all([requestStatus(ownerUrl), requestStatus(repoUrl)]);
    return { owner, repo, ownerStatus: o.status, repoStatus: r.status };
  } catch {
    return null;
  }
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    console.log('Usage: node url-audit.js --root <dir> [--out out.json] [--github-check] [--max-files 200000]');
    process.exit(0);
  }
  const root = path.resolve(args.root);

  const files = await fg(['**/*'], {
    cwd: root,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/target/**', '**/.venv/**'],
    suppressErrors: true,
  });

  const limited = files.slice(0, args.maxFiles);
  if (files.length > limited.length) {
    console.error(`[!] File limit hit: scanned ${limited.length}/${files.length}. Use --max-files to increase.`);
  }

  const findings = [];
  // Dedupe by normalized URL only (enterprise-friendly). We keep first occurrence as evidence.
  const seenUrl = new Set();

  for (const rel of limited) {
    const filePath = path.join(root, rel);
    let buf;
    try { buf = fs.readFileSync(filePath); } catch { continue; }
    if (isProbablyBinary(buf)) continue;

    const text = buf.toString('utf8');
    const lines = text.split(/\r?\n/);

    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];
      const urls = extractUrlsFromLine(line);
      if (urls.length === 0) continue;
      const execHints = detectAutoExecutionHints(line);

      for (const raw of urls) {
        const url = normalizeUrl(raw);
        if (!url) continue;
        if (seenUrl.has(url)) continue;
        seenUrl.add(url);
        const { category, risks } = classifyUrl(url);

        findings.push({
          url,
          file: rel,
          line: idx + 1,
          context: line.trim().slice(0, 400),
          category,
          risks,
          execHints,
        });
      }
    }
  }

  // Optional GitHub existence checks (only for findings that are GitHub URLs)
  if (args.githubCheck) {
    const gh = findings.filter(f => {
      try { return new URL(f.url).hostname.toLowerCase() === 'github.com'; } catch { return false; }
    });
    // Limit to avoid huge network load
    const uniqueRepoKeys = new Set();
    for (const f of gh) {
      try {
        const u = new URL(f.url);
        const parts = u.pathname.split('/').filter(Boolean);
        if (parts.length >= 2) uniqueRepoKeys.add(`${parts[0]}/${parts[1]}`);
      } catch {}
    }
    const repoList = Array.from(uniqueRepoKeys).slice(0, 2000);

    const repoStatus = new Map();
    // modest concurrency
    const CONC = 15;
    for (let i = 0; i < repoList.length; i += CONC) {
      const batch = repoList.slice(i, i + CONC);
      const checks = batch.map(async (r) => {
        const url = `https://github.com/${r}`;
        const info = await githubExistenceCheck(url);
        if (info) repoStatus.set(r, info);
      });
      await Promise.all(checks);
    }
    for (const f of gh) {
      try {
        const u = new URL(f.url);
        const parts = u.pathname.split('/').filter(Boolean);
        if (parts.length >= 2) {
          const k = `${parts[0]}/${parts[1]}`;
          if (repoStatus.has(k)) f.github = repoStatus.get(k);
        }
      } catch {}
    }
  }

  // Takeover feasibility checks (best-effort, non-invasive)
  // - GitHub existence: already attached as f.github
  // - Buckets: detect missing bucket-like endpoints
  // - Domains: detect unreachable host
  const downloadish = findings.filter(f => f.category === 'download');
  const CONC2 = 20;
  for (let i = 0; i < downloadish.length; i += CONC2) {
    const batch = downloadish.slice(i, i + CONC2);
    await Promise.all(batch.map(async (f) => {
      const take = {};
      // GitHub 404 check
      if (f.github) {
        if (f.github.ownerStatus === 404 || f.github.repoStatus === 404) {
          take.github = { status: 'missing', evidence: f.github };
        } else {
          take.github = { status: 'exists', evidence: f.github };
        }
      }
      // Bucket check (gcs/s3/azure)
      if (isLikelyGcs(f.url) || isLikelyS3(f.url) || isLikelyAzureBlob(f.url)) {
        const b = await checkBucketMissing(f.url);
        if (b) take.bucket = b;
      }
      // Domain reachability check
      const d = await checkDomainTakeoverSignals(f.url);
      if (d) take.domain = d;
      if (Object.keys(take).length) f.takeover = take;
    }));
  }

  fs.writeFileSync(args.outFile, JSON.stringify({ root, count: findings.length, findings }, null, 2));
  console.log(`[+] Wrote ${findings.length} URL findings to ${args.outFile}`);
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
