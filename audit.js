#!/usr/bin/env node
/**
 * AUDIT.JS - Supply Chain Scanner (v8.1 - JS/NPM Only)
 * ENGINES: AST + SourceMaps + Greedy Federation + Deep JSON
 * REMOVED: Python/PyPI logic
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const { SourceMapConsumer } = require('source-map');

// ==========================================
// 0. CLI OPTIONS
// ==========================================

function parseArgs(argv) {
    const out = {
        harDir: null,
        mode: 'default',
        minScore: null,
        outFile: 'vulnerabilities.json',
        verifySources: null, // comma-separated list
        concurrency: 8
    };
    const args = argv.slice(2);
    if (args.length === 0) return out;

    // positional: <har_directory>
    out.harDir = args[0] && !args[0].startsWith('-') ? args[0] : null;

    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === '--mode' && args[i + 1]) out.mode = args[++i];
        else if (a === '--min-score' && args[i + 1]) out.minScore = Number(args[++i]);
        else if (a === '--out' && args[i + 1]) out.outFile = args[++i];
        else if (a === '--verify-sources' && args[i + 1]) out.verifySources = args[++i];
        else if (a === '--concurrency' && args[i + 1]) out.concurrency = Number(args[++i]);
        else if (a === '-h' || a === '--help') out.help = true;
    }
    return out;
}

function logErr(...a) {
    console.error(...a);
}

function getModeConfig(mode, minScoreOverride) {
    // High recall by default, with sensible verification thresholds.
    const modes = {
        strict:   { minScore: 0.70 },
        default:  { minScore: 0.50 },
        paranoid: { minScore: 0.20 }
    };
    const m = modes[mode] || modes.default;
    return {
        mode: modes[mode] ? mode : 'default',
        minScore: Number.isFinite(minScoreOverride) ? minScoreOverride : m.minScore
    };
}

// ==========================================
// 1. CONFIGURATION & VALIDATION
// ==========================================

const NODE_BUILTINS = new Set(['assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https', 'net', 'os', 'path', 'perf_hooks', 'process', 'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'timers', 'tls', 'tty', 'url', 'util', 'v8', 'vm', 'worker_threads', 'zlib']);

// Refined NPM Validation (Anti-False Positive)
const isValidNpm = (name) => {
    if (!name || typeof name !== 'string' || name.length > 214) return false;
    const n = name.trim();
    if (NODE_BUILTINS.has(n) || n.startsWith('node:')) return false;
    if (n.startsWith('.') || n.startsWith('/') || n.startsWith('-') || n.startsWith('git') || n.startsWith('npm:') || n.includes('.js') || n.includes('.css')) return false;
    if (!/^(?:@[a-z0-9-]+\/)?[a-z0-9-._]+$/.test(n)) return false;
    
    // Noise Filter for minified vars
    const noise = new Set(['webpack', 'react', 'src', 'dist', 'app', 'undefined', 'null', 'window', 'document', 'default', 'prototype', 'anonymous', 'main', 'test']);
    if (noise.has(n.split('/')[0])) return false;

    return true;
};

// Normalize imports like "pkg/subpath" -> "pkg" and "@scope/pkg/subpath" -> "@scope/pkg"
function normalizeNpmName(raw) {
    if (!raw || typeof raw !== 'string') return null;
    let n = raw.trim();
    if (!n) return null;
    if (n.startsWith('node:')) n = n.slice(5);
    // Drop query/hash fragments
    n = n.split('?')[0].split('#')[0];
    // Reject obvious URLs/paths
    if (n.includes('://') || n.includes('\\')) return null;
    if (n.startsWith('.') || n.startsWith('/')) return null;
    // Remove common loaders prefixes
    n = n.replace(/^npm:/, '');

    // If it's scoped, keep first two parts; else keep first part.
    if (n.startsWith('@')) {
        const parts = n.split('/');
        if (parts.length >= 2) n = `${parts[0]}/${parts[1]}`;
    } else {
        n = n.split('/')[0];
    }
    return isValidNpm(n) ? n : null;
}

function isLikelyNpmFromStringLiteral(raw) {
    // Additional noise filtering specifically for string-literal harvesting.
    if (!raw || typeof raw !== 'string') return false;
    const s = raw.trim();
    if (!s) return false;
    if (s.length > 80) return false;
    // reject things that look like css sizes, versions, uuids, dates, selectors, attributes, etc.
    if (/\d+(?:\.\d+)?(?:rem|em|px|vh|vw|%)\b/i.test(s)) return false;
    if (/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+].+)?$/.test(s)) return false; // semver
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return false; // uuid
    if (/\b(aria-|data-|x-)[a-z0-9_-]+\b/i.test(s)) return false;
    if (/[\s:=]/.test(s)) return false;
    if (s.includes('.') && !s.startsWith('@')) return false; // dot is extremely noisy in literals
    if (/^[A-Z0-9_-]{2,}$/.test(s)) return false; // const-ish tokens
    if (/^[a-z]+-[a-z]+-(small|large|medium|xl|xs|sm|md|lg)$/i.test(s)) return false;
    return true;
}

function scoreForSource(source) {
    switch (source) {
        case 'ast': return 0.90;
        case 'package-json': return 0.85;
        case 'federation-shared': return 0.80;
        case 'federation-consume': return 0.75;
        case 'sourcemap': return 0.70;
        case 'string-literal': return 0.55;
        case 'webpack-comment': return 0.40;
        default: return 0.50;
    }
}

// ==========================================
// 2. SCANNING ENGINES
// ==========================================



function scanGreedyFederation(content) {
    const deps = new Set(); // Changed to Set to auto-deduplicate
    
    // Pattern 1: Shared Modules (Explicit Versioning)
    // Matches: f("package-name", "1.2.3")
    const sharedRegex = /\b[a-zA-Z0-9_.]+\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']/g;
    
    let match;
    while ((match = sharedRegex.exec(content)) !== null) {
        const pkgName = match[1];
        const version = match[2];

        // [STRICT VERSION FILTER]
        // 1. Must start with digit, ^, or ~
        if (!/^[0-9^~]/.test(version)) continue;
        
        // 2. Reject simple integers (0, 1, 4) often used for boolean/enums
        // Real packages are "1.0.0" or "^1.2", not "1"
        if (/^\d+$/.test(version)) continue;

        // 3. Reject "~0" (Common bitwise artifact)
        if (version === '~0') continue;

        // 4. Must contain a dot (Standard SemVer) unless it's a very specific range
        // This kills almost all CSS false positives
        if (!version.includes('.')) continue;

        if (isValidNpm(pkgName)) {
            // Use a string key for Set deduplication
            deps.add(JSON.stringify({ 
                name: pkgName, 
                version: version, 
                type: 'npm', 
                source: 'federation-shared' 
            }));
        }
    }

    // Pattern 2: Consumption (Default Import)
    const consumeRegex = /["']default["']\s*,\s*["'](@?[a-z0-9-./]+)["']/gi;
    
    while ((match = consumeRegex.exec(content)) !== null) {
        if (isValidNpm(match[1])) {
            deps.add(JSON.stringify({ 
                name: match[1], 
                type: 'npm', 
                source: 'federation-consume' 
            }));
        }
    }
    
    // Parse objects back from Set
    return Array.from(deps).map(item => JSON.parse(item));
}

// Add this function to your scanning engines
function scanWebpackComments(content) {
    const deps = new Set();
    // Regex to find "node_modules/package-name" in comments
    const regex = /node_modules\/(@[\w-]+\/[\w-]+|[\w-]+)/g; 
    let match;
    while ((match = regex.exec(content)) !== null) {
        if (isValidNpm(match[1])) {
            deps.add(match[1]);
        }
    }
    return Array.from(deps).map(name => ({ name, type: 'npm', source: 'webpack-comment' }));
}

// High-recall string literal harvester (best-effort)
// Extracts quoted strings and normalizes to npm package roots.
function scanStringLiterals(content) {
    const deps = new Set();
    // Handles "...", '...', and `...` (template literals are noisy; we still try)
    const strRe = /(?:"([^"\\\r\n]{1,220})"|'([^'\\\r\n]{1,220})'|`([^`\\\r\n]{1,220})`)/g;
    let m;
    while ((m = strRe.exec(content)) !== null) {
        const s = (m[1] || m[2] || m[3] || '').trim();
        if (!isLikelyNpmFromStringLiteral(s)) continue;
        const n = normalizeNpmName(s);
        if (n) deps.add(n);
    }
    return Array.from(deps).map(name => ({ name, type: 'npm', source: 'string-literal' }));
}

function parseVerifySources(arg, mode) {
    // Default: only verify higher-confidence sources (prevents 7k+ npm checks from string literals)
    const defaultsByMode = {
        strict:   new Set(['ast', 'sourcemap', 'federation-shared', 'federation-consume', 'package-json', 'asset-map']),
        default:  new Set(['ast', 'sourcemap', 'federation-shared', 'federation-consume', 'package-json', 'asset-map']),
        paranoid: new Set(['ast', 'sourcemap', 'federation-shared', 'federation-consume', 'package-json', 'asset-map', 'string-literal', 'webpack-comment'])
    };
    if (!arg) return defaultsByMode[mode] || defaultsByMode.default;
    return new Set(arg.split(',').map(s => s.trim()).filter(Boolean));
}

async function checkNpmBatch(items, concurrency) {
    const out = [];
    const queue = items.slice();
    const workers = Array.from({ length: Math.max(1, concurrency || 1) }, async () => {
        while (queue.length) {
            const item = queue.shift();
            if (!item) return;
            const status = await checkNpm(item.name);
            if (status === 'AVAILABLE') out.push(item);
        }
    });
    await Promise.all(workers);
    return out;
}
// [RESTORED] AST Engine (Parses Import/Require)
function scanJsAst(code) {
    const deps = new Set();
    const fallbackRegex = /node_modules\/((?:@[a-z0-9-._]+\/)?[a-z0-9-._]+)/gi;
    let match;
    while ((match = fallbackRegex.exec(code)) !== null) {
        if (isValidNpm(match[1])) deps.add(match[1]);
    }

    try {
        const ast = parser.parse(code, {
            sourceType: 'unambiguous',
            plugins: ['typescript', 'jsx', 'dynamicImport', 'classProperties'],
            errorRecovery: true
        });

        traverse(ast, {
            ImportDeclaration({ node }) { if (node.source?.value) deps.add(node.source.value); },
            ExportNamedDeclaration({ node }) { if (node.source?.value) deps.add(node.source.value); },
            ExportAllDeclaration({ node }) { if (node.source?.value) deps.add(node.source.value); },
            CallExpression({ node }) {
                if (node.callee.name === 'require' && node.arguments[0]?.type === 'StringLiteral') {
                    deps.add(node.arguments[0].value);
                }
                if (node.callee.type === 'Import' && node.arguments[0]?.type === 'StringLiteral') {
                    deps.add(node.arguments[0].value);
                }
            }
        });
    } catch (e) {}
    return Array.from(deps)
        .map(normalizeNpmName)
        .filter(Boolean)
        .map(n => ({ name: n, type: 'npm', source: 'ast' }));
}

// [RESTORED] Deep JSON Scanner (Covers package.json & Asset Maps)
function scanDeepJson(content) {
    const deps = [];
    try {
        const json = JSON.parse(content);
        const crawl = (obj) => {
            if (!obj || typeof obj !== 'object') return;
            
            // Asset Map Logic
            if (obj.name && (obj.source || obj.src || obj.url) && isValidNpm(obj.name)) {
                deps.push({ name: obj.name, type: 'npm', source: 'asset-map', definedSource: obj.source || obj.src || obj.url });
            }
            
            // Package.json Logic
            const keys = ['dependencies', 'devDependencies', 'peerDependencies', 'shared'];
            keys.forEach(k => {
                if (obj[k] && typeof obj[k] === 'object') {
                    Object.keys(obj[k]).forEach(pkg => { 
                        if (isValidNpm(pkg)) deps.push({ name: pkg, type: 'npm', source: 'package-json' }); 
                    });
                }
            });
            Object.values(obj).forEach(val => crawl(val));
        };
        crawl(json);
    } catch (e) {}
    return deps;
}

// [RESTORED] Source Map Scanner
async function scanSourceMap(rawMap) {
    const deps = new Set();
    try {
        const json = JSON.parse(rawMap);
        const consumer = await new SourceMapConsumer(json);
        consumer.sources.forEach(source => {
            if (source.includes('node_modules/')) {
                const parts = source.split('node_modules/').pop().split('/');
                let pkg = parts[0];
                if (pkg.startsWith('@') && parts.length > 1) pkg = `${parts[0]}/${parts[1]}`;
                if (isValidNpm(pkg)) deps.add(pkg);
            }
        });
        consumer.destroy();
    } catch (e) {}
    return Array.from(deps).map(n => ({ name: n, type: 'npm', source: 'sourcemap' }));
}

// ==========================================
// 3. MAIN ANALYZER
// ==========================================

async function analyzeHar(harPath) {
    console.log(`[*] Analyzing: ${path.basename(harPath)}`);
    const har = JSON.parse(fs.readFileSync(harPath));
    const results = new Map();

    // Helper to merge findings + keep best score
    const add = (items, sourceUrl) => items.forEach(i => {
        const normalized = normalizeNpmName(i.name) || i.name;
        const key = `${i.type}:${normalized}`;
        const score = scoreForSource(i.source);
        if (!results.has(key)) {
            results.set(key, {
                ...i,
                name: normalized,
                foundIn: sourceUrl,
                score
            });
        } else {
            const cur = results.get(key);
            if (i.version && !cur.version) cur.version = i.version;
            // preserve highest score, and keep best evidence source
            if (score > (cur.score ?? 0)) {
                cur.score = score;
                cur.source = i.source;
                cur.foundIn = sourceUrl;
            }
        }
    });

    for (const entry of har.log.entries) {
        if (!entry.response.content.text) continue;
        let content = entry.response.content.text;
        if (entry.response.content.encoding === 'base64') {
            content = Buffer.from(content, 'base64').toString('utf-8');
        }

        const url = entry.request.url.split('?')[0];
        const mime = entry.response.content.mimeType || '';

        // 1. Javascript (AST + Greedy Federation + High-recall strings + Comment hints)
        if (url.endsWith('.js') || mime.includes('javascript')) {
            add(scanGreedyFederation(content), url);
            add(scanJsAst(content), url);
            add(scanWebpackComments(content), url);
            add(scanStringLiterals(content), url);
        }

        // 2. JSON (Deep Scan)
        if (url.endsWith('.json') || mime.includes('json')) {
            add(scanDeepJson(content), url);
        }

        // 3. Source Maps
        if (url.endsWith('.map')) {
            add(await scanSourceMap(content), url);
        }
    }
    return Array.from(results.values());
}

// ==========================================
// 4. REGISTRY CHECKER & REPORTER
// ==========================================

const checkNpm = (pkg) => new Promise((resolve) => {
    https.get(`https://registry.npmjs.org/${encodeURIComponent(pkg)}`, (res) => {
        resolve(res.statusCode === 404 ? 'AVAILABLE' : 'TAKEN');
    }).on('error', () => resolve('ERROR'));
});

async function main() {
    const args = parseArgs(process.argv);
    if (args.help || !args.harDir) {
        console.log("Usage: node audit.js <har_directory> [--mode strict|default|paranoid] [--min-score 0.5] [--verify-sources ast,sourcemap,...] [--concurrency 8] [--out vulnerabilities.json]");
        process.exit(args.help ? 0 : 1);
    }
    const { minScore, mode } = getModeConfig(args.mode, args.minScore);
    const verifySources = parseVerifySources(args.verifySources, mode);
    const targetDir = args.harDir;

    let files = [];
    try {
        files = fs.readdirSync(targetDir).filter(f => f.endsWith('.har'));
    } catch (e) {
        logErr(`[!] Failed to read HAR dir: ${targetDir}: ${e.message}`);
        process.exit(2);
    }
    if (files.length === 0) return console.log("[-] No HAR files found.");

    const candidates = new Map();

    for (const file of files) {
        const findings = await analyzeHar(path.join(targetDir, file));
        findings.forEach(f => {
            const key = `${f.type}:${f.name}`;
            if (!candidates.has(key)) candidates.set(key, f);
        });
    }

    const uniqueList = Array.from(candidates.values());
    const toCheck = uniqueList
        .filter(i => (i.score ?? 0) >= minScore)
        .filter(i => verifySources.has(i.source));
    console.log(`[*] Mode: ${mode} | minScore=${minScore}`);
    console.log(`[*] verifySources=${Array.from(verifySources).sort().join(',')}`);
    console.log(`[*] Verifying ${toCheck.length}/${uniqueList.length} unique NPM candidates (scored & filtered)...`);

    let vulnerable = [];
    try {
        vulnerable = await checkNpmBatch(toCheck, args.concurrency);
    } catch (e) {
        logErr(`[!] Batch npm verification failed: ${e.message}`);
    }
    for (const item of vulnerable) {
        console.log(`\x1b[31m[!] VULNERABLE: ${item.name}\x1b[0m (Found in: ${item.foundIn})`);
        if (item.version) console.log(`    ↳ Target Version: ${item.version}`);
        if (item.source) console.log(`    ↳ Detection Method: ${item.source}`);
        if (Number.isFinite(item.score)) console.log(`    ↳ Confidence Score: ${item.score}`);
    }

    if (vulnerable.length > 0) {
        try {
            fs.writeFileSync(args.outFile, JSON.stringify(vulnerable, null, 2));
        } catch (e) {
            logErr(`[!] Failed to write output file ${args.outFile}: ${e.message}`);
            process.exit(3);
        }
        console.log(`\n\n[+] ${vulnerable.length} vulnerabilities saved to ${args.outFile}`);
    } else {
        console.log("\n\n\x1b[32m[+] No claimable packages found.\x1b[0m");
    }
}

main().catch((e) => {
    logErr(`[!] Fatal error: ${e && e.stack ? e.stack : e}`);
    process.exit(99);
});
