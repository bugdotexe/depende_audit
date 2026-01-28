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
// 1. CONFIGURATION & VALIDATION
// ==========================================

const NODE_BUILTINS = new Set(['assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https', 'net', 'os', 'path', 'perf_hooks', 'process', 'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'timers', 'tls', 'tty', 'url', 'util', 'v8', 'vm', 'worker_threads', 'zlib']);

// Refined NPM Validation (Anti-False Positive)
const isValidNpm = (name) => {
    if (!name || typeof name !== 'string' || name.length > 214) return false;
    const n = name.trim();
    if (NODE_BUILTINS.has(n) || n.startsWith('node:')) return false;
    if (n.startsWith('.') || n.startsWith('/') || n.includes('.js') || n.includes('.css')) return false;
    if (!/^(?:@[a-z0-9-*~][a-z0-9-*._~]*\/)?[a-z0-9-*~][a-z0-9-*._~]*$/.test(n)) return false;
    
    // Noise Filter for minified vars
    const noise = new Set(['webpack', 'react', 'src', 'dist', 'app', 'undefined', 'null', 'window', 'document', 'default', 'prototype', 'anonymous', 'main', 'test']);
    if (noise.has(n.split('/')[0])) return false;

    return true;
};

// ==========================================
// 2. SCANNING ENGINES
// ==========================================

// [NEW] Greedy Federation Engine (Matches .f("pkg","ver") patterns)
function scanGreedyFederation(content) {
    const deps = [];
    // Pattern 1: Webpack Federation Shared Scope
    const federationRegex = /\.f\("([^"]+)","([^"]+)"/g;
    let match;
    while ((match = federationRegex.exec(content)) !== null) {
        if (isValidNpm(match[1])) {
            deps.push({ name: match[1], version: match[2], type: 'npm', source: 'federation-shared' });
        }
    }
    // Pattern 2: Webpack Consumption (l("default","pkg"))
    const consumeRegex = /[a-zA-Z]\("default","([^"]+)",\s*!?[01]/g;
    while ((match = consumeRegex.exec(content)) !== null) {
        if (isValidNpm(match[1])) {
            deps.push({ name: match[1], type: 'npm', source: 'federation-consume' });
        }
    }
    return deps;
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
    return Array.from(deps).filter(isValidNpm).map(n => ({ name: n, type: 'npm', source: 'ast' }));
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

    // Helper to merge findings
    const add = (items, sourceUrl) => items.forEach(i => {
        const key = `${i.type}:${i.name}`;
        if (!results.has(key)) {
            i.foundIn = sourceUrl;
            results.set(key, i);
        } else if (i.version && !results.get(key).version) {
            results.get(key).version = i.version;
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

        // 1. Javascript (AST + Greedy Federation)
        if (url.endsWith('.js') || mime.includes('javascript')) {
            add(scanGreedyFederation(content), url);
            add(scanJsAst(content), url);
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
    const targetDir = process.argv[2];
    if (!targetDir) return console.log("Usage: node audit.js <har_directory>");

    const files = fs.readdirSync(targetDir).filter(f => f.endsWith('.har'));
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
    console.log(`[*] Verifying ${uniqueList.length} unique NPM candidates...`);

    const vulnerable = [];
    for (const item of uniqueList) {
        const status = await checkNpm(item.name);
        if (status === 'AVAILABLE') {
            console.log(`\x1b[31m[!] VULNERABLE: ${item.name}\x1b[0m (Found in: ${item.foundIn})`);
            if (item.version) console.log(`    ↳ Target Version: ${item.version}`);
            if (item.source) console.log(`    ↳ Detection Method: ${item.source}`);
            vulnerable.push(item);
        } 
    }

    if (vulnerable.length > 0) {
        const out = 'vulnerabilities.json';
        fs.writeFileSync(out, JSON.stringify(vulnerable, null, 2));
        console.log(`\n\n[+] ${vulnerable.length} vulnerabilities saved to ${out}`);
    } else {
        console.log("\n\n\x1b[32m[+] No claimable packages found.\x1b[0m");
    }
}

main();
