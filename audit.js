#!/usr/bin/env node
/**
 * AUDIT.JS - Supply Chain Scanner (v7.2)
 * Verbose Reporting + Greedy Federation Detection
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

// ==========================================
// 1. REFINED VALIDATION
// ==========================================

const NODE_BUILTINS = new Set(['assert', 'buffer', 'child_process', 'crypto', 'fs', 'http', 'https', 'os', 'path', 'process', 'stream', 'url', 'util', 'v8', 'vm', 'zlib', 'events', 'tls', 'net']);

const isValidPkg = (name) => {
    if (!name || typeof name !== 'string' || name.length > 214) return false;
    const n = name.trim();
    if (NODE_BUILTINS.has(n) || n.startsWith('node:')) return false;
    if (n.startsWith('.') || n.startsWith('/') || n.includes('.js') || n.includes('.css')) return false;
    if (!/^(?:@[a-z0-9-*~][a-z0-9-*._~]*\/)?[a-z0-9-*~][a-z0-9-*._~]*$/.test(n)) return false;
    
    const noise = new Set(['webpack', 'react', 'src', 'dist', 'app', 'undefined', 'null', 'window', 'document', 'default', 'prototype', 'anonymous']);
    if (noise.has(n.split('/')[0])) return false;

    return true;
};

// ==========================================
// 2. GREEDY SCANNING ENGINES
// ==========================================

function scanGreedyFederation(content) {
    const deps = [];
    // Matches f("pkg","version",...) pattern found in remoteEntry and runtime files
    const federationRegex = /\.f\("([^"]+)","([^"]+)"/g;
    let match;
    while ((match = federationRegex.exec(content)) !== null) {
        if (isValidPkg(match[1])) {
            deps.push({ name: match[1], version: match[2], type: 'npm' });
        }
    }
    // Fallback for l("default","pkg",...) consume patterns
    const consumeRegex = /[a-zA-Z]\("default","([^"]+)",\s*!?[01]/g;
    while ((match = consumeRegex.exec(content)) !== null) {
        if (isValidPkg(match[1])) {
            deps.push({ name: match[1], type: 'npm' });
        }
    }
    return deps;
}

function scanDeepJson(content) {
    const deps = [];
    try {
        const json = JSON.parse(content);
        const crawl = (obj) => {
            if (!obj || typeof obj !== 'object') return;
            if (obj.name && (obj.source || obj.src || obj.url) && isValidPkg(obj.name)) {
                deps.push({ name: obj.name, type: 'npm' });
            }
            const keys = ['dependencies', 'devDependencies', 'peerDependencies', 'shared'];
            keys.forEach(k => {
                if (obj[k] && typeof obj[k] === 'object') {
                    Object.keys(obj[k]).forEach(pkg => { if (isValidPkg(pkg)) deps.push({ name: pkg, type: 'npm' }); });
                }
            });
            Object.values(obj).forEach(val => crawl(val));
        };
        crawl(json);
    } catch (e) {}
    return deps;
}

// ==========================================
// 3. HAR ANALYZER (Verbose Mode)
// ==========================================

async function analyzeHar(harPath) {
    console.log(`[*] Analyzing: ${path.basename(harPath)}`);
    const har = JSON.parse(fs.readFileSync(harPath));
    const results = new Map();

    for (const entry of har.log.entries) {
        if (!entry.response.content.text) continue;
        let content = entry.response.content.text;
        if (entry.response.content.encoding === 'base64') {
            content = Buffer.from(content, 'base64').toString('utf-8');
        }

        const url = entry.request.url.split('?')[0];
        const findings = [];

        if (url.endsWith('.js') || (entry.response.content.mimeType || '').includes('javascript')) {
            findings.push(...scanGreedyFederation(content));
        } else if (url.endsWith('.json') || (entry.response.content.mimeType || '').includes('json')) {
            findings.push(...scanDeepJson(content));
        }

        findings.forEach(f => {
            const key = `${f.type}:${f.name}`;
            if (!results.has(key)) {
                results.set(key, { ...f, foundIn: url });
            } else if (f.version && !results.get(key).version) {
                results.get(key).version = f.version;
            }
        });
    }
    return Array.from(results.values());
}

// ==========================================
// 4. REGISTRY & REPORTING
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
    const candidates = new Map();

    for (const file of files) {
        const results = await analyzeHar(path.join(targetDir, file));
        results.forEach(r => {
            const key = `${r.type}:${r.name}`;
            if (!candidates.has(key)) candidates.set(key, r);
        });
    }

    const uniqueList = Array.from(candidates.values());
    console.log(`[*] Verifying ${uniqueList.length} packages...`);

    const vulnerable = [];
    for (const item of uniqueList) {
        const status = await checkNpm(item.name);
        if (status === 'AVAILABLE') {
            console.log(`\x1b[31m[!] VULNERABLE: ${item.name}\x1b[0m (Found in: ${item.foundIn})`);
            if (item.version) console.log(`    ↳ Target Version: ${item.version}`);
            vulnerable.push(item);
        }
    }

    if (vulnerable.length > 0) {
        const out = 'vulnerabilities.json';
        fs.writeFileSync(out, JSON.stringify(vulnerable, null, 2));
        console.log(`\n[+] ${vulnerable.length} vulnerabilities saved to ${out}`);
    } else {
        console.log("\n\x1b[32m[+] No claimable packages found.\x1b[0m");
    }
}

main();
