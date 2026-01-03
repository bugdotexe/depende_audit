#!/usr/bin/env node

/**
 * PRODUCTION READY DEPENDENCY CONFUSION SCANNER
 * Features:
 * 1. AST Source Code Parsing (Babel)
 * 2. package.json Integration (Manifest Analysis)
 * 3. Monorepo/Workspace Support (Eliminates False Positives)
 * 4. Smart Scope Intelligence (Prevents Privacy Leaks)
 */

const fs = require('fs').promises;
const path = require('path');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const https = require('https');

// ==========================================
// CONFIGURATION & CONSTANTS
// ==========================================

const NODE_BUILTIN_MODULES = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
  'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
  'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net',
  'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring', 'readline',
  'repl', 'stream', 'string_decoder', 'timers', 'tls', 'trace_events', 'tty',
  'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
  'node:assert', 'node:child_process', 'node:crypto', 'node:fs', 'node:os',
  'node:path', 'node:process', 'node:stream', 'node:util', 'node:test'
]);

// Directories to strictly ignore
const IGNORE_DIRS = new Set(['node_modules', 'dist', 'build', '.git', '.next', 'coverage']);

if (process.argv.length < 3) {
  console.error('Usage: node main.js <target-directory> [output-file]');
  process.exit(1);
}

const rootDir = path.resolve(process.argv[2]);
const outputFile = process.argv[3] || 'scan-report.txt';

// GLOBAL STATE
const packageOccurrences = new Map(); // Map<PkgName, Set<FilePaths>>
const localPackageNames = new Set();  // Names of packages defined INSIDE this repo (Monorepo support)
const declaredDependencies = new Set(); // Dependencies listed in package.json files

// ==========================================
// FILE SYSTEM & MANIFEST LOGIC
// ==========================================

async function getFiles(dir) {
  let sourceFiles = [];
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      if (entry.name.startsWith('.') || IGNORE_DIRS.has(entry.name)) continue;
      
      const res = path.resolve(dir, entry.name);
      
      if (entry.isDirectory()) {
        sourceFiles = sourceFiles.concat(await getFiles(res));
      } else {
        // 1. Collect Source Code
        if (/\.(js|jsx|ts|tsx|cjs|mjs)$/.test(entry.name)) {
          sourceFiles.push(res);
        }
        // 2. Parse package.json for Metadata
        if (entry.name === 'package.json') {
          await parsePackageJson(res);
        }
      }
    }
  } catch (err) { /* ignore access errors */ }
  return sourceFiles;
}

/**
 * Reads package.json to:
 * 1. Whitelist local packages (Monorepo logic)
 * 2. Record declared dependencies
 */
async function parsePackageJson(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    const json = JSON.parse(content);

    // If this package.json has a "name", it is a LOCAL package.
    // We should never flag this as missing.
    if (json.name) {
      localPackageNames.add(json.name);
    }

    // Collect all dependency types
    ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'].forEach(type => {
      if (json[type]) {
        Object.keys(json[type]).forEach(dep => declaredDependencies.add(dep));
      }
    });
  } catch (err) {
    // Malformed package.json, skip
  }
}

// ==========================================
// AST PARSING LOGIC
// ==========================================

function normalizePackageName(rawName) {
  // Handle scoped packages @scope/pkg
  if (rawName.startsWith('@')) {
    const parts = rawName.split('/');
    if (parts.length < 2) return null;
    return parts.slice(0, 2).join('/');
  }
  
  // Handle deep imports (lodash/map -> lodash)
  const parts = rawName.split('/');
  return parts[0];
}

function isValidPackageName(name) {
  if (!name || name.startsWith('.') || name.startsWith('/')) return false;
  if (name.startsWith('node:') || NODE_BUILTIN_MODULES.has(name)) return false;
  if (localPackageNames.has(name)) return false; // CRITICAL: Ignore local monorepo packages
  
  // Filter garbage/paths
  const localPatterns = ['src', 'lib', 'test', 'utils', 'config', 'app', 'components'];
  if (localPatterns.includes(name)) return false;
  
  return true;
}

async function extractImports(filePath) {
  const imports = new Set();
  let code; 
  try { code = await fs.readFile(filePath, 'utf8'); } catch { return []; }

  let ast;
  try {
    ast = parser.parse(code, {
      sourceType: 'module',
      plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties', 'dynamicImport'],
      errorRecovery: true
    });
  } catch { return []; }

  traverse(ast, {
    ImportDeclaration({ node }) {
      if (node.source?.value) imports.add(node.source.value);
    },
    CallExpression({ node }) {
      if (node.callee.name === 'require' && node.arguments[0]?.type === 'StringLiteral') {
        imports.add(node.arguments[0].value);
      }
      if (node.callee.type === 'Import' && node.arguments[0]?.type === 'StringLiteral') {
        imports.add(node.arguments[0].value);
      }
    },
    ExportNamedDeclaration({ node }) {
      if (node.source?.value) imports.add(node.source.value);
    },
    ExportAllDeclaration({ node }) {
      if (node.source?.value) imports.add(node.source.value);
    }
  });
  return Array.from(imports);
}

// ==========================================
// SECURITY CHECKS & NETWORK LOGIC
// ==========================================

function makeRequest(url) {
  return new Promise((resolve) => {
    const req = https.get(url, { headers: { 'User-Agent': 'SecScanner/1.0' } }, (res) => resolve(res.statusCode));
    req.on('error', () => resolve(500));
    req.setTimeout(3000, () => { req.destroy(); resolve(408); });
  });
}

/**
 * Checks if the Scope (@org) exists.
 * Returns TRUE if scope is owned (Safe).
 * Returns FALSE if scope is 404 (Critical).
 */
async function checkScopeSafety(scopeName) {
  const clean = scopeName.replace('@', '');
  const orgStatus = await makeRequest(`https://www.npmjs.com/org/${clean}`);
  if (orgStatus === 200) return true;
  
  const userStatus = await makeRequest(`https://www.npmjs.com/~${clean}`);
  if (userStatus === 200) return true;
  
  return false;
}

async function checkPackage(name) {
  const isDeclared = declaredDependencies.has(name);
  
  // 1. SCOPED PACKAGES (@mycorp/pkg)
  if (name.startsWith('@')) {
    const scope = name.split('/')[0];
    
    // Safety Check: Does the owner exist?
    const scopeExists = await checkScopeSafety(scope);
    
    if (scopeExists) {
      // Scope exists -> Package is likely private -> SAFE.
      // We do NOT ping NPM for the full package name to avoid leaking internal names.
      return { name, isVulnerable: false, reason: 'Private Scope (Safe)', declared: isDeclared };
    } else {
      // Scope 404 -> Anyone can register this! -> CRITICAL.
      return { name, isVulnerable: true, severity: 'CRITICAL', reason: 'Scope Available (Takeover)', declared: isDeclared };
    }
  }

  // 2. PUBLIC PACKAGES (lodash, react)
  const status = await makeRequest(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  
  if (status === 404) {
    // If it's missing on NPM...
    if (isDeclared) {
      // ...and listed in package.json -> Dependency Confusion Risk
      return { name, isVulnerable: true, severity: 'HIGH', reason: 'Dependency Confusion (Declared but missing on NPM)', declared: true };
    } else {
      // ...and NOT in package.json -> Likely a typo or leftover code (Phantom Import)
      return { name, isVulnerable: true, severity: 'MEDIUM', reason: 'Phantom Import (Undeclared & Missing)', declared: false };
    }
  }

  return { name, isVulnerable: false, reason: 'Exists on NPM', declared: isDeclared };
}

// ==========================================
// MAIN EXECUTION
// ==========================================

async function main() {
  console.log(`[*] Scanning target: ${rootDir}`);
  
  // Step 1: File Discovery & Manifest Parsing
  // This populates 'localPackageNames' and 'declaredDependencies'
  const sourceFiles = await getFiles(rootDir);
  console.log(`[*] Context: Found ${localPackageNames.size} local packages (workspace) and ${declaredDependencies.size} declared dependencies.`);

  // Step 2: Extract Imports from Source Code
  for (const file of sourceFiles) {
    const rawImports = await extractImports(file);
    for (const imp of rawImports) {
      const normalized = normalizePackageName(imp);
      if (normalized && isValidPackageName(normalized)) {
        if (!packageOccurrences.has(normalized)) packageOccurrences.set(normalized, new Set());
        packageOccurrences.get(normalized).add(file);
      }
    }
  }

  const candidates = Array.from(packageOccurrences.keys());
  console.log(`[*] Validating ${candidates.length} unique candidates...`);

  // Step 3: Analysis
  const report = [];
  const BATCH_SIZE = 20;
  
  for (let i = 0; i < candidates.length; i += BATCH_SIZE) {
    const batch = candidates.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(batch.map(checkPackage));
    
    for (const res of results) {
      if (res.isVulnerable) report.push(res);
    }
    process.stdout.write(`\r[*] Progress: ${Math.min(i + BATCH_SIZE, candidates.length)}/${candidates.length}`);
  }
  console.log('\n');

  // Step 4: Reporting
  if (report.length === 0) {
    console.log('[+] No vulnerabilities found.');
  } else {
    console.log('=== VULNERABILITY REPORT ===');
    let fileOut = `SCAN REPORT\n`;
    
    // Sort: CRITICAL first, then HIGH, then MEDIUM
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2 };
    report.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    for (const item of report) {
      const color = item.severity === 'CRITICAL' ? '\x1b[31m' : (item.severity === 'HIGH' ? '\x1b[33m' : '\x1b[36m');
      console.log(`${color}[${item.severity}] ${item.name} \x1b[0m`);
      console.log(`    Reason: ${item.reason}`);
      console.log(`    Declared in package.json: ${item.declared}`);
      console.log(`    Found in: ${Array.from(packageOccurrences.get(item.name))[0]} (and others...)`);
      
      fileOut += `[${item.severity}] ${item.name} | ${item.reason}\n`;
      fileOut += `Files: ${Array.from(packageOccurrences.get(item.name)).join(', ')}\n\n`;
    }
    
    await fs.writeFile(outputFile, fileOut);
    console.log(`\n[+] Full report saved to ${outputFile}`);
  }
}

main().catch(console.error);
