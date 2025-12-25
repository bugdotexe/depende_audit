/**
 * DEPENDENCY CONFUSION SCANNER
 * 1. Scans GitHub Org for package.json files.
 * 2. Extracts ALL scoped dependencies (e.g. @org/pkg).
 * 3. Checks registry.npmjs.org to see if they exist publicly.
 * 4. Highlights [404] packages as potential targets.
 */

const https = require('https');

// ==========================================
// ⚙️ CONFIGURATION
// ==========================================
const ORG = process.argv[2];
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || null;

if (!ORG || !GITHUB_TOKEN) {
    console.error("Usage: node dependency-confusion-scan.js <ORG_NAME>");
    console.error("❌ Error: Missing GITHUB_TOKEN. Set it in env or hardcode it.");
    process.exit(1);
}

const headers = {
    'User-Agent': 'Dep-Confusion-Scanner',
    'Authorization': `token ${GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github.v3+json'
};

// ==========================================
// 🛠 HELPERS
// ==========================================

function ghRequest(path) {
    return new Promise((resolve) => {
        const req = https.get({ hostname: 'api.github.com', path, headers }, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => resolve(res.statusCode === 200 ? JSON.parse(data) : null));
        });
        req.on('error', () => resolve(null));
    });
}

function checkNpm(pkgName) {
    return new Promise((resolve) => {
        // We use the root registry URL. 404 = Not found (Private/Available).
        const req = https.get(`https://registry.npmjs.org/${pkgName}`, (res) => {
            // Drain data to free memory
            res.on('data', () => {}); 
            res.on('end', () => {
                if (res.statusCode === 200) resolve('EXIST');
                else if (res.statusCode === 404) resolve('404');
                else resolve(`ERR:${res.statusCode}`);
            });
        });
        req.on('error', () => resolve('ERROR'));
    });
}

// ==========================================
// 🚀 MAIN LOGIC
// ==========================================

async function main() {
    console.log(`\n🔎 Scanning Organization: ${ORG} ...`);
    
    // 1. Fetch Repos (Loop handles pagination for >100 repos)
    let repos = [];
    let page = 1;
    let keepFetching = true;

    while (keepFetching) {
        process.stdout.write(`   Fetching page ${page}... \r`);
        const batch = await ghRequest(`/orgs/${ORG}/repos?per_page=100&page=${page}`);
        if (batch && batch.length > 0) {
            repos = repos.concat(batch);
            page++;
            if (batch.length < 100) keepFetching = false;
        } else {
            keepFetching = false;
        }
    }
    console.log(`   ✅ Found ${repos.length} repositories. Parsing dependencies...`);

    const foundPackages = new Set();

    // 2. Scan Repos for package.json
    let processed = 0;
    for (const repo of repos) {
        if (repo.archived) continue;

        const pkgData = await ghRequest(`/repos/${ORG}/${repo.name}/contents/package.json`);
        
        if (pkgData && pkgData.content) {
            try {
                const json = JSON.parse(Buffer.from(pkgData.content, 'base64').toString());
                const allDeps = {
                    ...json.dependencies,
                    ...json.devDependencies,
                    ...json.peerDependencies,
                    ...json.optionalDependencies
                };

                Object.keys(allDeps).forEach(pkg => {
                    // We specifically care about Scoped packages for this attack vector
                    if (pkg.startsWith('@')) {
                        foundPackages.add(pkg);
                    }
                });
            } catch (e) { /* Ignore invalid JSON */ }
        }
        processed++;
        if (processed % 10 === 0) process.stdout.write('.');
    }

    console.log(`\n\n📦 Checking ${foundPackages.size} unique scoped packages against NPM registry...`);
    console.log('------------------------------------------------');

    const sortedPackages = Array.from(foundPackages).sort();
    
    // 3. Check NPM Registry
    // We run sequentially or in small batches to avoid rate limiting
    for (const pkg of sortedPackages) {
        const status = await checkNpm(pkg);
        
        if (status === '404') {
            // 🚨 POTENTIAL VULNERABILITY
            // Green text for easy visibility
            console.log(`\x1b[32m- ${pkg.padEnd(40)} [404 / PRIVATE / VULNERABLE]\x1b[0m`);
        } else if (status === 'EXIST') {
            // Standard text
            console.log(`- ${pkg.padEnd(40)} [Exist]`);
        } else {
            console.log(`- ${pkg.padEnd(40)} [Error: ${status}]`);
        }
    }
    
    console.log('------------------------------------------------');
    console.log('🏁 Scan Complete.');
}

main();
