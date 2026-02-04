const fs = require('fs');
const { chromium } = require('playwright-extra');
const stealth = require('puppeteer-extra-plugin-stealth');
const path = require('path');

chromium.use(stealth());

// --- CONFIGURATION ---
const CONCURRENCY = 5; // How many sites to scan at once
const TIMEOUT = 45000; // 45 seconds max per site

(async () => {
  const inputFile = process.argv[2];
  const outputDir = process.argv[3] || './hars';

  if (!inputFile) {
    console.error('Usage: node har.js <subdomains.txt> [output_directory]');
    process.exit(1);
  }

  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const targets = fs.readFileSync(inputFile, 'utf-8')
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0);

  console.log(`[*] Loaded ${targets.length} targets.`);
  console.log(`[*] Mode: High Performance (Blocking Images/Fonts, Concurrency: ${CONCURRENCY})`);

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });

  // WORKER FUNCTION
  const processSite = async (rawTarget) => {
    const url = rawTarget.startsWith('http') ? rawTarget : `https://${rawTarget}`;
    const safeName = rawTarget.replace(/^https?:\/\//, '').replace(/[^a-z0-9]/gi, '_');
    const harPath = path.join(outputDir, `${safeName}.har`);
    
    // Skip if already exists
    if (fs.existsSync(harPath)) return;

    let context = null;
    try {
      context = await browser.newContext({
        recordHar: { path: harPath, content: 'embed' },
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        viewport: { width: 1920, height: 1080 },
        ignoreHTTPSErrors: true
      });

      const page = await context.newPage();

      // OPTIMIZATION: Block heavy assets (We only need JS/HTML/JSON)
      await page.route('**/*', route => {
        const type = route.request().resourceType();
        if (['image', 'media', 'font', 'stylesheet', 'other'].includes(type)) {
          return route.abort();
        }
        route.continue();
      });

      // Navigate - wait for DOM, not Network Idle (Fixes Timeouts)
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });

      // Trigger Lazy Loading (Scroll down)
      await page.evaluate(async () => {
         window.scrollTo(0, document.body.scrollHeight);
         await new Promise(r => setTimeout(r, 1000));
      });

    } catch (e) {
      console.log(`\x1b[31m[-] Failed: ${url} (${e.message.split('\n')[0]})\x1b[0m`);
    } finally {
      if (context) {
        await context.close(); // Save HAR
        // Verify HAR size (ignore empty files)
        try {
            const stats = fs.statSync(harPath);
            if (stats.size < 100) {
                fs.unlinkSync(harPath); // Delete empty files
                console.log(`\x1b[33m[!] Empty HAR deleted: ${safeName}\x1b[0m`);
            } else {
                console.log(`\x1b[32m[+] Saved: ${safeName}.har (${(stats.size/1024).toFixed(2)} KB)\x1b[0m`);
            }
        } catch(e) {}
      }
    }
  };

  // BATCH PROCESSING
  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    const batch = targets.slice(i, i + CONCURRENCY);
    console.log(`\n[*] Processing Batch ${Math.floor(i/CONCURRENCY) + 1}/${Math.ceil(targets.length/CONCURRENCY)}...`);
    await Promise.all(batch.map(target => processSite(target)));
  }

  console.log(`\n[*] Scan complete.`);
  await browser.close();
})();
