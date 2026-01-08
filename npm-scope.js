async function eA(scope) {
    let page = 0; // Start at 0, will increment
    let allPackages = [];
    let seen = new Set();
    console.log(`🚀 Starting Brute-Force Extraction for ${scope}...`);

    while (true) {
        try {
            console.log(`...Fetching page ${page}`);
            
            // Fetch internal API
            let response = await fetch(`https://www.npmjs.com/org/${scope}?page=${page}`, {
                headers: { "x-spiferack": "1" }
            });

            if (!response.ok) {
                console.error(`❌ Error on page ${page}: ${response.status}`);
                break;
            }

            let data = await response.json();
            let objects = data.packages.objects;

            // STOP CONDITION: If no objects returned, we are done.
            if (!objects || objects.length === 0) {
                console.log("ℹ️ No objects found. Reached end of list.");
                break;
            }

            let newFound = 0;
            objects.forEach(pkg => {
                if (pkg.name && !seen.has(pkg.name)) {
                    allPackages.push(pkg.name);
                    seen.add(pkg.name);
                    newFound++;
                }
            });

            console.log(`✅ Page ${page}: Found ${newFound} new packages (Total: ${allPackages.length})`);
            
            // If we found 0 new packages, we might be looping or done
            if (newFound === 0) {
                console.log("ℹ️ No new packages on this page. Stopping.");
                break;
            }

            page++;
            await new Promise(r => setTimeout(r, 1500)); // Sleep 1.5s to be polite

        } catch (e) {
            console.error(`❌ Critical Error: ${e}`);
            break;
        }
    }

    console.log(`\n🎯 DONE! Found ${allPackages.length} unique packages.`);
    console.log("⬇️ Copy the JSON list below:");
    console.log(JSON.stringify(allPackages));
}

// RUN IT
eA('airbnb');
