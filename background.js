let currentTabTechnologies = {};
let isAnalyzing = {};

// Listen for messages from popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'START_DETECTION') {
        startDetection(message.tabId)
            .then(() => sendResponse({ success: true }))
            .catch(error => sendResponse({ error: error.message }));
        return true; // Keep the message port open for async response
    } else if (message.type === 'GET_TECHNOLOGIES') {
        browser.tabs.query({ active: true, currentWindow: true })
            .then(tabs => {
                const tabId = tabs[0]?.id;
                sendResponse({
                    type: 'TECH_DATA',
                    data: currentTabTechnologies[tabId] || null,
                    isAnalyzing: isAnalyzing[tabId] || false
                });
            })
            .catch(error => {
                sendResponse({
                    type: 'TECH_DATA',
                    data: null,
                    isAnalyzing: false,
                    error: error.message
                });
            });
        return true; // Keep the message port open for async response
    }
});

async function startDetection(tabId) {
    try {
        isAnalyzing[tabId] = true;
        browser.runtime.sendMessage({ type: 'ANALYSIS_STATUS', isAnalyzing: true });

        // Clear previous results
        currentTabTechnologies[tabId] = null;

        // On mobile, we need to ensure we have permission to inject scripts
        try {
            await browser.tabs.executeScript(tabId, {
                code: 'true' // Just a dummy script to check permissions
            });
        } catch (error) {
            throw new Error("Permission denied to access this page");
        }

        // Inject and execute detection script
        const results = await browser.tabs.executeScript(tabId, {
            code: `(${detectTechnologies.toString()})();`
        });

        if (!results || results.length === 0) {
            throw new Error("No results returned from detection script");
        }

        // Store and send initial results
        currentTabTechnologies[tabId] = results[0];

        // Send initial results
        browser.runtime.sendMessage({
            type: 'TECH_DETECTED',
            data: results[0],
            isAnalyzing: true
        });

        // Fetch WHOIS data for the domain (only on mobile if we have internet)
        try {
            const tab = await browser.tabs.get(tabId);
            if (tab.url) {
                const url = new URL(tab.url);
                const hostname = url.hostname;
                const domainParts = hostname.split('.');
                // Get the base domain (e.g., example.com from www.example.com)
                if (domainParts.length > 2 && domainParts[0] === 'www') {
                    domainParts.shift();
                }
                const domain = domainParts.join('.');

                // Fetch WHOIS data
                const whoisData = await fetchWhoisDataBackground(domain);

                // Add WHOIS data to results
                if (whoisData && whoisData.length > 0) {
                    if (!currentTabTechnologies[tabId].whois) {
                        currentTabTechnologies[tabId].whois = [];
                    }

                    if (!currentTabTechnologies[tabId].domainExpiration) {
                        currentTabTechnologies[tabId].domainExpiration = [];
                    }

                    // Add registration and expiration data to the domainExpiration category
                    const expirationData = whoisData.filter(item =>
                        item.name === 'Registration Date' ||
                        item.name === 'Expiration Date' ||
                        item.name === 'Expiration Status'
                    );

                    if (expirationData.length > 0) {
                        currentTabTechnologies[tabId].domainExpiration =
                            [...currentTabTechnologies[tabId].domainExpiration, ...expirationData];
                    }

                    // Add other WHOIS data to the whois category
                    const otherWhoisData = whoisData.filter(item =>
                        item.name !== 'Registration Date' &&
                        item.name !== 'Expiration Date' &&
                        item.name !== 'Expiration Status'
                    );

                    if (otherWhoisData.length > 0) {
                        currentTabTechnologies[tabId].whois =
                            [...currentTabTechnologies[tabId].whois, ...otherWhoisData];
                    }
                }
            }
        } catch (whoisError) {
            console.error('Error fetching WHOIS data:', whoisError);
        }

        // Complete the analysis
        isAnalyzing[tabId] = false;

        // Send the final results
        browser.runtime.sendMessage({
            type: 'TECH_DETECTED',
            data: currentTabTechnologies[tabId],
            isAnalyzing: false
        });
    } catch (error) {
        console.error('Analysis failed:', error);
        isAnalyzing[tabId] = false;
        browser.runtime.sendMessage({
            type: 'ANALYSIS_ERROR',
            error: error.message,
            isAnalyzing: false
        });
        throw error;
    }
}

// Function to fetch WHOIS data in the background script
async function fetchWhoisDataBackground(domain) {
    try {
        // Use fetch API to get WHOIS data from whois.com
        const response = await fetch(`https://www.whois.com/whois/${domain}`);
        const html = await response.text();

        // Parse the HTML using DOMParser
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');

        // Extract WHOIS data
        const whoisData = [];

        // Find the WHOIS data container
        const dataContainer = doc.querySelector('.whois-data') ||
            doc.querySelector('#registryData') ||
            doc.querySelector('.df-block');

        if (!dataContainer) {
            return [];
        }

        // Function to extract date from text
        function extractDate(text) {
            // Common date formats in WHOIS data
            const datePatterns = [
                /(\d{4}-\d{2}-\d{2})/,                   // YYYY-MM-DD
                /(\d{2}-\w{3}-\d{4})/,                   // DD-MMM-YYYY
                /(\d{2}\/\d{2}\/\d{4})/,                 // DD/MM/YYYY or MM/DD/YYYY
                /(\w+ \d{1,2}, \d{4})/,                  // Month DD, YYYY
                /(\d{1,2}-\w+-\d{4})/,                   // D-MMM-YYYY
                /(\d{1,2} \w+ \d{4})/                    // DD Month YYYY
            ];

            for (const pattern of datePatterns) {
                const match = text.match(pattern);
                if (match) return match[1];
            }
            return null;
        }

        // Extract creation date
        const creationLabels = ['Creation Date:', 'Registered on:', 'Domain Registration Date:',
            'Registration Date:', 'Created on:', 'Created:', 'Domain Created:'];

        let creationDate = null;

        for (const label of creationLabels) {
            if (dataContainer.textContent.includes(label)) {
                const textAfterLabel = dataContainer.textContent.split(label)[1].split('\n')[0].trim();
                creationDate = extractDate(textAfterLabel);
                if (creationDate) break;
            }
        }

        if (creationDate) {
            whoisData.push({
                name: 'Registration Date',
                version: creationDate,
                icon: '📅'
            });
        }

        // Extract expiration date
        const expirationLabels = ['Expiration Date:', 'Registry Expiry Date:', 'Expires on:',
            'Expiry Date:', 'Expires:', 'Domain Expires:'];

        let expirationDate = null;

        for (const label of expirationLabels) {
            if (dataContainer.textContent.includes(label)) {
                const textAfterLabel = dataContainer.textContent.split(label)[1].split('\n')[0].trim();
                expirationDate = extractDate(textAfterLabel);
                if (expirationDate) break;
            }
        }

        if (expirationDate) {
            whoisData.push({
                name: 'Expiration Date',
                version: expirationDate,
                icon: '⏱️'
            });

            // Calculate days until expiration
            try {
                const expDate = new Date(expirationDate);
                const today = new Date();
                const daysLeft = Math.ceil((expDate - today) / (1000 * 60 * 60 * 24));

                if (!isNaN(daysLeft)) {
                    let status = '✅ Valid';
                    let icon = '✅';

                    if (daysLeft < 0) {
                        status = '⚠️ Expired';
                        icon = '⚠️';
                    } else if (daysLeft < 30) {
                        status = `⚠️ Expiring soon (${daysLeft} days)`;
                        icon = '⚠️';
                    } else {
                        status = `✅ Valid (${daysLeft} days left)`;
                    }

                    whoisData.push({
                        name: 'Expiration Status',
                        version: status,
                        icon: icon
                    });
                }
            } catch (e) {
                console.error("Error calculating expiration days:", e);
            }
        }

        // Extract registrar information
        const registrarLabels = ['Registrar:', 'Sponsoring Registrar:'];

        for (const label of registrarLabels) {
            if (dataContainer.textContent.includes(label)) {
                const textAfterLabel = dataContainer.textContent.split(label)[1].split('\n')[0].trim();
                if (textAfterLabel) {
                    whoisData.push({
                        name: 'Registrar',
                        version: textAfterLabel.substring(0, 50), // Limit length
                        icon: '🏢'
                    });
                    break;
                }
            }
        }

        // Extract name servers
        if (dataContainer.textContent.includes('Name Server:')) {
            const nsText = dataContainer.textContent.split('Name Server:')[1];
            const nameServers = nsText.split('\n')
                .filter(line => line.includes('.'))
                .map(line => line.trim())
                .filter(line => line.length > 0)
                .slice(0, 2)  // Take first two name servers only
                .join(', ');

            if (nameServers) {
                whoisData.push({
                    name: 'Name Servers',
                    version: nameServers,
                    icon: '🌐'
                });
            }
        }

        // Extract domain status
        if (dataContainer.textContent.includes('Domain Status:')) {
            const statusText = dataContainer.textContent.split('Domain Status:')[1].split('\n')[0].trim();
            if (statusText) {
                whoisData.push({
                    name: 'Domain Status',
                    version: statusText.substring(0, 50), // Limit length
                    icon: '🔒'
                });
            }
        }

        return whoisData;
    } catch (error) {
        console.error("Error in fetchWhoisDataBackground:", error);
        return [];
    }
}

function detectTechnologies() {
    return {
        frameworks: detectFrameworks(),
        libraries: detectLibraries(),
        buildTools: detectBuildTools(),
        serverTech: detectServerTech(),
        fullStack: detectFullStack(),
        markup: detectMarkupLanguage(),
        encoding: detectCharacterEncoding(),
        images: detectImageFormats(),
        serverInfo: detectServerInfo(),
        emailServer: detectEmailServer(),
        dnsInfo: detectDNSInfo(),
        whois: getWhoisInfo(),
        emails: detectEmailAddresses(),
        forms: detectForms(),
        apis: detectAPIs(),
        domainExpiration: detectDomainExpiration(),
        adNetworks: detectAdNetworks(),
        tagManagers: detectTagManagers(),
        trackers: detectTrackers(),
        analytics: detectAnalytics(),
        paymentGateways: detectPaymentGateways(),
        socialMediaLinks: detectSocialMediaLinks(),
    };

    function detectFrameworks() {
        const frameworks = [];

        // Enhanced React detection
        if (
            window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
            document.querySelector('[data-reactroot], [data-reactid], [data-react-helmet]') ||
            window.React ||
            document.querySelector('*[class*="react-"], *[class*="_react-"]') ||
            !!Object.keys(window).find(key => key.startsWith('__REACT_')) ||
            !!Object.keys(window).find(key => key.startsWith('__NEXT_'))
        ) {
            frameworks.push({
                name: 'React',
                version: getReactVersion(),
                icon: '⚛️'
            });

            // Next.js specific detection
            if (
                window.__NEXT_DATA__ ||
                document.querySelector('#__next') ||
                document.querySelector('script[src*="_next/"]') ||
                document.querySelector('link[href*="_next/"]')
            ) {
                frameworks.push({
                    name: 'Next.js',
                    version: getNextVersion(),
                    icon: '▲'
                });
            }
        }
        // Svelte detection
        if (
            document.querySelector('script[type="module"][src*="svelte"]') ||
            document.querySelector('*[class*="svelte-"]') ||
            window.__SVELTE__ ||
            document.head.innerHTML.includes('svelte-') ||
            !!Object.keys(window).find(key => key.startsWith('__SVELTE'))
        ) {
            frameworks.push({
                name: 'Svelte',
                version: getSvelteVersion(),
                icon: '🎯'
            });

            // SvelteKit detection
            if (
                document.querySelector('script[src*="/@fs/"]') ||
                document.querySelector('script[src*="/_app/"]') ||
                window.__SVELTEKIT_APP__
            ) {
                frameworks.push({
                    name: 'SvelteKit',
                    version: 'Detected',
                    icon: '⚡'
                });
            }
        }

        // SolidJS detection
        if (
            document.querySelector('script[type="module"][src*="solid"]') ||
            document.querySelector('style[data-solid]') ||
            window._$SOLID_ ||
            document.querySelector('*[data-solid]') ||
            !!Object.keys(window).find(key => key.includes('SOLID'))
        ) {
            frameworks.push({
                name: 'SolidJS',
                version: getSolidVersion(),
                icon: '💎'
            });
        }

        // Enhanced Vue detection
        if (
            window.__VUE__ ||
            document.querySelector('[data-v-]') ||
            document.querySelector('*[class*="-vue-"]') ||
            !!Object.keys(window).find(key => key.startsWith('__VUE_')) ||
            document.querySelector('#app[data-v-app]') ||
            document.querySelector('script[src*="vue."]') ||
            document.querySelector('script[src*="vue@"]')
        ) {
            frameworks.push({
                name: 'Vue',
                version: getVueVersion(),
                icon: '🟢'
            });

            // Nuxt.js detection
            if (
                window.__NUXT__ ||
                document.querySelector('#__nuxt') ||
                document.querySelector('script[src*="/_nuxt/"]')
            ) {
                frameworks.push({
                    name: 'Nuxt.js',
                    version: getNuxtVersion(),
                    icon: '🟩'
                });
            }
        }

        // Angular detection
        if (
            window.angular ||
            document.querySelector('[ng-version], [ng-app], [ng-controller]') ||
            document.querySelector('*[class*="ng-"]') ||
            !!Object.keys(window).find(key => key.startsWith('NG_'))
        ) {
            frameworks.push({
                name: 'Angular',
                version: getAngularVersion(),
                icon: '🅰️'
            });
        }

        return frameworks;
    }

    function detectLibraries() {
        const libraries = [];

        // jQuery detection
        if (
            window.jQuery ||
            window.$ ||
            document.querySelector('script[src*="jquery"]')
        ) {
            libraries.push({
                name: 'jQuery',
                version: window.jQuery?.fn?.jquery || getScriptVersion('jquery'),
                icon: '🎯'
            });
        }

        // Enhanced Bootstrap detection
        if (
            document.querySelector('link[href*="bootstrap"]') ||
            document.querySelector('script[src*="bootstrap"]') ||
            document.querySelector('.container-fluid, .row, .col, .modal') ||
            document.querySelector('*[class*="bs-"]') ||
            typeof window.bootstrap !== 'undefined'
        ) {
            libraries.push({
                name: 'Bootstrap',
                version: getBootstrapVersion(),
                icon: '🅱️'
            });
        }

        // Tailwind detection
        if (
            document.querySelector('*[class*="sm:"], *[class*="md:"], *[class*="lg:"]') ||
            document.querySelector('script[src*="tailwind"]') ||
            document.querySelector('*[class*="space-y-"], *[class*="grid-cols-"]')
        ) {
            libraries.push({
                name: 'Tailwind CSS',
                version: getTailwindVersion(),
                icon: '🌊'
            });
        }

        return libraries;
    }

    function detectBuildTools() {
        const tools = [];

        // Webpack detection
        if (window.webpackJsonp || window.__webpack_require__ || document.querySelector('script[src*="webpack"]')) {
            tools.push({
                name: 'Webpack',
                version: 'Detected',
                icon: '📦'
            });
        }

        // Vite detection
        if (document.querySelector('script[type="module"][src*="@vite"], script[type="module"][src*="@react-refresh"]')) {
            tools.push({
                name: 'Vite',
                version: 'Detected',
                icon: '⚡'
            });
        }

        return tools;
    }

    function detectServerTech() {
        const tech = [];
        const generator = document.querySelector('meta[name="generator"]')?.content;

        if (generator) {
            tech.push({
                name: 'Generator',
                version: generator,
                icon: '⚙️'
            });
        }

        // Check for common server-side technologies
        const poweredBy = document.querySelector('meta[name="powered-by"]')?.content;
        if (poweredBy) {
            tech.push({
                name: 'Powered By',
                version: poweredBy,
                icon: '🔋'
            });
        }

        return tech;
    }

    function detectFullStack() {
        const stacks = [];

        // MERN Stack detection
        const hasMongoDB = document.querySelector('script[src*="mongodb"]') ||
            window.MongoDB ||
            document.querySelector('meta[name="database"][content*="MongoDB"]');

        const hasExpress = document.querySelector('script[src*="express"]') ||
            document.querySelector('meta[name="powered-by"][content*="Express"]');

        const hasReact = window.React || document.querySelector('[data-reactroot]');

        const hasNode = document.querySelector('script[src*="node_modules"]') ||
            document.querySelector('meta[name="powered-by"][content*="Node"]');

        if (hasMongoDB && hasExpress && hasReact && hasNode) {
            stacks.push({
                name: 'MERN Stack',
                version: 'Detected',
                icon: '🚀'
            });
        }

        // MEAN Stack (MongoDB, Express, Angular, Node)
        const hasAngular = window.angular || document.querySelector('[ng-app]');

        if (hasMongoDB && hasExpress && hasAngular && hasNode) {
            stacks.push({
                name: 'MEAN Stack',
                version: 'Detected',
                icon: '🚀'
            });
        }

        return stacks;
    }

    function detectMarkupLanguage() {
        const markups = [];

        // Check DOCTYPE
        const doctype = document.doctype;
        if (doctype) {
            let doctypeInfo = '';
            if (doctype.name === 'html' && doctype.publicId === '' && doctype.systemId === '') {
                doctypeInfo = 'HTML5';
            } else if (doctype.publicId.includes('XHTML')) {
                doctypeInfo = 'XHTML';
            } else if (doctype.publicId.includes('HTML 4.01')) {
                doctypeInfo = 'HTML 4.01';
            } else {
                doctypeInfo = `${doctype.name} (${doctype.publicId || 'No Public ID'})`;
            }

            markups.push({
                name: 'Document Type',
                version: doctypeInfo,
                icon: '📝'
            });
        }

        // Check for XML
        if (document.querySelector('*[xmlns]')) {
            markups.push({
                name: 'XML Namespaces',
                version: 'Detected',
                icon: '🔖'
            });
        }

        // Check for SVG
        if (document.querySelector('svg')) {
            markups.push({
                name: 'SVG',
                version: 'Detected',
                icon: '🖋️'
            });
        }

        // Check for MathML
        if (document.querySelector('math')) {
            markups.push({
                name: 'MathML',
                version: 'Detected',
                icon: '🧮'
            });
        }

        return markups;
    }

    function detectCharacterEncoding() {
        const encodings = [];

        // Check meta charset
        const charsetMeta = document.querySelector('meta[charset]');
        if (charsetMeta) {
            encodings.push({
                name: 'Character Encoding',
                version: charsetMeta.getAttribute('charset'),
                icon: '🔤'
            });
        } else {
            // Check content-type meta
            const contentTypeMeta = document.querySelector('meta[http-equiv="Content-Type"]');
            if (contentTypeMeta) {
                const content = contentTypeMeta.getAttribute('content');
                const charsetMatch = content.match(/charset=([^;]+)/i);
                if (charsetMatch) {
                    encodings.push({
                        name: 'Character Encoding',
                        version: charsetMatch[1],
                        icon: '🔤'
                    });
                }
            } else {
                // Fallback to document.characterSet
                encodings.push({
                    name: 'Character Encoding',
                    version: document.characterSet || 'Unknown',
                    icon: '🔤'
                });
            }
        }

        return encodings;
    }

    function detectImageFormats() {
        const images = document.querySelectorAll('img');
        const formats = new Map();

        images.forEach(img => {
            const src = img.src;
            if (src) {
                const extension = src.split('.').pop().toLowerCase().split('?')[0];
                if (extension) {
                    const count = formats.get(extension) || 0;
                    formats.set(extension, count + 1);
                }
            }
        });

        // Check background images in CSS
        const elements = document.querySelectorAll('*');
        elements.forEach(el => {
            const style = window.getComputedStyle(el);
            const bgImage = style.backgroundImage;
            if (bgImage && bgImage !== 'none') {
                const matches = bgImage.match(/\.(jpg|jpeg|png|gif|webp|svg|avif)[\?'")]/i);
                if (matches && matches[1]) {
                    const ext = matches[1].toLowerCase();
                    const count = formats.get(ext) || 0;
                    formats.set(ext, count + 1);
                }
            }
        });

        const result = [];
        formats.forEach((count, format) => {
            let icon = '🖼️';
            if (format === 'svg') icon = '🖋️';
            else if (format === 'webp' || format === 'avif') icon = '🚀';
            else if (format === 'gif') icon = '🎞️';

            result.push({
                name: format.toUpperCase(),
                version: `${count} images`,
                icon: icon
            });
        });

        return result;
    }

    function detectServerInfo() {
        const serverInfo = [];

        // Try to get server info from headers via meta tags (some sites expose this)
        const serverMeta = document.querySelector('meta[name="server"], meta[name="host-server"]');
        if (serverMeta) {
            serverInfo.push({
                name: 'Server',
                version: serverMeta.getAttribute('content'),
                icon: '🖥️'
            });
        }

        // Check for CDNs
        const cdns = [
            { pattern: 'cdn.cloudflare.net', name: 'Cloudflare CDN' },
            { pattern: 'amazonaws.com', name: 'AWS' },
            { pattern: 'cloudfront.net', name: 'AWS CloudFront' },
            { pattern: 'akamai', name: 'Akamai' },
            { pattern: 'fastly.net', name: 'Fastly' },
            { pattern: 'cdnjs.cloudflare.com', name: 'CDNJS (Cloudflare)' },
            { pattern: 'googleapis.com', name: 'Google APIs' },
            { pattern: 'gstatic.com', name: 'Google Static' },
            { pattern: 'jsdelivr.net', name: 'jsDelivr' },
            { pattern: 'unpkg.com', name: 'UNPKG' }
        ];

        const scripts = document.querySelectorAll('script[src], link[rel="stylesheet"][href]');
        const detectedCdns = new Set();

        scripts.forEach(element => {
            const url = element.src || element.href;
            if (url) {
                cdns.forEach(cdn => {
                    if (url.includes(cdn.pattern)) {
                        detectedCdns.add(cdn.name);
                    }
                });
            }
        });

        detectedCdns.forEach(cdn => {
            serverInfo.push({
                name: 'CDN',
                version: cdn,
                icon: '🌐'
            });
        });

        return serverInfo;
    }

    function detectEmailServer() {
        const emailInfo = [];

        // Check for common mail client references
        const mailtoLinks = document.querySelectorAll('a[href^="mailto:"]');
        if (mailtoLinks.length > 0) {
            emailInfo.push({
                name: 'Email Links',
                version: `${mailtoLinks.length} detected`,
                icon: '📧'
            });

            // Try to extract domains
            const domains = new Set();
            mailtoLinks.forEach(link => {
                const email = link.href.replace('mailto:', '').split('?')[0];
                const domain = email.split('@')[1];
                if (domain) domains.add(domain);
            });

            if (domains.size > 0) {
                emailInfo.push({
                    name: 'Email Domains',
                    version: Array.from(domains).join(', '),
                    icon: '🌐'
                });
            }
        }

        // Check for mail server headers exposed in meta
        const mailServerMeta = document.querySelector('meta[name="x-mail-server"]');
        if (mailServerMeta) {
            emailInfo.push({
                name: 'Mail Server',
                version: mailServerMeta.getAttribute('content'),
                icon: '📨'
            });
        }

        return emailInfo;
    }

    function detectEmailAddresses() {
        const emails = [];

        // Regex for finding email addresses
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

        // Search in the entire HTML content
        const pageContent = document.documentElement.innerHTML;
        const matches = pageContent.match(emailRegex) || [];

        // Also search in mailto links
        const mailtoLinks = document.querySelectorAll('a[href^="mailto:"]');
        mailtoLinks.forEach(link => {
            const email = link.href.replace('mailto:', '').split('?')[0].trim();
            if (email && !matches.includes(email)) {
                matches.push(email);
            }
        });

        // Deduplicate emails
        const uniqueEmails = [...new Set(matches)];

        // Format for display
        if (uniqueEmails.length > 0) {
            emails.push({
                name: 'Email Addresses',
                version: uniqueEmails.length > 5
                    ? `${uniqueEmails.slice(0, 5).join(', ')}... (${uniqueEmails.length} total)`
                    : uniqueEmails.join(', '),
                icon: '📧'
            });
        }

        return emails;
    }

    function detectTrackers() {
        const trackers = [];

        // Common trackers and their detection patterns
        const trackerPatterns = [
            { name: 'Google Analytics', pattern: ['google-analytics.com', 'ga.js', 'gtag.js'] },
            { name: 'Facebook Pixel', pattern: ['fbevents.js', 'facebook.com/tr'] },
            { name: 'Hotjar', pattern: ['hotjar.com', 'hj.js'] },
            { name: 'Piwik/Matomo', pattern: ['piwik.js', 'matomo.js'] },
            { name: 'LinkedIn Insight Tag', pattern: ['linkedin.com/insight'] },
            { name: 'Twitter Pixel', pattern: ['twq.js', 'twitter.com/ads'] },
            { name: 'AdRoll', pattern: ['adroll.com'] },
            { name: 'Criteo', pattern: ['criteo.com', 'criteo.net'] },
            { name: 'Taboola', pattern: ['taboola.com'] },
            { name: 'Outbrain', pattern: ['outbrain.com'] },
        ];

        // Check all scripts, iframes, and network requests
        const scripts = document.querySelectorAll('script[src]');
        const iframes = document.querySelectorAll('iframe[src]');
        const img = document.querySelectorAll('img[src]');

        const allSources = [
            ...Array.from(scripts).map(s => s.src),
            ...Array.from(iframes).map(i => i.src),
            ...Array.from(img).map(i => i.src),
            document.documentElement.innerHTML
        ];

        // Check for each tracker
        const detectedTrackers = new Set();
        allSources.forEach(source => {
            trackerPatterns.forEach(tracker => {
                tracker.pattern.forEach(pattern => {
                    if (source.includes(pattern)) {
                        detectedTrackers.add(tracker.name);
                    }
                });
            });
        });

        // Add detected trackers to the result
        if (detectedTrackers.size > 0) {
            trackers.push({
                name: 'Trackers',
                version: Array.from(detectedTrackers).join(', '),
                icon: '📊'
            });
        }

        return trackers;
    }

    function detectAnalytics() {
        const analytics = [];

        // Common analytics tools and their detection patterns
        const analyticsTools = [
            { name: 'Google Analytics', pattern: ['google-analytics.com', 'ga.js', 'gtag.js'], globalVar: 'ga' },
            { name: 'Google Tag Manager', pattern: ['googletagmanager.com', 'gtm.js'], globalVar: 'dataLayer' },
            { name: 'Mixpanel', pattern: ['mixpanel.com'], globalVar: 'mixpanel' },
            { name: 'Amplitude', pattern: ['amplitude.com'], globalVar: 'amplitude' },
            { name: 'Segment', pattern: ['segment.com'], globalVar: 'analytics' },
            { name: 'Matomo', pattern: ['matomo.js'], globalVar: '_paq' },
            { name: 'Hotjar', pattern: ['hotjar.com'], globalVar: 'hj' },
            { name: 'Adobe Analytics', pattern: ['omniture.com'], globalVar: 's' },
        ];

        // Check scripts and global variables
        const scripts = document.querySelectorAll('script[src]');
        const scriptSources = Array.from(scripts).map(s => s.src);
        const htmlContent = document.documentElement.innerHTML;

        // Check for each analytics tool
        const detectedAnalytics = new Set();
        analyticsTools.forEach(tool => {
            // Check script sources
            scriptSources.forEach(src => {
                tool.pattern.forEach(pattern => {
                    if (src.includes(pattern)) {
                        detectedAnalytics.add(tool.name);
                    }
                });
            });

            // Check global variables
            if (window[tool.globalVar]) {
                detectedAnalytics.add(tool.name);
            }
        });

        // Add detected analytics tools to the result
        if (detectedAnalytics.size > 0) {
            analytics.push({
                name: 'Analytics Tools',
                version: Array.from(detectedAnalytics).join(', '),
                icon: '📈'
            });
        }

        return analytics;
    }

    function detectPaymentGateways() {
        const paymentGateways = [];

        // Common payment gateways and their detection patterns
        const gatewayPatterns = [
            { name: 'Stripe', pattern: ['stripe.com', 'js.stripe.com'] },
            { name: 'PayPal', pattern: ['paypal.com', 'paypalobjects.com'] },
            { name: 'Square', pattern: ['squareup.com'] },
            { name: 'Braintree', pattern: ['braintreegateway.com'] },
            { name: 'Authorize.net', pattern: ['authorize.net'] },
            { name: 'Razorpay', pattern: ['razorpay.com'] },
            { name: '2Checkout', pattern: ['2checkout.com'] },
            { name: 'Adyen', pattern: ['adyen.com'] },
            { name: 'Buymeacoffee', pattern: ['buymeacoffee.com'] },
            { name: 'Patreon', pattern: ['patreon.com'] },
            { name: 'Ko-fi', pattern: ['ko-fi.com'] },
            { name: 'Ghost', pattern: ['ghost.org'] },
            { name: 'Coindrop', pattern: ['coindrop.to'] },
            { name: 'Tipeee', pattern: ['tipeee.com'] }
        ];

        // Check all scripts and iframes
        const scripts = document.querySelectorAll('script[src]');
        const iframes = document.querySelectorAll('iframe[src]');

        const allSources = [
            ...Array.from(scripts).map(s => s.src),
            ...Array.from(iframes).map(i => i.src),
            document.documentElement.innerHTML
        ];

        // Check for each payment gateway
        const detectedGateways = new Set();
        allSources.forEach(source => {
            gatewayPatterns.forEach(gateway => {
                gateway.pattern.forEach(pattern => {
                    if (source.includes(pattern)) {
                        detectedGateways.add(gateway.name);
                    }
                });
            });
        });

        // Add detected payment gateways to the result
        if (detectedGateways.size > 0) {
            paymentGateways.push({
                name: 'Payment Gateways',
                version: Array.from(detectedGateways).join(', '),
                icon: '💳'
            });
        }

        return paymentGateways;
    }

    function detectSocialMediaLinks() {
        const socialMediaLinks = [];

        // Common social media platforms and their URLs
        const socialMediaPlatforms = [
            { name: 'Facebook', pattern: ['facebook.com'] },
            { name: 'Twitter', pattern: ['twitter.com', 'x.com'] },
            { name: 'Instagram', pattern: ['instagram.com'] },
            { name: 'LinkedIn', pattern: ['linkedin.com'] },
            { name: 'YouTube', pattern: ['youtube.com'] },
            { name: 'Pinterest', pattern: ['pinterest.com'] },
            { name: 'TikTok', pattern: ['tiktok.com'] },
            { name: 'Snapchat', pattern: ['snapchat.com'] },
            { name: 'Medium', pattern: ['medium.com'] },
            { name: 'Twitch', pattern: ['twitch.tv'] },
            { name: 'WeChat', pattern: ['wechat.com'] },
            { name: 'Discord', pattern: ['discord.com'] },
            { name: 'Onlyfans', pattern: ['onlyfans.com'] },
            { name: 'Telegram', pattern: ['telegram.com', 'telegram.me', 'telegram.org'] },
        ];

        // Check all links on the page
        const links = document.querySelectorAll('a[href]');
        const detectedPlatforms = new Set();

        links.forEach(link => {
            const href = link.href;
            socialMediaPlatforms.forEach(platform => {
                platform.pattern.forEach(pattern => {
                    if (href.includes(pattern)) {
                        detectedPlatforms.add(platform.name);
                    }
                });
            });
        });

        // Add detected social media platforms to the result
        if (detectedPlatforms.size > 0) {
            socialMediaLinks.push({
                name: 'Social Media Links',
                version: Array.from(detectedPlatforms).join(', '),
                icon: '📱'
            });
        }

        return socialMediaLinks;
    }

    function detectAdNetworks() {
        const adNetworks = [];

        // Common ad networks and their detection patterns
        const adTech = [
            { name: 'Google Ads', pattern: ['adsbygoogle', 'googleads', 'doubleclick', 'googlesyndication'] },
            { name: 'Facebook Ads', pattern: ['facebook.com/tr', 'connect.facebook.net/signals'] },
            { name: 'Amazon Ads', pattern: ['amazon-adsystem', 'adthat.com'] },
            { name: 'AdRoll', pattern: ['adroll.com'] },
            { name: 'Criteo', pattern: ['criteo.com', 'criteo.net'] },
            { name: 'Taboola', pattern: ['taboola.com'] },
            { name: 'Outbrain', pattern: ['outbrain.com'] },
            { name: 'MediaMath', pattern: ['mathtag.com'] },
            { name: 'AppNexus', pattern: ['adnxs.com'] },
            { name: 'The Trade Desk', pattern: ['adsrvr.org'] },
            { name: 'Rubicon Project', pattern: ['rubiconproject.com'] },
            { name: 'OpenX', pattern: ['openx.net'] },
            { name: 'PubMatic', pattern: ['pubmatic.com'] },
            { name: 'Yandex Ads', pattern: ['yandex.ru/ads'] },
            { name: 'Media.net Ads', pattern: ['media.net'] },
            { name: 'Propellers Ads', pattern: ['propelleradscom'] },
            { name: 'Adsterra Ads', pattern: ['adsterra.com'] },
            { name: 'Adquake Ads', pattern: ['adquake.com'] },
            { name: 'Monetag Ads', pattern: ['monetag.com'] },
            { name: 'Ezoic Ads', pattern: ['ezoic.com'] },
            { name: 'PopAds', pattern: ['Popads.net'] },
            { name: 'Adcash Ads', pattern: ['adcash.com'] },
            { name: 'Mediavine Ads', pattern: ['mediavine.com'] },
            { name: 'RevContent Ads', pattern: ['revContent.com'] },
            { name: 'Skimlinks Ads', pattern: ['skimlinks.com'] },
            { name: 'Bidvertiser Ads', pattern: ['bidvertiser.com'] },
            { name: 'Adversal Ads', pattern: ['adversal.com'] },
            { name: 'Monumetric Ads', pattern: ['monumetric.com'] },
            { name: 'Sovrn Holdings Ads', pattern: ['sovrn.com'] },
            { name: 'Setupad Ads', pattern: ['setupad.com'] },
            { name: 'Taboola Ads', pattern: ['taboola.com'] },
            { name: 'ylliX Ads', pattern: ['ylliX.com'] },
        ];

        // Get all scripts, iframes, and img sources
        const scripts = document.querySelectorAll('script[src]');
        const iframes = document.querySelectorAll('iframe[src]');
        const img = document.querySelectorAll('img[src]');

        // Check scripts, iframes, and img sources for ad networks
        const allSources = [
            ...Array.from(scripts).map(s => s.src),
            ...Array.from(iframes).map(i => i.src),
            ...Array.from(img).map(i => i.src),
            document.documentElement.innerHTML
        ];

        // Check for each ad network
        const detectedNetworks = new Set();
        allSources.forEach(source => {
            adTech.forEach(ad => {
                ad.pattern.forEach(pattern => {
                    if (source.includes(pattern)) {
                        detectedNetworks.add(ad.name);
                    }
                });
            });
        });

        // Add detected ad networks to the result
        if (detectedNetworks.size > 0) {
            adNetworks.push({
                name: 'Ad Networks',
                version: Array.from(detectedNetworks).join(', '),
                icon: '📣'
            });
        }

        return adNetworks;
    }

    // Add new function to detect tag managers
    function detectTagManagers() {
        const tagManagers = [];

        // Common tag managers and their detection patterns
        const managers = [
            { name: 'Google Tag Manager', pattern: ['googletagmanager.com', 'gtm.js', 'gtm-'] },
            { name: 'Adobe Launch/DTM', pattern: ['assets.adobedtm.com', 'launch-', 'satelliteLib'] },
            { name: 'Tealium', pattern: ['tealium', 'utag.js'] },
            { name: 'Segment', pattern: ['segment.com/analytics.js', 'segment.io'] },
            { name: 'Ensighten', pattern: ['ensighten.com'] },
            { name: 'Matomo Tag Manager', pattern: ['matomo', 'piwik'] },
            { name: 'Commanders Act', pattern: ['commandersact.com'] },
            { name: 'Signal', pattern: ['signal.co'] },
            { name: 'Piwik PRO', pattern: ['piwik.pro'] }
        ];

        // Check all script tags and HTML content
        const scripts = document.querySelectorAll('script[src]');
        const scriptSources = Array.from(scripts).map(s => s.src);
        const htmlContent = document.documentElement.innerHTML;

        // Check for each tag manager
        const detectedManagers = new Set();

        // Check script sources
        scriptSources.forEach(src => {
            managers.forEach(manager => {
                manager.pattern.forEach(pattern => {
                    if (src.includes(pattern)) {
                        detectedManagers.add(manager.name);
                    }
                });
            });
        });

        // Check HTML content
        managers.forEach(manager => {
            manager.pattern.forEach(pattern => {
                if (htmlContent.includes(pattern)) {
                    detectedManagers.add(manager.name);
                }
            });
        });

        // Add GTM specific check
        if (window.google_tag_manager || window.dataLayer) {
            detectedManagers.add('Google Tag Manager');
        }

        // Add detected tag managers to the result
        if (detectedManagers.size > 0) {
            tagManagers.push({
                name: 'Tag Managers',
                version: Array.from(detectedManagers).join(', '),
                icon: '🏷️'
            });
        }

        return tagManagers;
    }

    // Add this function to the detectTechnologies function in background.js
    function detectAPIs() {
        const apis = [];

        // Check for fetch or XMLHttpRequest calls
        const originalFetch = window.fetch;
        const originalXHR = window.XMLHttpRequest.prototype.open;

        // Track API endpoints
        const apiEndpoints = new Set();

        // Monitor fetch calls
        if (originalFetch) {
            try {
                // We can only detect APIs that are called while we're monitoring
                // This won't catch APIs called before our script runs
                window.fetch = function (input, init) {
                    try {
                        const url = (input instanceof Request) ? input.url : input;
                        if (url && typeof url === 'string' && url.includes('/api/')) {
                            apiEndpoints.add(url);
                        }
                    } catch (e) { }
                    return originalFetch.apply(this, arguments);
                };

                // Restore original after a short time
                setTimeout(() => {
                    window.fetch = originalFetch;
                }, 3000);
            } catch (e) { }
        }

        // Monitor XHR calls
        if (originalXHR) {
            try {
                window.XMLHttpRequest.prototype.open = function (method, url) {
                    try {
                        if (url && typeof url === 'string' && url.includes('/api/')) {
                            apiEndpoints.add(url);
                        }
                    } catch (e) { }
                    return originalXHR.apply(this, arguments);
                };

                // Restore original after a short time
                setTimeout(() => {
                    window.XMLHttpRequest.prototype.open = originalXHR;
                }, 3000);
            } catch (e) { }
        }

        // Check for common API libraries
        if (window.axios) {
            apis.push({
                name: 'API Client',
                version: 'Axios detected',
                icon: '🔄'
            });
        }

        if (window.gapi) {
            apis.push({
                name: 'API Client',
                version: 'Google API Client',
                icon: '🔄'
            });
        }

        // Check script tags for API-related resources
        const scripts = document.querySelectorAll('script[src]');
        scripts.forEach(script => {
            if (script.src.includes('api.') || script.src.includes('/api/')) {
                apiEndpoints.add(script.src);
            }
        });

        // Look for GraphQL
        const hasGraphQLScript = Array.from(document.querySelectorAll('script')).some(script => {
            return script.src.includes('graphql') ||
                (script.textContent && script.textContent.includes('graphql'));
        });

        if (
            hasGraphQLScript ||
            window.hasOwnProperty('__APOLLO_CLIENT__') ||
            window.hasOwnProperty('__APOLLO_STATE__')
        ) {
            apis.push({
                name: 'GraphQL',
                version: 'Detected',
                icon: '📊'
            });
        }

        // Add detected API endpoints
        if (apiEndpoints.size > 0) {
            apis.push({
                name: 'API Endpoints',
                version: Array.from(apiEndpoints).slice(0, 3).join(', ') +
                    (apiEndpoints.size > 3 ? ` (${apiEndpoints.size} total)` : ''),
                icon: '🔌'
            });
        }

        return apis;
    }

    // Add this function to the detectTechnologies function in background.js
    function detectDomainExpiration() {
        const expirationInfo = [];

        // Get the current domain
        const domain = window.location.hostname;
        const domainParts = domain.split('.');
        const tld = domainParts.pop();
        const sld = domainParts.pop();
        const baseDomain = `${sld}.${tld}`;

        // Add basic domain info first
        expirationInfo.push({
            name: 'Domain',
            version: baseDomain,
            icon: '🌐'
        });

        // Extract domain age information from structured data if available
        const structuredData = extractStructuredData();
        if (structuredData && structuredData.dateCreated) {
            expirationInfo.push({
                name: 'Page Created',
                version: new Date(structuredData.dateCreated).toLocaleDateString(),
                icon: '📄'
            });
        }

        // Add domain age estimate based on page creation or copyright info
        const domainAge = estimateDomainAge();
        if (domainAge) {
            expirationInfo.push({
                name: 'Estimated Age',
                version: domainAge,
                icon: '⏳'
            });
        }

        // WHOIS data will be fetched by getWhoisInfo() and added later
        expirationInfo.push({
            name: 'Fetching WHOIS...',
            version: 'Use Our WhoIS LookUP Extension For WhoIS Info',
            icon: '🔄'
        });

        return expirationInfo;
    }

    // Extract copyright information from the page
    function extractCopyrightInfo() {
        // Common copyright selectors
        const copyrightSelectors = [
            'footer *:contains("©")',
            '.copyright',
            '.footer-copyright',
            '#copyright',
            'footer',
            '[class*="copyright"]',
            '[id*="copyright"]'
        ];

        // Custom function to find elements containing copyright text
        function getElementsWithCopyright() {
            const elements = [];
            const allElements = document.querySelectorAll('*');

            for (const el of allElements) {
                if (el.textContent && el.textContent.includes('©')) {
                    elements.push(el);
                }
            }

            return elements;
        }

        const copyrightElements = getElementsWithCopyright();

        if (copyrightElements.length > 0) {
            // Get the element with the shortest text that contains copyright symbol
            // to avoid getting large blocks of text
            const shortestElement = copyrightElements.reduce((prev, current) =>
                (prev.textContent.length < current.textContent.length) ? prev : current
            );

            const text = shortestElement.textContent.trim();

            // Extract the copyright statement
            const copyrightMatch = text.match(/©\s*(?:[^0-9]*)\s*((?:19|20)\d{2}(?:\s*[-–—]\s*(?:20)?\d{2})?)[^\n]*/);
            if (copyrightMatch) {
                return copyrightMatch[0].trim();
            }
        }

        return null;
    }

    // Function to fetch WHOIS data from whois.com
    async function fetchWhoisData(domain) {
        try {
            // Fetch the WHOIS page for the domain
            const response = await fetch(`https://www.whois.com/whois/${domain}`);
            const html = await response.text();

            // Create a temporary DOM element to parse the HTML
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');

            // Extract WHOIS data from the page
            const whoisData = [];

            // Find the WHOIS data container
            const dataContainer = doc.querySelector('.whois-data') ||
                doc.querySelector('#registryData') ||
                doc.querySelector('.df-block');

            if (!dataContainer) {
                return null;
            }

            // Function to extract date from text
            function extractDate(text) {
                // Common date formats in WHOIS data
                const datePatterns = [
                    /(\d{4}-\d{2}-\d{2})/,                   // YYYY-MM-DD
                    /(\d{2}-\w{3}-\d{4})/,                   // DD-MMM-YYYY
                    /(\d{2}\/\d{2}\/\d{4})/,                 // DD/MM/YYYY or MM/DD/YYYY
                    /(\w+ \d{1,2}, \d{4})/,                  // Month DD, YYYY
                    /(\d{1,2}-\w+-\d{4})/,                   // D-MMM-YYYY
                    /(\d{1,2} \w+ \d{4})/                    // DD Month YYYY
                ];

                for (const pattern of datePatterns) {
                    const match = text.match(pattern);
                    if (match) return match[1];
                }
                return null;
            }

            // Extract creation date
            const creationLabels = ['Creation Date:', 'Registered on:', 'Domain Registration Date:',
                'Registration Date:', 'Created on:', 'Created:', 'Domain Created:'];

            let creationDate = null;

            for (const label of creationLabels) {
                // Check if the text contains the label
                if (dataContainer.textContent.includes(label)) {
                    // Get the text after the label
                    const textAfterLabel = dataContainer.textContent.split(label)[1].split('\n')[0].trim();
                    creationDate = extractDate(textAfterLabel);
                    if (creationDate) break;
                }
            }

            if (creationDate) {
                whoisData.push({
                    name: 'Registration Date',
                    version: creationDate,
                    icon: '📅'
                });
            }

            // Extract expiration date
            const expirationLabels = ['Expiration Date:', 'Registry Expiry Date:', 'Expires on:',
                'Expiry Date:', 'Expires:', 'Domain Expires:'];

            let expirationDate = null;

            for (const label of expirationLabels) {
                if (dataContainer.textContent.includes(label)) {
                    const textAfterLabel = dataContainer.textContent.split(label)[1].split('\n')[0].trim();
                    expirationDate = extractDate(textAfterLabel);
                    if (expirationDate) break;
                }
            }

            if (expirationDate) {
                whoisData.push({
                    name: 'Expiration Date',
                    version: expirationDate,
                    icon: '⏱️'
                });

                // Calculate days until expiration
                try {
                    const expDate = new Date(expirationDate);
                    const today = new Date();
                    const daysLeft = Math.ceil((expDate - today) / (1000 * 60 * 60 * 24));

                    if (!isNaN(daysLeft)) {
                        let status = '✅ Valid';
                        let icon = '✅';

                        if (daysLeft < 0) {
                            status = '⚠️ Expired';
                            icon = '⚠️';
                        } else if (daysLeft < 30) {
                            status = `⚠️ Expiring soon (${daysLeft} days)`;
                            icon = '⚠️';
                        } else {
                            status = `✅ Valid (${daysLeft} days left)`;
                        }

                        whoisData.push({
                            name: 'Expiration Status',
                            version: status,
                            icon: icon
                        });
                    }
                } catch (e) {
                    console.error("Error calculating expiration days:", e);
                }
            }

            // Extract registrar information
            const registrarLabels = ['Registrar:', 'Sponsoring Registrar:'];

            for (const label of registrarLabels) {
                if (dataContainer.textContent.includes(label)) {
                    const textAfterLabel = dataContainer.textContent.split(label)[1].split('\n')[0].trim();
                    if (textAfterLabel) {
                        whoisData.push({
                            name: 'Registrar',
                            version: textAfterLabel.substring(0, 50), // Limit length
                            icon: '🏢'
                        });
                        break;
                    }
                }
            }

            // Extract domain status
            if (dataContainer.textContent.includes('Domain Status:')) {
                const statusText = dataContainer.textContent.split('Domain Status:')[1].split('\n')[0].trim();
                if (statusText) {
                    whoisData.push({
                        name: 'Domain Status',
                        version: statusText.substring(0, 50), // Limit length
                        icon: '🔒'
                    });
                }
            }

            return whoisData;
        } catch (error) {
            console.error("Error in fetchWhoisData:", error);
            return null;
        }
    }


    // Extract structured data that might contain registration information
    function extractStructuredData() {
        try {
            // Look for JSON-LD structured data
            const scriptTags = document.querySelectorAll('script[type="application/ld+json"]');
            for (const script of scriptTags) {
                try {
                    const data = JSON.parse(script.textContent);

                    // Check for WebSite, WebPage, or Organization schema
                    if (data['@type'] === 'WebSite' || data['@type'] === 'WebPage' || data['@type'] === 'Organization') {
                        return data;
                    }

                    // Handle array of structured data objects
                    if (Array.isArray(data)) {
                        for (const item of data) {
                            if (item['@type'] === 'WebSite' || item['@type'] === 'WebPage' || item['@type'] === 'Organization') {
                                return item;
                            }
                        }
                    }
                } catch (e) {
                    // Ignore JSON parsing errors
                }
            }
        } catch (e) {
            // Fallback to null if any error occurs
        }

        return null;
    }

    // Estimate domain age from available information
    function estimateDomainAge() {
        let estimatedYear = null;

        // Try to find a copyright year
        const copyrightText = extractCopyrightInfo();
        if (copyrightText) {
            const yearMatch = copyrightText.match(/\b(19|20)\d{2}\b/g);
            if (yearMatch && yearMatch.length > 0) {
                // Use the earliest year
                estimatedYear = Math.min(...yearMatch.map(Number));
            }
        }

        // Try to find creation date in meta tags
        if (!estimatedYear) {
            const creationMetaTags = [
                document.querySelector('meta[name="created"]'),
                document.querySelector('meta[name="date"]'),
                document.querySelector('meta[property="article:published_time"]'),
                document.querySelector('meta[name="DC.date.created"]')
            ];

            for (const meta of creationMetaTags) {
                if (meta) {
                    const content = meta.getAttribute('content');
                    if (content) {
                        try {
                            const date = new Date(content);
                            if (!isNaN(date.getFullYear())) {
                                estimatedYear = date.getFullYear();
                                break;
                            }
                        } catch (e) {
                            // Ignore date parsing errors
                        }
                    }
                }
            }
        }

        if (estimatedYear) {
            const currentYear = new Date().getFullYear();
            const age = currentYear - estimatedYear;
            return `~${age} years (since ${estimatedYear})`;
        }

        return null;
    }

    function detectForms() {
        const formInfo = [];

        // Get all forms
        const forms = document.querySelectorAll('form');

        if (forms.length > 0) {
            // Basic form info
            formInfo.push({
                name: 'Forms Detected',
                version: `${forms.length} forms`,
                icon: '📝'
            });

            // Categorize forms
            const loginForms = Array.from(forms).filter(form =>
                form.querySelector('input[type="password"]') ||
                form.id?.toLowerCase().includes('login') ||
                form.className?.toLowerCase().includes('login')
            ).length;

            const searchForms = Array.from(forms).filter(form =>
                form.querySelector('input[type="search"]') ||
                form.id?.toLowerCase().includes('search') ||
                form.className?.toLowerCase().includes('search')
            ).length;

            const contactForms = Array.from(forms).filter(form =>
                form.id?.toLowerCase().includes('contact') ||
                form.className?.toLowerCase().includes('contact')
            ).length;

            // Add form types if detected
            if (loginForms > 0) {
                formInfo.push({
                    name: 'Login Forms',
                    version: `${loginForms} detected`,
                    icon: '🔑'
                });
            }

            if (searchForms > 0) {
                formInfo.push({
                    name: 'Search Forms',
                    version: `${searchForms} detected`,
                    icon: '🔍'
                });
            }

            if (contactForms > 0) {
                formInfo.push({
                    name: 'Contact Forms',
                    version: `${contactForms} detected`,
                    icon: '✉️'
                });
            }
        }

        return formInfo;
    }

    // DNS information (limited to what's available client-side)
    function detectDNSInfo() {
        const dnsInfo = [];

        // Most DNS info requires server-side access, but we can detect some hints
        const domain = window.location.hostname;

        dnsInfo.push({
            name: 'Domain',
            version: domain,
            icon: '🌐'
        });

        // Check for subdomains
        const subdomainParts = domain.split('.');
        if (subdomainParts.length > 2) {
            // Likely has subdomain
            dnsInfo.push({
                name: 'Subdomain',
                version: subdomainParts[0],
                icon: '🏷️'
            });
        }

        return dnsInfo;
    }

    // WHOIS information (limited to what's exposed client-side)
    function getWhoisInfo() {
        const whoisInfo = [];

        // Get basic domain information
        const domain = window.location.hostname;
        const domainParts = domain.split('.');
        const tld = domainParts.pop();
        const sld = domainParts.pop();
        const baseDomain = `${sld}.${tld}`;

        whoisInfo.push({
            name: 'Domain',
            version: baseDomain,
            icon: '🌐'
        });

        whoisInfo.push({
            name: 'TLD',
            version: `.${tld}`,
            icon: '🔍'
        });

        // Check for organization information in meta tags
        const orgMetas = [
            document.querySelector('meta[name="organization"]'),
            document.querySelector('meta[property="og:site_name"]'),
            document.querySelector('meta[name="author"]'),
            document.querySelector('meta[name="copyright"]')
        ];

        for (const meta of orgMetas) {
            if (meta) {
                const content = meta.getAttribute('content') || meta.getAttribute('property');
                if (content) {
                    whoisInfo.push({
                        name: 'Organization',
                        version: content,
                        icon: '🏢'
                    });
                    break;
                }
            }
        }

        // Look for copyright information which often includes registration year
        const copyrightText = extractCopyrightInfo();
        if (copyrightText) {
            whoisInfo.push({
                name: 'Copyright',
                version: copyrightText,
                icon: '©️'
            });
        }

        // Fetch WHOIS data from whois.com
        fetchWhoisData(baseDomain).then(data => {
            if (data) {
                // Add the data to currentTabTechnologies
                if (currentTabTechnologies[tabId]) {
                    const whoisIndex = currentTabTechnologies[tabId].whois ?
                        currentTabTechnologies[tabId].whois : [];

                    // Add WHOIS data to the existing results
                    currentTabTechnologies[tabId].whois = [...whoisIndex, ...data];

                    // Notify popup about the updated data
                    browser.runtime.sendMessage({
                        type: 'TECH_DETECTED',
                        data: currentTabTechnologies[tabId],
                        isAnalyzing: false
                    });
                }
            }
        }).catch(error => {
            console.error("Error fetching WHOIS data:", error);
        });

        return whoisInfo;
    }

    // //Functions to check security loopholes in the domain
    // function detectMixedContent() {
    //     const vulnerabilities = [];

    //     // Check for HTTP resources on an HTTPS page
    //     if (window.location.protocol === 'https:') {
    //         const httpResources = [];

    //         // Check images, scripts, iframes, and stylesheets
    //         const elements = document.querySelectorAll('img[src^="http://"], script[src^="http://"], iframe[src^="http://"], link[href^="http://"]');
    //         elements.forEach(el => {
    //             const src = el.src || el.href;
    //             if (src.startsWith('http://')) {
    //                 httpResources.push(src);
    //             }
    //         });

    //         if (httpResources.length > 0) {
    //             vulnerabilities.push({
    //                 name: 'Mixed Content',
    //                 description: 'HTTP resources loaded on an HTTPS page',
    //                 details: httpResources.slice(0, 5).join(', ') + (httpResources.length > 5 ? `... (${httpResources.length} total)` : ''),
    //                 severity: 'High',
    //                 icon: '⚠️'
    //             });
    //         }
    //     }

    //     return vulnerabilities;
    // }

    // function detectMissingSecurityHeaders() {
    //     const vulnerabilities = [];

    //     // List of recommended security headers
    //     const requiredHeaders = [
    //         'Content-Security-Policy',
    //         'X-Frame-Options',
    //         'Strict-Transport-Security',
    //         'X-Content-Type-Options',
    //         'Referrer-Policy'
    //     ];

    //     // Get response headers (requires background script or server-side implementation)
    //     const missingHeaders = requiredHeaders.filter(header => {
    //         return !document.querySelector(`meta[http-equiv="${header}"]`) && !(header in window.performance.getEntries()[0].responseHeaders);
    //     });

    //     if (missingHeaders.length > 0) {
    //         vulnerabilities.push({
    //             name: 'Missing Security Headers',
    //             description: 'Recommended security headers are missing',
    //             details: missingHeaders.join(', '),
    //             severity: 'Medium',
    //             icon: '🛡️'
    //         });
    //     }

    //     return vulnerabilities;
    // }

    // function detectOutdatedLibraries() {
    //     const vulnerabilities = [];

    //     // List of libraries and their minimum safe versions
    //     const libraryVersions = {
    //         'jQuery': '3.0.0',
    //         'Bootstrap': '4.0.0',
    //         'React': '16.0.0',
    //         'Vue': '2.6.0',
    //         'Angular': '8.0.0'
    //     };

    //     // Check for outdated libraries
    //     const outdatedLibs = [];
    //     for (const [lib, minVersion] of Object.entries(libraryVersions)) {
    //         const version = getLibraryVersion(lib); // Use your existing getScriptVersion function
    //         if (version && version < minVersion) {
    //             outdatedLibs.push(`${lib} (${version})`);
    //         }
    //     }

    //     if (outdatedLibs.length > 0) {
    //         vulnerabilities.push({
    //             name: 'Outdated Libraries',
    //             description: 'Outdated libraries with known vulnerabilities',
    //             details: outdatedLibs.join(', '),
    //             severity: 'High',
    //             icon: '📚'
    //         });
    //     }

    //     return vulnerabilities;
    // }

    // New version detection functions
    function getSvelteVersion() {
        try {
            const script = document.querySelector('script[src*="svelte"]');
            const version = script?.src.match(/svelte@(\d+\.\d+\.\d+)/);
            return version?.[1] || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getSolidVersion() {
        try {
            const script = document.querySelector('script[src*="solid"]');
            const version = script?.src.match(/solid@(\d+\.\d+\.\d+)/);
            return version?.[1] || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function detectLibraries() {
        const libraries = [];

        // jQuery detection
        if (
            window.jQuery ||
            window.$ ||
            document.querySelector('script[src*="jquery"]')
        ) {
            libraries.push({
                name: 'jQuery',
                version: window.jQuery?.fn?.jquery || getScriptVersion('jquery'),
                icon: '🎯'
            });
        }

        // Enhanced Bootstrap detection
        if (
            document.querySelector('link[href*="bootstrap"]') ||
            document.querySelector('script[src*="bootstrap"]') ||
            document.querySelector('.container-fluid, .row, .col, .modal') ||
            document.querySelector('*[class*="bs-"]') ||
            typeof window.bootstrap !== 'undefined'
        ) {
            libraries.push({
                name: 'Bootstrap',
                version: getBootstrapVersion(),
                icon: '🅱️'
            });
        }

        // Tailwind detection
        if (
            document.querySelector('*[class*="sm:"], *[class*="md:"], *[class*="lg:"]') ||
            document.querySelector('script[src*="tailwind"]') ||
            document.querySelector('*[class*="space-y-"], *[class*="grid-cols-"]')
        ) {
            libraries.push({
                name: 'Tailwind CSS',
                version: getTailwindVersion(),
                icon: '🌊'
            });
        }

        return libraries;
    }

    function detectBuildTools() {
        const tools = [];

        // Webpack detection
        if (window.webpackJsonp || window.__webpack_require__ || document.querySelector('script[src*="webpack"]')) {
            tools.push({
                name: 'Webpack',
                version: 'Detected',
                icon: '📦'
            });
        }

        // Vite detection
        if (document.querySelector('script[type="module"][src*="@vite"], script[type="module"][src*="@react-refresh"]')) {
            tools.push({
                name: 'Vite',
                version: 'Detected',
                icon: '⚡'
            });
        }

        return tools;
    }

    function detectServerTech() {
        const tech = [];
        const generator = document.querySelector('meta[name="generator"]')?.content;

        if (generator) {
            tech.push({
                name: 'Generator',
                version: generator,
                icon: '⚙️'
            });
        }

        // Check for common server-side technologies
        const poweredBy = document.querySelector('meta[name="powered-by"]')?.content;
        if (poweredBy) {
            tech.push({
                name: 'Powered By',
                version: poweredBy,
                icon: '🔋'
            });
        }

        return tech;
    }

    function getReactVersion() {
        try {
            const versions = [
                window.React?.version,
                window.__REACT_DEVTOOLS_GLOBAL_HOOK__?.renderers?.get(1)?.version,
                document.querySelector('[data-reactroot]')?.dataset?.reactVersion,
                getScriptVersion('react')
            ];
            return versions.find(v => v) || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getNextVersion() {
        try {
            return window.__NEXT_DATA__?.buildId ? 'Detected' : 'Unknown';
        } catch {
            return 'Detected';
        }
    }

    function getVueVersion() {
        try {
            const versions = [
                window.__VUE__?.version,
                window.Vue?.version,
                getScriptVersion('vue')
            ];
            return versions.find(v => v) || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getSvelteVersion() {
        try {
            const script = document.querySelector('script[src*="svelte"]');
            const version = script?.src.match(/svelte@(\d+\.\d+\.\d+)/);
            return version?.[1] || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getSolidVersion() {
        try {
            const script = document.querySelector('script[src*="solid"]');
            const version = script?.src.match(/solid@(\d+\.\d+\.\d+)/);
            return version?.[1] || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getAngularVersion() {
        try {
            return document.querySelector('[ng-version]')?.getAttribute('ng-version') || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getBootstrapVersion() {
        try {
            const link = document.querySelector('link[href*="bootstrap"]');
            const script = document.querySelector('script[src*="bootstrap"]');
            const version = link?.href.match(/bootstrap@(\d+\.\d+\.\d+)/) ||
                script?.src.match(/bootstrap@(\d+\.\d+\.\d+)/);
            return version?.[1] || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getTailwindVersion() {
        try {
            const script = document.querySelector('script[src*="tailwind"]');
            const version = script?.src.match(/tailwind@(\d+\.\d+\.\d+)/);
            return version?.[1] || 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getNodeVersion() {
        try {
            const expressScript = document.querySelector('script[src*="express"]');
            if (expressScript) {
                const version = expressScript.src.match(/express@(\d+\.\d+\.\d+)/);
                if (version?.[1]) return `Express ${version[1]}`;
            }

            const nextScript = document.querySelector('script[src*="next"]');
            if (nextScript) {
                const version = nextScript.src.match(/next@(\d+\.\d+\.\d+)/);
                if (version?.[1]) return `Next.js ${version[1]}`;
            }

            return 'Detected';
        } catch {
            return 'Detected';
        }
    }

    function getScriptVersion(library) {
        try {
            const script = Array.from(document.scripts)
                .find(s => s.src?.includes(library));
            const version = script?.src.match(new RegExp(`${library}@(\\d+\\.\\d+\\.\\d+)`));
            return version?.[1] || null;
        } catch {
            return null;
        }
    }

    function getScriptVersion(library) {
        try {
            const script = Array.from(document.scripts)
                .find(s => s.src?.includes(library));
            const version = script?.src.match(new RegExp(`${library}@(\\d+\\.\\d+\\.\\d+)`));
            return version?.[1] || null;
        } catch {
            return null;
        }
    }
}
