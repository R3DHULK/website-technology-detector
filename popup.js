document.addEventListener('DOMContentLoaded', () => {
    const detectButton = document.getElementById('detectButton');
    const resultsDiv = document.getElementById('results');
    let isAnalyzing = false;

    // Initialize state
    updateButtonState();
    checkCurrentState();

    detectButton.addEventListener('click', async () => {
        try {
            const tabs = await browser.tabs.query({ active: true, currentWindow: true });
            if (tabs.length === 0) {
                showError("No active tab found");
                return;
            }

            const tabId = tabs[0].id;

            isAnalyzing = true;
            updateButtonState();
            showLoading();

            // On mobile, we need to ensure we have permission to access the tab
            try {
                await browser.tabs.executeScript(tabId, {
                    code: 'true' // Just a dummy script to check permissions
                });
            } catch (err) {
                showError("Permission denied. Please grant permission to access this page.");
                isAnalyzing = false;
                updateButtonState();
                return;
            }

            browser.runtime.sendMessage({
                type: 'START_DETECTION',
                tabId: tabId
            });
        } catch (error) {
            showError(error.message);
            isAnalyzing = false;
            updateButtonState();
        }
    });

    // Listen for messages
    browser.runtime.onMessage.addListener((message) => {
        switch (message.type) {
            case 'TECH_DETECTED':
                isAnalyzing = false;
                updateButtonState();
                displayResults(message.data);
                break;
            case 'ANALYSIS_STATUS':
                isAnalyzing = message.isAnalyzing;
                updateButtonState();
                if (isAnalyzing) showLoading();
                break;
            case 'ANALYSIS_ERROR':
                isAnalyzing = false;
                updateButtonState();
                showError(message.error);
                break;
        }
    });

    function updateButtonState() {
        detectButton.disabled = isAnalyzing;
        detectButton.innerHTML = isAnalyzing ?
            '<span class="spinner"></span>Analyzing...' :
            'Start Detection';
    }

    function showLoading() {
        resultsDiv.innerHTML = `
        <div class="status-message loading">
          Analyzing page technologies...
        </div>
      `;
    }

    function showError(error) {
        resultsDiv.innerHTML = `
        <div class="error-message">
          ${error}
        </div>
      `;
    }

    async function checkCurrentState() {
        try {
            const response = await browser.runtime.sendMessage({ type: 'GET_TECHNOLOGIES' });
            if (response) {
                isAnalyzing = response.isAnalyzing;
                updateButtonState();

                if (response.data) {
                    displayResults(response.data);
                } else if (isAnalyzing) {
                    showLoading();
                }
            }
        } catch (error) {
            console.error("Error checking current state:", error);
        }
    }

    function displayResults(data) {
        resultsDiv.innerHTML = '';

        const categories = [
            { key: 'frameworks', title: 'Frameworks' },
            { key: 'libraries', title: 'Libraries' },
            { key: 'buildTools', title: 'Build Tools' },
            { key: 'serverTech', title: 'Server Technologies' },
            { key: 'fullStack', title: 'Full Stack Technologies' },
            { key: 'markup', title: 'Markup Languages' },
            { key: 'encoding', title: 'Character Encoding' },
            { key: 'images', title: 'Image Formats' },
            { key: 'serverInfo', title: 'Server Information' },
            { key: 'emailServer', title: 'Email Server' },
            { key: 'dnsInfo', title: 'DNS Information' },
            { key: 'whois', title: 'Domain Information' },
            { key: 'emails', title: 'Email Addresses' },
            { key: 'forms', title: 'Forms' },
            { key: 'apis', title: 'API Detection' },
            { key: 'adNetworks', title: 'Ad Networks' },
            { key: 'tagManagers', title: 'Tag Managers' },
            { key: 'domainExpiration', title: 'Domain Expiration' },
            { key: 'trackers', title: 'Trackers' },
            { key: 'analytics', title: 'Analytics' },
            { key: 'paymentGateways', title: 'Payment Gateways' },
            { key: 'socialMediaLinks', title: 'Social Media Links' },
        ];

        const hasAnyTech = categories.some(cat => data[cat.key]?.length > 0);

        if (!hasAnyTech) {
            resultsDiv.innerHTML = `
          <div class="status-message">
            No technologies detected on this page
          </div>
        `;
            return;
        }

        categories.forEach(category => {
            if (data[category.key]?.length > 0) {
                const groupDiv = document.createElement('div');
                groupDiv.className = 'tech-group';

                const techItems = data[category.key].map(tech => `
                  <div class="tech-item">
                    <div class="tech-name">
                      <span class="tech-icon">${tech.icon || '🔧'}</span>
                      <span>${tech.name}</span>
                    </div>
                    ${tech.version ? `<span class="version">${tech.version}</span>` : ''}
                  </div>
                `).join('');

                groupDiv.innerHTML = `
                    <h2>${category.title}</h2>
                    ${techItems}
                `;

                resultsDiv.appendChild(groupDiv);
            }
        });
    }
});