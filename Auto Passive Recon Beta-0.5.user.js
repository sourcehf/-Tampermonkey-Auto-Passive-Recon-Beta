// ==UserScript==
// @name         Auto Passive Recon Beta
// @namespace    http://tampermonkey.net/
// @version      0.5
// @description  Advanced passive reconnaissance with Wappalyzer-style detection
// @author       Source | BTC: 3NgAAB4hkGc42Uo3NYtzVNhiwsJ3nbpo9y
// @match        *://*/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @require      https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js
// ==/UserScript==

(function() {
    'use strict';


    const signatures = {
        frameworks: {
            'React': {
                js: [
                    { match: () => window.React?.version, version: 'window.React.version' },
                    { match: () => window.ReactDOM?.version, version: 'window.ReactDOM.version' },
                    { match: () => document.querySelector('[data-reactroot]'), version: null },
                    { match: () => window._REACT_DEVTOOLS_GLOBAL_HOOK__, version: null }
                ],
                html: [
                    { match: /<[^>]+data-react/, version: null },
                    { match: /<[^>]+react-id/, version: null }
                ],
                meta: [
                    { match: 'meta[name="react-version"]', version: 'content' }
                ]
            },
            'Angular': {
                js: [
                    { match: () => window.angular?.version?.full, version: 'window.angular.version.full' },
                    { match: () => document.querySelector('[ng-version]')?.getAttribute('ng-version'), version: 'attr:ng-version' }
                ],
                html: [
                    { match: /<[^>]+ng-controller/, version: null },
                    { match: /<[^>]+ng-app/, version: null },
                    { match: /<[^>]+ng-/, version: null }
                ]
            },
            'Vue.js': {
                js: [
                    { match: () => window.Vue?.version, version: 'window.Vue.version' },
                    { match: () => document.querySelector('[data-v-app]'), version: null }
                ],
                html: [
                    { match: /<[^>]+data-v-/, version: null },
                    { match: /<[^>]+v-for/, version: null },
                    { match: /<[^>]+v-if/, version: null }
                ]
            },
            'Socket.io': {
                js: [
                    { match: () => window.io || document.querySelector('script[src*="socket.io"]'), version: null }
                ],
                html: [
                    { match: /socket\.io.*\.js/i, version: null }
                ]
            },
            'jQuery': {
                js: [
                    { match: () => window.jQuery?.fn?.jquery || window.$?.fn?.jquery,
                      version: () => window.jQuery?.fn?.jquery || window.$?.fn?.jquery }
                ],
                html: [
                    { match: /<script[^>]*jquery[^>]*\.js/i, version: null },
                    { match: /\/jquery[\d.]*\.js/i, version: null }
                ]
            },
            'jQuery UI': {
                js: [
                    { match: () => window.jQuery?.ui, version: () => window.jQuery?.ui?.version }
                ],
                html: [
                    { match: /jquery-ui/i, version: null }
                ]
            },
            'Bootstrap': {
                js: [
                    { match: () => window.bootstrap?.Modal, version: null }
                ],
                html: [
                    { match: /bootstrap(\.min)?\.css/, version: null },
                    { match: /class="[^"]*navbar/, version: null },
                    { match: /class="[^"]*container/, version: null }
                ]
            },
            'TailwindCSS': {
                html: [
                    { match: /tailwind(\.min)?\.css/, version: null },
                    { match: /class="[^"]*text-\w{1,3}-\d{3}/, version: null }
                ]
            },
            'Next.js': {
                js: [
                    { match: () => window.__NEXT_DATA__, version: null }
                ],
                html: [
                    { match: /<div id="__next"/, version: null }
                ]
            },
            'Nuxt.js': {
                html: [
                    { match: /<div id="__nuxt"/, version: null },
                    { match: /_nuxt\//, version: null }
                ]
            },
            'Express': {
                headers: [
                    { match: 'x-powered-by', value: 'Express' }
                ]
            },
            'Laravel': {
                html: [
                    { match: /<meta name="csrf-token"/, version: null }
                ],
                headers: [
                    { match: 'set-cookie', value: 'laravel_session' }
                ]
            }
        },
        analytics: {
            'Google Analytics': {
                js: [
                    { match: () => window.ga?.getAll?.()?.[0]?.get('version'), version: 'window.ga.getAll()[0].get("version")' },
                    { match: () => window.google_tag_manager, version: null },
                    { match: () => window.gtag, version: null }
                ],
                html: [
                    { match: /google-analytics.com\/analytics.js/, version: null },
                    { match: /google-analytics.com\/ga.js/, version: null }
                ]
            },
            'Google Tag Manager': {
                html: [
                    { match: /googletagmanager.com\/gtm.js/, version: null },
                    { match: /googletagmanager.com\/gtag\/js/, version: null }
                ],
                js: [
                    { match: () => window.google_tag_manager, version: null }
                ]
            },
            'Matomo': {
                js: [
                    { match: () => window._paq, version: null }
                ]
            },
            'Plausible': {
                js: [
                    { match: () => window.plausible, version: null }
                ],
                html: [
                    { match: /plausible\.io\/js/, version: null }
                ]
            }
        },
        cms: {
            'WordPress': {
                meta: [
                    { match: 'meta[name="generator"][content*="WordPress"]', version: 'content:WordPress ([\\d.]+)' }
                ],
                html: [
                    { match: /<link[^>]+wp-content/, version: null },
                    { match: /<link[^>]+wp-includes/, version: null }
                ],
                js: [
                    { match: () => window.wp?.version, version: 'window.wp.version' }
                ]
            },
            'Drupal': {
                js: [
                    { match: () => window.Drupal?.version, version: 'window.Drupal.version' }
                ],
                meta: [
                    { match: 'meta[name="generator"][content*="Drupal"]', version: 'content:Drupal ([\\d.]+)' }
                ],
                html: [
                    { match: /sites\/all\/themes/, version: null },
                    { match: /sites\/all\/modules/, version: null }
                ]
            },
            'MyBB': {
                js: [
                    { match: () => window.MyBB || window.quickreply, version: null }
                ],
                html: [
                    { match: /mybb\.(com|js)/i, version: null },
                    { match: /MyBB/i, version: null }
                ]
            }
        },
        libraries: {
            'Chart.js': {
                js: [
                    { match: () => window.Chart?.version, version: 'window.Chart.version' }
                ],
                html: [
                    { match: /chart\.js/i, version: null }
                ]
            },
            'Highlight.js': {
                js: [
                    { match: () => window.hljs, version: null }
                ],
                html: [
                    { match: /highlight\.js|\.hljs/i, version: null }
                ]
            },
            'Select2': {
                js: [
                    { match: () => window.jQuery?.fn?.select2, version: null }
                ],
                html: [
                    { match: /select2[\.-]/i, version: null }
                ]
            },
            'SoundManager': {
                js: [
                    { match: () => window.soundManager, version: null }
                ],
                html: [
                    { match: /soundmanager2/i, version: null }
                ]
            },
            'Lodash': {
                js: [
                    { match: () => window._, version: '_.VERSION' }
                ]
            },
            'Moment.js': {
                js: [
                    { match: () => window.moment, version: 'window.moment.version' }
                ]
            },
            'Axios': {
                js: [
                    { match: () => window.axios, version: 'window.axios.VERSION' }
                ]
            },
            'Font Awesome': {
                html: [
                    { match: /font-awesome(\.min)?\.css/, version: null },
                    { match: /class="[^"]*fa-/, version: null }
                ]
            },
            'DataTables': {
                js: [
                    { match: () => window.$.fn?.dataTable, version: null }
                ],
                html: [
                    { match: /dataTables(\.min)?\.css/, version: null }
                ]
            }
        },
        cdn: {
            'Cloudflare': {
                html: [
                    { match: /cloudflare\.com/i, version: null }
                ],
                headers: [
                    { match: 'cf-ray', value: '' },
                    { match: 'server', value: 'cloudflare' }
                ]
            },
            'cdnjs': {
                html: [
                    { match: /cdnjs\.cloudflare\.com/i, version: null }
                ]
            },
            'jsDelivr': {
                html: [
                    { match: /cdn\.jsdelivr\.net/, version: null }
                ]
            },
            'Unpkg': {
                html: [
                    { match: /unpkg\.com/, version: null }
                ]
            }
        },
        languages: {
            'PHP': {
                headers: [
                    { match: 'x-powered-by', value: 'PHP' }
                ],
                html: [
                    { match: /\.php([?/]|$)/i, version: null },
                    { match: /<\?php/i, version: null }
                ]
            },
            'Node.js': {
                js: [
                    { match: () => window.process?.versions?.node, version: 'window.process.versions.node' }
                ],
                headers: [
                    { match: 'x-powered-by', value: 'Node.js' }
                ]
            }
        },
        security: {
            'HSTS': {
                headers: [
                    { match: 'strict-transport-security', value: '' }
                ]
            },
            'reCAPTCHA': {
                js: [
                    { match: () => window.grecaptcha, version: null }
                ],
                html: [
                    { match: /www\.google\.com\/recaptcha/, version: null }
                ]
            },
            'hCaptcha': {
                html: [
                    { match: /hcaptcha\.com\/captcha/, version: null }
                ]
            },
            'CSP': {
                headers: [
                    { match: 'content-security-policy', value: '' }
                ]
            }
        },
        misc: {
            'HTTP/2': {

                js: [
                    {
                        match: () => {
                            const entries = performance.getEntriesByType('navigation');
                            return entries.length > 0 && entries[0].nextHopProtocol === 'h2';
                        },
                        version: null
                    }
                ]
            },
            'RSS': {
                html: [
                    { match: /<link[^>]+type=["']application\/rss\+xml["']/, version: null },
                    { match: /<link[^>]+type=["']application\/atom\+xml["']/, version: null }
                ]
            }
        },
        payment: {
            'Stripe': {
                js: [
                    { match: () => window.Stripe, version: null }
                ],
                html: [
                    { match: /js\.stripe\.com/, version: null }
                ]
            },
            'PayPal': {
                js: [
                    { match: () => window.paypal, version: null }
                ],
                html: [
                    { match: /paypal\.com\/sdk/, version: null }
                ]
            }
        },
        optimization: {
            'Webpack': {
                js: [
                    { match: () => window.webpackJsonp, version: null }
                ]
            },
            'Babel': {
                js: [
                    { match: () => window._babelPolyfill, version: null }
                ]
            }
        },
        database: {
            'MongoDB': {
                headers: [
                    { match: 'x-mongodb-server', value: '' }
                ]
            },
            'MySQL': {
                headers: [
                    { match: 'x-powered-by', value: 'mysql' }
                ]
            }
        }
    };


    const reconData = {
        url: window.location.href,
        timestamp: new Date().toISOString(),
        metadata: {
            title: '',
            scripts: [],
            links: []
        },
        postRequests: [],
        cookiesEnabled: true,
        technologies: {
            frameworks: [],
            cms: [],
            libraries: [],
            cdn: [],
            languages: [],
            security: [],
            misc: []
        },
        enabledDomains: {} // Added domain tracking property
    };


    function detectTechnologies() {
        if (!isDomainEnabled()) return;
        const results = {
            frameworks: [],
            cms: [],
            libraries: [],
            cdn: [],
            languages: [],
            security: [],
            misc: []
        };

        function addTechnology(category, name, version = null) {
            if (!results[category].some(tech => tech.name === name)) {
                results[category].push({ name, version });
            }
        }


        if (typeof jQuery !== 'undefined') {
            addTechnology('frameworks', 'jQuery', jQuery.fn.jquery);


            if (jQuery.ui) {
                addTechnology('libraries', 'jQuery UI', jQuery.ui.version);
            }


            if (jQuery.fn.select2) {
                addTechnology('libraries', 'Select2');
            }
        }


        const scripts = Array.from(document.getElementsByTagName('script'));
        const links = Array.from(document.getElementsByTagName('link'));

        [...scripts, ...links].forEach(element => {
            const src = (element.src || element.href || '').toLowerCase();
            const content = element.textContent || '';

            if (src.includes('cloudflare.com')) {
                addTechnology('cdn', 'Cloudflare');
                if (src.includes('cdnjs.cloudflare.com')) {
                    addTechnology('cdn', 'cdnjs');
                }
            }

            if (src.includes('highlight.js') || src.includes('hljs')) {
                addTechnology('libraries', 'Highlight.js');
            }
            if (src.includes('chart.js')) {
                addTechnology('libraries', 'Chart.js');
            }
            if (src.includes('select2')) {
                addTechnology('libraries', 'Select2');
            }
            if (src.includes('soundmanager2')) {
                addTechnology('libraries', 'SoundManager');
            }
            if (src.includes('jquery-ui')) {
                const version = src.match(/jquery-ui[.-]([0-9.]+)/i)?.[1];
                if (version) addTechnology('libraries', 'jQuery UI', version);
            }
        });

        if (window.hljs || document.querySelector('.hljs')) {
            addTechnology('libraries', 'Highlight.js');
        }
        if (window.Chart) {
            addTechnology('libraries', 'Chart.js', window.Chart.version);
        }
        if (window.soundManager) {
            addTechnology('libraries', 'SoundManager', window.soundManager.version);
        }
        if (document.querySelector('.select2, .select2-container')) {
            addTechnology('libraries', 'Select2');
        }

        const htmlContent = document.documentElement.innerHTML;
        if (
            htmlContent.includes('cloudflare.com') ||
            document.querySelector('meta[name="cf-ray"]') ||
            document.querySelector('[data-cf-]')
        ) {
            addTechnology('cdn', 'Cloudflare');
        }

        if (htmlContent.includes('cdnjs.cloudflare.com')) {
            addTechnology('cdn', 'cdnjs');
        }

        const mybbIndicators = [
            '#quick_reply_form',
            '.post_button',
            'script[src*="jscripts/"]',
            'link[href*="cache/themes"]',
            '.author_buttons',
            '.post_management_buttons',
            '#panel',
            '.thead'  // MyBB specific class
        ];

        if (
            mybbIndicators.some(selector => document.querySelector(selector)) ||
            window.MyBB ||
            window.quickreply ||
            htmlContent.includes('MyBB.')
        ) {
            addTechnology('cms', 'MyBB');
        }

        if (
            window.io ||
            document.querySelector('script[src*="socket.io"]') ||
            scripts.some(script => script.src.includes('socket.io')) ||
            typeof io !== 'undefined'
        ) {
            addTechnology('frameworks', 'Socket.io');
        }

        if (
            document.querySelector('a[href$=".php"]') ||
            window.location.href.includes('.php') ||
            document.querySelector('script[src$=".php"]')
        ) {
            addTechnology('languages', 'PHP');
        }

        if (window.performance?.getEntriesByType) {
            const navEntry = performance.getEntriesByType('navigation')[0];
            if (navEntry?.nextHopProtocol === 'h2') {
                addTechnology('misc', 'HTTP/2');
            }
        }

        fetch(window.location.href, { method: 'HEAD' })
            .then(response => {
                if (response.headers.get('strict-transport-security')) {
                    addTechnology('security', 'HSTS');
                }
            })
            .catch(() => {});

        fetch(window.location.href, { method: 'HEAD' })
            .then(response => {
                // Cloudflare detection
                if (response.headers.get('cf-ray') || response.headers.get('server')?.toLowerCase().includes('cloudflare')) {
                    addTechnology('cdn', 'Cloudflare');
                }

                // HSTS detection
                if (response.headers.get('strict-transport-security')) {
                    addTechnology('security', 'HSTS');
                }

                // HTTP/2 detection
                if (response.headers.get('X-Firefox-Spdy') === 'h2') {
                    addTechnology('misc', 'HTTP/2');
                }

                // Frame protection detection
                if (response.headers.get('x-frame-options')) {
                    addTechnology('security', 'X-Frame-Options');
                }

                // Cookie detection
                const cookies = document.cookie;
                if (cookies.includes('mybb')) {
                    addTechnology('cms', 'MyBB');
                }

                // Additional MyBB detection from cookies
                if (cookies.includes('sid') || cookies.includes('mybbuser')) {
                    addTechnology('cms', 'MyBB');
                }

                // Update stored data after header checks
                reconData.technologies = results;
                const storedData = GM_getValue('reconData', {});
                const normalizedUrl = normalizeUrl(window.location.href);
                storedData[normalizedUrl] = reconData;
                GM_setValue('reconData', storedData);
            })
            .catch(error => console.debug('Header fetch error:', error));

        // Collect metadata
        reconData.metadata.title = document.title;

        // Collect script sources
        reconData.metadata.scripts = Array.from(document.getElementsByTagName('script'))
            .map(script => script.src)
            .filter(src => src) // Only include scripts with src attribute
            .map(src => {
                // Extract filename from path
                const parts = src.split('/');
                return {
                    filename: parts[parts.length - 1],
                    path: src
                };
            });

        // Collect CSS and other resource links
        reconData.metadata.links = Array.from(document.getElementsByTagName('link'))
            .filter(link => link.href) // Only include links with href
            .map(link => ({
                type: link.rel,
                filename: link.href.split('/').pop(),
                path: link.href
            }));

        // Store results
        reconData.technologies = results;
        const storedData = GM_getValue('reconData', {});
        const normalizedUrl = normalizeUrl(window.location.href);
        storedData[normalizedUrl] = reconData;
        GM_setValue('reconData', storedData);
    }

    // Create and inject UI styles
    function injectStyles() {
        const styles = `
            #recon-control-panel {
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: #1a2233;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.4);
                z-index: 9999;
                color: #e2e8f0;
                font-family: Arial, sans-serif;
                min-width: 200px;
            }
            #recon-control-panel h3 {
                margin: 0 0 10px 0;
                font-size: 14px;
                color: #ffffff;
            }
            .recon-toggle {
                display: flex;
                align-items: center;
                margin: 5px 0;
            }
            .recon-toggle label {
                margin-left: 8px;
                font-size: 12px;
            }
            .recon-button {
                background: #2c5282;
                border: none;
                color: white;
                padding: 5px 10px;
                border-radius: 4px;
                cursor: pointer;
                margin: 5px 0;
                width: 100%;
                font-size: 12px;
            }
            .recon-button:hover {
                background: #2b6cb0;
            }
            #recon-data-window {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: #1a2233;
                border-radius: 8px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.4);
                z-index: 10000;
                width: 80%;
                max-width: 800px;
                height: 80vh;
                display: none;
                font-family: Arial, sans-serif;
                display: flex;
                flex-direction: column;
            }
            #recon-data-header {
                position: sticky;
                top: 0;
                background: #233044;
                padding: 15px;
                border-radius: 8px 8px 0 0;
                border-bottom: 2px solid #34495e;
                flex-shrink: 0;
            }
            #recon-data-content {
                padding: 20px;
                overflow-y: auto;
                flex-grow: 1;
                background: #1a2233;
                border-radius: 0 0 8px 8px;
            }
            .recon-header-button {
                background: #2c5282;
                border: none;
                color: white;
                padding: 5px 15px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
                margin-left: 10px;
            }
            .recon-header-button:hover {
                background: #2b6cb0;
            }
            #recon-close-button {
                background: #c53030;
            }
            #recon-close-button:hover {
                background: #e53e3e;
            }
        `;

        const styleElement = document.createElement('style');
        styleElement.textContent = styles;
        document.head.appendChild(styleElement);

        // Update/add these specific styles
        const dataWindowStyles = `
            #recon-data-header {
                position: sticky;
                top: 0;
                background: #233044;
                padding: 15px;
                border-radius: 8px 8px 0 0;
                border-bottom: 2px solid #34495e;
                z-index: 1000;
            }
            .recon-header-content {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 20px;
            }
            .recon-header-title {
                font-size: 18px;
                color: #e2e8f0;
                margin: 0;
                white-space: nowrap;
            }
            .recon-header-center {
                flex: 1;
                text-align: center;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .recon-header-buttons {
                display: flex;
                gap: 10px;
                white-space: nowrap;
            }
            .btc-address {
                display: inline-block;
                max-width: 200px;
                overflow: hidden;
                text-overflow: ellipsis;
                vertical-align: bottom;
            }

            .recon-data-section {
                margin-bottom: 25px;
                background: #233044;
                padding: 15px;
                border-radius: 6px;
                border: 1px solid #34495e;
            }
            .recon-data-section h3 {
                color: #4ade80;
                margin: 0 0 15px 0;
                font-size: 16px;
                border-bottom: 2px solid #34495e;
                padding-bottom: 8px;
            }
            .recon-url-entry {
                background: #1a2233;
                padding: 15px;
                margin: 15px 0;
                border-radius: 6px;
                border: 1px solid #34495e;
            }
            .recon-url-title {
                color: #4ade80;
                font-size: 14px;
                font-weight: bold;
                margin-bottom: 10px;
            }
            .recon-url-title a {
                color: inherit;
                text-decoration: none;
            }
            .recon-url-title a:hover {
                text-decoration: underline;
            }
            .recon-data-item {
                margin: 8px 0;
                padding: 5px 0;
            }
            .recon-data-item strong {
                color: #60a5fa;
                margin-right: 5px;
            }
            .recon-script-link {
                display: block;
                color: #4ade80 !important;
                text-decoration: none;
                padding: 3px 0;
                margin: 2px 0;
            }
            .recon-script-link:hover {
                text-decoration: underline;
            }
            pre {
                background: #1a2233 !important;
                padding: 12px !important;
                border-radius: 6px !important;
                border: 1px solid #34495e !important;
                color: #4ade80 !important;
                margin: 10px 0 !important;
                white-space: pre-wrap !important;
                word-break: break-word !important;
                font-size: 12px !important;
            }
            .recon-tech-item {
                padding: 5px 15px;
                color: #e2e8f0;
            }
        `;

        styleElement.textContent += dataWindowStyles;
    }

    // Create control panel UI
    function createControlPanel() {
        const panel = document.createElement('div');
        panel.id = 'recon-control-panel';

        panel.innerHTML = `
            <h3>Recon Control Panel</h3>
            <div class="recon-domains" style="margin-bottom: 10px;">
                <strong style="color: #4ade80;">Active Domains:</strong>
                <div id="domain-list" style="
                    max-height: 100px;
                    overflow-y: auto;
                    margin: 5px 0;
                    padding: 5px;
                    background: #1a1a1a;
                    border-radius: 4px;
                "></div>
            </div>
            <div class="recon-toggle">
                <input type="checkbox" id="toggle-tech" checked>
                <label for="toggle-tech">Technologies</label>
            </div>
            <div class="recon-toggle">
                <input type="checkbox" id="toggle-wss" checked>
                <label for="toggle-wss">WSS Connections</label>
            </div>
            <div class="recon-toggle">
                <input type="checkbox" id="toggle-post" checked>
                <label for="toggle-post">POST Requests</label>
            </div>
            <div class="recon-toggle">
                <input type="checkbox" id="toggle-cookies" checked>
                <label for="toggle-cookies">Cookies</label>
            </div>
            <div class="recon-toggle">
                <input type="checkbox" id="toggle-auth" checked>
                <label for="toggle-auth">Auth Tokens</label>
            </div>
            <button class="recon-button" id="view-data">View Data</button>
            <button class="recon-button" id="clear-data">Clear Data</button>
        `;

        document.body.appendChild(panel);
        updateDomainList();
    }

    // Create and manage data window
    function createDataWindow() {
        const window = document.createElement('div');
        window.id = 'recon-data-window';
        window.style.display = 'none';

        window.innerHTML = `
            <div id="recon-data-header">
                <div class="recon-header-content">
                    <h2 class="recon-header-title">Reconnaissance Data</h2>
                    <div class="recon-header-center">
                        <span style="color: #4ade80;">Donate BTC: </span>
                        <span class="btc-address" style="color: #60a5fa; cursor: pointer;"
                              onclick="(${copyToClipboard.toString()})('3NgAAB4hkGc42Uo3NYtzVNhiwsJ3nbpo9y')">
                            3NgAAB4hkGc42Uo3NYtzVNhiwsJ3nbpo9y
                        </span>
                    </div>
                    <div class="recon-header-buttons">
                        <button class="recon-header-button" id="recon-export-json-view">Export JSON</button>
                        <button class="recon-header-button" id="recon-export-pdf-view">Export PDF</button>
                        <button class="recon-header-button" id="recon-close-button">✕</button>
                    </div>
                </div>
            </div>
            <div id="recon-data-content"></div>
        `;

        document.body.appendChild(window);
    }

    function updateDataWindow() {
        const content = document.getElementById('recon-data-content');
        const data = GM_getValue('reconData', {});

        let html = `
            <div class="recon-data-section">
                <h3>POST Requests</h3>
                ${Object.entries(data).map(([encodedUrl, urlData]) => {
                    const url = decodeURIComponent(encodedUrl);
                    return urlData.postRequests && urlData.postRequests.length ? `
                        <div class="recon-url-entry">
                            <div class="recon-url-title">
                                <a href="${url}" target="_blank">${url}</a>
                            </div>
                            ${urlData.postRequests.map(request => `
                                <div class="recon-data-item">
                                    <div><strong>Endpoint:</strong>
                                        <a href="${request.url}" target="_blank" class="recon-script-link">
                                            ${request.url}
                                        </a>
                                    </div>
                                    <div><strong>Timestamp:</strong> ${request.timestamp}</div>
                                    <div><strong>Payload:</strong></div>
                                    <pre>${formatPostData(request.data)}</pre>
                                    ${request.headers ? `
                                        <div><strong>Headers:</strong></div>
                                        <pre>${JSON.stringify(request.headers, null, 2)}</pre>
                                    ` : ''}
                                    ${request.cookies ? `
                                        <div><strong>Session Cookies:</strong></div>
                                        <pre>${JSON.stringify(request.cookies, null, 2)}</pre>
                                    ` : ''}
                                </div>
                            `).join('<hr style="border: 0; border-top: 1px solid #34495e; margin: 15px 0;">')}
                        </div>
                    ` : '';
                }).join('')}
            </div>

            <div class="recon-data-section">
                <h3>Reconnaissance History</h3>
                ${Object.entries(data).map(([encodedUrl, urlData]) => {
                    const url = decodeURIComponent(encodedUrl);
                    return `
                        <div class="recon-url-entry">
                            <div class="recon-url-title">
                                <a href="${url}" target="_blank">${url}</a>
                            </div>
                            <div class="recon-data-item">
                                <strong>Title:</strong> ${urlData.metadata?.title || 'N/A'}
                            </div>
                            <div class="recon-data-item">
                                <strong>Timestamp:</strong> ${urlData.timestamp}
                            </div>
                            <div class="recon-data-item">
                                <strong>Scripts:</strong>
                                ${urlData.metadata?.scripts
                                    .filter(script => script.path)
                                    .map(script => `
                                        <a href="${script.path}" target="_blank" class="recon-script-link">
                                            ${script.filename}
                                        </a>
                                    `).join('') || 'None detected'}
                            </div>
                            <div class="recon-data-item">
                                <strong>Technologies:</strong>
                                ${Object.entries(urlData.technologies).map(([category, techs]) =>
                                    techs.length ? `
                                        <div class="recon-tech-item">
                                            <strong>${category}:</strong>
                                            ${techs.map(tech => `${tech.name}${tech.version ? ` (${tech.version})` : ''}`).join(', ')}
                                        </div>
                                    ` : ''
                                ).join('')}
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;

        content.innerHTML = html;
    }

    function showDataWindow() {
        const window = document.getElementById('recon-data-window');
        if (window) {
            updateDataWindow();
            window.style.display = 'flex';
        }
    }

    function hideDataWindow() {
        const window = document.getElementById('recon-data-window');
        if (window) {
            window.style.display = 'none';
        }
    }

    // Add event listeners for all UI elements
    function addEventListeners() {
        // Control Panel Listeners
        const viewDataBtn = document.getElementById('view-data');
        const clearDataBtn = document.getElementById('clear-data');
        const toggleTech = document.getElementById('toggle-tech');

        // Data Window Listeners
        const closeBtn = document.getElementById('recon-close-button');
        const exportJsonBtn = document.getElementById('recon-export-json-view');
        const exportPdfBtn = document.getElementById('recon-export-pdf-view');

        // Add listeners only if elements exist
        if (viewDataBtn) {
            viewDataBtn.addEventListener('click', showDataWindow);
        }

        if (clearDataBtn) {
            clearDataBtn.addEventListener('click', () => {
                if (confirm('Are you sure you want to clear all reconnaissance data? This action cannot be undone.')) {
                    GM_deleteValue('reconData');
                    console.log('Data cleared');
                    // Optional: Show feedback to user
                    alert('All reconnaissance data has been cleared.');
                }
            });
        }

        if (toggleTech) {
            toggleTech.addEventListener('change', (e) => {
                console.log('Technologies logging:', e.target.checked);
            });
        }

        if (closeBtn) {
            closeBtn.addEventListener('click', hideDataWindow);
        }

        if (exportJsonBtn) {
            exportJsonBtn.addEventListener('click', () => {
                try {
                    const data = GM_getValue('reconData', {});

                    // Create a decoded copy of the data with proper structure
                    const decodedData = Object.entries(data).reduce((acc, [encodedUrl, urlData]) => {
                        try {
                            const decodedUrl = decodeURIComponent(encodedUrl);
                            acc[decodedUrl] = {
                                url: decodedUrl,
                                timestamp: urlData.timestamp || new Date().toISOString(),
                                metadata: {
                                    title: urlData.metadata?.title || '',
                                    scripts: urlData.metadata?.scripts || [],
                                    links: urlData.metadata?.links || []
                                },
                                postRequests: urlData.postRequests?.map(request => ({
                                    url: request.url,
                                    timestamp: request.timestamp,
                                    data: request.data,
                                    headers: request.headers || {},
                                    cookies: request.cookies || {},
                                    type: request.type || 'xhr'
                                })) || [],
                                technologies: {
                                    frameworks: urlData.technologies?.frameworks || [],
                                    cms: urlData.technologies?.cms || [],
                                    libraries: urlData.technologies?.libraries || [],
                                    cdn: urlData.technologies?.cdn || [],
                                    languages: urlData.technologies?.languages || [],
                                    security: urlData.technologies?.security || [],
                                    misc: urlData.technologies?.misc || []
                                },
                                cookiesEnabled: Boolean(urlData.cookiesEnabled)
                            };
                        } catch (e) {
                            console.debug('Error processing URL:', encodedUrl, e);
                        }
                        return acc;
                    }, {});

                    // Create and trigger download
                    const blob = new Blob([JSON.stringify(decodedData, null, 2)], {type: 'application/json'});
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `recon-data-${new Date().toISOString().split('T')[0]}.json`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                } catch (e) {
                    console.error('Error exporting data:', e);
                    alert('Error exporting data. Check console for details.');
                }
            });
        }

        if (exportPdfBtn) {
            exportPdfBtn.addEventListener('click', exportToPDF);
        }

        const toggleCookies = document.getElementById('toggle-cookies');
        if (toggleCookies) {
            toggleCookies.addEventListener('change', (e) => {
                reconData.cookiesEnabled = e.target.checked;
                console.log('Cookie logging:', e.target.checked);
            });
        }
    }

    // Enhanced POST request monitoring
    function getCookiesData() {
        if (!reconData.cookiesEnabled) return null;

        const cookies = {};
        document.cookie.split(';').forEach(cookie => {
            const [key, value] = cookie.trim().split('=').map(part => part.trim());
            // Include all cookies when enabled
            cookies[key] = value;
        });

        return cookies;
    }

    function monitorPostRequests() {
        if (!isDomainEnabled()) return;
        const storedData = GM_getValue('reconData', {});
        const normalizedUrl = normalizeUrl(window.location.href);

        if (!storedData[normalizedUrl]) {
            storedData[normalizedUrl] = {
                ...reconData,
                postRequests: []
            };
        }

        // Fetch API monitoring
        const originalFetch = window.fetch;
        window.fetch = async function(...args) {
            const request = args[0];
            const options = args[1] || {};

            if (options.method === 'POST' || (request instanceof Request && request.method === 'POST')) {
                try {
                    const url = request instanceof Request ? request.url : (typeof request === 'string' ? request : request.url);
                    const timestamp = new Date().toISOString();
                    let postData;
                    let headers = {};

                    if (request instanceof Request) {
                        const clonedRequest = request.clone();
                        for (const [key, value] of clonedRequest.headers.entries()) {
                            headers[key] = value;
                        }

                        const contentType = clonedRequest.headers.get('content-type');
                        if (contentType && contentType.includes('application/json')) {
                            postData = await clonedRequest.json();
                        } else {
                            postData = await clonedRequest.text();
                        }
                    } else {
                        postData = options.body;
                        headers = options.headers || {};
                    }

                    if (typeof postData === 'string' && postData.startsWith('{')) {
                        try {
                            postData = JSON.parse(postData);
                        } catch (e) {}
                    }

                    // Add to stored data
                    storedData[normalizedUrl].postRequests.push({
                        url: url.toString(),
                        timestamp,
                        data: postData,
                        headers: headers,
                        cookies: getCookiesData()
                    });

                    GM_setValue('reconData', storedData);
                } catch (e) {
                    console.debug('Error capturing POST data:', e);
                }
            }

            return originalFetch.apply(this, args);
        };

        // XHR monitoring
        const originalXHROpen = window.XMLHttpRequest.prototype.open;
        const originalXHRSetRequestHeader = window.XMLHttpRequest.prototype.setRequestHeader;
        const originalXHRSend = window.XMLHttpRequest.prototype.send;

        window.XMLHttpRequest.prototype.open = function(method, url) {
            this._method = method;
            this._url = url.toString();
            this._headers = {};
            return originalXHROpen.apply(this, arguments);
        };

        window.XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
            this._headers[header] = value;
            return originalXHRSetRequestHeader.apply(this, arguments);
        };

        window.XMLHttpRequest.prototype.send = function(data) {
            if (this._method === 'POST') {
                try {
                    let postData = data;

                    if (data instanceof FormData) {
                        postData = Array.from(data.entries()).reduce((acc, [key, value]) => {
                            acc[key] = value;
                            return acc;
                        }, {});
                    }
                    else if (typeof data === 'string' && data.startsWith('{')) {
                        try {
                            postData = JSON.parse(data);
                        } catch (e) {}
                    }

                    // Add to stored data
                    storedData[normalizedUrl].postRequests.push({
                        url: this._url,
                        timestamp: new Date().toISOString(),
                        data: postData,
                        headers: this._headers || {},
                        cookies: getCookiesData()
                    });

                    GM_setValue('reconData', storedData);
                } catch (e) {
                    console.debug('Error capturing POST data:', e);
                }
            }

            return originalXHRSend.call(this, data);
        };

        // Form submission monitoring
        document.addEventListener('submit', function(e) {
            const form = e.target;
            if (form.method.toLowerCase() === 'post') {
                const formData = new FormData(form);
                const data = Array.from(formData.entries()).reduce((acc, [key, value]) => {
                    acc[key] = value;
                    return acc;
                }, {});

                // Add to stored data
                storedData[normalizedUrl].postRequests.push({
                    url: form.action,
                    timestamp: new Date().toISOString(),
                    data: data,
                    type: 'form-submission',
                    cookies: getCookiesData()
                });

                GM_setValue('reconData', storedData);
            }
        }, true);
    }

    // Update the display of POST requests in updateDataWindow
    function formatPostData(data) {
        if (!data) return 'No data captured';
        try {
            if (typeof data === 'string') {
                // Try to parse as JSON first
                try {
                    return JSON.stringify(JSON.parse(data), null, 2);
                } catch (e) {
                    return data;
                }
            }
            return JSON.stringify(data, null, 2);
        } catch (e) {
            return String(data);
        }
    }

    // Update the PDF export function
    function exportToPDF() {
        const content = document.getElementById('recon-data-content');
        if (!content) return;

        // Create a clean copy of the content without control panel
        const cleanContent = content.cloneNode(true);
        // Remove any control panels if they exist
        const controlPanels = cleanContent.querySelectorAll('#recon-control-panel');
        controlPanels.forEach(panel => panel.remove());

        // Create printable content
        const printContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Reconnaissance Report</title>
                <style>
                    @page {
                        margin: 2cm;
                        size: A4;
                    }
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.4;
                        background: #1a2233;
                        color: #e2e8f0;
                        margin: 0;
                        padding: 20px;
                    }
                    .report-header {
                        text-align: center;
                        padding: 15px;
                        background: #233044;
                        border-radius: 4px;
                        margin-bottom: 20px;
                        border: 1px solid #34495e;
                        page-break-after: avoid;
                    }
                    .report-header h1 {
                        color: #4ade80;
                        margin: 0 0 10px 0;
                    }
                    .recon-data-section {
                        background: #233044;
                        padding: 15px;
                        margin-bottom: 20px;
                        border: 1px solid #34495e;
                        border-radius: 4px;
                        page-break-inside: avoid;
                    }
                    .recon-data-section h3 {
                        color: #4ade80;
                        border-bottom: 1px solid #34495e;
                        padding-bottom: 5px;
                        margin: 0 0 10px 0;
                    }
                    .recon-url-entry {
                        background: #1a2233;
                        padding: 12px;
                        margin: 15px 0;
                        border: 1px solid #34495e;
                        border-radius: 4px;
                        page-break-inside: avoid;
                    }
                    .recon-data-item {
                        margin: 8px 0;
                        page-break-inside: avoid;
                    }
                    pre {
                        background: #1a2233 !important;
                        padding: 10px !important;
                        border: 1px solid #34495e !important;
                        color: #4ade80 !important;
                        white-space: pre-wrap !important;
                        word-break: break-word !important;
                        font-size: 11px !important;
                        margin: 8px 0 !important;
                        page-break-inside: avoid !important;
                    }
                    hr {
                        border: 0;
                        border-top: 1px solid #34495e;
                        margin: 10px 0;
                    }
                    a { color: #4ade80; }
                    #recon-control-panel { display: none !important; }
                    @media print {
                        body {
                            -webkit-print-color-adjust: exact !important;
                            print-color-adjust: exact !important;
                        }
                        .no-print { display: none !important; }
                        * { page-break-inside: avoid !important; }
                    }
                </style>
            </head>
            <body>
                <div class="report-header">
                    <h1>Reconnaissance Report</h1>
                    <p>Generated: ${new Date().toLocaleString()}</p>
                    <div style="margin: 10px 0; text-align: center;">
                        <span style="color: #4ade80;">Donate BTC: </span>
                        <span style="color: #60a5fa;">3NgAAB4hkGc42Uo3NYtzVNhiwsJ3nbpo9y</span>
                    </div>
                    <div style="text-align: center;">
                        <button class="no-print" id="print-button" style="
                            padding: 10px 20px;
                            background: #2c5282;
                            color: white;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            margin: 10px auto;
                            display: inline-block;
                        ">Save as PDF</button>
                    </div>
                </div>
                <script>
                    document.getElementById('print-button').onclick = function() {
                        this.style.display = 'none';
                        window.print();
                        this.style.display = 'block';
                    };
                </script>
                ${cleanContent.innerHTML}
            </body>
            </html>
        `;

        // Open in new tab
        const printTab = window.open('', '_blank');
        printTab.document.write(printContent);
        printTab.document.close();
    }

    // Add this helper function for copying text
    function copyToClipboard(text) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        alert('BTC address copied to clipboard!');
    }

    // Add this helper function for URL handling
    function normalizeUrl(url) {
        try {
            // Decode the URL first in case it's already encoded
            const decodedUrl = decodeURIComponent(url);
            // Then encode it to ensure consistent format
            return encodeURIComponent(decodedUrl);
        } catch (e) {
            return encodeURIComponent(url);
        }
    }

    // Add function to update domain list
    function updateDomainList() {
        const domainList = document.getElementById('domain-list');
        if (!domainList) return;

        const currentDomain = window.location.hostname;
        const storedData = GM_getValue('reconData', {});
        const domains = new Set();

        // Collect all domains from stored data
        Object.keys(storedData).forEach(url => {
            try {
                const domain = new URL(decodeURIComponent(url)).hostname;
                domains.add(domain);
            } catch (e) {}
        });

        // Add current domain if not in list
        domains.add(currentDomain);

        // Get enabled states
        const enabledDomains = GM_getValue('enabledDomains', {});

        // Update domain list HTML
        domainList.innerHTML = Array.from(domains).map(domain => `
            <div class="domain-item" style="
                display: flex;
                align-items: center;
                margin: 3px 0;
                padding: 2px;
            ">
                <input type="checkbox"
                    id="domain-${domain}"
                    ${enabledDomains[domain] !== false ? 'checked' : ''}
                    style="margin-right: 5px;">
                <label for="domain-${domain}" style="
                    color: ${domain === currentDomain ? '#4ade80' : '#e2e8f0'};
                    font-size: 12px;
                    cursor: pointer;
                ">${domain}</label>
            </div>
        `).join('');

        // Add event listeners for checkboxes
        domains.forEach(domain => {
            const checkbox = document.getElementById(`domain-${domain}`);
            if (checkbox) {
                checkbox.addEventListener('change', (e) => {
                    const enabledDomains = GM_getValue('enabledDomains', {});
                    enabledDomains[domain] = e.target.checked;
                    GM_setValue('enabledDomains', enabledDomains);
                });
            }
        });
    }

    // Update initialize function
    function initialize() {
        // Initialize enabled domains if not exists
        const enabledDomains = GM_getValue('enabledDomains', {});
        const currentDomain = window.location.hostname;
        if (!(currentDomain in enabledDomains)) {
            enabledDomains[currentDomain] = true;
            GM_setValue('enabledDomains', enabledDomains);
        }

        injectStyles();
        createControlPanel();
        createDataWindow();
        addEventListeners();
        monitorPostRequests();

        // Run detection after initial load
        detectTechnologies();

        // Run detection again after all resources are loaded
        window.addEventListener('load', () => {
            setTimeout(detectTechnologies, 1000);
        });
    }

    // Start the script
    initialize();

    // Update detection and monitoring functions to check if domain is enabled
    function isDomainEnabled() {
        const enabledDomains = GM_getValue('enabledDomains', {});
        const currentDomain = window.location.hostname;
        return enabledDomains[currentDomain] !== false;
    }
})();