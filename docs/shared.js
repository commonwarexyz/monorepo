function getRelativePathToIndex() {
    const path = window.location.pathname;
    const pathSegments = path.split('/').filter(segment => segment !== '');
    let relativePath = '';

    if (pathSegments.length <= 1) {
        // At root directory or /index.html
        relativePath = 'index.html';
    } else if (pathSegments.length >= 2) {
        // In a subdirectory
        relativePath = '../'.repeat(pathSegments.length - 1) + 'index.html';
    }

    return relativePath;
}


function insertLogo() {
    const path = window.location.pathname;
    const isHomePage = path === '/' || path === '/index.html';

    let logoHTML = `
    <div class="logo-line">
        <span class="edge-logo-symbol">+</span>
        <span class="horizontal-logo-symbol">~</span>
        <span class="horizontal-logo-symbol"> </span>
        <span class="horizontal-logo-symbol">-</span>
        <span class="horizontal-logo-symbol">+</span>
        <span class="horizontal-logo-symbol">-</span>
        <span class="horizontal-logo-symbol">+</span>
        <span class="horizontal-logo-symbol"> </span>
        <span class="horizontal-logo-symbol">-</span>
        <span class="horizontal-logo-symbol">+</span>
        <span class="horizontal-logo-symbol">-</span>
        <span class="horizontal-logo-symbol">~</span>
        <span class="horizontal-logo-symbol">~</span>
        <span class="edge-logo-symbol">*</span>
    </div>
    <div class="logo-line">
        <span class="vertical-logo-symbol">|</span>
        <span class="logo-text"> commonware </span>
        <span class="vertical-logo-symbol"> </span>
    </div>
    <div class="logo-line">
        <span class="edge-logo-symbol">*</span>
        <span class="horizontal-logo-symbol">~</span>
        <span class="horizontal-logo-symbol">+</span>
        <span class="horizontal-logo-symbol">+</span>
        <span class="horizontal-logo-symbol">-</span>
        <span class="horizontal-logo-symbol"> </span>
        <span class="horizontal-logo-symbol">~</span>
        <span class="horizontal-logo-symbol">-</span>
        <span class="horizontal-logo-symbol">+</span>
        <span class="horizontal-logo-symbol"> </span>
        <span class="horizontal-logo-symbol">-</span>
        <span class="horizontal-logo-symbol">*</span>
        <span class="horizontal-logo-symbol">-</span>
        <span class="edge-logo-symbol">+</span>
    </div>
    `;

    if (!isHomePage) {
        // Wrap the logo in an anchor tag linking back to the homepage
        const hrefToIndex = getRelativePathToIndex();
        logoHTML = `
        <a href="${hrefToIndex}" class="logo-link">
            ${logoHTML}
        </a>
        `;
    }

    document.getElementById('logo-placeholder').innerHTML = logoHTML;
    initializeLogoAnimations();
}

function initializeLogoAnimations() {
    const horizontalSymbols = [" ", "*", "+", "-", "~"];
    const verticalSymbols = [" ", "*", "+", "|"];
    const edgeSymbols = [" ", "*", "+"];

    function getRandomItem(arr) {
        return arr[Math.floor(Math.random() * arr.length)];
    }

    function getRandomDuration(min) {
        return Math.random() * (10000 - min) + min;
    }

    function updateSymbol(symbol, choices) {
        symbol.innerText = getRandomItem(choices);
        setTimeout(() => updateSymbol(symbol, choices), getRandomDuration(500));
    }

    document.querySelectorAll('.horizontal-logo-symbol').forEach(symbol => {
        setTimeout(() => updateSymbol(symbol, horizontalSymbols), getRandomDuration(1500));
    });

    document.querySelectorAll('.vertical-logo-symbol').forEach(symbol => {
        setTimeout(() => updateSymbol(symbol, verticalSymbols), getRandomDuration(1500));
    });

    document.querySelectorAll('.edge-logo-symbol').forEach(symbol => {
        setTimeout(() => updateSymbol(symbol, edgeSymbols), getRandomDuration(1500));
    });
}

function setExternalLinksToOpenInNewTab() {
    for (const link of document.querySelectorAll('a')) {
        const href = link.getAttribute('href');
        if (href && href.startsWith('http')) {
            link.setAttribute('target', '_blank');
            link.setAttribute('rel', 'noopener noreferrer');
        }
    }
}

function insertFooter() {
    // If the footer placeholder doesn't exist, skip footer insertion.
    const footerPlaceholder = document.getElementById('footer-placeholder');
    if (!footerPlaceholder) {
        return;
    }

    // Insert the footer.
    const currentYear = new Date().getFullYear();
    const footerHTML = `
    <div class="footer">
        <div class="socials">
            <a href="/hiring.html">Hiring</a>
            <a href="/benchmarks.html">Benchmarks</a>
            <a href="https://github.com/commonwarexyz/monorepo">GitHub</a>
            <a href="https://x.com/commonwarexyz">X</a>
            <a href="https://youtube.com/playlist?list=PLnVJ5S1DIyuFQ9cIE_oE-U3Wl3JDgZQ8A">Podcast</a>
            <a style="cursor:pointer" id="theme-toggle" />
        </div>
        &copy; ${currentYear} Commonware, Inc. All rights reserved.
    </div>
    `;
    footerPlaceholder.innerHTML = footerHTML;
}

function getCurrentTheme() {
    // Override the theme if the OS prefers dark mode.
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const storedTheme = localStorage.getItem('theme');
    if (prefersDark && !storedTheme) {
        localStorage.setItem('theme', 'dark');
        storedTheme = 'dark';
    }

    return storedTheme || 'light';
}

function updateTheme(theme) {
    if (!(theme === 'light' || theme === 'dark')) {
        console.error('Invalid theme:', theme);
        return;
    }

    const globalThemeStyle = document.getElementById('theme-style');
    if (!globalThemeStyle) {
        return;
    }

    // Update the global theme style based on the selected theme.
    const darkThemeStyle = `
        html, body {
            background-color: #202124;
            color: #fff;
        }

        a {
            color: #04a5e5;
        }
    `;
    globalThemeStyle.innerHTML = theme === 'light' ? '' : darkThemeStyle;

    const themeToggle = document.getElementById('theme-toggle');
    if (!themeToggle) {
        return;
    }

    // Update the theme toggle button text
    themeToggle.innerHTML = `Theme: ${theme === 'light' ? '☀️' : '🌙'}`;
}

function initTheme() {
    // Initialize the theme based on localStorage or default to light mode.
    const currentTheme = getCurrentTheme();
    updateTheme(currentTheme);

    const themeToggle = document.getElementById('theme-toggle');
    if (!themeToggle) {
        return;
    }

    // Register the click event listener for the theme toggle button.
    themeToggle.addEventListener("click", function() {
        const currentTheme = getCurrentTheme();

        if (currentTheme === 'light') {
            updateTheme('dark');
            localStorage.setItem('theme', 'dark');
        } else {
            updateTheme('light');
            localStorage.setItem('theme', 'light');
        }
    });
}

// Load the logo when the DOM content is loaded
document.addEventListener('DOMContentLoaded', () => {
    insertLogo();
    insertFooter();
    setExternalLinksToOpenInNewTab();
    initTheme();
});
