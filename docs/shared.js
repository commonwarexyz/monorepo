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
        logoHTML = `
        <a href="/index.html" class="logo-link">
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
            <a href="https://github.com/commonwarexyz/monorepo">GitHub</a>
            <a href="/benchmarks.html">Benchmarks</a>
            <a href="/hiring.html">Hiring</a>
            <a href="https://x.com/commonwarexyz">X</a>
            <a href="/podcast.html">Podcast</a>
        </div>
        &copy; ${currentYear} Commonware, Inc. All rights reserved.
    </div>
    `;
    footerPlaceholder.innerHTML = footerHTML;
}

// Trim leading and trailing blank lines from all <pre><code> blocks
function trimCode() {
    const codeBlocks = document.querySelectorAll('pre code');

    for (const block of codeBlocks) {
        const lines = block.innerHTML.split('\n');
        // Remove leading blank lines
        while (lines.length > 0 && lines[0].trim() === '') {
            lines.shift();
        }
        // Remove trailing blank lines
        while (lines.length > 0 && lines[lines.length - 1].trim() === '') {
            lines.pop();
        }
        block.innerHTML = lines.join('\n');

        // Remove whitespace text nodes between <pre> and <code>
        const pre = block.parentElement;
        if (pre && pre.tagName === 'PRE') {
            for (const child of [...pre.childNodes]) {
                if (child.nodeType === Node.TEXT_NODE) {
                    pre.removeChild(child);
                }
            }
        }
    }
}

// Load the logo when the DOM content is loaded
document.addEventListener('DOMContentLoaded', () => {
    insertLogo();
    insertFooter();
    setExternalLinksToOpenInNewTab();
    trimCode();
});
