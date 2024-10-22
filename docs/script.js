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

// Load the logo when the DOM content is loaded
document.addEventListener('DOMContentLoaded', insertLogo);
