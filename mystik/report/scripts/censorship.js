'use strict';

function enableCensorship() {
    let censoredElements = document.querySelectorAll('[data-censored]');

    for (const element of censoredElements) {
        if (!element.classList.contains('blur-sm')) {
            element.classList.add('blur-sm');
        }
    }

    utilities.setParameter('isCensored', true);
}

function disableCensorship() {
    let censoredElements = document.querySelectorAll('[data-censored]');

    for (const element of censoredElements) {
        if (element.classList.contains('blur-sm')) {
            element.classList.remove('blur-sm');
        }
    }

    utilities.setParameter('isCensored', false);
}

function checkCensorship() {
    return utilities.getBooleanParameter('isCensored');
}

function refreshCensorship() {
    const isCensored = checkCensorship();

    if (isCensored === true) {
        enableCensorship();
    } else {
        disableCensorship();
    }
}

function setupCensorshipButtons() {
    let censorshipButtons = document.querySelectorAll('[data-role="toggle-censorship"]');

    for (const button of censorshipButtons) {
        button.addEventListener('click', () => {
            const isCensored = checkCensorship();

            if (isCensored === true) {
                disableCensorship();
            } else {
                enableCensorship();
            }
        })
    }
}

function setupCensorship() {
    const isCensored = checkCensorship();

    if (isCensored === true) {
        enableCensorship();
    } else {
        disableCensorship();
    }

    setupCensorshipButtons();
}

// We export these functions for use in other scripts.
window.censorship = {
    enableCensorship,
    disableCensorship,
    checkCensorship,
    refreshCensorship,
    setupCensorship
}
