'use strict';

function setupDescription(rootContainer, descriptions) {
    /**
     * This function is used to setup the description within each finding's details.
     */
    const container = rootContainer.querySelector('[data-role="description-container"]');

    for (const description of descriptions) {
        const paragraph = document.createElement('p');
        paragraph.textContent = description;
        container.appendChild(paragraph);
    }
}

function setupPatterns(rootContainer, patterns) {
    /**
     * This function is used to setup the patterns within each finding's details.
     */
    const container = rootContainer.querySelector('[data-role="pattern-container"]');
    const template = document.querySelector('[data-id="finding-tag-template"]');

    for (const pattern of patterns) {
        const patternTag = template.content.firstElementChild.cloneNode(true);
        patternTag.querySelector('i').classList.add('fa-percent');
        patternTag.querySelector('span').textContent = pattern;
        container.appendChild(patternTag);
    }
}

function setupIndicators(rootContainer, rating, idealRating, indicators) {
    /**
     * This function is used to setup the indicators within each finding's details.
     */
    const container = rootContainer.querySelector('[data-role="indicator-container"]');
    const template = document.querySelector('[data-id="finding-tag-template"]');

    for (const [reason, delta] of indicators) {
        const indicatorTag = template.content.firstElementChild.cloneNode(true);
        indicatorTag.querySelector('span').textContent = `${reason} (${ delta > 0 ? '+' : '' }${delta})`;
        const icon = indicatorTag.querySelector('i');

        if (delta > 0) {
            icon.classList.add('fa-plus');
        } else {
            icon.classList.add('fa-minus');
        }

        container.appendChild(indicatorTag);
    }

    container.parentElement.querySelector('[data-content="rating-text"]').textContent = `(${rating} actual / ${idealRating} ideal)`;
}

function setupContext(rootContainer, contextBase64, contextStart=0, highlightStart=0, highlightEnd=0, rowSize=16) {
    /**
     * This function is used to setup the context viewers within each finding's details.
     **/
    const contextByteArray = utilities.base64ToByteArray(contextBase64);

    viewers.setupAddressViewer(rootContainer, contextByteArray, contextStart, rowSize);
    viewers.setupHexViewer(rootContainer, contextByteArray, highlightStart, highlightEnd, rowSize);
    viewers.setupTextViewer(rootContainer, contextByteArray, highlightStart, highlightEnd, rowSize);
    viewers.setupRenderViewer(rootContainer, contextByteArray, highlightStart, highlightEnd);
}

function createDetails(containerRoot, descriptions, patterns, rating, idealRating, indicators, contextBase64, contextStart=0, highlightStart=0, highlightEnd=0, rowSize=16) {
    const template = document.querySelector('[data-id="finding-details-template"]');
    const detailsContainer = template.content.firstElementChild.cloneNode(true);

    setupDescription(detailsContainer, descriptions);
    setupPatterns(detailsContainer, patterns);
    setupIndicators(detailsContainer, rating, idealRating, indicators);
    setupContext(detailsContainer, contextBase64, contextStart, highlightStart, highlightEnd, rowSize);

    containerRoot.appendChild(detailsContainer);

    return detailsContainer;
}

function removeFindings() {
    const findingsContainer = document.querySelector('[data-id="finding-container"]');
    findingsContainer.replaceChildren();
}

function createFinding(uuid, fileName, valueBase64, rating, idealRating, patterns, name, descriptions, indicators, contextBase64, contextStart=0, highlightStart=0, highlightEnd=0, rowSize=16) {
    const template = document.querySelector('[data-id="finding-template"]');
    const finding = template.content.firstElementChild.cloneNode(true);
    finding.setAttribute('data-id', uuid);

    // We start by setting some of the easy properties up.
    finding.querySelector('[data-content="name"]').textContent = name;
    finding.querySelector('[data-content="file-name"]').textContent = fileName;

    // Then we convert the value into a best-guess string.
    const valueByteArray = utilities.base64ToByteArray(valueBase64);
    const value = utilities.byteArrayToString(valueByteArray);

    // We determine how much of the value to make censored.
    let valueSlice = Math.max(2, Math.floor(value.length / 4));

    const valueCensored = finding.querySelector('[data-content="value-censored"]');
    const valueLeftover = finding.querySelector('[data-content="value-leftover"]');

    valueCensored.textContent = value.slice(0, value.length - valueSlice);
    valueLeftover.textContent = value.slice(-valueSlice);

    // To prevent any HTML indentation from being copied through the selection,
    // we manually copy the value's data to the clipboard.
    finding.querySelector('[data-content="value"]').addEventListener('copy', (event) => {
        event.preventDefault();
        event.clipboardData.setData('text/plain', valueCensored.textContent + valueLeftover.textContent);
    });

    // We also setup the ratings based on their indicators.
    const ratingContainer = finding.querySelector('[data-content="rating"]');
    const relativeRating = rating / idealRating;
    const maxStars = 5;

    for (let index = 0; index < maxStars; index++) {
        const icon = document.createElement('i');
        icon.classList.add('fa-solid', 'fa-star');
        ratingContainer.appendChild(icon);

        if (index / maxStars < relativeRating) {
            icon.classList.add('text-orange-500');
        }
    }

    // Now we hook up creation/destruction of the details container to a button.
    // Yay, optimizations.
    const detailsButton = finding.querySelector('[data-role="view-details-button"]');
    const detailsButtonIcon = detailsButton.querySelector('i');

    detailsButton.addEventListener('click', () => {
        if (detailsButton.getAttribute('data-expanded') === null) {
            detailsButton.setAttribute('data-expanded', true);
            detailsButtonIcon.classList.add('fa-minus');
            detailsButtonIcon.classList.remove('fa-plus');

            const detailsContainer = finding.querySelector('[data-role="details-container"]') || createDetails(
                finding,
                descriptions,
                patterns,
                rating,
                idealRating,
                indicators,
                contextBase64,
                contextStart,
                highlightStart,
                highlightEnd,
                rowSize
            );

            detailsContainer.classList.remove('hidden');
            detailsContainer.style.setProperty('height', '0px');

            // As soon as the grow animation ends, we remove our style hack.
            const callback = () => {
                detailsContainer.removeEventListener('transitionend', callback);

                if (detailsButton.getAttribute('data-expanded') === null) {
                    return;
                }

                detailsContainer.style.removeProperty('height');
            };

            detailsContainer.addEventListener('transitionend', callback);

            // We give it one animation frame before continuing on.
            // We wait for two frames, just to be safe for processing.
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    detailsContainer.style.setProperty('height', `${detailsContainer.scrollHeight}px`);
                });
            });
        } else {
            // If the details container exists, we start hiding it.
            detailsButton.removeAttribute('data-expanded');
            detailsButtonIcon.classList.add('fa-plus');
            detailsButtonIcon.classList.remove('fa-minus');

            const detailsContainer = finding.querySelector('[data-role="details-container"]');
            detailsContainer.style.setProperty('height', `${detailsContainer.scrollHeight}px`);

            // As soon as the shrink animation ends, we destroy the container.
            const callback = () => {
                detailsContainer.removeEventListener('transitionend', callback);

                if (detailsButton.getAttribute('data-expanded') !== null) {
                    return;
                }

                detailsContainer.remove();
            };

            detailsContainer.addEventListener('transitionend', callback);

            // We give it one animation frame before continuing on.
            // If we don't request two frames here, FireFox will break.
            // This issue is probably caused by where our callback falls
            // in the list; some items which are key for this to work
            // have not been called on our first frame.
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    detailsContainer.style.setProperty('height', '0px');
                });
            });
        }
    });

    document.querySelector('[data-id="finding-container"]').appendChild(finding);
}

function refreshFindings(findings, descriptions, sorting) {
    /**
     * This function refreshes the finding list (this should be called on page
     * changes or filter changes).
     */
    document.querySelector('[data-id="finding-container"]').replaceChildren();

    const findingCount = Object.keys(findings).length;
    const pageSize = utilities.getIntegerParameter('pageSize', 8, 8, 16);
    const totalPages = Math.floor(findingCount / pageSize);
    const pageIndex = utilities.getIntegerParameter('pageIndex', 0, 0, totalPages);

    const startIndex = pageIndex * pageSize;
    const stopIndex = Math.min(findingCount, startIndex + pageSize);

    for (let index = startIndex; index < stopIndex; index++) {
        const uuid = sorting[index];
        const finding = findings[uuid];

        createFinding(
            uuid,
            finding.fileName,
            finding.capture,
            finding.rating,
            finding.idealRating,
            [finding.pattern],
            finding.name,
            descriptions[finding.name],
            finding.indicators,
            finding.context,
            finding.contextStart,
            (finding.captureStart - finding.contextStart),
            (finding.captureEnd - finding.contextStart),
            24
        )
    }

    const buttonStartIndex = Math.max(pageIndex - 3, 0);
    const buttonStopIndex = Math.min(pageIndex + 4, totalPages);
    const buttonTemplate = document.querySelector('[data-id="page-button-template"]');
    const buttonContainer = document.querySelector('[data-id="page-button-container"]');
    buttonContainer.replaceChildren();

    for (let index = buttonStartIndex; index <= buttonStopIndex; index++) {
        const button = buttonTemplate.content.firstElementChild.cloneNode(true);
        button.textContent = index + 1;

        if (index === pageIndex) {
            button.classList.add('text-white', 'border-white');
            button.classList.remove('text-gray-400', 'border-gray-400');
        } else {
            button.addEventListener('click', (event) => {
                event.preventDefault();

                utilities.setParameter('pageIndex', index);
                refreshFindings(findings, descriptions, sorting);
            });
        }

        buttonContainer.appendChild(button);
    }

    const pageButtonFirst = document.querySelector('[data-id="page-button--first"]');
    pageButtonFirst.setAttribute('data-page', 0)

    const pageButtonLast = document.querySelector('[data-id="page-button--last"]');
    pageButtonLast.setAttribute('data-page', totalPages)

    censorship.refreshCensorship();
}

window.findings = {
    refreshFindings
}
