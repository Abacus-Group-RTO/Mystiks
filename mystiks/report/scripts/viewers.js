'use strict';

function setupAddressViewer(container, byteArray, startPosition=0, rowSize=16) {
    /**
     * This function sets up our address viewer, with addressing relative to the start position.
     **/
    const addressViewer = container.querySelector('[data-role="address-viewer"]');
    addressViewer.replaceChildren();

    for (let index = 0; index < byteArray.length; index += rowSize) {
        let addressElement = document.createElement('span');
        addressElement.classList.add('bg-zate-800', 'px-2', 'select-all');
        addressElement.textContent = utilities.valueToHex(startPosition + index, 4);

        if (index === 0) {
            addressElement.classList.add('rounded-t-md');
        }

        if (index / rowSize === Math.floor(byteArray.length / rowSize)) {
            addressElement.classList.add('rounded-b-md');
        }

        addressViewer.appendChild(addressElement);
    }
}

function setupHexViewer(container, byteArray, highlightStart=0, highlightEnd=0, rowSize=16) {
    /**
     * This function sets up the hex viewer based on the given byte array.
     **/
    const hexViewer = container.querySelector('[data-role="hex-viewer"]');
    hexViewer.setAttribute('data-size', byteArray.length);
    hexViewer.replaceChildren();

    let hexRow = null;

    for (let index = 0; index < byteArray.length; index++) {
        const value = byteArray[index];

        if (index % rowSize === 0) {
            if (hexRow !== null) {
                hexViewer.appendChild(hexRow);
            }

            hexRow = document.createElement('div');
        }

        let hexColumn = document.createElement('span');
        hexColumn.setAttribute('data-index', index);
        hexColumn.classList.add('px-1', 'border', 'border-transparent');
        hexColumn.textContent = utilities.valueToHex(value);

        if (highlightStart <= index && highlightEnd > index) {
            hexColumn.classList.add('bg-zate-800', 'text-orange-300');
            hexColumn.setAttribute('data-highlighted', true);
        } else if (index % 2 === 0) {
            // Originally, I was going to color this based on
            // whether the value was 0x00 or not. This looks terrible
            // in practice, however, as text data will be all white
            // due to the limited occurrence of the 0x00 character.
            // Human eyes prefer landmarks, so we instead artificially
            // color each column with this tint. We lose some visual
            // information but it's a compromise we need to make.
            hexColumn.classList.add('text-gray-400');
            hexColumn.setAttribute('data-tinted', true);

        }

        hexRow.appendChild(hexColumn);
    }

    hexViewer.appendChild(hexRow);
}

function setupTextViewer(container, byteArray, highlightStart=0, highlightEnd=0, rowSize=16) {
    /**
     * This function sets up the text viewer based on the given byte array.
     **/
    const textViewer = container.querySelector('[data-role="text-viewer"]');
    textViewer.setAttribute('data-size', byteArray.length);
    textViewer.replaceChildren();

    let textRow = null;

    for (let index = 0; index < byteArray.length; index++) {
        const value = byteArray[index];

        if (index % rowSize === 0) {
            if (textRow !== null) {
                textViewer.appendChild(textRow);
            }

            textRow = document.createElement('div');
        }

        let textColumn = document.createElement('span');
        textColumn.setAttribute('data-index', index);
        textColumn.classList.add('border', 'border-transparent');
        textColumn.textContent = utilities.valueToCharacter(value);

        if (highlightStart <= index && highlightEnd > index) {
            textColumn.classList.add('bg-zate-800', 'text-orange-300');
            textColumn.setAttribute('data-highlighted', true);
        } else if (value < 32 || value > 126) {
            textColumn.classList.add('text-gray-400');
            textColumn.setAttribute('data-tinted', true);
        }

        textRow.appendChild(textColumn);
    }

    textViewer.appendChild(textRow);
}

function setupSelector() {
    /**
     * This function is used to setup the selector hook for the hex and text viewers.
     **/
    let selectedViewer = null;
    let selectedElements = [];
    let mirroredElements = [];

    // We define some local functions here for later use. They don't really
    // need to be functions, but this makes the later code cleaner.
    function stopSelectingViewer() {
        if (selectedViewer === null) {
            return;
        }

        selectedViewer.classList.remove('hide-selection');
        selectedViewer = null;
    }

    function stopSelectingElements() {
        if (selectedElements.length === 0) {
            return;
        }

        for (const element of selectedElements) {
            if (element.getAttribute('data-highlighted') !== null) {
                element.classList.add('bg-zate-800', 'text-orange-300');
            } else if (element.getAttribute('data-tinted') !== null) {
                element.classList.add('text-gray-400');
            }

            element.classList.remove('bg-blue-500', 'text-white');
        }

        for (const element of mirroredElements) {
            element.classList.add('border-transparent');
            element.classList.remove('border-y-blue-500', 'border-l-blue-500', 'border-r-blue-500');
        }

        selectedElements = [];
        mirroredElements = [];
    }

    document.addEventListener('copy', (event) => {
        if (selectedElements.length === 0) {
            return;
        }

        // If we have some elements selected, we take over the copy operation.
        event.preventDefault();

        let clipboardText = '';

        for (const element of selectedElements) {
            clipboardText += element.textContent;
        }

        event.clipboardData.setData('text/plain', clipboardText);
    });

    document.addEventListener('selectionchange', () => {
        let selection = window.getSelection();

        stopSelectingViewer();
        stopSelectingElements();

        // If the selection is empty, we just stop selecting everything and return.
        if (selection.isCollapsed) {
            return;
        }

        // We get the elements at the start and end of the selection.
        const anchorParent = selection.anchorNode.parentElement;
        const focusParent = selection.focusNode.parentElement;

        // We also save their index (if any) for later.
        const anchorIndex = anchorParent.getAttribute('data-index');
        const focusIndex = focusParent.getAttribute('data-index');

        // If the selection is not over two columns, we return.
        if (anchorIndex === null || focusIndex === null) {
            return;
        }

        const anchorViewer = anchorParent.parentElement.parentElement;
        const focusViewer = focusParent.parentElement.parentElement;

        // If the selection spans beyond one viewer, we return.
        if (anchorViewer !== focusViewer) {
            return;
        }

        const hexViewer = anchorViewer.parentElement.querySelector('[data-role="hex-viewer"]');
        const textViewer = anchorViewer.parentElement.querySelector('[data-role="text-viewer"]');

        // We use ternary comparisons here to quickly determine which viewer is which.
        selectedViewer = anchorViewer === hexViewer ? hexViewer : textViewer;
        selectedViewer.classList.add('hide-selection');

        const mirroredViewer = anchorViewer === hexViewer ? textViewer : hexViewer;

        // We determine our start and stop index.
        const startIndex = Math.min(anchorIndex, focusIndex);
        const endIndex = Math.max(anchorIndex, focusIndex);

        for (let index = startIndex; index <= endIndex; index++) {
            const selectedElement = selectedViewer.querySelector(`[data-index="${index}"]`);
            const mirroredElement = mirroredViewer.querySelector(`[data-index="${index}"]`);

            selectedElement.classList.add('bg-blue-500', 'text-white');

            if (selectedElement.getAttribute('data-highlighted') !== null) {
                selectedElement.classList.remove('bg-zate-800', 'text-orange-300');
            } else if (selectedElement.getAttribute('data-tinted') !== null) {
                selectedElement.classList.remove('text-gray-400');
            }

            mirroredElement.classList.add('border-y-blue-500');

            if (index === startIndex) {
                mirroredElement.classList.add('border-l-blue-500');
            }

            if (index === endIndex) {
                mirroredElement.classList.add('border-r-blue-500');
            }

            selectedElements.push(selectedElement);
            mirroredElements.push(mirroredElement);
        }
    });
}

function setupRenderViewer(container, byteArray, highlightStart=0, highlightEnd=0) {
    /**
     * This function is used to setup the render viewer for the context panel.
     **/
    const renderViewer = container.querySelector('[data-role="render-viewer"]');
    renderViewer.value = utilities.byteArrayToString(byteArray, true);

    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            renderViewer.style.setProperty('height', `${renderViewer.scrollHeight * 1.25}px`);
        });
    });
}

window.viewers = {
    setupAddressViewer,
    setupHexViewer,
    setupTextViewer,
    setupSelector,
    setupRenderViewer
}

window.addEventListener('DOMContentLoaded', () => {
    setupSelector();
});
