'use strict';

function getParameter(key, defaultValue=null) {
    const url = new URL(window.location.href);
    return url.searchParams.get(key) || defaultValue;
}

function setParameter(key, value) {
    const url = new URL(window.location);
    url.searchParams.set(key, value);
    window.history.pushState({}, '', url);
}

function deleteParameter(key) {
    const url = new URL(window.location);
    url.searchParams.delete(key);
    window.history.pushState({}, '', url);
}

function getBooleanParameter(key, defaultValue=null) {
    const value = getParameter(key, defaultValue);

    if (value === 'true') {
        return true;
    } else if (value === 'false') {
        return false;
    } else {
        return null;
    }
}

function getIntegerParameter(key, defaultValue=null, minimumValue=null, maximumValue=null) {
    const value = parseInt(getParameter(key, defaultValue));
    const isBelowMinimum = minimumValue !== null && value < minimumValue;
    const isAboveMaximum = maximumValue !== null && value > maximumValue;

    if (value === NaN || isBelowMinimum || isAboveMaximum) {
        return defaultValue;
    } else {
        return value;
    }
}

function valueToHex(value, minBytes=1) {
    /**
     * This function converts the given value (presumably an integer) into a hex string.
     **/
    return value.toString(16).padStart(minBytes * 2, '0');
}

// No longer in use since we can utilize Base64.
// function hexToByteArray(hex) {
//     /**
//      * This function converts the given hex string into a byte array.
//      **/
//     return Uint8Array.from(hex.match(/[0-9A-Z]{2}/gi).map((chunk) => parseInt(chunk, 16)));
// }

function valueToCharacter(value, allowNewline=false) {
    /**
     * This function converts the given integer into a character, but
     * only if the integer can be represented with standard ASCII. Bytes
     * that cannot be represented with standard ASCII are converted to
     * "." characters.
     **/

    if (allowNewline && value == 10) {
        return '\n';
    } else if (value < 32 || value > 126) {
        return '.';
    } else {
        return String.fromCharCode(value);
    }
}

function base64ToByteArray(base64) {
    /**
     * This function converts the given base-64 string to a byte array.
     **/
    const binString = atob(base64);
    return Uint8Array.from(binString, (character) => character.codePointAt(0));
}

function byteArrayToString(byteArray, allowNewline=false) {
    /**
     * This function converts the given byte array into a string, but
     * only if each byte can be represented with standard ASCII. Bytes
     * that cannot be represented with standard ASCII are converted to
     * "." characters.
     **/
    let string = '';

    for (let index = 0; index < byteArray.length; index++) {
        string += valueToCharacter(byteArray[index], allowNewline);
    }

    return string;
}


// We export these functions for use in other scripts.
window.utilities = {
    getParameter,
    setParameter,
    deleteParameter,
    getBooleanParameter,
    getIntegerParameter,
    valueToHex,
    valueToCharacter,
    base64ToByteArray,
    byteArrayToString
}
