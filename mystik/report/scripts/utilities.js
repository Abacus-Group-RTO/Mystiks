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

function getIntegerParameter(key, defaultValue=null) {
    const value = getParameter(key, defaultValue);
    return value !== null ? parseInt(value) : defaultValue;
}

// We export these functions for use in other scripts.
window.utilities = {
    getParameter,
    setParameter,
    deleteParameter,
    getBooleanParameter,
    getIntegerParameter
}
