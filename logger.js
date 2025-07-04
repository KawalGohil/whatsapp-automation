// logger.js
// A simple logger utility to standardize console output.

const getTimestamp = () => new Date().toISOString();

const info = (message, ...args) => {
    console.log(`[INFO] ${getTimestamp()} - ${message}`, ...args);
};

const warn = (message, ...args) => {
    console.warn(`[WARN] ${getTimestamp()} - ${message}`, ...args);
};

const error = (message, ...args) => {
    console.error(`[ERROR] ${getTimestamp()} - ${message}`, ...args);
};

module.exports = {
    info,
    warn,
    error,
};
