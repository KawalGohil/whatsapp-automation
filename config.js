const path = require('path');

// Use process.env.NODE_ENV if set, otherwise default to 'development'
const isProduction = (process.env.NODE_ENV || 'development') === 'production';

// Define base directory for persistent data
// Use /var/data in production, or __dirname in development
const dataDir = isProduction ? '/var/data' : __dirname;

const config = {
    // Define paths for persistent data. This is used by database.js and server.js
    paths: {
        data: dataDir,
        database: path.join(dataDir, 'whatsapp_automation.db'),
        session: path.join(dataDir, '.wwebjs_auth'), // For whatsapp-web.js sessions
        sessionStore: path.join(dataDir, 'sessions.db'), // For express-session
    },

    // Group creation settings from your original config
    group: {
        autoCreate: true,
        name: 'Automated Sales Team',
        role: 'Sales',
    },

    // Puppeteer settings
    puppeteer: {
        // In production, Puppeteer MUST run in headless mode.
        headless: isProduction,
    },

    // Delays and rate-limiting from your original config
    rateLimits: {
        retries: {
            maxRetries: 3,
            initialBackoff: 2000,
        },
    },
};

// Log the configuration for debugging (will be visible in Railway logs)
console.log('Application configuration:', {
    NODE_ENV: process.env.NODE_ENV,
    isProduction,
    dataDir,
    paths: config.paths
});

module.exports = config;
