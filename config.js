const path = require('path');

// Render provides a persistent disk mount at /var/data
// Use this for storing session and database files.
const dataDir = process.env.NODE_ENV === 'production' 
    ? '/var/data' 
    : __dirname;

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
        // Locally, this will be false unless NODE_ENV is set to 'production'.
        headless: process.env.NODE_ENV === 'production',
    },

    // Delays and rate-limiting from your original config
    rateLimits: {
        groupCreationDelay: 4823,
        retries: {
            maxRetries: 3,
            initialBackoff: 2000,
        },
    },
};

