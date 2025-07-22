const { execSync } = require('child_process');
const os = require('os');
const logger = require('../logger');

function killOrphanedChrome() {
    try {
        if (os.platform() === 'win32') {
            execSync('taskkill /f /im chrome.exe /t', { stdio: 'ignore' });
        } else {
            execSync("pkill -f '(chrome|chromium|puppeteer)' || true", { stdio: 'ignore' });
        }
        logger.info('[CHROME] Killed orphaned Chrome/Chromium processes.');
    } catch (error) {
        logger.warn('[CHROME] Failed to kill Chrome:', error.message);
    }
}

module.exports = { killOrphanedChrome };
