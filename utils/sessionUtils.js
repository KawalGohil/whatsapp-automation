const fs = require('fs');
const path = require('path');

async function deleteSessionFolder(sessionPath, maxAttempts = 3) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      if (fs.existsSync(sessionPath)) {
        fs.rmSync(sessionPath, { recursive: true, force: true });
        logger.info(`Deleted session at ${sessionPath}`);
      }
      return;
    } catch (err) {
      if (err.code === 'EBUSY') {
        logger.warn(`EBUSY on attempt ${attempt} for ${sessionPath}. Retrying...`);
        await new Promise(res => setTimeout(res, 800));
      } else {
        logger.error(`Failed to delete session at ${sessionPath}:`, err.message);
        break;
      }
    }
  }
  logger.error(`Failed to cleanup session folder after ${maxAttempts} attempts: ${sessionPath}`);
}
module.exports = { deleteSessionFolder };
