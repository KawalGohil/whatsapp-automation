// utils/inviteLogger.js
const fs = require('fs');
const path = require('path');
const dayjs = require('dayjs');
const config = require('../config');

function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

async function writeInviteLog(username, groupName, inviteLink) {
    const logDir = path.join(config.paths.data, 'invite-logs');
    const filename = `group_invite_log_${username}_${dayjs().format('YYYY-MM-DD')}.csv`;

    ensureDir(logDir);
    const filePath = path.join(logDir, filename);

    const isFirstWrite = !fs.existsSync(filePath);
    const csvLine = `"${groupName}","${inviteLink}"\n`;

    if (isFirstWrite) {
        fs.writeFileSync(filePath, `"Group Name","Invite Link"\n`, 'utf8');
    }

    fs.appendFileSync(filePath, csvLine, 'utf8');
}

module.exports = { writeInviteLog };
