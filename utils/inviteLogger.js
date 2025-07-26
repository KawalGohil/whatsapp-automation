const fs = require('fs');
const path = require('path');
const dayjs = require('dayjs');
const config = require('../config');

function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

function writeInviteLog(username, groupName, inviteLink = '', status = 'Success', reason = '') {
    const logDir = path.join(config.paths.data, 'invite-logs');
    ensureDir(logDir);

    const filename = `group_invite_log_${username}_${dayjs().format('YYYY-MM-DD')}.csv`;
    const filePath = path.join(logDir, filename);

    const isFirstWrite = !fs.existsSync(filePath);
    if (isFirstWrite) {
        fs.writeFileSync(filePath, `"Group Name","Invite Link","Status","Reason"\n`, 'utf8');
    }

    const line = `"${groupName}","${inviteLink}","${status}","${reason.replace(/(\r\n|\n|\r)/gm, ' ').replace(/"/g, "'")}"\n`;
    fs.appendFileSync(filePath, line, 'utf8');
}


module.exports = { writeInviteLog };
