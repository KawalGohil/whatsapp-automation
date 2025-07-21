const logger = require('./logger');
const { readState, writeState } = require('./stateManager');
const config = require('./config'); // Make sure config is imported
const { writeInviteLog } = require('./utils/inviteLogger');


const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function getRandomDelay(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function createGroup(client, username, groupName, participants, desiredAdminJid = null) {
    const state = readState();

    // Check if a group with this name has already been created
    if (state.createdGroups[groupName]) {
        logger.info(`Group "${groupName}" has already been created (ID: ${state.createdGroups[groupName]}). Skipping.`);
        return;
    }

    if (!participants || participants.length === 0) {
        logger.error(`Cannot create group "${groupName}" because no participants were provided.`);
        return;
    }

    // Use a fixed 1-5 second random delay
    const randomDelay = getRandomDelay(1000, 5000);

    logger.info(`Waiting for ${randomDelay / 1000} seconds before creating group "${groupName}"...`);
    await delay(randomDelay);

    logger.info(`Attempting to create group "${groupName}" with ${participants.length} members.`);

    let attempt = 0;
    const { maxRetries, initialBackoff } = config.rateLimits.retries;

    while (attempt < maxRetries) {
        try {
            logger.info(`Attempting to create group "${groupName}" (Attempt ${attempt + 1}/${maxRetries})...`);
            const group = await client.createGroup(groupName, participants);

            if (!group.gid) {
                logger.error(`Group creation did not return a group ID. Response: ${JSON.stringify(group)}`);
                throw new Error(`Group creation failed for "${groupName}". Response from API: ${JSON.stringify(group)}`);
            }

            const fullGroupChat = await client.getChatById(group.gid._serialized);
            const groupId = group.gid._serialized;
            logger.info(`Group created successfully! Name: ${groupName}, ID: ${groupId}`);

            // New: Promote desired admin if provided
            if (desiredAdminJid) {
                try {
                    // Ensure the desired admin is part of the group before promoting
                    const groupParticipants = Object.keys(group.participants);

                    const adminExistsInGroup = groupParticipants.includes(desiredAdminJid);

                    if (adminExistsInGroup) {
                        await fullGroupChat.promoteParticipants([desiredAdminJid]);
                        logger.info(`Promoted ${desiredAdminJid} to admin in group ${groupName}.`);
                    } else {
                        logger.warn(`Desired admin ${desiredAdminJid} not found in group ${groupName}. Cannot promote.`);
                    }
                } catch (adminPromoteErr) {
                    logger.error(`Failed to promote ${desiredAdminJid} to admin in group ${groupName}:`, adminPromoteErr);
                }
            }

            try {
                const inviteCode = await fullGroupChat.getInviteCode();
                const inviteLink = `https://chat.whatsapp.com/${inviteCode}`;
                try {
                    await writeInviteLog(username, groupName, inviteLink);
                    logger.info(`Logged invite link for "${groupName}": ${inviteLink}`);
                } catch (err) {
                    logger.error(`Failed to log invite for "${groupName}":`, err.message);
                }

            } catch (linkErr) {
                logger.warn(`Could not get invite link for group ${groupName}:`, linkErr.message);
            }
            // Save the new group's ID to the state file to prevent re-creation
            state.createdGroups[groupName] = groupId;
            writeState(state);
            return; // Exit the function successfully

        } catch (err) {
            attempt++;
            logger.error(`Attempt ${attempt}/${maxRetries} failed for "${groupName}":`, err.message);
            if (attempt < maxRetries) {
                const backoffTime = initialBackoff * Math.pow(2, attempt - 1);
                logger.info(`Waiting for ${backoffTime / 1000} seconds before retrying...`);
                await delay(backoffTime);
            } else {
                logger.error(`All ${maxRetries} retries failed for group "${groupName}". Giving up.`);
            }
        }
    }
}

module.exports = { createGroup };
