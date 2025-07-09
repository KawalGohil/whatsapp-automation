const config = require('./config');
const logger = require('./logger');
const { readState, writeState } = require('./stateManager');

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function getRandomDelay(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function createGroup(client, groupName, participants, desiredAdminJid = null) {
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

    const { min, max } = config.rateLimits.groupCreationDelay;
    const randomDelay = getRandomDelay(min, max);

    logger.info(`Waiting for ${randomDelay / 1000} seconds before creating group...`);
    await delay(randomDelay);

    logger.info(`Attempting to create group "${groupName}" with ${participants.length} members.`);

    let attempt = 0;
    const { maxRetries, initialBackoff } = config.rateLimits.retries;

    while (attempt < maxRetries) {
        try {
            logger.info(`Attempting to create group "${groupName}" (Attempt ${attempt + 1}/${maxRetries})...`);
            const group = await client.createGroup(groupName, contacts);
            const fullGroupChat = await client.getChatById(group.gid);
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
