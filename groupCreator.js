const config = require('./config');
const logger = require('./logger');
const { readState, writeState } = require('./stateManager');

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function getRandomDelay(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function createGroup(client, groupName, participants) {
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
            const group = await client.createGroup(groupName, participants);
            const groupId = group.gid._serialized;
            logger.info(`Group created successfully! Name: ${groupName}, ID: ${groupId}`);

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
