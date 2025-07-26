const logger = require('./logger');
const { readState, writeState } = require('./stateManager');
const config = require('./config'); // Make sure config is imported
const { writeInviteLog } = require('./utils/inviteLogger');
// Debounce map to track last emit per user
const logUpdateDebounceMap = {};


const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function emitLogUpdated(username) {
    const now = Date.now();
    const lastEmit = logUpdateDebounceMap[username] || 0;
    const debounceDuration = 12000; // 12 seconds

    if (now - lastEmit > debounceDuration) {
        if (global.io && global.userSockets?.[username]) {
            global.io.to(global.userSockets[username]).emit('log_updated');
            logUpdateDebounceMap[username] = now;
            console.log(`[EMIT] log_updated emitted to ${username}`);
        }
    } else {
        console.log(`[EMIT] Skipped log_updated for ${username} (debounced)`);
    }
}


function getRandomDelay(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Add jitter to prevent thundering herd
function calculateBackoffWithJitter(attempt, baseDelay) {
    const exponentialDelay = baseDelay * Math.pow(2, attempt);
    const jitter = Math.random() * 0.3 * exponentialDelay; // 30% jitter
    return Math.floor(exponentialDelay + jitter);
}

// More comprehensive client validation
function validateClientState(client) {
    if (!client) {
        throw new Error('Client is null or undefined');
    }
    
    if (!client.pupPage || !client.pupBrowser) {
        throw new Error('Client browser/page not initialized');
    }
    
    if (!client.info || !client.info.pushname) {
        throw new Error('Client not fully authenticated (missing user info)');
    }
    
    // Check if page is still connected
    if (client.pupPage.isClosed()) {
        throw new Error('Client page has been closed');
    }
    
    return true;
}

async function createGroup(client, username, groupName, participants, desiredAdminJid = null, sessionId) {
    // Use before each group creation attempt
    validateClientState(client);

    const state = readState();
    if (!client.info || !client.info.pushname) {
    logger.warn(`[CLIENT] Client is not fully ready (missing pushname).`);
    }

    // Check if a group with this name has already been created
    if (state.createdGroups[groupName]) {
        logger.info(`Group "${groupName}" has already been created (ID: ${state.createdGroups[groupName]}). Skipping.`);
        return;
    }

    if (!participants || participants.length === 0) {
        logger.error(`Cannot create group "${groupName}" because no participants were provided.`);
        return;
    }

    // Validate participant numbers format
    const validParticipants = participants.filter(p => {
        const isValid = p && typeof p === 'string' && p.endsWith('@c.us') && p.length >= 15;
        if (!isValid) {
            logger.warn(`Invalid participant format: ${p}`);            
        }
        return isValid;
    });

    if (validParticipants.length === 0) {
        throw new Error('No valid participants found after validation');
    }

    // Increase initial delay for rate limiting
    const randomDelayValue = getRandomDelay(10000, 15000); // 10-15 seconds
    logger.info(`Waiting for ${randomDelayValue / 1000} seconds before creating group "${groupName}"...`);
    await delay(randomDelayValue);

    let attempt = 0;
    const { maxRetries, initialBackoff } = config.rateLimits.retries;

    while (attempt < maxRetries) {
        try {
            logger.info(`Attempting to create group "${groupName}" (Attempt ${attempt + 1}/${maxRetries}) with ${validParticipants.length} validated members...`);
            
            // Use in retry logic
            if (attempt > 0) {
                const backoffTime = calculateBackoffWithJitter(attempt, initialBackoff);
                logger.info(`Waiting ${backoffTime}ms before retry ${attempt + 1}`);
                await delay(backoffTime);
            }

            const confirmedParticipants = [];
            for (const jid of validParticipants) {
                const reg = await client.isRegisteredUser(jid).catch(err => {
                    logger.warn(`[VALIDATION] Error while verifying ${jid}: ${err.message}`);
                    return null;
                });
                if (reg?.jid || typeof reg === 'boolean') {
                    // Some newer versions return boolean true instead of object
                    confirmedParticipants.push(jid);
                } else {
                    logger.warn(`[VALIDATION] Could not confirm registration for: ${jid}`);
                }

            }

            if (confirmedParticipants.length === 0) {
                throw new Error('No registered WhatsApp users found among provided numbers.');
            }

            // Fetch Contact to force session sync with WhatsApp backend
            await Promise.all(confirmedParticipants.map(jid => client.getContactById(jid).catch(err => {
                logger.warn(`[CONTACT] Failed to fetch contact ${jid}: ${err.message}`);
            })));

            // Your own JID, e.g., client.info.wid._serialized
            const ownJid = client.info?.wid?._serialized;
            if (!ownJid) {
                throw new Error('Could not retrieve own WhatsApp ID');
            }

            let group;
            try {
                group = await client.createGroup(groupName, confirmedParticipants);
            } catch (error) {
                // Directly catch the known error from the library
                if (error.message.includes('CreateGroupError: An unknown error occupied')) {
                    logger.error(`[WHATSAPP-API] Fatal library error during group creation: ${error.message}`);
                    // Throw a new error to break the retry loop immediately
                    throw new Error('Non-retriable error: Group creation failed due to a known library issue.');
                }
                // Re-throw other unexpected errors
                logger.error('Error on createGroup:', error);
                throw error;
            }

            // This check is now a fallback for other unexpected return types
            if (!group || !group.gid || !group.gid._serialized) {
                logger.error('[ERROR] Invalid group object returned:', group);
                throw new Error('Invalid group object returned from createGroup');
            }

            // Proceed to add participants (no changes here, but for context)
            const chat = await client.getChatById(group.gid._serialized);
            const toAdd = confirmedParticipants.filter(jid => jid !== ownJid);
            if (toAdd.length > 0) {
              try {
                await chat.addParticipants(toAdd);
                logger.info(`Added participants to group "${groupName}": ${toAdd}`);
              } catch (err) {
                logger.error(`Failed to add participants: ${err.message}`);
              }
            }


            // Enhanced error checking
            if (typeof group === 'string') {
                if (group.includes('CreateGroupError: An unknown error occupied')) {
                    logger.error(`[WHATSAPP-API] Known library issue encountered: ${group}`);
                    logger.error(`[DEBUG] Group: ${groupName}, Participants: ${confirmedParticipants.length}, Attempt: ${attempt + 1}`);
                    throw new Error(`WhatsApp API limitation: Group creation temporarily unavailable`);
                }
                throw new Error(`WhatsApp returned error: ${group}`);
            }

            if (!group || typeof group !== 'object' || !group.gid?._serialized) {
                logger.error(`[WHATSAPP] Unexpected response format:`, JSON.stringify(group, null, 2));
                throw new Error('Group creation failed: Invalid response structure from WhatsApp');
            }

            const fullGroupChat = await client.getChatById(group.gid._serialized);
            const groupId = group.gid._serialized;
            logger.info(`Group created successfully! Name: ${groupName}, ID: ${groupId}`);

            // Promote desired admin if provided
            if (desiredAdminJid) {
                try {
                    // Add a delay before promotion to ensure group is ready
                    await delay(8000); // Increased from 5000
                    
                    const groupParticipants = await fullGroupChat.participants.map(p => p.id._serialized);
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
                // Add a delay before getting invite code to ensure group is ready
                await delay(5000); // Increased from 3000
                
                const inviteCode = await fullGroupChat.getInviteCode();
                const inviteLink = `https://chat.whatsapp.com/${inviteCode}`;
                try {
                    await writeInviteLog(username, groupName, inviteLink, 'Success', '');
                    emitLogUpdated(username);
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
            const errorMsg = err.message || String(err);
            logger.error(`Attempt ${attempt}/${maxRetries} failed for "${groupName}": ${errorMsg}`);
            
            // Check for specific error conditions
            if (errorMsg.includes('Session closed') || 
                errorMsg.includes('Execution context was destroyed') ||
                errorMsg.includes('Client session is not ready') ||
                errorMsg.includes('Client session is not in ready state')) {
                logger.error(`[RETRY] Aborting further retries due to session issue: ${errorMsg}`);
                throw new Error(`Session error: ${errorMsg}`);
            }
            
            if (attempt >= maxRetries) {
                logger.error(`All ${maxRetries} retries failed for group "${groupName}". Last error: ${errorMsg}`);
                throw new Error(`Failed to create group after ${maxRetries} attempts: ${errorMsg}`);
            }
        }
    }
}
module.exports = { createGroup };