const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client, LocalAuth } = require('whatsapp-web.js');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
const logger = require('./logger');
const config = require('./config');
const dayjs = require('dayjs');  // Add this line
const { createGroup } = require('./groupCreator');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { addUser, findUser } = require('./database');
const { execSync } = require('child_process');
const { killOrphanedChrome } = require('./utils/processCleaner');
const { v4: uuidv4 } = require('uuid'); // Import UUID
const { deleteSessionFolder } = require('./utils/sessionUtils');
const app = express();
const server = http.createServer(app);
// --- Multi-Client Management ---
const clients = {}; // Stores active client instances
const initializingSessions = {}; // Tracks sessions that are currently starting up
const latestQRCodes = {}; // Stores the latest QR code for each client
const destroyingSessions = {};


// Configure Socket.IO with CORS and other options
const io = new Server(server, {
    cors: {
        origin: '*', // In production, replace with your frontend URL
        methods: ['GET', 'POST'],
        credentials: true
    },
    // Enable WebSocket transport
    transports: ['websocket', 'polling']
});

global.io = io; // ✅ make available globally
global.userSockets = {}; // reuse your existing object that stores socket IDs per user

// --- Middleware ---
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
logger.info('[SERVER] Express middleware for JSON and URL-encoded data configured.');

// --- Session Management Setup ---
// --- Session Management Setup ---
const sessionMiddleware = session({
    store: new SQLiteStore({
        db: path.basename(config.paths.sessionStore),
        dir: path.dirname(config.paths.sessionStore),
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key-goes-here', // Use environment variable for secret
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }, // 1 week
});
app.use(sessionMiddleware);
logger.info('[SERVER] Session middleware configured and applied.');

// Share session middleware with Socket.IO
io.use((socket, next) => {
    sessionMiddleware(socket.request, socket.request.res || {}, next);
    logger.info('[SERVER] Socket.IO session middleware applied.');
});

// --- File Upload Setup ---
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
    logger.info(`[SERVER] Created uploads directory: ${uploadsDir}`);
} else {
    logger.info(`[SERVER] Uploads directory already exists: ${uploadsDir}`);
}
const upload = multer({ dest: uploadsDir });
logger.info('[SERVER] Multer upload configured.');

// --- Authentication Routes ---
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    logger.info(`[REGISTER] Attempt for username: ${username}`);
    if (!username || !password) {
        logger.warn('[REGISTER] Missing username or password. Returning 400.');
        return res.status(400).json({ error: 'Username and password are required.' });
    }
    if (typeof username !== 'string' || username.length < 3 || !/^[a-zA-Z0-9]+$/.test(username)) {
        logger.warn(`[REGISTER] Invalid username format: ${username}. Returning 400.`);
        return res.status(400).json({ error: 'Username must be at least 3 characters and alphanumeric.' });
    }
    if (typeof password !== 'string' || password.length < 6 || /^[0-9]+$/.test(password) || /^[a-zA-Z]+$/.test(password)) {
        logger.warn(`[REGISTER] Invalid password format for username: ${username}. Returning 400.`);
        return res.status(400).json({ error: 'Password must be at least 6 characters and contain both letters and numbers.' });
    }
    addUser(username, password, (err, user) => {
        if (err) {
            if (err.code === 'SQLITE_CONSTRAINT') {
                logger.warn(`[REGISTER] Username already exists: ${username}. Returning 409.`);
                return res.status(409).json({ error: 'Username already exists.' });
            }
            logger.error('[REGISTER] Error registering user:', err);
            return res.status(500).json({ error: 'Error registering user.' });
        }
        logger.info(`[REGISTER] User registered successfully: ${username}. Setting session.`);
        req.session.user = { id: user.id, username: username };
        res.status(201).json({ message: 'User registered successfully.' });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    logger.info(`[LOGIN] Attempt for username: ${username}`);
    if (!username || !password) {
        logger.warn('[LOGIN] Missing username or password. Returning 400.');
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    findUser(username, password, (err, user) => {
        if (err) {
            logger.error('[LOGIN] Error finding user:', err);
            return res.status(500).json({ error: 'Server error during login.' });
        }
        if (!user) {
            logger.warn(`[LOGIN] Invalid username or password for ${username}. Returning 401.`);
            return res.status(401).json({ error: 'Invalid username or password.' });
        }
        logger.info(`[LOGIN] User ${username} logged in successfully. Setting session.`);
        req.session.user = { id: user.id, username: user.username };
        res.status(200).json({ message: 'Login successful.' });
    });
});

// Helper function to kill orphaned Chromium processes
function killChromiumProcesses() {
    logger.info('[CHROMIUM] Attempting to kill orphaned Chromium/Puppeteer processes.');
    try {
        execSync("pkill -f '(chrome|chromium|puppeteer)' || true", { stdio: 'ignore' });
        logger.info('[CHROMIUM] Killed orphaned Chromium/Puppeteer processes (if any).');
    } catch (err) {
        // Only log if it's not the expected 'no process found' error
        if (!err.message.includes('Command failed')) {
            logger.error('[CHROMIUM] Error killing Chromium/Puppeteer processes:', err);
        } else {
            logger.info('[CHROMIUM] No orphaned Chromium/Puppeteer processes found to kill.');
        }
    }
}

async function logoutUser(clientId) {
    destroyingSessions[clientId] = true;

    while (initializingSessions[clientId]) {
        logger.warn(`[SAFEGUARD] Waiting for ${clientId}'s init to finish before destroying.`);
        await new Promise((res) => setTimeout(res, 100));
    }

    try {
        if (clients[clientId]) {
            logger.info(`[LOGOUT] Destroying client for ${clientId}`);
            await clients[clientId].destroy();
            delete clients[clientId];
        }

        // killOrphanedChrome(); // This is too aggressive and closes all chrome instances
        await new Promise((r) => setTimeout(r, 500));

        const sessionPath = path.join(config.paths.session, clientId);
        await deleteSessionFolder(sessionPath);

        if (userSockets[clientId]) {
            io.to(userSockets[clientId]).emit('status', 'Logged out. Please scan again.');
            io.to(userSockets[clientId]).emit('client_ready', false);
        }

    } catch (err) {
        logger.error(`[LOGOUT] Error during logout for ${clientId}:`, err.message);
    } finally {
        delete destroyingSessions[clientId];
        delete initializingSessions[clientId];
        delete latestQRCodes[clientId];
    }
}


app.post('/logout', async (req, res) => {
    const username = req.session.user?.username;
    logger.info(`[LOGOUT] Attempt for user: ${username || 'Unknown'}`);
    
    // Clean up the WhatsApp client instance if it exists
    if (username) {
        if (clients[username]) {
            logger.info(`[LOGOUT] Found active WhatsApp client for user: ${username}. Attempting to destroy.`);
            try {
                await logoutUser(username);
                // The client is already deleted within logoutUser
                logger.info(`[LOGOUT] Successfully destroyed WhatsApp client for user: ${username}.`);
            } catch (error) {
                logger.error(`[LOGOUT] Error destroying WhatsApp client for ${username}:`, error);
            }
        } else {
            logger.info(`[LOGOUT] No active WhatsApp client found for user: ${username}.`);
        }
        // Clear any pending initialization
        if (initializingSessions[username]) {
            delete initializingSessions[username];
            logger.info(`[LOGOUT] Cleared pending initialization for user: ${username}.`);
        }

        // --- Kill orphaned Chromium processes before deleting session folder ---
        // killChromiumProcesses(); // This is too aggressive
    }
    
    // Clear the session
    req.session.destroy((err) => {
        if (err) {
            logger.error('[LOGOUT] Error destroying session:', err);
            return res.status(500).json({ error: 'Logout failed.' });
        }
        res.clearCookie('connect.sid');
        logger.info(`[LOGOUT] Session destroyed and cookie cleared for user: ${username}`);
        res.status(200).json({ message: 'Logged out successfully.' });
    });
});

app.get('/check-auth', (req, res) => {
    if (req.session.user) {
        logger.info(`[AUTH] User ${req.session.user.username} is authenticated.`);
        res.status(200).json({ user: req.session.user });
    } else {
        logger.warn('[AUTH] User not authenticated. Returning 401.');
        res.status(401).send('Not authenticated');
    }
});

// Middleware to protect routes that require authentication
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        logger.info(`[AUTH] Middleware: User ${req.session.user.username} is authenticated. Proceeding.`);
        return next();
    }
    logger.warn('[AUTH] Middleware: User not authenticated. Blocking access.');
    res.status(401).send('You must be logged in to access this resource.');
};


async function initializeClient(clientId, io, isRetry = false) {
    logger.info(`[DEBUG] Initialization request for session: ${clientId}${isRetry ? ' (retry)' : ''}`);

    // If a client for this session is already ready, send ready status and return
    if (clients[clientId] && clients[clientId].info && clients[clientId].info.pushname) {
        logger.info(`[DEBUG] Client for ${clientId} is already connected and ready. Notifying frontend.`);
        if (userSockets[clientId]) {
            io.to(userSockets[clientId]).emit('status', 'Client is already connected!');
            io.to(userSockets[clientId]).emit('client_ready', true);
        }
        return;
    }

    // If a client for this session already exists, destroy it to ensure a clean start
    if (clients[clientId]) {
        logger.warn(`[DEBUG] Existing client for session ${clientId} found. Destroying before re-initializing.`);
        try {
            await clients[clientId].destroy();
            logger.info(`[DEBUG] Successfully destroyed old client for ${clientId}.`);
        } catch (e) {
            logger.error(`[DEBUG] Error destroying old client for ${clientId}:`, e);
        }
        delete clients[clientId];
    }

    if (destroyingSessions[clientId]) {
        logger.warn(`[SAFEGUARD] Skipping init for ${clientId}; destroy in progress.`);
        return;
    }

    // If another request is already initializing this session, tell the user to wait.
    if (initializingSessions[clientId]) {
        logger.info(`[DEBUG] Session for ${clientId} is already initializing. Notifying client to wait.`);
        // If we have a QR code, send it to the new socket
        if (userSockets[clientId]) {
            if (latestQRCodes[clientId]) {
                logger.info(`[DEBUG] Re-sending latest QR code for ${clientId} to new socket connection.`);
                io.to(userSockets[clientId]).emit('qr', latestQRCodes[clientId]);
                io.to(userSockets[clientId]).emit('status', 'Please scan the QR code.');
            } else {
                io.to(userSockets[clientId]).emit('status', 'Please wait while we prepare your session...');
            }
            io.to(userSockets[clientId]).emit('client_ready', false);
        }
        return;
    }

    try {
        initializingSessions[clientId] = true;
        logger.info(`[DEBUG] Initializing new WhatsApp client for session: ${clientId}`);

        const client = new Client({
            authStrategy: new LocalAuth({ clientId }),
            puppeteer: {
                headless: config.puppeteer.headless,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu'
                ],
            }
        });

        // Debug: Listen for all client events
        client.on('qr', (qr) => {
            logger.info(`[DEBUG] QR code generated for ${clientId}. Sending to client.`);
            latestQRCodes[clientId] = qr; // Store the latest QR
            if (userSockets[clientId]) {
                io.to(userSockets[clientId]).emit('qr', qr);
            } else {
                logger.warn(`[DEBUG] No active socket found for ${clientId} to send QR code. Destroying client.`);
                // If no socket is found, destroy the client to prevent unnecessary QR generation and resource usage
                (async () => {
                    try {
                        await client.destroy();
                        logger.info(`[DEBUG] Client for ${clientId} destroyed due to no active socket.`);
                    } catch (e) {
                        logger.error(`[DEBUG] Error destroying client for ${clientId} (no active socket):`, e);
                    }
                })();
                delete initializingSessions[clientId];
                delete latestQRCodes[clientId];
                return; // Exit the QR handler as client is destroyed
            }
        });

        client.on('ready', () => {
            logger.info(`[DEBUG] WhatsApp Client for ${clientId} is ready!`);
            clients[clientId] = client;
            delete latestQRCodes[clientId]; // Clear QR on ready
            if (userSockets[clientId]) {
                io.to(userSockets[clientId]).emit('status', 'Client is ready!');
                io.to(userSockets[clientId]).emit('client_ready', true);
            }
            delete initializingSessions[clientId];
        });

        client.on('auth_failure', async (message) => {
            logger.warn(`[DEBUG] Auth failure for ${clientId}: ${message}`);
            const sessionPath = path.join(config.paths.session, clientId);
            // Kill currently running Chrome instances
            killOrphanedChrome();
            // Wait before deletion
            await new Promise((res) => setTimeout(res, 500));
            // Clean up session safely
            await deleteSessionFolder(sessionPath);        
            delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
        });

        client.on('disconnected', async (reason) => {
            logger.warn(`[CLIENT] Disconnected for ${clientId}: ${reason}`);

            // If a logout is already in progress, let it handle the cleanup.
            if (destroyingSessions[clientId]) {
                logger.info(`[CLIENT] Disconnect event for ${clientId} ignored, logout in progress.`);
                return;
           }

            const sessionPath = path.join(config.paths.session, clientId);

            // Removing aggressive cleanup from automatic disconnect event.
            // A user-initiated logout is a better place for this.
            // killOrphanedChrome(); 
    
    await new Promise(r => setTimeout(r, 800));

    await deleteSessionFolder(sessionPath); // Safe removal

    if (userSockets[clientId]) {
        io.to(userSockets[clientId]).emit('status', 'Disconnected. Please scan again.');
        io.to(userSockets[clientId]).emit('client_ready', false);
    }

    delete clients[clientId];
    delete initializingSessions[clientId];
    delete latestQRCodes[clientId];

    // ✳️ Now safe to retry initialization
    await new Promise(r => setTimeout(r, 500)); // (optional buffer)
    initializeClient(clientId, io, true);
});

        // Debug: Listen for all other events (for future debugging)
        client.on('change_state', (state) => {
            logger.info(`[DEBUG] Client state changed for ${clientId}: ${state}`);
        });
        client.on('message', (msg) => {
            // logger.info(`[DEBUG] Message event for ${clientId}: ${msg.body}`); // Commented out to prevent logging chat messages
        });
        client.on('authenticated', () => {
            logger.info(`[DEBUG] Client for ${clientId} authenticated.`);
        });
        client.on('loading_screen', (percent, message) => {
            logger.info(`[DEBUG] Loading screen for ${clientId}: ${percent}% - ${message}`);
            // Only update status if not 100% or if client is not yet marked as ready
            if (percent < 100 && !clients[clientId]) {
                if (userSockets[clientId]) {
                    io.to(userSockets[clientId]).emit('status', `Loading: ${percent}% - ${message}`);
                }
            }
        });

        await client.initialize().catch(async err => {
            logger.error(`[DEBUG] Failed to initialize client for ${clientId}:`, err);
            // --- New logic: If Puppeteer/Chromium launch error, clean up session dir and retry once ---
            if (!isRetry && err && (String(err).includes('Failed to launch the browser process') || String(err).includes('ProcessSingleton'))) {
                logger.warn(`[DEBUG] Puppeteer launch error for ${clientId}. Attempting cleanup and retry.`);
                // Kill orphaned Chromium processes before deleting session dir
                killChromiumProcesses();
                const sessionDir = path.join(config.paths.session, clientId);
                try {
                    if (fs.existsSync(sessionDir)) {
                        fs.rmSync(sessionDir, { recursive: true, true: true }); // Use force: true for older Node.js versions
                        logger.info(`[DEBUG] Deleted session directory for ${clientId} due to Puppeteer launch error.`);
                    }
                } catch (cleanupErr) {
                    logger.error(`[DEBUG] Error cleaning up session directory for ${clientId}:`, cleanupErr);
                }
                // Retry initialization once
                logger.info(`[DEBUG] Retrying WhatsApp client initialization for ${clientId} after session cleanup.`);
                delete initializingSessions[clientId];
                await initializeClient(clientId, socket, true);
                return;
            }
            // User-friendly error message
            const userFriendlyMsg = 'Could not start WhatsApp session. Please try again in a few seconds.';
            if (userSockets[clientId]) {
                io.to(userSockets[clientId]).emit('status', userFriendlyMsg);
            }
            delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
        });
    } catch (err) {
        logger.error(`[DEBUG] Failed to initialize client for ${clientId}:`, err);
        if (userSockets[clientId]) {
            io.to(userSockets[clientId]).emit('status', 'Could not start WhatsApp session. Please try again in a few seconds.');
        }
        delete initializingSessions[clientId];
        delete latestQRCodes[clientId];
    }
}

// --- Socket.IO Connection ---
io.use((socket, next) => {
    // Allow connection for authentication
    if (socket.handshake.auth && socket.handshake.auth.username) {
        socket.user = { username: socket.handshake.auth.username };
        logger.info(`[SOCKET.IO] User ${socket.user.username} authenticated via handshake auth.`);
        return next();
    }
    
    // Also allow if user is in session (for page refreshes)
    if (socket.request.session && socket.request.session.user) {
        socket.user = socket.request.session.user;
        logger.info(`[SOCKET.IO] User ${socket.user.username} authenticated via session.`);
        return next();
    }
    
    logger.warn('[SOCKET.IO] Unauthorized socket connection attempt.');
     next(new Error('Unauthorized'));
  });

// Handle new connections
io.on('connection', (socket) => {
    logger.info(`[SOCKET.IO] User connected: ${socket.user?.username || 'Unknown'}. Socket ID: ${socket.id}`);

    const username = socket.user.username;
    global.userSockets[username] = socket.id; // ✅ Store globally
    logger.info(`[SOCKET.IO] User '${username}' connected with socket ID: ${socket.id}`);

    if (!initializingSessions[username] && (!clients[username] || !clients[username].info?.pushname)) {
        logger.info(`[DEBUG] Initializing client for user: ${username}`);
        initializeClient(username, io);
    } else {
        logger.info(`[DEBUG] Client for ${username} is already initializing or connected. Skipping duplicate init.`);
        if (clients[username]?.info?.pushname) {
            io.to(socket.id).emit('status', 'Client is already connected!');
            io.to(socket.id).emit('client_ready', true);
        } else {
            io.to(socket.id).emit('status', 'Client is initializing. Please wait...');
            io.to(socket.id).emit('client_ready', false);
        }
    }

    socket.on('disconnect', (reason) => {
        logger.info(`[SOCKET.IO] User disconnected: ${username}. Socket ID: ${socket.id}. Reason: ${reason}`);
        if (global.userSockets[username] === socket.id) {
            delete global.userSockets[username];
        }
    });

    socket.on('error', (error) => {
        console.error('Socket error:', error);
    });
});



// --- New Route for Manual Group Creation ---
app.post('/create-group', isAuthenticated, async (req, res) => {
    const sanitizedClientId = req.session.user.username;
    const { groupName, numbers, desiredAdminNumber } = req.body;

    if (!groupName || !numbers) {
        return res.status(400).send('Group name and numbers are required.');
    }

    const client = clients[sanitizedClientId];
    if (!client) {
        return res.status(400).send('WhatsApp client not ready.');
    }

    // Sanitize numbers
    const sanitize = (num) => {
        if (!num) return null;
        let cleaned = String(num).replace(/[^0-9]/g, '');
        if (cleaned.length === 10) cleaned = '91' + cleaned;
        return cleaned.length >= 10 ? `${cleaned}@c.us` : null;
    };

    const participants = numbers.split(/[,\n]/).map(sanitize).filter(Boolean);
    if (participants.length === 0) {
        return res.status(400).send('No valid participant numbers provided.');
    }

    const adminJid = sanitize(desiredAdminNumber);
    const validAdminJid = adminJid && participants.includes(adminJid) ? adminJid : null;
    const sessionId = uuidv4(); // Generate a session ID for manual creation

    try {
        await createGroup(client, sanitizedClientId, groupName, participants, validAdminJid, sessionId);
        res.status(200).json({ message: `Group "${groupName}" created successfully.` });
    } catch (error) {
        logger.error(`[CREATE-GROUP] Failed to create group "${groupName}":`, error.message);
        res.status(500).send('Failed to create group.');
    }
});


// --- Routes ---
app.post('/upload', isAuthenticated, upload.single('contacts'), (req, res) => {
    const sanitizedClientId = req.session.user.username;
    logger.info(`[UPLOAD] CSV received from: ${sanitizedClientId}`);

    const contactsFile = req.file;
    if (!contactsFile) {
        logger.warn(`[UPLOAD] No file uploaded.`);
        return res.status(400).json({ error: 'CSV file is required.' });
    }

    // Respond immediately for fire-and-forget (else move below)
    res.status(202).json({ message: 'File uploaded. Processing will continue in the background.' });

    const sessionId = uuidv4(); // Generate session ID

    // Process in background
    setImmediate(async () => {
        let createdGroups = [];
        let failedGroups = [];

        try {
            const rows = [];
            await new Promise((resolve, reject) => {
                fs.createReadStream(contactsFile.path)
                    .pipe(csv())
                    .on('data', (row) => rows.push(row))
                    .on('end', resolve)
                    .on('error', reject);
            });

            fs.unlinkSync(contactsFile.path);
            const logDir = path.join(config.paths.data, 'invite-logs');

            for (const row of rows) {
                let groupName, participants, validAdminJid;
                try {
                    // ==> Validate and extract row data as in your code, e.g.:
                    const bookingID = row['Booking ID']?.trim();
                    const propertyName = row['property name']?.trim();
                    const checkInDate = row['check-in']?.trim();
                    const adminRaw = row['admin number'];
                    if (!bookingID || !propertyName || !checkInDate) {
                        throw new Error('Missing one or more mandatory group name fields (Booking ID, property name, check-in).');
                    }
                    groupName = `${bookingID} - ${propertyName} - ${checkInDate}`;

                    // Extract participants
                    const sanitize = (num) => {
                        if (!num) return null;
                        let cleaned = String(num).replace(/[^0-9]/g, '');
                        if (cleaned.length === 10) cleaned = '91' + cleaned;
                        return cleaned.length >= 10 ? `${cleaned}@c.us` : null;
                    };
                    const participantFields = Object.keys(row).filter(
                        key =>
                            row[key] &&
                            /number|contact|guest|^s$/i.test(key) &&
                            key.toLowerCase() !== 'admin number'
                    );
                    participants = participantFields
                        .map(field => sanitize(row[field]))
                        .filter(Boolean);
                    if (participants.length === 0) {
                        throw new Error('No valid participant numbers found.');
                    }
                    // Admin logic
                    const adminJid = sanitize(adminRaw);
                    validAdminJid = (adminJid && participants.includes(adminJid)) ? adminJid : null;
                    // You can warn if admin present but not valid for this group
                } catch (extractionErr) {
                    failedGroups.push({
                        groupName: groupName || '[Unknown]',
                        error: `Input error: ${extractionErr.message}`,
                    });
                    continue;
                }

                const client = clients[sanitizedClientId];
                
                if (global.io && global.userSockets?.[sanitizedClientId]) {
                    global.io.to(global.userSockets[sanitizedClientId]).emit('upload_aborted', {
                        failedGroups,
                        message: 'Disconnected during upload. Some groups were not created.',
                    });
                }

            if (!client || client.destroyed || !client.info || !client.pupBrowser) {
    failedGroups.push({
        groupName: row['...'],
        error: 'Client not ready or session already closed.',
    });

    if (global.io && global.userSockets?.[sanitizedClientId]) {
        global.io.to(global.userSockets[sanitizedClientId]).emit('upload_aborted', {
            failedGroups,
            message: `Disconnected or invalid session. Group ${groupName} not created.`,
        });
    }

    break; // or continue, based on logic
}

                let message;
                try {
                    await createGroup(client, sanitizedClientId, groupName, participants, validAdminJid, sessionId);
                    logger.info(`[UPLOAD] Successfully processed group: ${groupName}`);
                    createdGroups.push({ groupName });
                    message = `Successfully created group "${groupName}"`;
                } catch (creationErr) {
                    logger.error(`[UPLOAD] Group creation failed for ${groupName}:`, creationErr.message);
                    failedGroups.push({
                        groupName,
                        error: `Group creation failed: ${creationErr.message}`,
                    });
                    message = `Failed to create group "${groupName}"`;
                }

                // Emit progress after each attempt
                if (global.io && global.userSockets?.[sanitizedClientId]) {
                    global.io.to(global.userSockets[sanitizedClientId]).emit('upload_progress', {
                        current: createdGroups.length + failedGroups.length,
                        total: rows.length,
                        currentGroup: groupName,
                        message: message,
                    });
                }
            }
            
            // Emit final completion event once the entire loop is done
            if (global.io && global.userSockets?.[sanitizedClientId]) {
                global.io.to(global.userSockets[sanitizedClientId]).emit('upload_complete', {
                    successCount: createdGroups.length,
                    failedCount: failedGroups.length,
                    failedGroups: failedGroups
                });
            }

            fs.writeFileSync(path.join(logDir, `group_error_log_${sanitizedClientId}_${sessionId}_${dayjs()
                .format('YYYY-MM-DD_HH-mm')}.json`), 
            JSON.stringify(failedGroups, null, 2));

        } catch (outerErr) {
            // Major CSV or unexpected error (e.g., file not readable)
            logger.error(`[UPLOAD] Background processing crashed for user ${sanitizedClientId}:`, outerErr);
            // Optionally: log or notify admin
        }
    });
});

// New route to list available log files for the user
app.get('/list-logs', isAuthenticated, (req, res) => {
    const logDir = path.join(config.paths.data, 'invite-logs');
    const username = req.session.user.username;

    fs.readdir(logDir, (err, files) => {
        if (err) {
            logger.error(`[LIST-LOGS] Error reading log directory for ${username}:`, err);
            return res.status(500).json({ error: 'Could not list log files.' });
        }

        const userLogs = files
            .filter(file => file.startsWith(`group_invite_log_${username}_`) && file.endsWith('.csv'))
            .map(file => {
                const dateStr = file
                    .replace(`group_invite_log_${username}_`, '')
                    .replace('.csv', '');
                return {
                    filename: file,
                    display: `Invite log — ${dateStr}`
                };
            });

        res.status(200).json(userLogs);
    });
});




// Route to download the invite log CSV for the current session
app.get('/download/invite-log/:filename', isAuthenticated, (req, res) => {
    const logDir = path.join(config.paths.data, 'invite-logs');
    const filename = req.params.filename;
    const username = req.session.user.username;

    // Security check: Ensure the user is only downloading their own logs
    if (!filename.startsWith(`group_invite_log_${username}`)) {
        logger.warn(`[DOWNLOAD-LOG] Unauthorized attempt by ${username} to download ${filename}`);
        return res.status(403).json({ error: 'Forbidden' });
    }

    const logPath = path.join(logDir, filename);

    try {
        if (fs.existsSync(logPath)) {
            res.download(logPath, filename);
        } else {
            return res.status(404).json({ error: 'Log file not found.' });
        }
    } catch (err) {
        logger.error(`[DOWNLOAD-LOG] Error reading log file ${filename}:`, err);
        return res.status(500).json({ error: 'Error accessing log file.' });
    }
});

// --- Error handling middleware for structured error responses ---
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({ error: err.message || 'Internal server error.' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    logger.info(`Server is listening on port ${PORT}`);
});
