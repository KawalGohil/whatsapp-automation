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
const { createGroup } = require('./groupCreator');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { addUser, findUser } = require('./database');
const { execSync } = require('child_process');

const app = express();
const server = http.createServer(app);

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

app.post('/logout', async (req, res) => {
    const username = req.session.user?.username;
    logger.info(`[LOGOUT] Attempt for user: ${username || 'Unknown'}`);
    
    // Clean up the WhatsApp client instance if it exists
    if (username) {
        if (clients[username]) {
            logger.info(`[LOGOUT] Found active WhatsApp client for user: ${username}. Attempting to destroy.`);
            try {
                await clients[username].destroy();
                delete clients[username];
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
        killChromiumProcesses();

        // --- Do NOT delete WhatsApp session folder for this user to allow persistent login ---
        // const sessionDir = path.join(config.paths.session, username);
        // try {
        //     if (fs.existsSync(sessionDir)) {
        //         fs.rmSync(sessionDir, { recursive: true, force: true });
        //         logger.info(`Deleted WhatsApp session folder for user: ${username}`);
        //     }
        // } catch (err) {
        //     logger.error(`Error deleting session folder for ${username}:`, err);
        // }
    }
    
    // Clear the session
    req.session.destroy((err) => {
        if (err) {
            logger.error('[LOGOUT] Error destroying session:', err);
            return res.status(500).json({ error: 'Could not log out.' });
        }
        res.clearCookie('connect.sid');
        logger.info(`[LOGOUT] Session destroyed and cookie cleared for user: ${username || 'Unknown'}.`);
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

// --- Multi-Client Management ---
const clients = {}; // Stores active client instances
const initializingSessions = {}; // Tracks sessions that are currently starting up
const latestQRCodes = {}; // Stores the latest QR code for each client
const userSockets = {}; // Stores the latest socket ID for each user

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

        client.on('auth_failure', (msg) => {
            const errorMsg = `Authentication failed. Please try again.`;
            logger.error(`[DEBUG] Authentication failure for ${clientId}: ${msg}. Deleting session data.`);
            if (userSockets[clientId]) {
                io.to(userSockets[clientId]).emit('status', errorMsg);
            }
            // On auth_failure, delete the session folder to force a fresh QR scan
            const sessionDir = path.join(config.paths.session, clientId);
            try {
                if (fs.existsSync(sessionDir)) {
                    fs.rmSync(sessionDir, { recursive: true, force: true });
                    logger.info(`[DEBUG] Deleted WhatsApp session folder for ${clientId} due to authentication failure.`);
                }
            } catch (cleanupErr) {
                logger.error(`[DEBUG] Error cleaning up session directory for ${clientId} after auth_failure:`, cleanupErr);
            }
            delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
        });

        client.on('disconnected', (reason) => {
            logger.warn(`[DEBUG] Client for ${clientId} was disconnected: ${reason}.`);
            if (userSockets[clientId]) {
                io.to(userSockets[clientId]).emit('status', 'Client disconnected. Attempting to re-initialize...');
                io.to(userSockets[clientId]).emit('client_ready', false);
            }
            if (clients[clientId]) delete clients[clientId];
            if (initializingSessions[clientId]) delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
            // Attempt to re-initialize the client on disconnect to get a new QR if needed
            // This handles QR refresh if the client disconnects due to QR expiration
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
    userSockets[username] = socket.id; // Store the current socket ID for the user
    logger.info(`[DEBUG] User '${username}' connected with socket ID: ${socket.id}`);

    // Only initialize if not already initializing or connected
    if (!initializingSessions[username] && (!clients[username] || clients[username].info == null || !clients[username].info.pushname)) {
        logger.info(`[DEBUG] Initializing client for user: ${username}`);
        initializeClient(username, io);
    } else {
        logger.info(`[DEBUG] Client for ${username} is already initializing or connected. Skipping duplicate initialization.`);
        // If client is already ready, send ready status to the current socket
        if (clients[username] && clients[username].info && clients[username].info.pushname) {
            io.to(socket.id).emit('status', 'Client is already connected!');
            io.to(socket.id).emit('client_ready', true);
        } else {
            // If client is initializing, send a generic initializing status
            io.to(socket.id).emit('status', 'Client is initializing. Please wait...');
            io.to(socket.id).emit('client_ready', false);
            // The initializeClient function (if already running) will eventually emit the QR or ready status
        }
    }

    // Handle disconnection
    socket.on('disconnect', (reason) => {
        logger.info(`[SOCKET.IO] User disconnected: ${socket.user?.username || 'Unknown'}. Socket ID: ${socket.id}. Reason: ${reason}`);
        logger.info(`[DEBUG] User with socket ID: ${socket.id} disconnected.`);
        // If this was the last active socket for the user, clear it
        if (userSockets[username] === socket.id) {
            delete userSockets[username];
        }
    });

    // Handle errors
    socket.on('error', (error) => {
        console.error('Socket error:', error);
    });
});


// --- Routes ---
app.post('/upload', isAuthenticated, upload.single('contacts'), async (req, res) => {
    const sanitizedClientId = req.session.user.username; // Use username from session
    logger.info(`[UPLOAD] Group creation requested by: ${sanitizedClientId}`);
    if (!sanitizedClientId || !clients[sanitizedClientId]) {
        logger.warn(`[UPLOAD] Invalid or inactive session for: ${sanitizedClientId}`);
        return res.status(400).send('Invalid or inactive session. Please login again.');
    }
    let groupName;
    let contacts = [];
    if (req.is('application/json')) {
        groupName = req.body.groupName;
        const numbers = req.body.numbers;
        const desiredAdminNumber = req.body.desiredAdminNumber; // New: Get desired admin number

        if (!groupName || typeof groupName !== 'string' || groupName.trim().length < 3 || /^[-\s]+$/.test(groupName) || /^[0-9]+$/.test(groupName) || /[^a-zA-Z0-9 _-]/.test(groupName)) {
            logger.warn(`[UPLOAD] Invalid group name: '${groupName}' by user: ${sanitizedClientId}`);
            return res.status(400).send('Group name must be at least 3 characters, can only contain letters, numbers, spaces, dashes, and underscores.');
        }
        if (!Array.isArray(numbers) || numbers.length === 0) {
            logger.warn(`[UPLOAD] No phone numbers provided by user: ${sanitizedClientId}`);
            return res.status(400).send('At least one phone number is required.');
        }
        contacts = numbers.map(n => {
            let num = String(n).replace(/[^0-9]/g, '');
            return num ? `${num}@c.us` : null;
        }).filter(Boolean);

        // New: Validate desiredAdminNumber if provided
        if (desiredAdminNumber) {
            let adminNum = String(desiredAdminNumber).replace(/[^0-9]/g, '');
            if (!adminNum) {
                logger.warn(`[UPLOAD] Invalid desired admin number: '${desiredAdminNumber}' by user: ${sanitizedClientId}`);
                return res.status(400).send('Desired admin number is invalid.');
            }
            // Ensure the desired admin is part of the participants list
            if (!contacts.includes(`${adminNum}@c.us`)) {
                contacts.push(`${adminNum}@c.us`); // Add admin to participants if not already present
            }
        }
        if (contacts.length === 0) {
            logger.warn(`[UPLOAD] No valid phone numbers after sanitization by user: ${sanitizedClientId}`);
            return res.status(400).send('No valid phone numbers provided.');
        }
    } else {
        groupName = req.body.groupName;
        const contactsFile = req.file;
        const desiredAdminNumber = req.body.desiredAdminNumber; // New: Get desired admin number

        if (!groupName || typeof groupName !== 'string' || groupName.trim().length < 3 || /^[-\s]+$/.test(groupName) || /^[0-9]+$/.test(groupName) || /[^a-zA-Z0-9 _-]/.test(groupName)) {
            logger.warn(`[UPLOAD] Invalid group name: '${groupName}' by user: ${sanitizedClientId}`);
            return res.status(400).send('Group name must be at least 3 characters, can only contain letters, numbers, spaces, dashes, and underscores.');
        }
        if (!contactsFile) {
            logger.warn(`[UPLOAD] No contacts file provided by user: ${sanitizedClientId}`);
            return res.status(400).send('Contacts file is required.');
        }

        // New: Validate desiredAdminNumber if provided
        if (desiredAdminNumber) {
            let adminNum = String(desiredAdminNumber).replace(/[^0-9]/g, '');
            if (!adminNum) {
                logger.warn(`[UPLOAD] Invalid desired admin number: '${desiredAdminNumber}' by user: ${sanitizedClientId}`);
                return res.status(400).send('Desired admin number is invalid.');
            }
            // Add admin to participants if not already present (will be handled after CSV parsing)
        }
        try {
            contacts = await new Promise((resolve, reject) => {
                const result = [];
                fs.createReadStream(contactsFile.path)
                    .pipe(csv())
                    .on('data', (row) => {
                        if (row.phone) {
                            let num = String(row.phone).replace(/[^0-9]/g, '');
                            if (num) result.push(`${num}@c.us`);
                        }
                    })
                    .on('end', () => {
                        fs.unlinkSync(contactsFile.path);
                        resolve(result);
                    })
                    .on('error', (err) => {
                        fs.unlinkSync(contactsFile.path);
                        logger.error(`[UPLOAD] Error processing CSV for user: ${sanitizedClientId}`, err);
                        reject(err);
                    });
            });
        } catch (err) {
            logger.error(`[UPLOAD] Failed to process CSV for user: ${sanitizedClientId}`, err);
            return res.status(400).send('Failed to process CSV file.');
        }
        if (contacts.length === 0) {
            logger.warn(`[UPLOAD] No valid phone numbers found in CSV by user: ${sanitizedClientId}`);
            return res.status(400).send('No contacts with a valid phone number found in the CSV.');
        }
    }
    const creatorJid = `${sanitizedClientId.replace(/[^0-9]/g, '')}@c.us`;
    contacts = contacts.filter(num => num !== creatorJid);
    if (contacts.length === 0) {
        logger.warn(`[UPLOAD] Only creator's number present for group: '${groupName}' by user: ${sanitizedClientId}`);
        return res.status(400).send('Cannot create a group with only yourself. Please add other participants.');
    }
    logger.info(`[UPLOAD] Creating group '${groupName}' for user: ${sanitizedClientId} with ${contacts.length} participants.`);
    try {
        const adminJid = desiredAdminNumber ? `${String(desiredAdminNumber).replace(/[^0-9]/g, '')}@c.us` : null;
            await createGroup(clients[sanitizedClientId], groupName, contacts, adminJid);
        logger.info(`[UPLOAD] Group creation process started for '${groupName}' by user: ${sanitizedClientId}`);
        res.send('Group creation process started.');
    } catch (error) {
        const errorMsg = `Failed to create group: ${error.message}`;
        logger.error(`[UPLOAD] ${errorMsg} for group: '${groupName}' by user: ${sanitizedClientId}`);
        if (!res.headersSent) {
            res.status(500).send(errorMsg);
        }
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
