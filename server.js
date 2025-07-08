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

// Share session middleware with Socket.IO
io.use((socket, next) => {
    sessionMiddleware(socket.request, socket.request.res || {}, next);
});

// --- File Upload Setup ---
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}
const upload = multer({ dest: uploadsDir });

// --- Authentication Routes ---
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    logger.info(`[REGISTER] Attempt for username: ${username}`);
    if (!username || !password) {
        logger.warn('[REGISTER] Missing username or password');
        return res.status(400).json({ error: 'Username and password are required.' });
    }
    if (typeof username !== 'string' || username.length < 3 || !/^[a-zA-Z0-9]+$/.test(username)) {
        logger.warn(`[REGISTER] Invalid username: ${username}`);
        return res.status(400).json({ error: 'Username must be at least 3 characters and alphanumeric.' });
    }
    if (typeof password !== 'string' || password.length < 6 || /^[0-9]+$/.test(password) || /^[a-zA-Z]+$/.test(password)) {
        logger.warn(`[REGISTER] Invalid password for username: ${username}`);
        return res.status(400).json({ error: 'Password must be at least 6 characters and contain both letters and numbers.' });
    }
    addUser(username, password, (err, user) => {
        if (err) {
            if (err.code === 'SQLITE_CONSTRAINT') {
                logger.warn(`[REGISTER] Username already exists: ${username}`);
                return res.status(409).json({ error: 'Username already exists.' });
            }
            logger.error('[REGISTER] Error registering user:', err);
            return res.status(500).json({ error: 'Error registering user.' });
        }
        logger.info(`[REGISTER] User registered successfully: ${username}`);
        req.session.user = { id: user.id, username: username };
        res.status(201).json({ message: 'User registered successfully.' });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    findUser(username, password, (err, user) => {
        if (err) {
            logger.error('Error finding user:', err);
            return res.status(500).json({ error: 'Server error during login.' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }
        req.session.user = { id: user.id, username: user.username };
        res.status(200).json({ message: 'Login successful.' });
    });
});

// Helper function to kill orphaned Chromium processes
function killChromiumProcesses() {
    try {
        execSync("pkill -f '(chrome|chromium|puppeteer)' || true", { stdio: 'ignore' });
        logger.info('Killed orphaned Chromium/Puppeteer processes (if any).');
    } catch (err) {
        // Only log if it's not the expected 'no process found' error
        if (!err.message.includes('Command failed')) {
            logger.error('Error killing Chromium/Puppeteer processes:', err);
        }
        // Otherwise, ignore (no processes to kill is fine)
    }
}

app.post('/logout', async (req, res) => {
    const username = req.session.user?.username;
    
    // Clean up the WhatsApp client instance if it exists
    if (username) {
        if (clients[username]) {
            try {
                logger.info(`Destroying WhatsApp client for user: ${username}`);
                await clients[username].destroy();
                delete clients[username];
            } catch (error) {
                logger.error(`Error destroying WhatsApp client for ${username}:`, error);
            }
        }
        // Clear any pending initialization
        delete initializingSessions[username];

        // --- Kill orphaned Chromium processes before deleting session folder ---
        killChromiumProcesses();

        // --- Delete WhatsApp session folder for this user ---
        const sessionDir = path.join(config.paths.session, username);
        try {
            if (fs.existsSync(sessionDir)) {
                fs.rmSync(sessionDir, { recursive: true, force: true });
                logger.info(`Deleted WhatsApp session folder for user: ${username}`);
            }
        } catch (err) {
            logger.error(`Error deleting session folder for ${username}:`, err);
        }
    }
    
    // Clear the session
    req.session.destroy((err) => {
        if (err) {
            logger.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Could not log out.' });
        }
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logged out successfully.' });
    });
});

app.get('/check-auth', (req, res) => {
    if (req.session.user) {
        res.status(200).json({ user: req.session.user });
    } else {
        res.status(401).send('Not authenticated');
    }
});

// Middleware to protect routes that require authentication
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    }
    res.status(401).send('You must be logged in to access this resource.');
};

// --- Multi-Client Management ---
const clients = {}; // Stores active client instances
const initializingSessions = {}; // Tracks sessions that are currently starting up
const latestQRCodes = {}; // Stores the latest QR code for each client

async function initializeClient(clientId, socket, isRetry = false) {
    logger.info(`[DEBUG] Initialization request for session: ${clientId}${isRetry ? ' (retry)' : ''}`);

    // If a client for this session is already ready, skip re-initialization
    if (clients[clientId] && clients[clientId].info && clients[clientId].info.pushname) {
        logger.info(`[DEBUG] Client for ${clientId} is already connected and ready. Skipping re-initialization.`);
        socket.emit('status', 'Client is already connected!');
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
        if (latestQRCodes[clientId]) {
            logger.info(`[DEBUG] Re-sending latest QR code for ${clientId} to new socket connection.`);
            socket.emit('qr', latestQRCodes[clientId]);
        } else {
            socket.emit('status', 'Please wait while we prepare your session...');
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
            socket.emit('qr', qr);
        });

        client.on('ready', () => {
            logger.info(`[DEBUG] WhatsApp Client for ${clientId} is ready!`);
            clients[clientId] = client;
            delete latestQRCodes[clientId]; // Clear QR on ready
            socket.emit('status', 'Client is ready!');
            delete initializingSessions[clientId];
        });

        client.on('auth_failure', (msg) => {
            const errorMsg = `Authentication failed. Please try again.`;
            logger.error(`[DEBUG] Authentication failure for ${clientId}: ${msg}`);
            socket.emit('status', errorMsg);
            delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
        });

        client.on('disconnected', (reason) => {
            logger.warn(`[DEBUG] Client for ${clientId} was disconnected: ${reason}`);
            socket.emit('status', 'Client disconnected. Please refresh and log in again.');
            if (clients[clientId]) delete clients[clientId];
            if (initializingSessions[clientId]) delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
        });

        // Debug: Listen for all other events (for future debugging)
        client.on('change_state', (state) => {
            logger.info(`[DEBUG] Client state changed for ${clientId}: ${state}`);
        });
        client.on('message', (msg) => {
            logger.info(`[DEBUG] Message event for ${clientId}: ${msg.body}`);
        });
        client.on('authenticated', () => {
            logger.info(`[DEBUG] Client for ${clientId} authenticated.`);
        });
        client.on('loading_screen', (percent, message) => {
            logger.info(`[DEBUG] Loading screen for ${clientId}: ${percent}% - ${message}`);
        });

        await client.initialize().catch(async err => {
            // --- New logic: If Puppeteer/Chromium launch error, clean up session dir and retry once ---
            if (!isRetry && err && (String(err).includes('Failed to launch the browser process') || String(err).includes('ProcessSingleton'))) {
                // Kill orphaned Chromium processes before deleting session dir
                killChromiumProcesses();
                const sessionDir = path.join(config.paths.session, clientId);
                try {
                    if (fs.existsSync(sessionDir)) {
                        fs.rmSync(sessionDir, { recursive: true, force: true });
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
            logger.error(`[DEBUG] Failed to initialize client for ${clientId}:`, err);
            socket.emit('status', userFriendlyMsg);
            delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
        });
    } catch (err) {
        logger.error(`[DEBUG] Failed to initialize client for ${clientId}:`, err);
        socket.emit('status', 'Could not start WhatsApp session. Please try again in a few seconds.');
        delete initializingSessions[clientId];
        delete latestQRCodes[clientId];
    }
}

// --- Socket.IO Connection ---
io.use((socket, next) => {
    // Allow connection for authentication
    if (socket.handshake.auth && socket.handshake.auth.username) {
        socket.user = { username: socket.handshake.auth.username };
        return next();
    }
    
    // Also allow if user is in session (for page refreshes)
    if (socket.request.session && socket.request.session.user) {
        socket.user = socket.request.session.user;
        return next();
    }
    
    next(new Error('Unauthorized'));
});

// Handle new connections
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.user?.username || 'Unknown'}`);
    
    // Handle disconnection
    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.user?.username || 'Unknown'}`);
    });
    
    // Handle errors
    socket.on('error', (error) => {
        console.error('Socket error:', error);
    });
});

io.on('connection', (socket) => {
    const username = socket.user.username;
    logger.info(`[DEBUG] User '${username}' connected with socket ID: ${socket.id}`);

    // Only initialize if not already initializing or connected
    if (!initializingSessions[username] && (!clients[username] || clients[username].info == null || !clients[username].info.pushname)) {
        logger.info(`[DEBUG] Initializing client for user: ${username}`);
        initializeClient(username, socket);
    } else {
        logger.info(`[DEBUG] Client for ${username} is already initializing or connected. Skipping duplicate initialization.`);
        if (clients[username] && clients[username].info && clients[username].info.pushname) {
            socket.emit('status', 'Client is already connected!');
        } else {
            socket.emit('status', 'Client is initializing. Please wait...');
        }
    }

    socket.on('disconnect', () => {
        logger.info(`[DEBUG] User with socket ID: ${socket.id} disconnected.`);
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
        if (contacts.length === 0) {
            logger.warn(`[UPLOAD] No valid phone numbers after sanitization by user: ${sanitizedClientId}`);
            return res.status(400).send('No valid phone numbers provided.');
        }
    } else {
        groupName = req.body.groupName;
        const contactsFile = req.file;
        if (!groupName || typeof groupName !== 'string' || groupName.trim().length < 3 || /^[-\s]+$/.test(groupName) || /^[0-9]+$/.test(groupName) || /[^a-zA-Z0-9 _-]/.test(groupName)) {
            logger.warn(`[UPLOAD] Invalid group name: '${groupName}' by user: ${sanitizedClientId}`);
            return res.status(400).send('Group name must be at least 3 characters, can only contain letters, numbers, spaces, dashes, and underscores.');
        }
        if (!contactsFile) {
            logger.warn(`[UPLOAD] No contacts file provided by user: ${sanitizedClientId}`);
            return res.status(400).send('Contacts file is required.');
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
        await createGroup(clients[sanitizedClientId], groupName, contacts);
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
