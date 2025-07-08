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
    
    if (!username) {
        return res.status(400).json({ error: 'No user session found' });
    }

    logger.info(`Starting logout process for user: ${username}`);
    
    // 1. Clean up the WhatsApp client instance if it exists
    if (clients[username]) {
        try {
            logger.info(`Destroying WhatsApp client for user: ${username}`);
            await clients[username].destroy();
            delete clients[username];
            logger.info(`Successfully destroyed WhatsApp client for user: ${username}`);
        } catch (error) {
            logger.error(`Error destroying WhatsApp client for ${username}:`, error);
        }
    }

    // 2. Clear any pending initialization and QR codes
    delete initializingSessions[username];
    delete latestQRCodes[username];

    // 3. Kill orphaned Chromium processes
    try {
        killChromiumProcesses();
        logger.info(`Killed orphaned Chromium processes for user: ${username}`);
    } catch (error) {
        logger.error(`Error killing Chromium processes for ${username}:`, error);
    }

    // 4. Delete WhatsApp session folder
    const sessionDir = path.join(config.paths.session, username);
    try {
        if (fs.existsSync(sessionDir)) {
            fs.rmSync(sessionDir, { recursive: true, force: true });
            logger.info(`Deleted WhatsApp session folder for user: ${username}`);
        } else {
            logger.info(`No session folder found for user: ${username}`);
        }
    } catch (err) {
        logger.error(`Error deleting session folder for ${username}:`, err);
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

    // Clean up any existing client or initialization state
    const cleanupExistingSession = async () => {
        if (clients[clientId]) {
            try {
                logger.warn(`[DEBUG] Cleaning up existing client for ${clientId}`);
                await clients[clientId].destroy();
            } catch (e) {
                logger.error(`[DEBUG] Error cleaning up existing client:`, e);
            } finally {
                delete clients[clientId];
            }
        }
        delete initializingSessions[clientId];
        delete latestQRCodes[clientId];
    };

    // Check if we already have a connected client
    if (clients[clientId] && clients[clientId].info && clients[clientId].info.pushname) {
        const client = clients[clientId];
        try {
            // Verify the client is actually connected
            const state = await client.getState();
            if (state === 'CONNECTED') {
                logger.info(`[DEBUG] Client for ${clientId} is already connected and ready.`);
                socket.emit('status', 'Client is already connected!');
                return;
            } else {
                logger.warn(`[DEBUG] Client for ${clientId} exists but state is ${state}. Reinitializing...`);
                await cleanupExistingSession();
            }
        } catch (e) {
            logger.error(`[DEBUG] Error checking client state:`, e);
            await cleanupExistingSession();
        }
    }

    // If another request is already initializing this session, check if we have a valid QR code
    if (initializingSessions[clientId]) {
        logger.info(`[DEBUG] Session for ${clientId} is already initializing.`);
        
        // Check if we have a valid QR code (not expired)
        const qrData = latestQRCodes[clientId];
        if (qrData && qrData.expiresAt > Date.now()) {
            logger.info(`[DEBUG] Re-sending valid QR code for ${clientId} to new socket connection.`);
            socket.emit('qr', qrData.code);
            socket.emit('status', 'Please scan the QR code to continue...');
        } else {
            // No valid QR code, clear any expired ones
            if (qrData) {
                logger.info(`[DEBUG] Clearing expired QR code for ${clientId}`);
                delete latestQRCodes[clientId];
            }
            socket.emit('status', 'Please wait while we prepare your session...');
            
            // If we're not retrying and there's no valid QR, force a new one
            if (!isRetry) {
                logger.info(`[DEBUG] No valid QR code found, forcing new QR generation for ${clientId}`);
                try {
                    if (clients[clientId]) {
                        await clients[clientId].destroy();
                        delete clients[clientId];
                    }
                    delete initializingSessions[clientId];
                    return initializeClient(clientId, socket, true);
                } catch (e) {
                    logger.error(`[DEBUG] Error during QR refresh for ${clientId}:`, e);
                }
            }
        }
        return;
    }

    try {
        initializingSessions[clientId] = true;
        logger.info(`[DEBUG] Initializing new WhatsApp client for session: ${clientId}`);

        // Clean up any existing session data if this is a retry
        if (isRetry) {
            logger.info(`[DEBUG] Retry attempt, cleaning up previous session data for ${clientId}`);
            const sessionDir = path.join(config.paths.session, clientId);
            try {
                // Wait a bit before retrying
                await new Promise(resolve => setTimeout(resolve, 5000));
                
                // Retry initialization with a fresh start
                logger.info(`[DEBUG] Retrying initialization for ${clientId}...`);
                try {
                    await client.destroy();
                } catch (e) {
                    logger.error(`[DEBUG] Error destroying client during retry:`, e);
                }
                
                // Clear any existing state
                delete clients[clientId];
                delete initializingSessions[clientId];
                delete latestQRCodes[clientId];
                
                // Retry initialization
                return initializeClient(clientId, socket, true);
            } catch (e) {
                logger.error(`[DEBUG] Error during retry cleanup for ${clientId}:`, e);
            }
        }

        // Configure the WhatsApp client with proper error handling
        const client = new Client({
            authStrategy: new LocalAuth({
                clientId: clientId,
                dataPath: config.paths.session,
                clearAuthDataOnLogout: true
            }),
            puppeteer: {
                headless: config.puppeteer.headless,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu',
                    '--single-process',
                    '--no-zygote',
                    '--disable-setuid-sandbox',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process'
                ],
                timeout: 60000, // Increase timeout to 60 seconds
                ignoreHTTPSErrors: true,
                defaultViewport: { width: 1280, height: 800 }
            },
            takeoverOnConflict: true,
            takeoverTimeoutMs: 10000,
            qrMaxRetries: 3,
            restartOnAuthFail: true,
            ffmpegPath: 'ffmpeg' // Ensure ffmpeg is in PATH
        });

        // Set up a timeout for the initialization
        const initTimeout = setTimeout(() => {
            if (!client.info) {
                logger.error(`[DEBUG] Initialization timeout for ${clientId}`);
                socket.emit('status', 'Initialization timed out. Please try again.');
                client.destroy().catch(e => logger.error('Error destroying client after timeout:', e));
                delete initializingSessions[clientId];
                delete latestQRCodes[clientId];
            }
        }, 120000); // 2 minutes timeout

        // Handle QR code generation with expiration
        client.on('qr', (qr) => {
            logger.info(`[DEBUG] QR code generated for ${clientId}. Sending to client.`);
            
            // Store the latest QR with timestamp
            latestQRCodes[clientId] = {
                code: qr,
                generatedAt: Date.now(),
                expiresAt: Date.now() + (20 * 1000) // 20 seconds expiration (WhatsApp Web default)
            };
            
            // Send the QR code to the client
            socket.emit('qr', qr);
            socket.emit('status', 'Please scan the QR code to continue...');
            
            // Set a timeout to clear the QR code after expiration
            setTimeout(() => {
                if (latestQRCodes[clientId] && latestQRCodes[clientId].code === qr) {
                    logger.info(`[DEBUG] QR code expired for ${clientId}`);
                    delete latestQRCodes[clientId];
                    
                    // Notify the client that the QR has expired
                    if (socket.connected) {
                        socket.emit('qr_expired');
                        socket.emit('status', 'QR code expired. Please wait for a new one...');
                    }
                }
            }, 20000); // 20 seconds
        });

        // Handle successful client initialization
        client.on('ready', () => {
            logger.info(`[DEBUG] WhatsApp Client for ${clientId} is ready!`);
            
            // Store the client instance
            clients[clientId] = client;
            
            // Clean up
            delete latestQRCodes[clientId];
            delete initializingSessions[clientId];
            
            // Notify the client
            socket.emit('status', 'Connected to WhatsApp!');
            
            // Send a confirmation that we're ready
            socket.emit('ready');
        });

        // Handle authentication failures
        client.on('auth_failure', (msg) => {
            const errorMsg = `Authentication failed: ${msg || 'Unknown error'}`;
            logger.error(`[DEBUG] Authentication failure for ${clientId}:`, msg);
            
            // Clean up
            if (clients[clientId]) delete clients[clientId];
            delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
            
            // Notify the client
            socket.emit('status', errorMsg);
            socket.emit('auth_failure', errorMsg);
            
            // Clean up session directory to force fresh login
            const sessionDir = path.join(config.paths.session, clientId);
            try {
                if (fs.existsSync(sessionDir)) {
                    fs.rmSync(sessionDir, { recursive: true, force: true });
                    logger.info(`[DEBUG] Cleared session directory after auth failure for ${clientId}`);
                }
            } catch (err) {
                logger.error(`[DEBUG] Error clearing session directory:`, err);
            }
        });

        // Handle disconnection
        client.on('disconnected', (reason) => {
            logger.warn(`[DEBUG] Client for ${clientId} was disconnected: ${reason}`);
            
            // Clean up
            if (clients[clientId]) delete clients[clientId];
            delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
            
            // Notify the client
            socket.emit('status', 'Disconnected from WhatsApp. Please refresh and log in again.');
            socket.emit('disconnected', reason);
            
            // Clean up session directory if needed
            if (reason === 'NAVIGATION' || reason === 'CONFLICT') {
                const sessionDir = path.join(config.paths.session, clientId);
                try {
                    if (fs.existsSync(sessionDir)) {
                        fs.rmSync(sessionDir, { recursive: true, force: true });
                        logger.info(`[DEBUG] Cleared session directory after ${reason} for ${clientId}`);
                    }
                } catch (err) {
                    logger.error(`[DEBUG] Error clearing session directory:`, err);
                }
            }
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

        // Handle initialization with proper cleanup
        try {
            await client.initialize();
            
            // Clear the initialization timeout on success
            clearTimeout(initTimeout);
            
            // Add a ping mechanism to detect dead connections
            const pingInterval = setInterval(() => {
                if (!client.info) {
                    clearInterval(pingInterval);
                    return;
                }
                client.getState().catch(err => {
                    logger.error(`[DEBUG] Connection check failed for ${clientId}:`, err);
                    clearInterval(pingInterval);
                    client.destroy().catch(e => logger.error('Error destroying client after ping failure:', e));
                    delete clients[clientId];
                    socket.emit('disconnected', 'Connection lost');
                });
            }, 30000); // Check every 30 seconds
            
            // Clean up on client destruction
            client.on('destroy', () => {
                clearInterval(pingInterval);
                clearTimeout(initTimeout);
                delete clients[clientId];
                delete initializingSessions[clientId];
                delete latestQRCodes[clientId];
            });
            
        } catch (err) {
            // Clear the timeout on error
            clearTimeout(initTimeout);
            
            // Handle Puppeteer/Chromium launch errors with cleanup and retry
            const errorMessage = String(err);
            const isPuppeteerError = errorMessage.includes('Failed to launch the browser process') || 
                                   errorMessage.includes('ProcessSingleton') ||
                                   errorMessage.includes('Navigation timeout');
            
            if (!isRetry && isPuppeteerError) {
                logger.error(`[DEBUG] Puppeteer error for ${clientId}, cleaning up and retrying:`, err);
                
                // Kill orphaned Chromium processes before deleting session dir
                killChromiumProcesses();
                
                // Clean up session directory
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
            
            // Clean up any remaining resources
            delete initializingSessions[clientId];
            delete latestQRCodes[clientId];
            
            // Try to destroy the client if it exists
            if (client) {
                try {
                    await client.destroy();
                } catch (e) {
                    logger.error(`[DEBUG] Error destroying client after initialization failure:`, e);
                } finally {
                    delete clients[clientId];
                }
            }
            
            // Notify the client with a user-friendly message
            let userFriendlyMessage = 'Failed to connect to WhatsApp. Please try again later.';
            if (errorMessage.includes('timeout') || errorMessage.includes('Navigation timeout')) {
                userFriendlyMessage = 'Connection timed out. Please check your internet connection and try again.';
            } else if (errorMessage.includes('Failed to launch browser') || errorMessage.includes('ProcessSingleton')) {
                userFriendlyMessage = 'Could not start browser. The system may be busy. Please try again in a moment.';
            }
            
            socket.emit('status', userFriendlyMessage);
            socket.emit('error', { 
                code: 'INIT_FAILED', 
                message: errorMessage,
                retryable: false
            });
            
            // Clean up session directory to force fresh login on next attempt
            const sessionDir = path.join(config.paths.session, clientId);
            try {
                if (fs.existsSync(sessionDir)) {
                    fs.rmSync(sessionDir, { recursive: true, force: true });
                    logger.info(`[DEBUG] Cleared session directory after initialization failure for ${clientId}`);
                }
            } catch (e) {
                logger.error(`[DEBUG] Error cleaning up session directory:`, e);
            }
        }
    } catch (err) {
        logger.error(`[DEBUG] Failed to initialize client for ${clientId}:`, err);
        socket.emit('status', 'Could not start WhatsApp session. Please try again in a few seconds.');
        delete initializingSessions[clientId];
        delete latestQRCodes[clientId];
    }
}

// ... (rest of the code remains the same)
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
