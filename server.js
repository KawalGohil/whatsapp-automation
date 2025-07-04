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
    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    addUser(username, password, (err, user) => {
        if (err) {
            if (err.code === 'SQLITE_CONSTRAINT') {
                return res.status(409).send('Username already exists.');
            }
            logger.error('Error registering user:', err);
            return res.status(500).send('Error registering user.');
        }
        // Log the user in automatically after registration
        req.session.user = { id: user.id, username: username };
        res.status(201).send({ message: 'User registered successfully.' });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    findUser(username, password, (err, user) => {
        if (err) {
            logger.error('Error finding user:', err);
            return res.status(500).send('Server error during login.');
        }
        if (!user) {
            return res.status(401).send('Invalid username or password.');
        }
        req.session.user = { id: user.id, username: user.username };
        res.status(200).send({ message: 'Login successful.' });
    });
});

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

async function initializeClient(clientId, socket) {
    logger.info(`Initialization request for session: ${clientId}`);

    // If a client for this session already exists, destroy it to ensure a clean start
    if (clients[clientId]) {
        logger.warn(`An existing client for session ${clientId} was found. Destroying it before re-initializing.`);
        try {
            await clients[clientId].destroy();
            logger.info(`Successfully destroyed old client for ${clientId}.`);
        } catch (e) {
            logger.error(`Error destroying old client for ${clientId}:`, e);
        }
        delete clients[clientId];
    }

    // If another request is already initializing this session, tell the user to wait.
    if (initializingSessions[clientId]) {
        logger.info(`Session for ${clientId} is already initializing. Notifying client to wait.`);
        socket.emit('status', 'Please wait while we prepare your session...');
        return;
    }

    try {
        initializingSessions[clientId] = true;
        logger.info(`Initializing new WhatsApp client for session: ${clientId}`);

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

        client.on('qr', (qr) => {
            logger.info(`QR code generated for ${clientId}. Sending to client.`);
            socket.emit('qr', qr);
        });

        client.on('ready', () => {
            logger.info(`WhatsApp Client for ${clientId} is ready!`);
            clients[clientId] = client;
            socket.emit('status', 'Client is ready!');
            delete initializingSessions[clientId];
        });

        client.on('auth_failure', (msg) => {
            const errorMsg = `Authentication failed: ${msg}. Please try again.`;
            logger.error(`Authentication failure for ${clientId}: ${msg}`);
            socket.emit('status', errorMsg);
            delete initializingSessions[clientId];
        });

        client.on('disconnected', (reason) => {
            logger.warn(`Client for ${clientId} was disconnected: ${reason}`);
            socket.emit('status', 'Client disconnected. Please refresh and log in again.');
            if (clients[clientId]) delete clients[clientId];
            if (initializingSessions[clientId]) delete initializingSessions[clientId];
        });

        await client.initialize().catch(err => {
            const errorMsg = 'Failed to initialize WhatsApp client. Please try again.';
            logger.error(`Failed to initialize client for ${clientId}:`, err);
            socket.emit('status', errorMsg);
            delete initializingSessions[clientId];
        });
    } catch (err) {
        logger.error(`Failed to initialize client for ${clientId}:`, err);
        socket.emit('status', 'Error: Could not initialize WhatsApp session.');
        delete initializingSessions[clientId];
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
    logger.info(`User '${username}' connected with socket ID: ${socket.id}`);

    // Automatically initialize the client for the logged-in user
    initializeClient(username, socket);

    socket.on('disconnect', () => {
        logger.info(`User with socket ID: ${socket.id} disconnected.`);
    });
});

// --- Routes ---
app.post('/upload', isAuthenticated, upload.single('contacts'), (req, res) => {
    const { groupName } = req.body;
    const contactsFile = req.file;
    const sanitizedClientId = req.session.user.username; // Use username from session

    if (!sanitizedClientId || !clients[sanitizedClientId]) {
        return res.status(400).send('Invalid or inactive session. Please login again.');
    }

    if (!groupName || !contactsFile) {
        return res.status(400).send('Group name and contacts file are required.');
    }

    const contacts = [];
    fs.createReadStream(contactsFile.path)
        .pipe(csv())
        .on('data', (row) => {
            if (row.phone) {
                contacts.push(`${row.phone}@c.us`);
            }
        })
        .on('end', async () => {
            fs.unlinkSync(contactsFile.path);

            if (contacts.length === 0) {
                const errorMsg = 'No contacts with a \'phone\' column found in the CSV.';
                logger.error(errorMsg);
                return res.status(400).send(errorMsg);
            }

            logger.info(`Creating group '${groupName}' for session ${sanitizedClientId}.`);

            try {
                await createGroup(clients[sanitizedClientId], groupName, contacts);
                res.send('Group creation process started.');
            } catch (error) {
                const errorMsg = `Failed to create group: ${error.message}`;
                logger.error(errorMsg);
                if (!res.headersSent) {
                    res.status(500).send(errorMsg);
                }
            }
        });
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
