const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const config = require('./config');

const saltRounds = 10;

// Ensure the data directory exists
const ensureDirectoryExists = (filePath) => {
    const dirname = path.dirname(filePath);
    if (fs.existsSync(dirname)) {
        return true;
    }
    try {
        fs.mkdirSync(dirname, { recursive: true });
        console.log(`Created directory: ${dirname}`);
        return true;
    } catch (error) {
        console.error(`Error creating directory ${dirname}:`, error);
        return false;
    }
};

const dbPath = config.paths.database;

// Ensure the directory exists before creating the database
if (!ensureDirectoryExists(dbPath)) {
    console.error('Failed to create database directory. Check permissions.');
    process.exit(1);
}

// Now create or open the database
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        process.exit(1);
    }
    console.log('Connected to the SQLite database at:', dbPath);
    
    // Create users table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        } else {
            console.log('Users table is ready');
        }
    });
});

// Function to add a new user with a hashed password
function addUser(username, password, callback) {
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return callback(err);
        
        const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
        db.run(sql, [username, hash], function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    return callback(new Error('Username already exists'));
                }
                return callback(err);
            }
            callback(null, { id: this.lastID, username });
        });
    });
}

// Function to find a user and verify their password
function findUser(username, password, callback) {
    const sql = 'SELECT * FROM users WHERE username = ?';
    
    db.get(sql, [username], (err, user) => {
        if (err) return callback(err);
        if (!user) return callback(null, null);
        
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) return callback(err);
            if (!result) return callback(null, null);
            
            // Don't send the password hash back
            delete user.password;
            callback(null, user);
        });
    });
}

// Handle database errors
db.on('error', (err) => {
    console.error('Database error:', err);
});

process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing the database:', err.message);
        } else {
            console.log('Database connection closed');
        }
        process.exit(0);
    });
});

module.exports = { addUser, findUser, db };
