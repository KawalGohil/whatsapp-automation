const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const config = require('./config');

const saltRounds = 10;
const dbPath = config.paths.database;
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        return console.error('Error opening database', err.message);
    }
    console.log('Connected to the SQLite database.');
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);
});

// Function to add a new user with a hashed password
function addUser(username, password, callback) {
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            return callback(err);
        }
        const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
        db.run(sql, [username, hash], function(err) {
            if (err) {
                return callback(err);
            }
            callback(null, { id: this.lastID });
        });
    });
}

// Function to find a user and verify their password
function findUser(username, password, callback) {
    const sql = `SELECT * FROM users WHERE username = ?`;
    db.get(sql, [username], (err, user) => {
        if (err) {
            return callback(err);
        }
        if (!user) {
            return callback(null, null); // User not found
        }
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                return callback(err);
            }
            if (result) {
                callback(null, user); // Passwords match
            } else {
                callback(null, null); // Passwords don't match
            }
        });
    });
}

module.exports = { addUser, findUser, db };
