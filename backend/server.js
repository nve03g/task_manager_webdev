// to run this file: node server.js

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const bcrypt = require('bcrypt'); // for password hashing
const jwt = require('jsonwebtoken'); // for generating authentication tokens
const { resolve } = require('path');
const { rejects } = require('assert');
const { JWT_SECRET_KEY } = require('./key_config');
const redis = require('redis');

const app = express();
const httpsPort = 443; // Beveiligde HTTPS-poort
const client = redis.createClient();

client.on('error', (err) => {
    console.error('Redis error:', err);
});

// Connect the Redis client
(async () => {
    try {
        await client.connect();
        console.log('Redis client connected');
    } catch (err) {
        console.error('Failed to connect to Redis:', err);
        process.exit(1); // Exit the process if Redis connection fails
    }
})();

// middleware
app.use(cors());
app.use(express.json()); // to parse json
app.use((req, res, next) => { // verkeer naar HTTPS forceren
    if (!req.secure) {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
});
const checkTokenBlacklist = async (req, res, next) => { // middleware to check token validity
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const isBlacklisted = await client.get(token);
        if (isBlacklisted === 'blacklisted') {
            return res.status(401).json({ error: 'Token is blacklisted. Please log in again.' });
        }
        next(); // proceed if the token is valid
    } catch (err) {
        console.error('Redis error in middleware:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
};

// protect all routes except public ones (=> user authorization)
app.use((req, res, next) => {
    const publicRoutes = ['/login', '/signup'];
    if (publicRoutes.includes(req.path)) {
        return next(); // skip middleware for public routes
    }
    return checkTokenBlacklist(req, res, next); // apply middleware to all other routes
});

// database connection
const db = new sqlite3.Database('database.db', sqlite3.OPEN_READWRITE, (err) => { // user: Luc - another_password
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to database.');
    }
});

// API endpoint to get all users - DELETE LATER
app.get('/users', (req, res) => {
    const query = 'SELECT userID, username, password FROM User';
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            res.status(500).json({ error: 'Failed to fetch users' });
        } else {
            res.json(rows)
        }
    });
});

// API endpoint to login user
app.post('/login', async (req, res) => { // use async function for handling database queries or API calls
    // handle user login
    const { username, password } = req.body;

    // validate user input
    if (!username || !password) {
        res.status(400).json({ error: 'Username and password are required.' });
    }
    try {
        // find user in database
        const query = 'SELECT * FROM User WHERE username = ?';
        const user = await new Promise((resolve, reject) => {
            db.get(query, [username], (err, row) => {
                if (err) reject(err); // reject the promise on error
                resolve(row); // fulfill the promise with data
            });
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        // compare passwords
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        // generate token (JWT), used to securely transfer information over the web (ie. between client and server)
        const token = jwt.sign({ id: user.userID, username: user.username }, JWT_SECRET_KEY, { expiresIn: '1h' }); // JWT_SECRET_KEY can be found in the key_config.js file, because it should not be hard-coded in the backend for safety purposes

        // respond with the token
        res.status(200).json({ message: 'Login successful.', token });
    } catch (error) {
        console.error('Error during login:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API endpoint to logout user
app.post('/logout', (req, res) => { // no need to use async function, because no database operations
    /* chosen strategy for user logout: token invalidation (blacklist)
        -> Store issued tokens in a database or in-memory store (e.g., Redis).
        -> Mark tokens as invalid once the user logs out.
        -> During authentication, check if the token is valid (not in the blacklist). 
        used when you want more control (e.g., invalidating tokens server-side)
    */
    const token = req.headers.authorization?.split(' ')[1]; // extract the token from the request header

    if (!token) {
        return res.status(400).json({ error: 'Token missing from request.' });
    }

    // add token to the blacklist with the remaining expiration time
    const decoded = jwt.decode(token);
    if (decoded && decoded.exp) {
        const expiresIn = decoded.exp * 1000 - Date.now();

        // make sure expiresIn is a positive integer
        const expirationInSeconds = Math.floor(expiresIn / 1000); // convert to integer and put in seconds

        if (expirationInSeconds > 0) {
            client.set(token, 'blacklisted', { EX: expirationInSeconds }) // add to Redis with TTL (time to live)
                .catch((err) => {
                    console.error('Error setting blacklisted token:', err);
                });
        } else {
            console.error('Invalid expiration time:', expirationInSeconds);
        }

        return res.status(200).json({ message: 'Logout successful.' });
    } else {
        return res.status(400).json({ error: 'Invalid token.' });
    }
});

// load SSL-certificate files
const options = {
    key: fs.readFileSync('../private-key.pem'), // private key
    cert: fs.readFileSync('../public-cert.pem'), // public certificate
};

// make a secure HTTPS-server
const httpsServer = https.createServer(options, app);

// start the secure server
httpsServer.listen(httpsPort, () => {
    console.log(`Secure server running at https://localhost:${httpsPort}`);
});
