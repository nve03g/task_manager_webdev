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

        // decode the token to retrieve user details
        const decoded = jwt.verify(token, JWT_SECRET_KEY);
        req.user = { id: decoded.id, username: decoded.username }; // attach user info to the request object

        next(); // proceed if the token is valid
    } catch (err) {
        console.error('Token verification failed:', err.message);
        res.status(401).json({ error: 'Invalid token.' });
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
            db.get(query, [username], (err, row) => { // use parametrized statement to prevent SQL injection
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

// API endpoint to sign up new user
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        // check if user already exists
        const existingUser = await new Promise((resolve, reject) => {
            const query = 'SELECT * FROM User WHERE username = ?';
            db.get(query, [username], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists.' });
        }

        // hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // insert new user into database
        await new Promise((resolve, reject) => {
            const query = 'INSERT INTO User (username, password) VALUES (?,?)';
            db.run(query, [username, hashedPassword], function (err) {
                if (err) reject(err);
                resolve();
            });
        });

        // respond with success message
        res.status(201).json({ message: 'User created successfully.' });
    } catch (error) {
        console.error('Error during signup:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API endpoint to make new project
app.post('/projects', async (req, res) => {
    const { title } = req.body;
    const userID = req.user.id; // extracted from the token via middleware

    // validate input
    if (!title) {
        return res.status(400).json({ error: 'Project title is required.' });
    }

    try {
        // start transaction
        // a transaction is a sequence of one or more database operations that are executed as a single unit => either all operations within the transaction are completed or none of them are applied (transaction rollback)
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // insert new project into Project table
        const projectID = await new Promise((resolve, reject) => {
            const query = 'INSERT INTO Project (title) VALUES (?)';
            db.run(query, [title], function (err) {
                if (err) reject(err);
                else resolve(this.lastID); // get new project ID
            });
        });

        // link project to its creator in the Project_User table
        await new Promise((resolve, reject) => {
            const query = 'INSERT INTO Project_User (projectID, userID, role) VALUES (?, ?, ?)';
            db.run(query, [projectID, userID, 'admin'], (err) => { // set project creator to 'admin' role
                if (err) reject(err);
                else resolve();
            });
        });

        // commit transaction
        await new Promise((resolve, reject) => {
            db.run('COMMIT;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        res.status(201).json({ message: 'Project created successfully.', projectID });
    } catch (error) {
        console.error('Error creating project:', error.message);

        // rollback transaction on failure
        await new Promise((resolve, reject) => {
            db.run('ROLLBACK;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API endpoint to assign a user to a project
app.post('/projects/:projectId/assign-user', async (req, res) => {
    const { projectId } = req.params;
    const { userId, role } = req.body;
    const requestingUserId = req.user.id; // user attached to request by middleware

    // validate inputs
    if (!projectId || !userId || !role) {
        return res.status(400).json({ error: 'Project ID, user ID and role are required.' });
    }
    if (!['admin', 'general'].includes(role)) {
        return res.status(400).json({ error: 'Role must be either "admin" or "general".' });
    }

    try {
        // verify that the requesting user is an admin in the project
        const isAdminQuery = `SELECT role FROM Project_User WHERE projectID = ? AND userID = ? AND role = 'admin'`;
        const isAdmin = await new Promise((resolve, reject) => {
            db.get(isAdminQuery, [projectId, requestingUserId], (err, row) => {
                if (err) reject(err);
                resolve(row ? true : false);
            });
        });

        if (!isAdmin) {
            return res.status(403).json({ error: 'Only administrators can assign users to this project.' });
        }

        // check if user is already assigned to project
        const checkUserQuery = `SELECT * FROM Project_User WHERE projectID = ? AND userID = ?`;
        const existingAssignment = await new Promise((resolve, reject) => {
            db.get(checkUserQuery, [projectId, userId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingAssignment) { // user already assigned
            // update user role
            const updateRoleQuery = `UPDATE Project_User SET role = ? WHERE projectID = ? AND userID = ?`;
            await new Promise((resolve, reject) => {
                db.run(updateRoleQuery, [role, projectId, userId], (err) => {
                    if (err) reject(err);
                    resolve();
                });
            });

            return res.status(200).json({message: 'User role updated successfully.'});
        } else { // user is not yet assigned
            // insert new assigned user
            const insertQuery = `INSERT INTO Project_User (projectID, userID, role) VALUES (?,?,?)`;
            await new Promise((resolve, reject)=>{
                db.run(insertQuery, [projectId, userId, role], (err)=>{
                    if (err) reject(err);
                    resolve();
                });
            });

            return res.status(201).json({message: 'User assigned to project successfully.'});
        }
    } catch (error) {
        console.error('Error assigning user to project:', error.message);
        res.status(500).json({error: 'Internal server error.'});
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
