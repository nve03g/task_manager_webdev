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
const db = new sqlite3.Database('database.db', sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to database.');
    }
});

// helper function to format the date as DD/MM/YYYY (in database default YYYY-MM-DD)
const formatDate = (isoDate) => {
    const [year, month, day] = isoDate.split('-');
    return `${day}/${month}/${year}`;
};





// **********---------------------- FUNCTIONAL ENDPOINTS ----------------------**********

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

        // respond with the token and user data
        res.status(200).json({ message: 'Login successful.', token, user });
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

// API endpoint to make new project, while also assigning users and their roles
app.post('/projects', async (req, res) => {
    const { title, description, users } = req.body; // `users` is an array of objects: { userId, role }
    const creatorId = req.user.id; // extracted from token via middleware

    // validate input
    if (!title) {
        return res.status(400).json({ error: 'Project title is required.' });
    }
    if (users && !Array.isArray(users)) {
        return res.status(400).json({ error: 'Users must be an array.' });
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

        // insert new project
        const projectId = await new Promise((resolve, reject) => {
            const query = `INSERT INTO Project (title, description, createdBy, creationDate) VALUES (?, ?, ?, DATE('now'))`;
            db.run(query, [title, description, creatorId], function (err) {
                if (err) reject(err);
                else resolve(this.lastID); // get new project ID
            });
        });

        // assign the creator as an admin
        await new Promise((resolve, reject) => {
            const query = 'INSERT INTO Project_User (projectID, userID, role) VALUES (?, ?, ?)';
            db.run(query, [projectId, creatorId, 'admin'], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // assign additional users if provided
        if (users) {
            for (const { userId, role } of users) {
                // validate role
                if (!['admin', 'general'].includes(role)) {
                    throw new Error(`Invalid role for user ${userId}.`);
                }

                await new Promise((resolve, reject) => {
                    const query = 'INSERT INTO Project_User (projectID, userID, role) VALUES (?, ?, ?)';
                    db.run(query, [projectId, userId, role], (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            }
        }

        // commit transaction
        await new Promise((resolve, reject) => {
            db.run('COMMIT;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // fetch the created project to include the formatted creation date
        const project = await new Promise((resolve, reject) => {
            const query = `SELECT projectID, title, description, createdBy, strftime('%Y-%m-%d', creationDate) AS creationDate FROM Project WHERE projectID = ?`;
            db.get(query, [projectId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        project.creationDate = formatDate(project.creationDate); // format the date

        res.status(201).json({ message: 'Project created successfully.', project });
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

// API endpoint to edit/update project details (title, assigned users and their roles)
app.put('/projects/:projectId', async (req, res) => {
    const { projectId } = req.params;
    const { title, description, users } = req.body; // `users` is an array of objects: { userId, role }
    const requestingUserId = req.user.id; // extracted from token via middleware

    // validate input
    if (!title && !description && !users) {
        return res.status(400).json({ error: 'Either title, description, or users must be provided for update.' });
    }
    if (users && !Array.isArray(users)) {
        return res.status(400).json({ error: 'Users must be an array.' });
    }

    try {
        // verify the requesting user is an admin in the project
        const isAdminQuery = `SELECT role FROM Project_User WHERE projectID = ? AND userID = ? AND role = 'admin'`;
        const isAdmin = await new Promise((resolve, reject) => {
            db.get(isAdminQuery, [projectId, requestingUserId], (err, row) => {
                if (err) reject(err);
                resolve(row ? true : false);
            });
        });

        if (!isAdmin) {
            return res.status(403).json({ error: 'Only administrators can update project details.' });
        }

        // fetch the `createdBy` user for the project (this user must remain admin in the project, and cannot change its role)
        const createdByQuery = `SELECT createdBy FROM Project WHERE projectID = ?`;
        const createdBy = await new Promise((resolve, reject) => {
            db.get(createdByQuery, [projectId], (err, row) => {
                if (err) reject(err);
                resolve(row.createdBy);
            });
        });

        // start transaction
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // update project title if provided
        if (title) {
            const updateTitleQuery = 'UPDATE Project SET title = ? WHERE projectID = ?';
            await new Promise((resolve, reject) => {
                db.run(updateTitleQuery, [title, projectId], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }

        // update project description if provided
        if (description) {
            const updateTitleQuery = 'UPDATE Project SET description = ? WHERE projectID = ?';
            await new Promise((resolve, reject) => {
                db.run(updateTitleQuery, [description, projectId], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }

        // update users if provided
        const warnings = [] // for collecting invalid operations warnings
        if (users) {
            for (const { userId, role } of users) {
                // prevent changes to the role of the original admin (`createdBy`)
                if (userId === createdBy) {
                    // console.log(`Skipping update for original admin userID: ${userId}`);
                    warnings.push(`Cannot modify the role of the original admin (userID: ${userId}).`);
                    continue; // skip any updates for this user (AKA the original admin)
                }

                // validate role
                if (!['admin', 'general'].includes(role)) {
                    warnings.push(`Invalid role for user ${userId}.`);
                    continue; // skip this user but continue processing others
                }

                try {
                    // check if user is already assigned to the project
                    const checkUserQuery = `SELECT * FROM Project_User WHERE projectID = ? AND userID = ?`;
                    const existingUser = await new Promise((resolve, reject) => {
                        db.get(checkUserQuery, [projectId, userId], (err, row) => {
                            if (err) reject(err);
                            resolve(row);
                        });
                    });

                    if (existingUser) {
                        // update the user's role
                        const updateRoleQuery = `UPDATE Project_User SET role = ? WHERE projectID = ? AND userID = ?`;
                        await new Promise((resolve, reject) => {
                            db.run(updateRoleQuery, [role, projectId, userId], (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                        });
                    } else {
                        // assign new user to the project
                        const insertUserQuery = `INSERT INTO Project_User (projectID, userID, role) VALUES (?, ?, ?)`;
                        await new Promise((resolve, reject) => {
                            db.run(insertUserQuery, [projectId, userId, role], (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                        });
                    }
                } catch (error) {
                    warnings.push('Error updating user ${userId}: ${error.message}');
                }
            }
        }

        // commit transaction
        await new Promise((resolve, reject) => {
            db.run('COMMIT;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // fetch the updated project and include formatted creation date
        const updatedProject = await new Promise((resolve, reject) => {
            const query = `SELECT projectID, title, description, createdBy, strftime('%Y-%m-%d', creationDate) AS creationDate FROM Project WHERE projectID = ?`;
            db.get(query, [projectId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        updatedProject.creationDate = formatDate(updatedProject.creationDate); // format the date

        // send response with warnings (if they exist)
        if (warnings.length > 0) {
            return res.status(200).json({ message: 'Project updated with warnings.', warnings, updatedProject });
        } else {
            return res.status(200).json({ message: 'Project updated successfully.', updatedProject });
        }
    } catch (error) {
        console.error('Error updating project:', error.message);

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

// API endpoint to delete users from a project (except from original admin)
app.delete('/projects/:projectId/users/:userId', async (req, res) => {
    const { projectId, userId } = req.params;
    const requestingUserId = req.user.id; // extracted from token via middleware

    try {
        // verify the requesting user is an admin in the project
        const isAdminQuery = `SELECT role FROM Project_User WHERE projectID = ? AND userID = ? AND role = 'admin'`;
        const isAdmin = await new Promise((resolve, reject) => {
            db.get(isAdminQuery, [projectId, requestingUserId], (err, row) => {
                if (err) reject(err);
                resolve(row ? true : false);
            });
        });

        if (!isAdmin) {
            return res.status(403).json({ error: 'Only administrators can delete users from a project.' });
        }

        // fetch the `createdBy` user for the project
        const createdByQuery = `SELECT createdBy FROM Project WHERE projectID = ?`;
        const createdBy = await new Promise((resolve, reject) => {
            db.get(createdByQuery, [projectId], (err, row) => {
                if (err) reject(err);
                resolve(row.createdBy);
            });
        });

        // prevent deletion of the original admin
        if (parseInt(userId, 10) === createdBy) {
            return res.status(400).json({ error: 'Cannot delete the original admin of the project.' });
        }

        // check if the user is part of the project
        const userExistsQuery = `SELECT * FROM Project_User WHERE projectID = ? AND userID = ?`;
        const userExists = await new Promise((resolve, reject) => {
            db.get(userExistsQuery, [projectId, userId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!userExists) {
            return res.status(404).json({ error: 'User is not part of this project.' });
        }

        // start transaction
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // delete the user from the project
        const deleteUserQuery = `DELETE FROM Project_User WHERE projectID = ? AND userID = ?`;
        await new Promise((resolve, reject) => {
            db.run(deleteUserQuery, [projectId, userId], (err) => {
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

        res.status(200).json({ message: 'User deleted from project successfully.' });
    } catch (error) {
        console.error('Error deleting user from project:', error.message);

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

// API endpoint to delete a project and all its dependencies
app.delete('/projects/:projectId', async (req, res) => {
    const { projectId } = req.params;
    const requestingUserId = req.user.id; // extracted from token via middleware

    try {
        // check if the project exists
        const projectExistsQuery = `SELECT * FROM Project WHERE projectID = ?`;
        const projectExists = await new Promise((resolve, reject) => {
            db.get(projectExistsQuery, [projectId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!projectExists) {
            return res.status(404).json({ error: 'Project not found.' });
        }

        // verify the requesting user is an admin in the project
        const isAdminQuery = `SELECT role FROM Project_User WHERE projectID = ? AND userID = ? AND role = 'admin'`;
        const isAdmin = await new Promise((resolve, reject) => {
            db.get(isAdminQuery, [projectId, requestingUserId], (err, row) => {
                if (err) reject(err);
                resolve(row ? true : false);
            });
        });

        if (!isAdmin) {
            return res.status(403).json({ error: 'Only administrators can delete the project.' });
        }

        // start transaction
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // delete task-user assignments
        const deleteTaskUserQuery = `DELETE FROM Task_User WHERE taskID IN (SELECT taskID FROM Task WHERE projectID = ?)`;
        await new Promise((resolve, reject) => {
            db.run(deleteTaskUserQuery, [projectId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // delete tasks
        const deleteTasksQuery = `DELETE FROM Task WHERE projectID = ?`;
        await new Promise((resolve, reject) => {
            db.run(deleteTasksQuery, [projectId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // delete project-user assignments
        const deleteProjectUserQuery = `DELETE FROM Project_User WHERE projectID = ?`;
        await new Promise((resolve, reject) => {
            db.run(deleteProjectUserQuery, [projectId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // delete the project itself
        const deleteProjectQuery = `DELETE FROM Project WHERE projectID = ?`;
        await new Promise((resolve, reject) => {
            db.run(deleteProjectQuery, [projectId], (err) => {
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

        res.status(200).json({ message: 'Project and all its dependencies deleted successfully.' });
    } catch (error) {
        console.error('Error deleting project:', error.message);

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

// API endpoint to add a task to a project
app.post('/projects/:projectId/tasks', async (req, res) => {
    const { projectId } = req.params;
    const { name, status, assignedUserIds, description } = req.body;
    const token = req.headers.authorization?.split(' ')[1];
    const decodedToken = jwt.verify(token, JWT_SECRET_KEY);
    const currentUserId = decodedToken.id;

    // validate input
    if (!name || !status) {
        return res.status(400).json({ error: 'Task name and status are required.' });
    }

    // validate assigned status
    const allowedStatuses = ["in progress", "A", "B"]; // CHANGE THESE
    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({ error: `Invalid status. Allowed values are: ${allowedStatuses.join(", ")}.` });
    }

    // validate assigned user(s)
    if (!assignedUserIds || !Array.isArray(assignedUserIds) || assignedUserIds.length === 0) {
        return res.status(400).json({ error: 'At least one user must be assigned to the task.' });
    }

    try {
        // check if the project exists
        const projectExists = await new Promise((resolve, reject) => {
            const query = 'SELECT * FROM Project WHERE projectID = ?';
            db.get(query, [projectId], (err, row) => {
                if (err) reject(err);
                resolve(!!row); // '!!': force to boolean value
            });
        });

        if (!projectExists) {
            return res.status(404).json({ error: 'Project not found.' });
        }

        // check if current user is an admin in the project
        const isAdmin = await new Promise((resolve, reject) => {
            const query = 'SELECT role FROM Project_User WHERE projectID = ? AND userID = ? AND role = ?';
            db.get(query, [projectId, currentUserId, 'admin'], (err, row) => {
                if (err) reject(err);
                resolve(!!row);
            });
        });

        if (!isAdmin) {
            return res.status(403).json({ error: 'You must be an administrator in this project to add tasks.' });
        }

        // insert the task into the database
        const newTaskId = await new Promise((resolve, reject) => {
            const query = `INSERT INTO Task (name, status, description, creationDate, createdBy, projectID) VALUES (?, ?, ?, DATE('now'), ?, ?)`;
            db.run(query, [name, status, description, currentUserId, projectId], function (err) {
                if (err) reject(err);
                resolve(this.lastID); // get the ID of the newly created task
            });
        });

        // check and add assigned users to the project if necessary
        const ensureUsersAddedToProject = assignedUserIds.map((assignedUserId) => {
            return new Promise((resolve, reject) => {
                const checkQuery = 'SELECT * FROM Project_User WHERE projectID = ? AND userID = ?';
                db.get(checkQuery, [projectId, assignedUserId], (err, row) => {
                    if (err) return reject(err);

                    if (!row) {
                        // if user is not yet assigned to project, add the user to the project as 'general'
                        const addQuery = 'INSERT INTO Project_User (projectID, userID, role) VALUES (?, ?, ?)';
                        db.run(addQuery, [projectId, assignedUserId, 'general'], (err) => {
                            if (err) return reject(err);
                            resolve();
                        });
                    } else {
                        resolve(); // user is already in the project
                    }
                });
            });
        });

        await Promise.all(ensureUsersAddedToProject);

        // assign user(s) to the new task
        const assignPromises = assignedUserIds.map((assignedUserId) => {
            return new Promise((resolve, reject) => {
                const query = 'INSERT INTO Task_User (taskID, userID) VALUES (?,?)';
                db.run(query, [newTaskId, assignedUserId], (err) => {
                    if (err) reject(err);
                    resolve();
                });
            });
        });

        await Promise.all(assignPromises);

        // fetch the created task to include the formatted creation date
        const task = await new Promise((resolve, reject) => {
            const query = `SELECT taskID, name, status, description, projectID, createdBy, strftime('%Y-%m-%d', creationDate) AS creationDate FROM Task WHERE taskID = ?`;
            db.get(query, [newTaskId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        task.creationDate = formatDate(task.creationDate); // format the date

        res.status(201).json({ message: 'Task created successfully.', task });
    } catch (error) {
        console.error('Error adding task:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API endpoint to edit/update task details (name, status, description)
app.put('/projects/:projectId/tasks/:taskId', async (req, res) => {
    const { projectId, taskId } = req.params;
    const { name, status, description } = req.body;
    const requestingUserId = req.user.id; // user attached to request by middleware

    // validate input
    if (!name && !status && !description) {
        return res.status(400).json({ error: 'At least one field must be provided to update task.' });
    }

    try {
        // check if the task exists in the project
        const taskQuery = `SELECT * FROM Task WHERE taskID = ? AND projectID = ?`;
        const task = await new Promise((resolve, reject) => {
            db.get(taskQuery, [taskId, projectId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!task) {
            return res.status(404).json({ error: 'Task not found in this project.' });
        }

        // check if the user is an admin in the project
        const isAdminQuery = `SELECT role FROM Project_User WHERE projectID = ? AND userID = ? AND role = 'admin'`;
        const isAdmin = await new Promise((resolve, reject) => {
            db.get(isAdminQuery, [projectId, requestingUserId], (err, row) => {
                if (err) reject(err);
                resolve(!!row);
            });
        });

        // check if the user is assigned to the task
        const isAssignedQuery = `SELECT * FROM Task_User WHERE taskID = ? AND userID = ?`;
        const isAssigned = await new Promise((resolve, reject) => {
            db.get(isAssignedQuery, [taskId, requestingUserId], (err, row) => {
                if (err) reject(err);
                resolve(!!row);
            });
        });

        // authorization: only admins or assigned users can update the task
        if (!isAdmin && !(isAssigned && status && !name)) {
            return res.status(403).json({
                error: 'Only administrators or assigned users can update the task. Assigned users can only update the status.',
            });
        }

        // if a non-admin user tries to update the name, reject the request
        if (!isAdmin && name) {
            return res.status(403).json({ error: 'Only administrators can update task name.' });
        }

        // build update query dynamically, based on provided fields
        const fieldsToUpdate = [];
        const values = [];
        if (name) {
            fieldsToUpdate.push('name = ?');
            values.push(name);
        }
        if (status) {
            const validStatuses = ['pending', 'in progress', 'completed']; // CHECK THIS: welke statussen?
            if (!validStatuses.includes(status)) {
                return res.status(400).json({ error: 'Invalid task status.' });
            }
            fieldsToUpdate.push('status = ?');
            values.push(status);
        }
        if (description) {
            fieldsToUpdate.push('description = ?');
            values.push(description);
        }
        values.push(taskId);

        const updateQuery = `UPDATE Task SET ${fieldsToUpdate.join(', ')} WHERE taskID = ?`;
        await new Promise((resolve, reject) => {
            db.run(updateQuery, values, (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        // fetch the created task to include the formatted creation date
        const updatedTask = await new Promise((resolve, reject) => {
            const query = `SELECT taskID, name, status, description, projectID, createdBy, strftime('%Y-%m-%d', creationDate) AS creationDate FROM Task WHERE taskID = ?`;
            db.get(query, [taskId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        updatedTask.creationDate = formatDate(updatedTask.creationDate); // format the date

        res.status(200).json({ message: 'Task updated successfully.', updatedTask });
    } catch (error) {
        console.error('Error updating task:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API endpoint to delete user from a task
app.delete('/tasks/:taskId/users/:userId', async (req, res) => {
    const { taskId, userId } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    const decodedToken = jwt.verify(token, JWT_SECRET_KEY);
    const currentUserId = decodedToken.id;

    try {
        // check if the task exists
        const taskExists = await new Promise((resolve, reject) => {
            const query = 'SELECT * FROM Task WHERE taskID = ?';
            db.get(query, [taskId], (err, row) => {
                if (err) reject(err);
                resolve(!!row);
            });
        });

        if (!taskExists) {
            return res.status(404).json({ error: 'Task not found.' });
        }

        // check if the current user is an admin in the project
        const projectIdQuery = `SELECT projectID FROM Task WHERE taskID = ?`;
        const projectId = await new Promise((resolve, reject) => {
            db.get(projectIdQuery, [taskId], (err, row) => {
                if (err) reject(err);
                resolve(row.projectID);
            });
        });

        const isAdmin = await new Promise((resolve, reject) => {
            const query = `SELECT role FROM Project_User WHERE projectID = ? AND userID = ? AND role = 'admin'`;
            db.get(query, [projectId, currentUserId], (err, row) => {
                if (err) reject(err);
                resolve(!!row);
            });
        });

        if (!isAdmin) {
            return res.status(403).json({ error: 'Only administrators can remove users from a task.' });
        }

        // check if the user is assigned to the task
        const userAssigned = await new Promise((resolve, reject) => {
            const query = `SELECT * FROM Task_User WHERE taskID = ? AND userID = ?`;
            db.get(query, [taskId, userId], (err, row) => {
                if (err) reject(err);
                resolve(!!row);
            });
        });

        if (!userAssigned) {
            return res.status(404).json({ error: 'User is not assigned to this task.' });
        }

        // ensure the task will still have at least one assigned user after removal
        const remainingUsersCount = await new Promise((resolve, reject) => {
            const query = `SELECT COUNT(*) AS userCount FROM Task_User WHERE taskID = ?`;
            db.get(query, [taskId], (err, row) => {
                if (err) reject(err);
                resolve(row.userCount);
            });
        });

        if (remainingUsersCount <= 1) {
            return res.status(400).json({ error: 'Cannot remove the last user assigned to the task. Assign another user first.' });
        }

        // Remove the user from the task
        await new Promise((resolve, reject) => {
            const query = `DELETE FROM Task_User WHERE taskID = ? AND userID = ?`;
            db.run(query, [taskId, userId], (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        res.status(200).json({ message: 'User removed from task successfully.' });
    } catch (error) {
        console.error('Error removing user from task:', error.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API endpoint to delete task from project
app.delete('/projects/:projectId/tasks/:taskId', async (req, res) => {
    const { projectId, taskId } = req.params;
    const requestingUserId = req.user.id; // user attached to request by middleware

    try {
        // check if the task exists in the project
        const taskBelongsToProjectQuery = `SELECT * FROM Task WHERE taskID = ? AND projectID = ?`;
        const task = await new Promise((resolve, reject) => {
            db.get(taskBelongsToProjectQuery, [taskId, projectId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!task) {
            return res.status(404).json({ error: 'Task not found in this project.' });
        }

        // check if the user is an admin in the project
        const isAdminQuery = `SELECT role FROM Project_User WHERE projectID = ? AND userID = ? AND role = 'admin'`;
        const isAdmin = await new Promise((resolve, reject) => {
            db.get(isAdminQuery, [projectId, requestingUserId], (err, row) => {
                if (err) reject(err);
                resolve(!!row);
            });
        });

        if (!isAdmin) {
            return res.status(403).json({ error: 'Only administrators can delete tasks.' });
        }

        // start transaction
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // delete associated Task_User bonds first
        const deleteTaskUserAssociationsQuery = `DELETE FROM Task_User WHERE taskID = ?`;
        await new Promise((resolve, reject) => {
            db.run(deleteTaskUserAssociationsQuery, [taskId], (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        // delete task from database
        const deleteTaskQuery = `DELETE FROM Task WHERE taskID = ?`;
        await new Promise((resolve, reject) => {
            db.run(deleteTaskQuery, [taskId], (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        // commit transaction
        await new Promise((resolve, reject) => {
            db.run('COMMIT;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        res.status(200).json({ message: 'Task deleted successfully.' });
    } catch (error) {
        console.error('Error deleting task:', error.message);

        // rollback transaction in case of an error
        await new Promise((resolve, reject) => {
            db.run('ROLLBACK;', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        res.status(500).json({ error: 'Internal server error.' });
    }
});


// API endpoint to validate token (used by frontend)
app.post('/validate-token', checkTokenBlacklist, (req, res) => {
    // If the token is valid, the middleware (checkTokenBlacklist) will call `next()` and this handler will be executed
    res.status(200).json({ message: 'Token is valid.', user: req.user, }); // req.user contains { id, username } from the decoded token
});





// **********---------------------- DESIGN ENDPOINTS ----------------------**********
// API endpoint to get all projects for the authenticated user
app.get('/projects', checkTokenBlacklist, async (req, res) => {
    const userId = req.user.id;

    try {
        const query = 'SELECT * FROM Project WHERE createdBy = ? OR projectID IN (SELECT projectID FROM Project_User WHERE userID = ?)'; // user is either the creator of the project or is part of the project
        const projects = await db.all(query, [userId, userId]);

        res.json({ projects });
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// API endpoint to get user specific data (for profile)
app.get('/profile', checkTokenBlacklist, async (req, res) => {
    const userId = req.user.id;

  try {
    // get all projects this user has created
    const createdProjectsQuery = 'SELECT * FROM Project WHERE createdBy = ?';
    const createdProjects = await db.all(createdProjectsQuery, [userId]);

    // get all projects the user is assigned to
    const assignedProjectsQuery = 'SELECT * FROM Project WHERE projectID IN (SELECT projectID FROM Project_User WHERE userID = ?)';
    const assignedProjects = await db.all(assignedProjectsQuery, [userId]);

    // get this user's task count
    const assignedTasksCountQuery = 'SELECT COUNT(*) AS count FROM Task_User WHERE userID = ?';
    const assignedTasksCount = await db.get(assignedTasksCountQuery, [userId]);

    res.json({
      username: req.user.username,
      createdProjects,
      assignedProjects,
      assignedTasksCount: assignedTasksCount.count,
    });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Internal server error.' });
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
