// to run this file: node server.js

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
const port = 3001;

// middleware
app.use(cors());
app.use(express.json());

// database connection
const db = new sqlite3.Database('database_copy.db', sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to database.');
    }
});

// API endpoint to get all users
app.get('/users', (req, res) => {
    const query = 'SELECT userID, username, password FROM User';
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            res.status(500).json({error: 'Failed to fetch users'});
        } else {
            res.json(rows)
        }
    });
});

app.listen(port, () => {
    console.log(`Backend running at http://localhost:${port}`);
});
