// to run this file: node server.js

const express = require('express');
const app = express();
const port = 3001;

app.get('/', (req, res) => {
    res.send('Hello from the backend!');
});

app.listen(port, () => {
    console.log(`Backend running at http://localhost:${port}`);
});


// ------------------------------------------------------


// // was hiervoor dit:
// const express = require('express');
// const mongoose = require('mongoose');
// const bodyParser = require('body-parser');
// require('dotenv').config();
// const sequelize = require('./config/db');
// const userRoutes = require('./routes/userRoutes');

// const app = express();

// // Middleware
// app.use(bodyParser.json());

// // Routes
// app.use('/api/users', userRoutes);

// // Database connection
// sequelize.sync().then(() => {
//     console.log('Database connected!');
//     app.listen(process.env.PORT || 5000, () => console.log('Server running on port 5000'));
// }).catch((err) => console.error('Error connecting to database:', err));
