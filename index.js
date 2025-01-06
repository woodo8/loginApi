const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 8080;

const cors = require('cors');
app.use(cors());

// Middleware
app.use(bodyParser.json());

// Path to the JSON file
const USERS_FILE = path.join(__dirname, 'users.json');

// Secret key for JWT
const JWT_SECRET = 'your_secret_key_here';

// Function to read users from the file
const readUsersFromFile = () => {
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        return []; // Return an empty array if file doesn't exist or can't be read
    }
};

// Function to write users to the file
const writeUsersToFile = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

// Check API route
app.get('/', (req, res) => {
    res.status(200).json({ message: 'API is working!' });
});

// Signup endpoint
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const users = readUsersFromFile();

    // Check if user already exists
    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the new user
    users.push({ username, password: hashedPassword });
    writeUsersToFile(users);

    return res.status(201).json({ message: 'User created successfully' });
});

// Signin endpoint
app.post('/signin', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const users = readUsersFromFile();

    // Find user
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Generate JWT
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });

    return res.status(200).json({ message: 'Login successful', token });
});

// Protected route
app.get('/protected', (req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.status(200).json({ message: 'Welcome to the protected route', user: decoded });
    } catch (err) {
        res.status(401).json({ message: 'Invalid or expired token' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
