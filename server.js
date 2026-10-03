/**
 * server.js - Comprehensive Node.js and Express Backend Server
 * 
 * This file serves as the core entry point for the backend application,
 * responsible for handling incoming HTTP requests, managing middleware,
 * enforcing security practices, processing authentication logic, and 
 * interfacing with a secure database layer.
 */

const express = require('express');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. Security and Request Parsing Middleware
// ==========================================

// Helmet helps secure Express apps by setting various HTTP headers
app.use(helmet());

// Enable Cross-Origin Resource Sharing with restricted policies if needed
app.use(cors({
    origin: 'http://localhost:3000',
    optionsSuccessStatus: 200
}));

// Parse incoming JSON payloads and URL-encoded form data safely
app.use(express.json({ limit: '10kb' })); // Limit payload size to prevent DOS
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ==========================================
// 2. Database Simulation / Data Layer
// ==========================================
// In a production environment, replace this array with a robust database 
// connection (e.g., PostgreSQL, MongoDB, MySQL via ORM/ODM like Mongoose or Sequelize).
const userDatabase = [];

// ==========================================
// 3. API Endpoints & Route Handlers
// ==========================================

/**
 * Health Check Endpoint
 * Used to verify that the server is online and operational.
 */
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP', timestamp: new Date().toISOString() });
});

/**
 * User Registration Endpoint
 * Handles new account creation, password hashing, and storage.
 */
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Rigorous server-side input validation
        if (!username || typeof username !== 'string' || username.trim().length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters long.' });
        }

        if (!password || typeof password !== 'string' || password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
        }

        // Check if user already exists
        const existingUser = userDatabase.find(u => u.username === username.trim());
        if (existingUser) {
            return res.status(409).json({ error: 'Username is already taken.' });
        }

        // Generate a secure salt and hash the password using bcrypt
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Store user securely
        const newUser = {
            id: Date.now().toString(),
            username: username.trim(),
            passwordHash,
            createdAt: new Date().toISOString()
        };

        userDatabase.push(newUser);

        return res.status(201).json({ message: 'User registered successfully.' });

    } catch (error) {
        console.error('Registration Error:', error);
        return res.status(500).json({ error: 'Internal server error during registration.' });
    }
});

/**
 * User Login Endpoint
 * Verifies user credentials against stored secure hashes.
 */
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Input validation check
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required fields.' });
        }

        // Locate user in the database
        const user = userDatabase.find(u => u.username === username.trim());
        
        // Use a generic response pattern to prevent username enumeration attacks
        const genericAuthError = 'Invalid username or password.';
        if (!user) {
            return res.status(401).json({ error: genericAuthError });
        }

        // Securely compare the incoming plain-text password with the stored hash
        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: genericAuthError });
        }

        // Authentication successful (Session tokens or JWTs would typically be generated here)
        return res.status(200).json({ 
            message: 'Authentication successful.',
            userId: user.id,
            username: user.username 
        });

    } catch (error) {
        console.error('Login Error:', error);
        return res.status(500).json({ error: 'Internal server error during authentication.' });
    }
});

// ==========================================
// 4. Global Error Handling & Server Startup
// ==========================================

// Catch-all middleware for unhandled routes
app.use((req, res, next) => {
    res.status(404).json({ error: 'Endpoint not found.' });
});

// Global error handler middleware
app.use((err, req, res, next) => {
    console.error('Unhandled Exception:', err.stack);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
});

// Initialize server listening on designated port
app.listen(PORT, () => {
    console.log(`[Server Status] Running securely on http://localhost:${PORT}`);
});
        
