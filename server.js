/**
 * server.js - Production-Hardened Express Server
 */

require('dotenv').config(); // Load environment variables from a .env file
const express = require('express');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { z } = require('zod'); // Schema validation

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-dev-secret-change-in-prod';
const NODE_ENV = process.env.NODE_ENV || 'development';

// ==========================================
// 1. Security & Middleware Configuration
// ==========================================

// Set secure HTTP headers
app.use(helmet());

// Cookie parser for reading httpOnly auth cookies
app.use(cookieParser());

// Restrict CORS based on environment configuration
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true,
    optionsSuccessStatus: 200
}));

// Strictly limit request payload sizes
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Global Rate Limiter: Max 100 requests per 15 minutes per IP
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests from this IP, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(globalLimiter);

// Strict Rate Limiter for Auth Routes: Max 5 attempts per 15 minutes
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many authentication attempts. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// ==========================================
// 2. Input Validation Schemas (Zod)
// ==========================================

const registerSchema = z.object({
    username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_]+$/, {
        message: 'Username can only contain alphanumeric characters and underscores.'
    }),
    password: z.string().min(8).max(128).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
        message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number.'
    })
});

const loginSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(1)
});

// ==========================================
// 3. Database Layer Abstraction
// ==========================================

// In production, replace these mock functions with your database driver/ORM queries
const db = {
    async findUserByUsername(username) {
        // Example: return await User.findOne({ username });
        return null;
    },
    async createUser(userData) {
        // Example: return await User.create(userData);
        return userData;
    }
};

// ==========================================
// 4. API Routes
// ==========================================

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP', timestamp: new Date().toISOString() });
});

app.post('/api/register', authLimiter, async (req, res, next) => {
    try {
        // Validate input against schema
        const parseResult = registerSchema.safeParse(req.body);
        if (!parseResult.success) {
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: parseResult.error.issues.map(i => i.message) 
            });
        }

        const { username, password } = parseResult.data;

        const existingUser = await db.findUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ error: 'Username is already taken.' });
        }

        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const newUser = await db.createUser({
            username,
            passwordHash,
            createdAt: new Date().toISOString()
        });

        return res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        next(error);
    }
});

app.post('/api/login', authLimiter, async (req, res, next) => {
    try {
        const parseResult = loginSchema.safeParse(req.body);
        if (!parseResult.success) {
            return res.status(400).json({ error: 'Invalid username or password format.' });
        }

        const { username, password } = parseResult.data;
        const genericAuthError = 'Invalid username or password.';

        const user = await db.findUserByUsername(username);
        if (!user) {
            return res.status(401).json({ error: genericAuthError });
        }

        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: genericAuthError });
        }

        // Issue JWT token stored inside a secure HTTP-Only cookie
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('token', token, {
            httpOnly: true, // Prevents access via client-side JavaScript (XSS protection)
            secure: NODE_ENV === 'production', // Requires HTTPS in production
            sameSite: 'strict', // Protects against CSRF attacks
            maxAge: 3600000 // 1 hour
        });

        return res.status(200).json({ message: 'Authentication successful.' });
    } catch (error) {
        next(error);
    }
});

// ==========================================
// 5. Error Handling Middleware
// ==========================================

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found.' });
});

// Centralized error handler
app.use((err, req, res, next) => {
    console.error(`[Error] ${err.message}`, { stack: NODE_ENV === 'development' ? err.stack : undefined });
    
    res.status(err.status || 500).json({
        error: NODE_ENV === 'production' 
            ? 'An internal server error occurred.' 
            : err.message
    });
});

app.listen(PORT, () => {
    console.log(`[Server Status] Running in ${NODE_ENV} mode on port ${PORT}`);
});
        
