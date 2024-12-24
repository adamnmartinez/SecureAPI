const express = require('express');
const uuid = require('uuid');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const { rateLimit } = require('express-rate-limit');

// Rate Limiter

const register_limiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 5,
    message: {error: "Too many requests", message: "Please try again later"},
	standardHeaders: 'draft-8',
})

const authenticate_limiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 10,
    message: {error: "Too many requests", message: "Please try again later"},
	standardHeaders: 'draft-8',
})

// Input Validation Chains

const createUsernameChain = () => 
    body('username')
        .notEmpty().withMessage('Username cannot be empty.')
        .isString().withMessage('Username must be a string')
        .isLength({min: 3, max: 50}).withMessage('Username must be between 3 and 50 characters.')
        .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores.');

const createPasswordChain = () => 
    body('password')
        .notEmpty().withMessage('Password cannot be empty.')
        .isString().withMessage('Password must be a string')
        .isLength({min: 8, max: 50}).withMessage('Password must be between 8 and 50 characters.')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
        .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter.')
        .matches(/[0-9]/).withMessage('Password must contain at least one number.')
        .matches(/[!@#$%^&*]/).withMessage('Password must contain at least one special character.');

const app = express();

require('dotenv').config();
const PORT = process.env.API_PORT;

// CORS

const corsOptions = {
    origin : process.env.ORIGIN, 
    methods : process.env.ALLOWED_METHODS || "GET,POST",
    credentials : true,
    optionSuccessStatus : 200,
}

// MIDDLEWARE

app.use(cors(corsOptions));
app.use(express.json());
app.use((err, req, res, next) => {
    console.error(`[ERROR] ${err.message}`);
    res.status(500);
    res.json({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred.'
    });
});

// DATABASE

const db = mysql.createPool({
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASS,
    database: process.env.DATABASE,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectTimeout: 60000,
    connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 10,
    keepAliveInitialDelay: 10000,
    enableKeepAlive: true,
})

// METHODS

app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
    db.getConnection((err, connection) => {
        if(err) {
            console.error(err)
            process.exit(1);
        }
        if(connection) {
            connection.release()
        } 
        console.log(`Database Connected.`);
    })
})

app.get('/', (req, res) => {
    return res.json("Server running.");
})

app.post('/register', register_limiter, createUsernameChain(), createPasswordChain(), async (req, res, next) => {
    console.log(`[REGISTER] Registering new user...`)

    // Parse request body.
    const { username } = req.body;
    const { password } = req.body;

    // Get Validation Errors
    const validation = validationResult(req);

    try {
        if (!validation.isEmpty()) {
            console.log("[REGISTER] User could not be created. Bad Request.");
            res.status(400).json({error: "Bad Request", message: `${validation.array()[0].msg}`});
            return;
        }

        // Generate ID and Password Hash
        let id = uuid.v4();
        let hash = await bcrypt.hash(password, 10);

        // Construct SQL Query
        users_sql = `INSERT INTO users (id, username, hash) VALUES (?, ?, ?)`;
        let users_values = [id, username, hash];

        // Query Database
        db.query(users_sql, users_values, (q_err, q_res) => {
            if(q_err) {
                console.log("[REGISTER] User could not be created. Database Error.");
                switch (q_err.errno) {
                    case 1062: 
                        res.status(409).json({error: "Conflict", message: "Username is taken."});
                        break;
                    default: 
                        res.status(500).json({error: "Internal Server Error", message: "An unexpected error occured."});
                        break;
                }
                return;
            }
            console.log(`[REGISTER] User Registered.`);
            res.status(201).json({message: "User created."});
            return;
        })
    } catch (err) {
        console.log("[REGISTER] User could not be created. Internal Error.");
        return next(err);
    }
})

app.post('/authenticate', authenticate_limiter, createUsernameChain(), createPasswordChain(), async (req, res, next) => {
    console.log(`[AUTH] Logging in new user`)

    // Parse request body.
    const { username } = req.body;
    const { password } = req.body;

    // Get Validation Errors
    const validation = validationResult(req);

    try {
        if (!validation.isEmpty()) {
            console.log("[AUTH] User could not be authenticated. Bad Request.");
            res.status(400).json({error: "Bad Request", message: `${validation.array()[0].msg}`});
            return;
        }

        // Construct SQL Query
        users_sql = `SELECT hash FROM users WHERE username = ?`;
        let users_values = [username];

        // Query Database
        db.query(users_sql, users_values, (q_err, q_res) => {
            if(q_err) {
                console.log("[AUTH] User could not be authenticated. Database Error.");
                switch (q_err.errno) {
                    default: 
                        res.status(500).json({error: "Internal Server Error", message: "An unexpected error occured."});
                        break;
                }
                return;
            } else if (q_res.length == 0) {
                console.log("[AUTH] No such user found");
                res.status(401).json({error: "Unauthorized", message: "Invalid credentials"});
                return;
            } else {
                console.log(`[AUTH] User found.`);
                if (bcrypt.compareSync(password, q_res[0].hash)) {
                    res.status(200).json({message: "User authenticated."});
                } else {
                    res.status(401).json({error: "Unauthorized", message: "Invalid credentials."});
                }
                return;
            }
        })
    } catch (err) {
        console.log("[AUTH] User could not be authenticated. Internal Error.");
        return next(err);
    }
})


