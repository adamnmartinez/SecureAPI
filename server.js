const express = require('express');
const uuid = require('uuid');
const mysql = require('mysql2');
const cors = require('cors');
//const jshashes = require('jshashes');
const bcrypt = require('bcryptjs');
const app = express();

require('dotenv').config();
const PORT = process.env.PORT;

const corsOptions = {
    origin : process.env.ORIGIN, 
    methods : "GET,PUT,DELETE",
    credentials : true,
    optionSuccessStatus : 200,
}

app.use(cors(corsOptions));
app.use(express.json());

const db = mysql.createPool({
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASS,
    database: process.env.DATABASE,
    port: 3306,
    waitForConnections: true,
    connectTimeout: 60000,
    connectionLimit: 10,
    keepAliveInitialDelay: 10000,
    enableKeepAlive: true,
})

app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
    db.getConnection((err) => {
        if(err) throw err;
        console.log(`Database Connected.`);
    })
})

app.get('/', (req, res) => {
    return res.json("Server running.");
})

app.post('/register', async (req, res) => {
    console.log(`[REGISTER] Registering new user...`)

    // Parse request body.
    const { username } = req.body;
    const { password } = req.body;

    try {
        if (username == null || password == null) {
            res.status(400);
            res.json({error: "Bad Request", message: "The request was poorly formatted."});
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
                console.log("[REGISTER] User could not be created.");
                switch (q_err.errno) {
                    case 1062: 
                        res.status(409);
                        res.json({error: "Conflict", message: "Username is taken."});
                        break;
                    default: 
                        res.status(500);
                        res.json({error: "Internal Server Error", message: "An unexpected error occured."});
                        break;
                }
                return;
            }
            console.log(`[REGISTER] User Registered.`);
            res.status(201);
            res.json({error: "Created", message: "User created."});
            return;
        })
    } catch (e) {
        console.log(`[REGISTER] User Registered.`);
        res.status(500);
        res.json({error: "Internal Server Error", message: "An unexpected error occured."});
        return;
    }
})