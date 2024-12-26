const express = require("express");
const uuid = require("uuid");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { rateLimit } = require("express-rate-limit");
require("dotenv").config();

const PORT = process.env.API_PORT || 3000;

// bcrypt

const salt = 12;

// Rate Limiters

const register_limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many requests", message: "Please try again later" },
  standardHeaders: "draft-8",
});

const authenticate_limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many requests", message: "Please try again later" },
  standardHeaders: "draft-8",
});

const protected_limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many requests", message: "Please try again later" },
  standardHeaders: "draft-8",
});

// Input Validation Chains

const createUsernameChain = () =>
  body("username")
    .notEmpty()
    .withMessage("Username cannot be empty.")
    .isString()
    .withMessage("Username must be a string")
    .isLength({ min: 3, max: 50 })
    .withMessage("Username must be between 3 and 50 characters.")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage(
      "Username can only contain letters, numbers, and underscores.",
    );

const createPasswordChain = () =>
  body("password")
    .notEmpty()
    .withMessage("Password cannot be empty.")
    .isString()
    .withMessage("Password must be a string")
    .isLength({ min: 8, max: 50 })
    .withMessage("Password must be between 8 and 50 characters.")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter.")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter.")
    .matches(/[0-9]/)
    .withMessage("Password must contain at least one number.")
    .matches(/[!@#$%^&*]/)
    .withMessage("Password must contain at least one special character.");

const createTokenChain = () =>
  body("token")
    .notEmpty()
    .withMessage("Provided token is empty.")
    .isString()
    .withMessage("Provided token is not a string")
    .matches(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)
    .withMessage("Provided token is poorly-formatted.");

// MIDDLEWARE

const app = express();

const corsOptions = {
  origin: process.env.ORIGIN || null,
  methods: process.env.ALLOWED_METHODS || "GET,POST",
  credentials: true,
  optionSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(helmet());
app.use(express.json());
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${err.message}`);
  res.status(500).json({
    error: "Internal Server Error",
    message: "An unexpected error occurred.",
  });
});

// DATABASE

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DATABASE,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectTimeout: 60000,
  connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 10,
  keepAliveInitialDelay: 10000,
  enableKeepAlive: true,
});

// METHODS

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
  db.getConnection((err, connection) => {
    if (err) {
      console.error(`[ERROR] ${err.message}`);
      process.exit(1);
    }
    if (connection) {
      connection.release();
    }
    console.log(`Database Connected.`);
  });
});

app.get("/", (req, res) => {
  return res.status(200).json({ message: "Server running." });
});

app.post(
  "/register",
  register_limiter,
  createUsernameChain(),
  createPasswordChain(),
  async (req, res, next) => {
    console.log(`[REGISTER] Registering new user...`);

    // Parse request body.
    const { username } = req.body;
    const { password } = req.body;

    // Get Validation Errors
    const validation = validationResult(req);

    try {
      if (!validation.isEmpty()) {
        console.log("[REGISTER] User could not be created. Bad Request.");
        return res.status(400).json({
          error: "Bad Request",
          message: `${validation.array()[0].msg}`,
        });
      }

      // Generate ID and Password Hash
      let id = uuid.v4();
      let hash = await bcrypt.hash(password, salt);

      // Construct SQL Query
      users_sql = `INSERT INTO users (id, username, hash) VALUES (?, ?, ?)`;
      let users_values = [id, username, hash];

      // Query Database
      db.query(users_sql, users_values, (q_err, q_res) => {
        if (q_err) {
          console.log("[REGISTER] User could not be created. Database Error.");
          switch (q_err.errno) {
            case 1062:
              res
                .status(409)
                .json({ error: "Conflict", message: "Username is taken." });
              break;
            default:
              res.status(500).json({
                error: "Internal Server Error",
                message: "An unexpected error occured.",
              });
              break;
          }
          return;
        }
        console.log(`[REGISTER] User Registered.`);
        return res.status(201).json({ message: "User created." });
      });
    } catch (err) {
      console.log("[REGISTER] User could not be created. Internal Error.");
      return next(err);
    }
  },
);

app.post(
  "/authenticate",
  authenticate_limiter,
  createUsernameChain(),
  createPasswordChain(),
  async (req, res, next) => {
    console.log(`[AUTH] Logging in new user`);

    // Parse request body.
    const { username } = req.body;
    const { password } = req.body;

    // Get Validation Errors
    const validation = validationResult(req);

    try {
      if (!validation.isEmpty()) {
        console.log("[AUTH] User could not be authenticated. Bad Request.");
        return res.status(400).json({
          error: "Bad Request",
          message: `${validation.array()[0].msg}`,
        });
      }

      // Construct SQL Query
      users_sql = `SELECT hash FROM users WHERE username = ?`;
      let users_values = [username];

      // Query Database
      db.query(users_sql, users_values, (q_err, q_res) => {
        if (q_err) {
          console.log(
            "[AUTH] User could not be authenticated. Database Error.",
          );
          switch (q_err.errno) {
            default:
              res.status(500).json({
                error: "Internal Server Error",
                message: "An unexpected error occured.",
              });
              break;
          }
          return;
        } else if (q_res.length == 0) {
          console.log("[AUTH] No such user found");
          return res.status(401).json({
            error: "Unauthorized",
            message: "Username or password is incorrect.",
          });
        } else {
          if (bcrypt.compare(password, q_res[0].hash)) {
            console.log(`[AUTH] Credentials verified.`);
            let token = jwt.sign(
              { username: username },
              process.env.SECRET_KEY,
              { expiresIn: `${process.env.AUTH_EXPIRE}` },
            );
            return res
              .status(200)
              .json({ message: "User authenticated.", token: `${token}` });
          } else {
            console.log(`[AUTH] Could not verify credentials.`);
            return res.status(401).json({
              error: "Unauthorized",
              message: "Username or password is incorrect.",
            });
          }
        }
      });
    } catch (err) {
      console.log("[AUTH] User could not be authenticated. Internal Error.");
      return next(err);
    }
  },
);

app.post("/protected", protected_limiter, createTokenChain(), (req, res) => {
  const { token } = req.body;

  // Validate token field
  const validation = validationResult(req);

  if (!validation.isEmpty()) {
    console.log("[PROTECTED] User cannot access resource, bad token.");
    return res.status(400).json({
      error: "Bad Request",
      message: `${validation.array()[0].msg}`,
    });
  }

  // Verify token
  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(403).json({
          error: "Unauthorized",
          message:
            "Could not authorize user, expired token. Please log in again.",
        });
      } else if (err.name === "JsonWebTokenError") {
        return res.status(403).json({
          error: "Unauthorized",
          message:
            "Could not authorize user, invalid token. Please log in again.",
        });
      } else {
        return res.status(500).json({
          error: "Internal Server Error",
          message: "An unexpected error occured.",
        });
      }
    }
    return res
      .status(200)
      .json({ message: `User ${decoded.username} identity verified.` });
  });
});
