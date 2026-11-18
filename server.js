
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || "nexore-change-this-session-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, "public")));

// DATABASE SETUP
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(40) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Fix existing databases missing password_hash
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_hash TEXT
  `);

  // Ensure existing records have a created_at value
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);
}

// AUTHENTICATION
function auth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  next();
}

// HEALTH CHECK
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// HOMEPAGE
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// DASHBOARD
app.get("/dashboard", auth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// CURRENT USER
app.get("/api/me", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Please sign in" });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, email, created_at
       FROM users WHERE id = $1`,
      [req.session.userId]
    );

    if (!result.rows.length) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: "Account not found" });
    }

    res.json({ user: result.rows[0] });

  } catch (err) {
    console.error("Account error:", err);
    res.status(500).json({ error: "Could not load account" });
  }
});

// REGISTER
app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,40}$/.test(username)) {
    return res.status(400).json({
      error: "Username must be 3-40 characters."
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      error: "Invalid email address."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: "Password must be at least 8 characters."
    });
  }

  try {
    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [username, email, hash]
    );

    req.session.userId = result.rows[0].id;

    req.session.save(err => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({
          error: "Account created, but session failed."
        });
      }

      res.status(201).json({
        message: "Registration successful",
        redirect: "/dashboard"
      });
    });

  } catch (err) {
    console.error("Registration error:", err);

    if (err.code === "23505") {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }

    res.status(500).json({
      error: "Registration failed. Please try again."
    });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!email || !password) {
    return res.status(400).json({
      error: "Enter your email and password."
    });
  }

  try {
    const result = await pool.query(
      `SELECT id, password_hash
       FROM users
       WHERE email = $1`,
      [email]
    );

    if (
      !result.rows.length ||
      !result.rows[0].password_hash ||
      !(await bcrypt.compare(password, result.rows[0].password_hash))
    ) {
      return res.status(401).json({
        error: "Incorrect email or password. Accounts created before the password system update may need to register again."
      });
    }

    req.session.userId = result.rows[0].id;

    req.session.save(err => {
      if (err) {
        console.error("Login session error:", err);
        return res.status(500).json({
          error: "Could not create login session."
        });
      }

      res.json({
        message: "Login successful",
        redirect: "/dashboard"
      });
    });

  } catch (err) {
    console.error("Login error:", err);

    res.status(500).json({
      error: "Login failed. Please try again."
    });
  }
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: "Logout failed."
      });
    }

    res.clearCookie("connect.sid");
    res.json({ redirect: "/" });
  });
});

// 404
app.use((req, res) => {
  res.status(404).send("Page not found.");
});

// START SERVER
async function start() {
  try {
    await initDB();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("NEXORE running on port " + PORT);
    });

  } catch (err) {
    console.error("Startup error:", err);
    process.exit(1);
  }
}

start();
