
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

app.use(
  session({
    store: pool
      ? new PgSession({
          pool,
          createTableIfMissing: true,
          tableName: "session"
        })
      : undefined,
    secret: process.env.SESSION_SECRET || "change-this-secret-before-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

function requireDatabase(req, res, next) {
  if (!pool) {
    return res.status(503).json({
      error: "Database is not configured. Add DATABASE_URL in Render."
    });
  }
  next();
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

async function initializeDatabase() {
  if (!pool) {
    console.log("DATABASE_URL not configured. Database features are disabled.");
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("Database connected and initialized.");
}

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "online",
    website: "NEXORE",
    time: new Date().toISOString()
  });
});

// Homepage
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Current user
app.get("/api/me", (req, res) => {
  res.json({
    loggedIn: !!req.session.user,
    user: req.session.user || null
  });
});

// Registration
app.post("/api/register", requireDatabase, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "Complete all fields." });
    }

    if (!/^[a-zA-Z0-9_]{3,50}$/.test(username)) {
      return res.status(400).json({ error: "Invalid username." });
    }

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email." });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [username, email.toLowerCase(), hashedPassword]
    );

    req.session.user = result.rows[0];

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      user: req.session.user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }

    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed." });
  }
});

// Login
app.post("/api/login", requireDatabase, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Enter email and password." });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email.toLowerCase()]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Invalid login details." });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ error: "Invalid login details." });
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Login failed." });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email
      };

      res.json({
        success: true,
        message: "Login successful.",
        user: req.session.user
      });
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed." });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ error: "Could not log out." });
    }

    res.clearCookie("connect.sid");
    res.json({ success: true, message: "Logged out." });
  });
});

// Protected dashboard API
app.get("/api/dashboard", requireLogin, (req, res) => {
  res.json({
    success: true,
    user: req.session.user,
    message: "Welcome to NEXORE."
  });
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: "Page not found." });
});

// Error handler
app.use((error, req, res, next) => {
  console.error("Server error:", error);
  res.status(500).json({ error: "Internal server error." });
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`NEXORE running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}

startServer();
    
