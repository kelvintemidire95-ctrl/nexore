
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

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is missing. Add it in Render Environment.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 15000
});

app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Use a new, unique session table name.
const SESSION_TABLE = "nexore_sessions";

const sessionStore = new PgSession({
  pool,
  tableName: SESSION_TABLE,
  createTableIfMissing: false
});

app.use(
  session({
    name: "nexore.sid",
    store: sessionStore,
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: "auto",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

async function initDB() {
  // Create the session table ourselves before accepting requests.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS nexore_sessions (
      sid VARCHAR NOT NULL PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS nexore_sessions_expire_idx
    ON nexore_sessions (expire)
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(40) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_hash TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  // Make an old password column optional if it exists.
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
          AND column_name = 'password'
      ) THEN
        ALTER TABLE users
        ALTER COLUMN password DROP NOT NULL;
      END IF;
    END
    $$;
  `);

  console.log("NEXORE database ready");
}

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/");
  }

  next();
}

app.get("/", (req, res) => {
  if (req.session.userId) {
    return res.redirect("/dashboard");
  }

  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/api/me", async (req, res) => {
  try {
    if (!req.session.userId) {
      return sendError(res, 401, "Not logged in");
    }

    const result = await pool.query(
      `SELECT id, username, email, created_at
       FROM users
       WHERE id = $1`,
      [req.session.userId]
    );

    if (!result.rows.length) {
      return req.session.destroy(() => {
        sendError(res, 401, "Account not found");
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (error) {
    console.error("PROFILE ERROR:", error);
    sendError(res, 500, "Could not load profile");
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!username || !email || !password) {
      return sendError(res, 400, "All fields are required");
    }

    if (username.length < 3 || username.length > 40) {
      return sendError(res, 400, "Username must be 3 to 40 characters");
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return sendError(res, 400, "Enter a valid email address");
    }

    if (password.length < 6) {
      return sendError(res, 400, "Password must be at least 6 characters");
    }

    const existing = await pool.query(
      `SELECT id FROM users
       WHERE LOWER(username) = LOWER($1)
          OR LOWER(email) = LOWER($2)
       LIMIT 1`,
      [username, email]
    );

    if (existing.rows.length) {
      return sendError(res, 409, "Username or email already exists");
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [username, email, passwordHash]
    );

    const user = result.rows[0];

    req.session.userId = String(user.id);

    try {
      await saveSession(req);
    } catch (error) {
      console.error("REGISTER SESSION ERROR:", error);
      return sendError(
        res,
        500,
        "Account created, but login session failed. Please log in."
      );
    }

    res.status(201).json({
      success: true,
      message: "Registration successful",
      redirect: "/dashboard",
      user
    });

  } catch (error) {
    console.error("REGISTRATION ERROR:", error);

    if (error.code === "23505") {
      return sendError(res, 409, "Username or email already exists");
    }

    sendError(res, 500, "Registration failed. Please try again.");
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const login = String(
      req.body.email || req.body.username || ""
    ).trim();

    const password = String(req.body.password || "");

    if (!login || !password) {
      return sendError(
        res,
        400,
        "Email/username and password are required"
      );
    }

    const result = await pool.query(
      `SELECT id, username, email, password_hash, created_at
       FROM users
       WHERE LOWER(email) = LOWER($1)
          OR LOWER(username) = LOWER($1)
       LIMIT 1`,
      [login]
    );

    if (!result.rows.length) {
      return sendError(res, 401, "Invalid email/username or password");
    }

    const user = result.rows[0];

    if (!user.password_hash) {
      return sendError(
        res,
        401,
        "This account has no saved password. Please register again."
      );
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return sendError(res, 401, "Invalid email/username or password");
    }

    req.session.userId = String(user.id);

    try {
      await saveSession(req);
    } catch (error) {
      console.error("LOGIN SESSION ERROR:", error);
      return sendError(res, 500, "Login session failed. Please try again.");
    }

    res.json({
      success: true,
      message: "Login successful",
      redirect: "/dashboard"
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);
    sendError(res, 500, "Login failed. Please try again.");
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      console.error("LOGOUT ERROR:", error);
      return sendError(res, 500, "Logout failed");
    }

    res.clearCookie("nexore.sid", {
      httpOnly: true,
      secure: true,
      sameSite: "lax"
    });

    res.json({
      success: true,
      redirect: "/"
    });
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "NEXORE is running"
  });
});

app.use(express.static(path.join(__dirname, "public")));

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  if (res.headersSent) return next(error);

  sendError(res, 500, "Server error. Please try again.");
});

async function startServer() {
  try {
    await initDB();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`NEXORE running on port ${PORT}`);
    });
  } catch (error) {
    console.error("DATABASE STARTUP ERROR:", error);
    process.exit(1);
  }
}

startServer();
