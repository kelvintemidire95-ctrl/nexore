
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_EMAIL = "yemisiadeshola57@gmail.com";
const REFERRAL_REWARD = 50;
const MIN_WITHDRAWAL = 1000;
const SESSION_TABLE = "nexore_sessions";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing");
}

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is missing");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 15000
});

app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const sessionStore = new PgSession({
  pool,
  tableName: SESSION_TABLE,
  createTableIfMissing: false
});

app.use(session({
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
}));

function makeReferralCode() {
  return crypto.randomBytes(5).toString("hex").toUpperCase();
}

function error(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(err => err ? reject(err) : resolve());
  });
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    req.session.destroy(err => err ? reject(err) : resolve());
  });
}

function getReferralCookie(req) {
  const cookies = String(req.headers.cookie || "").split(";");
  const item = cookies.find(x =>
    x.trim().startsWith("nexore_ref=")
  );

  if (!item) return "";

  try {
    return decodeURIComponent(
      item.trim().slice("nexore_ref=".length)
    );
  } catch (_) {
    return "";
  }
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return error(res, 401, "Please log in first");
  }

  next();
}

async function requireAdmin(req, res, next) {
  try {
    if (!req.session.userId) {
      return error(res, 401, "Please log in first");
    }

    const result = await pool.query(
      "SELECT role FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (!result.rows.length || result.rows[0].role !== "admin") {
      return error(res, 403, "Admin access required");
    }

    next();
  } catch (err) {
    console.error("ADMIN CHECK:", err);
    return error(res, 500, "Could not verify admin access");
  }
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${SESSION_TABLE} (
      sid VARCHAR NOT NULL PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS nexore_sessions_expire_idx
    ON ${SESSION_TABLE}(expire)
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

  const migrations = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(30)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by BIGINT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS balance NUMERIC(14,2) NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS total_earnings NUMERIC(14,2) NOT NULL DEFAULT 0"
  ];

  for (const sql of migrations) {
    await pool.query(sql);
  }

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
        ALTER TABLE users ALTER COLUMN password DROP NOT NULL;
      END IF;
    END
    $$;
  `);

  const oldUsers = await pool.query(`
    SELECT id FROM users
    WHERE referral_code IS NULL OR referral_code = ''
  `);

  for (const user of oldUsers.rows) {
    let code;
    let exists = true;

    while (exists) {
      code = makeReferralCode();

      const check = await pool.query(
        "SELECT id FROM users WHERE referral_code = $1",
        [code]
      );

      exists = check.rows.length > 0;
    }

    await pool.query(
      "UPDATE users SET referral_code = $1 WHERE id = $2",
      [code, user.id]
    );
  }

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_referral_code_unique
    ON users(referral_code)
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS referrals (
      id BIGSERIAL PRIMARY KEY,
      referrer_id BIGINT NOT NULL REFERENCES users(id),
      referred_user_id BIGINT NOT NULL UNIQUE REFERENCES users(id),
      commission NUMERIC(14,2) NOT NULL DEFAULT 50,
      status VARCHAR(20) NOT NULL DEFAULT 'approved',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      wallet_address TEXT NOT NULL,
      network VARCHAR(60) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS referrals_referrer_idx
    ON referrals(referrer_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS withdrawals_user_idx
    ON withdrawals(user_id)
  `);

  // Promote the configured admin account if it already exists.
  await pool.query(
    "UPDATE users SET role = 'admin' WHERE LOWER(email) = LOWER($1)",
    [ADMIN_EMAIL]
  );

  const admin = await pool.query(
    `SELECT id, username, email, role
     FROM users
     WHERE LOWER(email) = LOWER($1)`,
    [ADMIN_EMAIL]
  );

  if (admin.rows.length) {
    console.log("NEXORE ADMIN ACCOUNT:", admin.rows[0]);
  } else {
    console.log("NEXORE ADMIN: account not registered yet");
  }

  console.log("NEXORE database ready");
}

// Remember referral codes from referral links.
app.use((req, res, next) => {
  const ref = String(req.query.ref || "").trim().toUpperCase();

  if (ref && /^[A-Z0-9]{5,30}$/.test(ref)) {
    res.cookie("nexore_ref", ref, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/"
    });
  }

  next();
});

// Home page
app.get("/", (req, res) => {
  if (req.session.userId) {
    return res.redirect("/dashboard");
  }

  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Dashboard page
app.get("/dashboard", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// Current logged-in user
app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, role, referral_code,
              balance, total_earnings, created_at
       FROM users WHERE id = $1`,
      [req.session.userId]
    );

    if (!result.rows.length) {
      await destroySession(req);
      return error(res, 401, "Account not found");
    }

    res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (err) {
    console.error("PROFILE ERROR:", err);
    error(res, 500, "Could not load profile");
  }
});

// Register
app.post("/api/register", async (req, res) => {
  const client = await pool.connect();

  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!username || !email || !password) {
      return error(res, 400, "All fields are required");
    }

    if (username.length < 3 || username.length > 40) {
      return error(res, 400, "Username must be 3 to 40 characters");
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return error(res, 400, "Enter a valid email address");
    }

    if (password.length < 6) {
      return error(res, 400, "Password must be at least 6 characters");
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await client.query("BEGIN");

    const duplicate = await client.query(
      `SELECT id FROM users
       WHERE LOWER(username) = LOWER($1)
          OR LOWER(email) = LOWER($2)
       LIMIT 1`,
      [username, email]
    );

    if (duplicate.rows.length) {
      await client.query("ROLLBACK");
      return error(res, 409, "Username or email already exists");
    }

    let referralCode;
    let codeExists = true;

    while (codeExists) {
      referralCode = makeReferralCode();

      const check = await client.query(
        "SELECT id FROM users WHERE referral_code = $1",
        [referralCode]
      );

      codeExists = check.rows.length > 0;
    }

    const refCode = getReferralCookie(req).toUpperCase();
    let referrerId = null;

    if (refCode) {
      const referrer = await client.query(
        "SELECT id FROM users WHERE referral_code = $1",
        [refCode]
      );

      if (referrer.rows.length) {
        referrerId = referrer.rows[0].id;
      }
    }

    const role = email === ADMIN_EMAIL ? "admin" : "user";

    const inserted = await client.query(
      `INSERT INTO users
       (username, email, password_hash, referral_code, referred_by, role)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, email, role, referral_code,
                 balance, total_earnings, created_at`,
      [username, email, passwordHash, referralCode, referrerId, role]
    );

    const user = inserted.rows[0];

    if (referrerId && String(referrerId) !== String(user.id)) {
      await client.query(
        `INSERT INTO referrals
         (referrer_id, referred_user_id, commission, status)
         VALUES ($1, $2, $3, 'approved')
         ON CONFLICT (referred_user_id) DO NOTHING`,
        [referrerId, user.id, REFERRAL_REWARD]
      );

      await client.query(
        `UPDATE users
         SET balance = balance + $1,
             total_earnings = total_earnings + $1
         WHERE id = $2`,
        [REFERRAL_REWARD, referrerId]
      );
    }

    await client.query("COMMIT");

    req.session.userId = String(user.id);

    try {
      await saveSession(req);
    } catch (sessionError) {
      console.error("REGISTER SESSION ERROR:", sessionError);
      return error(res, 500, "Account created. Please log in.");
    }

    res.clearCookie("nexore_ref", {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/"
    });

    res.status(201).json({
      success: true,
      message: "Registration successful",
      redirect: "/dashboard",
      user
    });
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}

    console.error("REGISTRATION ERROR:", err);

    if (err.code === "23505") {
      return error(res, 409, "Username or email already exists");
    }

    error(res, 500, "Registration failed. Please try again.");
  } finally {
    client.release();
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const login = String(
      req.body.email || req.body.username || ""
    ).trim();

    const password = String(req.body.password || "");

    if (!login || !password) {
      return error(
        res,
        400,
        "Email/username and password are required"
      );
    }

    const result = await pool.query(
      `SELECT id, username, email, password_hash
       FROM users
       WHERE LOWER(email) = LOWER($1)
          OR LOWER(username) = LOWER($1)
       LIMIT 1`,
      [login]
    );

    if (!result.rows.length) {
      return error(res, 401, "Invalid email/username or password");
    }

    const user = result.rows[0];

    if (
      !user.password_hash ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return error(res, 401, "Invalid email/username or password");
    }

    req.session.userId = String(user.id);
    await saveSession(req);

    res.json({
      success: true,
      message: "Login successful",
      redirect: "/dashboard"
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    error(res, 500, "Login failed. Please try again.");
  }
});

// Logout
app.post("/api/logout", async (req, res) => {
  try {
    await destroySession(req);

    res.clearCookie("nexore.sid", {
      httpOnly: true,
      secure: true,
      sameSite: "lax"
    });

    res.json({
      success: true,
      redirect: "/"
    });
  } catch (err) {
    console.error("LOGOUT ERROR:", err);
    error(res, 500, "Logout failed");
  }
});

// User dashboard data
app.get("/api/dashboard", requireLogin, async (req, res) => {
  try {
    const userResult = await pool.query(
      `SELECT id, username, email, role, referral_code,
              balance, total_earnings, created_at
       FROM users WHERE id = $1`,
      [req.session.userId]
    );

    if (!userResult.rows.length) {
      return error(res, 404, "User not found");
    }

    const user = userResult.rows[0];

    const [referrals, withdrawals, referralCount] = await Promise.all([
      pool.query(
        `SELECT r.id, r.commission, r.status, r.created_at,
                u.username AS referred_username
         FROM referrals r
         JOIN users u ON u.id = r.referred_user_id
         WHERE r.referrer_id = $1
         ORDER BY r.created_at DESC LIMIT 100`,
        [user.id]
      ),

      pool.query(
        `SELECT id, amount, wallet_address, network, status,
                admin_note, created_at, updated_at
         FROM withdrawals
         WHERE user_id = $1
         ORDER BY created_at DESC LIMIT 100`,
        [user.id]
      ),

      pool.query(
        `SELECT COUNT(*)::int AS total
         FROM referrals WHERE referrer_id = $1`,
        [user.id]
      )
    ]);

    const baseUrl = `${req.protocol}://${req.get("host")}`;

    res.json({
      success: true,
      user,
      stats: {
        referrals: referralCount.rows[0].total,
        totalEarnings: Number(user.total_earnings),
        balance: Number(user.balance),
        pendingWithdrawals: withdrawals.rows
          .filter(w => w.status === "pending")
          .reduce((sum, w) => sum + Number(w.amount), 0)
      },
      referralLink: `${baseUrl}/?ref=${user.referral_code}`,
      referralReward: REFERRAL_REWARD,
      minimumWithdrawal: MIN_WITHDRAWAL,
      referrals: referrals.rows,
      withdrawals: withdrawals.rows
    });
  } catch (err) {
    console.error("DASHBOARD ERROR:", err);
    error(res, 500, "Could not load dashboard");
  }
});

// Request withdrawal
app.post("/api/withdraw", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    const amount = Number(req.body.amount);
    const wallet = String(req.body.wallet_address || "").trim();
    const network = String(req.body.network || "").trim();

    if (!Number.isFinite(amount) || amount < MIN_WITHDRAWAL) {
      return error(
        res,
        400,
        `Minimum withdrawal is ₦${MIN_WITHDRAWAL.toLocaleString("en-NG")}`
      );
    }

    if (amount > 100000000) {
      return error(res, 400, "Invalid withdrawal amount");
    }

    if (wallet.length < 5 || wallet.length > 200) {
      return error(res, 400, "Enter a valid wallet or payment account");
    }

    if (!network || network.length > 60) {
      return error(res, 400, "Select a payment network");
    }

    await client.query("BEGIN");

    const user = await client.query(
      "SELECT balance FROM users WHERE id = $1 FOR UPDATE",
      [req.session.userId]
    );

    if (!user.rows.length) {
      await client.query("ROLLBACK");
      return error(res, 404, "Account not found");
    }

    if (Number(user.rows[0].balance) < amount) {
      await client.query("ROLLBACK");
      return error(res, 400, "Insufficient available balance");
    }

    await client.query(
      "UPDATE users SET balance = balance - $1 WHERE id = $2",
      [amount, req.session.userId]
    );

    const withdrawal = await client.query(
      `INSERT INTO withdrawals
       (user_id, amount, wallet_address, network)
       VALUES ($1, $2, $3, $4)
       RETURNING id, amount, status, created_at`,
      [req.session.userId, amount, wallet, network]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Withdrawal request submitted for admin review",
      withdrawal: withdrawal.rows[0]
    });
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}

    console.error("WITHDRAW ERROR:", err);
    error(res, 500, "Could not submit withdrawal");
  } finally {
    client.release();
  }
});

// Admin overview
app.get(
  "/api/admin/overview",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const [users, referrals, withdrawals, totals] = await Promise.all([
        pool.query(
          `SELECT id, username, email, role, balance,
                  total_earnings, created_at
           FROM users
           ORDER BY created_at DESC LIMIT 200`
        ),

        pool.query(
          `SELECT r.id, r.commission, r.status, r.created_at,
                  a.username AS referrer_username,
                  b.username AS referred_username,
                  a.id AS referrer_id,
                  b.id AS referred_user_id
           FROM referrals r
           JOIN users a ON a.id = r.referrer_id
           JOIN users b ON b.id = r.referred_user_id
           ORDER BY r.created_at DESC LIMIT 200`
        ),

        pool.query(
          `SELECT w.id, w.user_id, w.amount, w.wallet_address,
                  w.network, w.status, w.admin_note, w.created_at,
                  u.username, u.email
           FROM withdrawals w
           JOIN users u ON u.id = w.user_id
           ORDER BY w.created_at DESC LIMIT 200`
        ),

        pool.query(`
          SELECT
            (SELECT COUNT(*) FROM users)::int AS users,
            (SELECT COUNT(*) FROM referrals)::int AS referrals,
            (SELECT COALESCE(SUM(commission), 0) FROM referrals) AS commissions,
            (SELECT COUNT(*) FROM withdrawals
             WHERE status = 'pending')::int AS pending_withdrawals
        `)
      ]);

      const adminAccount = await pool.query(
        `SELECT id, username, email
         FROM users WHERE LOWER(email) = LOWER($1)`,
        [ADMIN_EMAIL]
      );

      res.json({
        success: true,
        totals: totals.rows[0],
        adminAccount: adminAccount.rows[0] || null,
        users: users.rows,
        referrals: referrals.rows,
        withdrawals: withdrawals.rows
      });
    } catch (err) {
      console.error("ADMIN OVERVIEW:", err);
      error(res, 500, "Could not load admin panel");
    }
  }
);

// Approve or reject withdrawal
app.post(
  "/api/admin/withdrawals/:id",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const id = Number(req.params.id);
      const action = String(req.body.action || "").toLowerCase();
      const note = String(req.body.note || "").trim().slice(0, 500);

      if (!Number.isSafeInteger(id) || id < 1) {
        return error(res, 400, "Invalid withdrawal ID");
      }

      if (!["approve", "reject"].includes(action)) {
        return error(res, 400, "Invalid action");
      }

      await client.query("BEGIN");

      c