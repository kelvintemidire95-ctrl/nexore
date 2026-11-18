
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const ADMIN_EMAIL = "yemisiadeshola57@gmail.com";
const REFERRAL_REWARD = 50;
const MIN_WITHDRAWAL = 1000;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing");
}

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is missing");
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  connectionTimeoutMillis: 10000
});

app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: "nexore_sessions",
    createTableIfMissing: true
  }),
  name: "nexore.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function makeReferralCode() {
  return crypto.randomBytes(5).toString("hex").toUpperCase();
}

function accountId(id) {
  return "NXR" + String(id).padStart(8, "0");
}

function publicUser(user) {
  return {
    id: Number(user.id),
    accountId: accountId(user.id),
    name: user.name,
    email: user.email,
    referralCode: user.referral_code,
    role: user.role,
    balance: Number(user.balance || 0),
    totalEarned: Number(user.total_earned || 0),
    totalWithdrawn: Number(user.total_withdrawn || 0),
    createdAt: user.created_at
  };
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Please log in to continue."
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (
    !req.session.userId ||
    req.session.role !== "admin"
  ) {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function getUser(id) {
  const result = await pool.query(
    `SELECT id, name, email, referral_code, role,
            balance, total_earned, total_withdrawn, created_at
     FROM users WHERE id = $1`,
    [id]
  );

  return result.rows[0] || null;
}

async function activity(userId, action, details) {
  await pool.query(
    `INSERT INTO activity_logs
     (user_id, action, details)
     VALUES ($1, $2, $3)`,
    [userId || null, action, String(details || "").slice(0, 500)]
  );
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      referral_code VARCHAR(20) UNIQUE,
      referred_by BIGINT,
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      total_earned NUMERIC(14,2) NOT NULL DEFAULT 0,
      total_withdrawn NUMERIC(14,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS referrals (
      id BIGSERIAL PRIMARY KEY,
      referrer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      referred_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      reward NUMERIC(14,2) NOT NULL DEFAULT 50,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS withdrawals (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(14,2) NOT NULL,
      bank_name VARCHAR(100) NOT NULL,
      account_name VARCHAR(120) NOT NULL,
      account_number VARCHAR(40) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS activity_logs (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(100) NOT NULL,
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS referrals_referrer_idx
    ON referrals(referrer_id);

    CREATE INDEX IF NOT EXISTS withdrawals_user_idx
    ON withdrawals(user_id);

    CREATE INDEX IF NOT EXISTS withdrawals_status_idx
    ON withdrawals(status);

    CREATE INDEX IF NOT EXISTS activity_created_idx
    ON activity_logs(created_at DESC);
  `);

  // Add missing columns when upgrading an older NEXORE database.
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(100);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(20);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by BIGINT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS balance NUMERIC(14,2) DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS total_earned NUMERIC(14,2) DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS total_withdrawn NUMERIC(14,2) DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();

    ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS bank_name VARCHAR(100) DEFAULT '';
    ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS account_name VARCHAR(120) DEFAULT '';
    ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS account_number VARCHAR(40) DEFAULT '';
    ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending';
    ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS admin_note TEXT;
    ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
  `);

  const missingCodes = await pool.query(
    `SELECT id FROM users
     WHERE referral_code IS NULL OR referral_code = ''`
  );

  for (const user of missingCodes.rows) {
    let assigned = false;

    while (!assigned) {
      try {
        await pool.query(
          "UPDATE users SET referral_code = $1 WHERE id = $2",
          [makeReferralCode(), user.id]
        );

        assigned = true;
      } catch (error) {
        if (error.code !== "23505") throw error;
      }
    }
  }

  await pool.query(
    "UPDATE users SET role = 'admin' WHERE LOWER(email) = $1",
    [ADMIN_EMAIL]
  );

  console.log("NEXORE database ready");
}

// HEALTH CHECK
app.get("/health", asyncHandler(async (req, res) => {
  await pool.query("SELECT 1");

  res.json({
    status: "ok",
    app: "NEXORE"
  });
}));

// WEBSITE PAGES
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.use(express.static(path.join(__dirname, "public")));

// PUBLIC CONFIGURATION
app.get("/api/config", (req, res) => {
  res.json({
    referralReward: REFERRAL_REWARD,
    minimumWithdrawal: MIN_WITHDRAWAL
  });
});

// CURRENT USER
app.get("/api/me", asyncHandler(async (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }

  const user = await getUser(req.session.userId);

  if (!user) {
    req.session.destroy(() => {});
    return res.json({ user: null });
  }

  res.json({
    user: publicUser(user)
  });
}));

// REGISTER
app.post("/api/register", asyncHandler(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = cleanEmail(req.body.email);
  const password = String(req.body.password || "");
  const referralCode = String(
    req.body.referralCode || ""
  ).trim().toUpperCase();

  if (name.length < 2 || name.length > 100) {
    return res.status(400).json({
      error: "Enter a valid full name."
    });
  }

  if (!validEmail(email)) {
    return res.status(400).json({
      error: "Enter a valid email address."
    });
  }

  if (password.length < 8 || password.length > 100) {
    return res.status(400).json({
      error: "Password must contain at least 8 characters."
    });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const client = await pool.connect();

  let newUser;

  try {
    await client.query("BEGIN");

    const existing = await client.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existing.rowCount) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error: "This email already has an account. Please log in."
      });
    }

    let referrer = null;

    if (referralCode) {
      const ref = await client.query(
        `SELECT id FROM users
         WHERE referral_code = $1
         FOR UPDATE`,
        [referralCode]
      );

      referrer = ref.rows[0] || null;
    }

    const role = email === ADMIN_EMAIL ? "admin" : "user";

    const inserted = await client.query(
      `INSERT INTO users
       (name, email, password_hash, referral_code, referred_by, role)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, referral_code, role,
       balance, total_earned, total_withdrawn, created_at`,
      [
        name,
        email,
        passwordHash,
        makeReferralCode(),
        referrer ? referrer.id : null,
        role
      ]
    );

    newUser = inserted.rows[0];

    if (referrer && Number(referrer.id) !== Number(newUser.id)) {
      await client.query(
        `INSERT INTO referrals
         (referrer_id, referred_id, reward)
         VALUES ($1, $2, $3)`,
        [referrer.id, newUser.id, REFERRAL_REWARD]
      );

      await client.query(
        `UPDATE users
         SET balance = balance + $1,
             total_earned = total_earned + $1
         WHERE id = $2`,
        [REFERRAL_REWARD, referrer.id]
      );

      await client.query(
        `INSERT INTO activity_logs
         (user_id, action, details)
         VALUES ($1, $2, $3)`,
        [
          referrer.id,
          "referral_reward",
          `₦${REFERRAL_REWARD} referral reward for ${email}`
        ]
      );
    }

    await client.query("COMMIT");

  } catch (error) {
    await client.query("ROLLBACK");

    if (error.code === "23505") {
      return res.status(409).json({
        error: "Account already exists or referral code collision. Try again."
      });
    }

    throw error;

  } finally {
    client.release();
  }

  req.session.userId = Number(newUser.id);
  req.session.role = newUser.role;

  await saveSession(req);

  await activity(
    newUser.id,
    "account_registered",
    "New NEXORE account created"
  );

  res.status(201).json({
    message: "Registration successful.",
    user: publicUser(newUser),
    redirect: "/dashboard"
  });
}));

// LOGIN
app.post("/api/login", asyncHandler(async (req, res) => {
  const email = cleanEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!validEmail(email) || !password) {
    return res.status(400).json({
      error: "Enter your email and password."
    });
  }

  const result = await pool.query(
    `SELECT id, name, email, password_hash, referral_code,
            role, balance, total_earned, total_withdrawn, created_at
     FROM users WHERE email = $1`,
    [email]
  );

  const user = result.rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({
      error: "Incorrect email or password."
    });
  }

  if (email === ADMIN_EMAIL && user.role !== "admin") {
    await pool.query(
      "UPDATE users SET role = 'admin' WHERE id = $1",
      [user.id]
    );

    user.role = "admin";
  }

  req.session.userId = Number(user.id);
  req.session.role = user.role;

  await saveSession(req);

  await activity(user.id, "login", "User logged in");

  res.json({
    message: "Login successful.",
    user: publicUser(user),
    redirect: "/dashboard"
  });
}));

// LOGOUT
app.post("/api/logout", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({
        error: "Unable to log out."
      });
    }

    res.clearCookie("nexore.sid", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    });

    res.json({
      message: "Logged out.",
      redirect: "/"
    });
  });
});

// MEMBER DASHBOARD
app.get("/api/dashboard", requireLogin, asyncHandler(async (req, res) => {
  const user = await getUser(req.session.userId);

  if (!user) {
    return res.status(404).json({
      error: "Account not found."
    });
  }

  const [referrals, withdrawals] = await Promise.all([
    pool.query(
      "SELECT COUNT(*)::int AS total FROM referrals WHERE referrer_id = $1",
      [user.id]
    ),

    pool.query(
      `SELECT id, amount, bank_name, account_name,
              account_number, status, admin_note, created_at
       FROM withdrawals
       WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 10`,
      [user.id]
    )
  ]);

  res.json({
    user: publicUser(user),

    stats: {
      referrals: referrals.rows[0].total,
      availableBalance: Number(user.balance),
      totalEarned: Number(user.total_earned),
      totalWithdrawn: Number(user.total_withdrawn)
    },

    referralLink:
      `${req.protocol}://${req.get("host")}/?ref=${encodeURIComponent(user.referral_code)}`,

    referralReward: REFERRAL_REWARD,
    minimumWithdrawal: MIN_WITHDRAWAL,
    withdrawals: withdrawals.rows
  });
}));

// REFERRAL LIST
app.get("/api/referrals", requireLogin, asyncHandler(async (req, res) => {
  const result = await pool.query(
    `SELECT r.id, r.reward, r.created_at,
            u.name, u.email
     FROM referrals r
     JOIN users u ON u.id = r.referred_id
     WHERE r.referrer_id = $1
     ORDER BY r.created_at DESC`,
    [req.session.userId]
  );

  res.json({
    referrals: result.rows
  });
}));

// WITHDRAWAL REQUEST
app.post("/api/withdraw", requireLogin, asyncHandler(async (req, res) => {
  const amount = Number(req.body.amount);
  const bankName = String(req.body.bankName || "").trim();
  const accountName = String(req.body.accountName || "").trim();
  const accountNumber = String(req.body.accountNumber || "").trim();

  if (!Number.isFinite(amount) || amount < MIN_WITHDRAWAL) {
    return res.status(400).json({
      error: `Minimum withdrawal is ₦${MIN_WITHDRAWAL}.`
    });
  }

  if (amount > 100000000) {
    return res.status(400).json({
      error: "Invalid withdrawal amount."
    });
  }

  if (bankName.length < 2 || bankName.length > 100) {
    return res.status(400).json({
      error: "Enter a valid bank name."
    });
  }

  if (accountName.length < 2 || accountName.length > 120) {
    return res.status(400).json({
      error: "Enter the account name."
    });
  }

  if (!/^[0-9]{10}$/.test(accountNumber)) {
    return res.status(400).json({
      error: "Account number must contain 10 digits."
    });
  }

  const client = await pool.connect();

  let withdrawal;

  try {
    await client.query("BEGIN");

    const userResult = await client.query(
      "SELECT balance FROM users WHERE id = $1 FOR UPDATE",
      [req.session.userId]
    );

    if (!userResult.rowCount) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "User account not found."
      });
    }

    if (Number(userResult.rows[0].balance) < amount) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Insufficient balance."
      });
    }

    await client.query(
      "UPDATE users SET balance = balance - $1 WHERE id = $2",
      [amount, req.session.userId]
    );

    const inserted = await client.query(
      `INSERT INTO withdrawals
       (user_id, amount, bank_name, account_name, account_number)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, amount, bank_name, account_name,
                 account_number, status, created_at`,
      [
        req.session.userId,
        amount,
        bankName,
        accountName,
        accountNumber
      ]
    );

    withdrawal = inserted.rows[0];

    await client.query(
      `INSERT INTO activity_logs
       (user_id, action, details)
       VALUES ($1, $2, $3)`,
      [
        req.session.userId,
        "withdrawal_requested",
        `Withdrawal request #${withdrawal.id}`
      ]
    );

    await client.query("COMMIT");

  } catch (error) {
    await client.query("ROLLBACK");
    throw error;

  } finally {
    client.release();
  }

  res.status(201).json({
    message: "Withdrawal request submitted successfully.",
    withdrawal
  });
}));

// WITHDRAWAL HISTORY
app.get("/api/withdrawals", requireLogin, asyncHandler(async (req, res) => {
  const result = await pool.query(
    `SELECT id, amount, bank_name, account_name,
            account_number, status, admin_note,
            created_at, updated_at
     FROM withdrawals
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [req.session.userId]
  );

  res.json({
    withdrawals: result.rows
  });
}));

// ADMIN OVERVIEW
app.get("/api/admin/overview", requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  const [stats, withdrawals, users, activities] = await Promise.all([
    pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM users) AS users,
        (SELECT COUNT(*)::int FROM referrals) AS referrals,
        (SELECT COUNT(*)::int FROM withdrawals
         WHERE status = 'pending') AS pending_withdrawals,
        (SELECT COALESCE(SUM(amount), 0) FROM withdrawals
         WHERE status = 'approved') AS paid_withdrawals,
        (SELECT COALESCE(SUM(balance), 0) FROM users)
         AS total_user_balance
    `),

    pool.query(`
      SELECT w.id, w.amount, w.bank_name, w.account_name,
             w.account_number, w.status, w.admin_note,
             w.created_at, u.name, u.email, u.id AS user_id
      FROM withdrawals w
      JOIN users u ON u.id = w.user_id
      ORDER BY
        CASE WHEN w.status = 'pending' THEN 0 ELSE 1 END,
        w.created_at DESC
      LIMIT 100
    `),

    pool.query(`
      SELECT id, name, email, role, balance,
             total_earned, total_withdrawn, created_at
      FROM users
      ORDER BY created_at DESC
      LIMIT 100
    `),

    pool.query(`
      SELECT a.id, a.action, a.details, a.created_at,
             u.name, u.email
      FROM activity_logs a
      LEFT JOIN users u ON u.id = a.user_id
      ORDER BY a.created_at DESC
      LIMIT 30
    `)
  ]);

  res.json({
    stats: stats.rows[0],
    withdrawals: withdrawals.rows,
    users: users.rows,
    activities: activities.rows
  });
}));

// ADMIN APPROVE OR REJECT WITHDRAWAL
app.post("/api/admin/withdrawals/:id", requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const action = String(req.body.action || "").toLowerCase();
  const note = String(req.body.note || "").trim().slice(0, 500);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({
      error: "Invalid withdrawal ID."
    });
  }

  if (!["approve", "reject"].includes(action)) {
    return res.status(400).json({
      error: "Choose approve or reject."
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const found = await client.query(
      
      "SELECT * FROM withdrawals WHERE id = $1 FOR UPDATE",
      [id]
    );

    if (!found.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "Withdrawal not found."
      });
    }

    const withdrawal = found.rows[0];

    if (withdrawal.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "This withdrawal has already been processed."
      });
    }

    if (action === "approve") {
      await client.query(
        `UPDATE withdrawals
         SET status = 'approved',
             admin_note = $1,
             updated_at = NOW()
         WHERE id = $2`,
        [note || "Approved by administrator.", id]
      );

      await client.query(
        `UPDATE users
         SET total_withdrawn = total_withdrawn + $1
         WHERE id = $2`,
        [withdrawal.amount, withdrawal.user_id]
      );
    } else {
      await client.query(
        `UPDATE withdrawals
         SET status = 'rejected',
             admin_note = $1,
             updated_at = NOW()
         WHERE id = $2`,
        [note || "Rejected by administrator.", id]
      );

      await client.query(
        "UPDATE users SET balance = balance + $1 WHERE id = $2",
        [withdrawal.amount, withdrawal.user_id]
      );
    }

    await client.query(
      `INSERT INTO activity_logs (user_id, action, details)
       VALUES ($1, $2, $3)`,
      [
        withdrawal.user_id,
        "withdrawal_" + action,
        `Withdrawal #${id} ${action}d by administrator`
      ]
    );

    await client.query("COMMIT");

    res.json({
      message: `Withdrawal ${action}d successfully.`
    });

  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

// ADMIN CHANGE USER ROLE
app.patch("/api/admin/users/:id/role", requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const role = String(req.body.role || "").toLowerCase();

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid user ID." });
  }

  if (!["user", "admin"].includes(role)) {
    return res.status(400).json({ error: "Invalid role." });
  }

  const target = await pool.query(
    "SELECT email FROM users WHERE id = $1",
    [id]
  );

  if (!target.rowCount) {
    return res.status(404).json({ error: "User not found." });
  }

  if (
    cleanEmail(target.rows[0].email) === ADMIN_EMAIL &&
    role !== "admin"
  ) {
    return res.status(400).json({
      error: "The primary administrator cannot be demoted."
    });
  }

  await pool.query(
    "UPDATE users SET role = $1 WHERE id = $2",
    [role, id]
  );

  await activity(
    req.session.userId,
    "user_role_changed",
    `Changed account ${id} role to ${role}`
  );

  res.json({ message: "User role updated successfully." });
}));

// ADMIN VIEW USER
app.get("/api/admin/users/:id", requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid user ID." });
  }

  const result = await pool.query(
    `SELECT id, name, email, referral_code, role,
            balance, total_earned, total_withdrawn, created_at
     FROM users WHERE id = $1`,
    [id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "User not found." });
  }

  const referrals = await pool.query(
    "SELECT COUNT(*)::int AS total FROM referrals WHERE referrer_id = $1",
    [id]
  );

  res.json({
    user: publicUser(result.rows[0]),
    referralCount: referrals.rows[0].total
  });
}));

// 404 HANDLER
app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API route not found." });
  }

  res.status(404).send("Page not found.");
});

// ERROR HANDLER
app.use((error, req, res, next) => {
  console.error("NEXORE error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "A server error occurred. Please try again."
  });
});

// START SERVER
initializeDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`NEXORE running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("NEXORE database initialization failed:", error);
    process.exit(1);
  });

process.on("unhandledRejection", error => {
  console.error("Unhandled promise rejection:", error);
});
