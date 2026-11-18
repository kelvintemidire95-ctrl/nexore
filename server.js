
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const path = require("path");
const crypto = require("crypto");

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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new PgSession({
    pool,
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

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// =====================================
// HELPERS
// =====================================

function makeReferralCode() {
  return crypto.randomBytes(5).toString("hex").toUpperCase();
}

function cleanEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function money(value) {
  return Number(Number(value || 0).toFixed(2));
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      message: "Please log in first."
    });
  }

  next();
}

async function requireAdmin(req, res, next) {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        success: false,
        message: "Please log in first."
      });
    }

    const result = await pool.query(
      "SELECT id, email, role FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (!result.rows.length || result.rows[0].role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required."
      });
    }

    next();
  } catch (error) {
    console.error("Admin check:", error);

    res.status(500).json({
      success: false,
      message: "Could not verify admin access."
    });
  }
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    referral_code: user.referral_code,
    balance: money(user.balance),
    total_earnings: money(user.total_earnings),
    created_at: user.created_at
  };
}

// =====================================
// DATABASE SETUP
// =====================================

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL DEFAULT '',
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      referral_code TEXT UNIQUE,
      referred_by BIGINT,
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      total_earnings NUMERIC(14,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS password_hash TEXT,
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS referral_code TEXT,
    ADD COLUMN IF NOT EXISTS referred_by BIGINT,
    ADD COLUMN IF NOT EXISTS balance NUMERIC(14,2) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS total_earnings NUMERIC(14,2) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS referrals (
      id BIGSERIAL PRIMARY KEY,
      referrer_id BIGINT NOT NULL REFERENCES users(id),
      referred_id BIGINT NOT NULL UNIQUE REFERENCES users(id),
      reward NUMERIC(14,2) NOT NULL DEFAULT 50,
      status TEXT NOT NULL DEFAULT 'completed',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      wallet TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS users_email_idx
    ON users(email)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS referrals_referrer_idx
    ON referrals(referrer_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS withdrawals_user_idx
    ON withdrawals(user_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS withdrawals_status_idx
    ON withdrawals(status)
  `);

  // Generate missing referral codes.
  const users = await pool.query(`
    SELECT id FROM users
    WHERE referral_code IS NULL OR referral_code = ''
  `);

  for (const user of users.rows) {
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
    CREATE UNIQUE INDEX IF NOT EXISTS users_referral_code_idx
    ON users(referral_code)
  `);

  // Promote the configured admin email if the account exists.
  // IMPORTANT: This does not verify ownership of that email address.
  await pool.query(
    "UPDATE users SET role = 'admin' WHERE LOWER(email) = $1",
    [ADMIN_EMAIL]
  );

  console.log("NEXORE database initialized.");
}

// =====================================
// REFERRAL COOKIE
// =====================================

app.use((req, res, next) => {
  const ref = String(req.query.ref || "").trim().toUpperCase();

  if (/^[A-F0-9]{6,20}$/.test(ref)) {
    res.cookie("nexore_ref", ref, {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/"
    });
  }

  next();
});

// =====================================
// WEBSITE PAGES
// =====================================

app.get("/", (req, res) => {
  if (req.session.userId) {
    return res.redirect("/dashboard");
  }

  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "NEXORE",
    status: "running"
  });
});

// =====================================
// CURRENT USER
// =====================================

app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (!result.rows.length) {
      req.session.destroy(() => {});

      return res.status(401).json({
        success: false,
        message: "Account not found."
      });
    }

    res.json({
      success: true,
      user: publicUser(result.rows[0])
    });
  } catch (error) {
    console.error("Current user:", error);

    res.status(500).json({
      success: false,
      message: "Could not load account."
    });
  }
});

// =====================================
// REGISTER
// =====================================

app.post("/api/register", async (req, res) => {
  const client = await pool.connect();

  try {
    const name = String(req.body.name || "").trim();
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");

    if (name.length < 2) {
      return res.status(400).json({
        success: false,
        message: "Enter your full name."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters."
      });
    }

    await client.query("BEGIN");

    const existing = await client.query(
      "SELECT id FROM users WHERE LOWER(email) = $1",
      [email]
    );

    if (existing.rows.length) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    let referralCode = makeReferralCode();

    while (true) {
      const check = await client.query(
        "SELECT id FROM users WHERE referral_code = $1",
        [referralCode]
      );

      if (!check.rows.length) break;

      referralCode = makeReferralCode();
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const inserted = await client.query(
      `INSERT INTO users
       (name, email, password_hash, referral_code)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, email, passwordHash, referralCode]
    );

    const newUser = inserted.rows[0];

    const refCode = String(
      req.cookies?.nexore_ref || req.body.referral_code || ""
    ).trim().toUpperCase();

    if (refCode && refCode !== referralCode) {
      const referrerResult = await client.query(
        `SELECT id FROM users
         WHERE referral_code = $1
         AND id != $2
         FOR UPDATE`,
        [refCode, newUser.id]
      );

      if (referrerResult.rows.length) {
        const referrerId = referrerResult.rows[0].id;

        await client.query(
          `UPDATE users
           SET balance = balance + $1,
               total_earnings = total_earnings + $1
           WHERE id = $2`,
          [REFERRAL_REWARD, referrerId]
        );

        await client.query(
          `UPDATE users SET referred_by = $1 WHERE id = $2`,
          [referrerId, newUser.id]
        );

        await client.query(
          `INSERT INTO referrals
           (referrer_id, referred_id, reward, status)
           VALUES ($1, $2, $3, 'completed')
           ON CONFLICT (referred_id) DO NOTHING`,
          [referrerId, newUser.id, REFERRAL_REWARD]
        );
      }
    }

    await client.query("COMMIT");

    req.session.userId = newUser.id;

    res.clearCookie("nexore_ref", { path: "/" });

    req.session.save((error) => {
      if (error) {
        console.error("Session save:", error);

        return res.status(500).json({
          success: false,
          message: "Account created, but login session failed. Please log in."
        });
      }

      res.status(201).json({
        success: true,
        message: "Registration successful.",
        redirect: "/dashboard",
        user: publicUser(newUser)
      });
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});

    console.error("Registration:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed. Please try again."
    });
  } finally {
    client.release();
  }
});

// =====================================
// LOGIN
// =====================================

app.post("/api/login", async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(email) = $1",
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    if (!user.password_hash) {
      return res.status(401).json({
        success: false,
        message: "This account needs a password reset."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    req.session.regenerate((error) => {
      if (error) {
        console.error("Session regenerate:", error);

        return res.status(500).json({
          success: false,
          message: "Login session failed."
        });
      }

      req.session.userId = user.id;

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save:", saveError);

          return res.status(500).json({
            success: false,
            message: "Could not create login session."
          });
        }

        res.json({
          success: true,
          message: "Login successful.",
          redirect: "/dashboard",
          user: publicUser(user)
        });
      });
    });
  } catch (error) {
    console.error("Login:", error);

    res.status(500).json({
      success: false,
      message: "Login failed. Please try again."
    });
  }
});

// =====================================
// LOGOUT
// =====================================

app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        success: false,
        message: "Logout failed."
      });
    }

    res.clearCookie("nexore.sid");

    res.json({
      success: true,
      redirect: "/"
    });
  });
});

// =====================================
// USER DASHBOARD DATA
// =====================================

app.get("/api/dashboard", requireLogin, async (req, res) => {
  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (!userResult.rows.length) {
      return res.status(404).json({
        success: false,
        message: "Account not found."
      });
    }

    const user = userResult.rows[0];

    const referralResult = await pool.query(
      `SELECT COUNT(*) AS total,
              COALESCE(SUM(reward), 0) AS earnings
       FROM referrals
       WHERE referrer_id = $1
       AND status = 'completed'`,
      [user.id]
    );

    const withdrawalResult = await pool.query(
      `SELECT id, amount, wallet, status, created_at, reviewed_at
       FROM withdrawals
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [user.id]
    );

    const pendingResult = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total
       FROM withdrawals
       WHERE user_id = $1 AND status = 'pending'`,
      [user.id]
    );

    const referralLink =
      `${req.protocol}://${req.get("host")}/?ref=${user.referral_code}`;

    res.json({
      success: true,
      user: publicUser(user),
      stats: {
        total_referrals: Number(referralResult.rows[0].total),
        referral_earnings: money(referralResult.rows[0].earnings),
        total_earnings: money(user.total_earnings),
        balance: money(user.balance),
        pending_withdrawals: money(pendingResult.rows[0].total)
      },
      referral_link: referralLink,
      referrals: {
        total: Number(referralResult.rows[0].total),
        reward_per_referral: REFERRAL_REWARD
      },
      withdrawals: withdrawalResult.rows.map((item) => ({
        ...item,
        amount: money(item.amount)
      })),
      minimum_withdrawal: MIN_WITHDRAWAL
    });
  } catch (error) {
    console.error("Dashboard:", error);

    res.status(500).json({
      success: false,
      message: "Could not load dashboard."
    });
  }
});

// =====================================
// REFERRAL LIST
// =====================================

app.get("/api/referrals", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.id, r.reward, r.status, r.created_at,
              u.name, u.email
       FROM referrals r
       JOIN users u ON u.id = r.referred_id
       WHERE r.referrer_id = $1
       ORDER BY r.created_at DESC`,
      [req.session.userId]
    );

    res.json({
      success: true,
      referrals: result.rows.map((row) => ({
        ...row,
        reward: money(row.reward)
      }))
    });
  } catch (error) {
    console.error("Referral list:", error);

    res.status(500).json({
      success: false,
      message: "Could not load referrals."
    });
  }
});

// =====================================
// WITHDRAWAL REQUEST
// =====================================

app.post("/api/withdraw", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    const amount = Number(req.body.amount);
    const wallet = String(req.body.wallet || "").trim();

    if (!Number.isFinite(amount) || amount < MIN_WITHDRAWAL) {
      return res.status(400).json({
        success: false,
        message: `Minimum withdrawal is ₦${MIN_WITHDRAWAL}.`
      });
    }

    if (amount > 100000000) {
      return res.status(400).json({
        success: false,
        message: "Invalid withdrawal amount."
      });
    }

    if (wallet.length < 5 || wallet.length > 250) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid payout wallet or account details."
      });
    }

    await client.query("BEGIN");

    const userResult = await client.query(
      `SELECT id, balance
       FROM users
       WHERE id = $1
       FOR UPDATE`,
      [req.session.userId]
    );

    if (!userResult.rows.length) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        message: "Account not found."
      });
    }

    const balance = Number(userResult.rows[0].balance);

    if (balance < amount) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        success: false,
        message: "Insufficient available balance."
      });
    }

    await client.query(
      `UPDATE users
       SET balance = balance - $1
       WHERE id = $2`,
      [amount, req.session.userId]
    );

    const withdrawal = await client.query(
      `INSERT INTO withdrawals
       (user_id, amount, wallet, status)
       VALUES ($1, $2, $3, 'pending')
       RETURNING *`,
      [req.session.userId, amount, wallet]
    );

    await client.query("COMMIT");

    res.status(201).json({
      success: true,
      message: "Withdrawal request submitted for review.",
      withdrawal: withdrawal.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});

    console.error("Withdrawal:", error);

    res.status(500).json({
      success: false,
      message: "Could not submit withdrawal."
    });
  } finally {
    client.release();
  }
});

// =====================================
// ADMIN OVERVIEW
// =====================================

app.get("/api/admin/overview", requireAdmin, async (req, res) => {
  try {
    const [users, referrals, withdrawals, totals] = await Promise.all([
      pool.query(`
        SELECT id, name, email, role, referral_code,
               balance, total_earnings, created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 500
      `),

      pool.query(`
        SELECT r.id, r.reward, r.status, r.created_at,
               a.id AS referrer_id,
               a.email AS referrer_email,
               b.id AS referred_id,
               b.email AS ref