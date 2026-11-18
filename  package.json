
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  store: new PgSession({
    pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || "change-this-secret-before-launch",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const money = value =>
  "₦" + Number(value || 0).toLocaleString("en-NG", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  });

const escapeHTML = value =>
  String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);

function page(title, content, user = null) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHTML(title)} | NEXORE</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#080d18;color:#f4f5f7;font-family:Arial,sans-serif}
header{padding:20px 6%;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #222b3c}
.logo{font-size:25px;font-weight:900;letter-spacing:3px;color:#e5b94f}
nav a{color:#ddd;text-decoration:none;margin-left:15px;font-size:14px}
main{max-width:1100px;margin:35px auto;padding:0 18px}
h1,h2{color:#f1c65c}
p{color:#b9c0ce;line-height:1.6}
.hero{padding:55px 25px;background:linear-gradient(135deg,#151f34,#0c1321);border:1px solid #303b50;border-radius:18px;text-align:center}
.hero h1{font-size:42px;margin:10px}
.btn{display:inline-block;background:#e5b94f;color:#101522;padding:13px 20px;border:0;border-radius:8px;text-decoration:none;font-weight:bold;cursor:pointer;margin:5px}
.btn.secondary{background:#202c40;color:#fff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin:22px 0}
.card{background:#111a2a;border:1px solid #27344a;border-radius:13px;padding:20px;margin:14px 0}
.stat{font-size:25px;font-weight:bold;color:#f1c65c;margin-top:10px}
input,select,textarea{width:100%;padding:13px;margin:8px 0 15px;border:1px solid #34425a;border-radius:8px;background:#0b1220;color:white}
label{color:#cbd2df;font-size:14px}
form{max-width:520px}
table{width:100%;border-collapse:collapse;min-width:600px}
th,td{text-align:left;padding:13px;border-bottom:1px solid #293448;font-size:14px}
th{color:#e5b94f}
.table-wrap{overflow-x:auto}
.notice{padding:13px;background:#172a26;border:1px solid #315b49;border-radius:8px;margin:15px 0;color:#b8f0d0}
.error{padding:13px;background:#351b25;border:1px solid #713343;border-radius:8px;margin:15px 0;color:#ffc4ce}
.small{font-size:13px;color:#929bad}
footer{text-align:center;padding:35px;color:#778197}
a{color:#e5b94f}
</style>
</head>
<body>
<header>
<a class="logo" href="/">NEXORE</a>
<nav>
<a href="/">Home</a>
${user ? `
<a href="/dashboard">Dashboard</a>
<a href="/campaigns">Campaigns</a>
<a href="/wallet">Wallet</a>
<a href="/logout">Logout</a>
` : `
<a href="/login">Login</a>
<a href="/register">Join</a>
`}
</nav>
</header>
<main>${content}</main>
<footer>NEXORE · CONNECT • SHARE • EARN</footer>
</body>
</html>`;
}

function message(text, type = "notice") {
  return `<div class="${type}">${escapeHTML(text)}</div>`;
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) {
    return res.status(403).send(page("Access denied",
      "<h1>Access denied</h1><p>Administrator access is required.</p>",
      req.session.user));
  }
  next();
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      referral_code TEXT UNIQUE NOT NULL,
      referred_by INTEGER REFERENCES users(id),
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS campaigns (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      commission NUMERIC(14,2) NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS commissions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      description TEXT NOT NULL DEFAULT 'Affiliate commission',
      status TEXT NOT NULL DEFAULT 'approved',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      method TEXT NOT NULL,
      account_details TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPassword) {
    const existing = await pool.query(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1)",
      [adminEmail]
    );

    if (!existing.rowCount) {
      const hashed = await bcrypt.hash(adminPassword, 12);
      const code = crypto.randomBytes(5).toString("hex").toUpperCase();

      await pool.query(
        `INSERT INTO users
        (name,email,password,referral_code,is_admin)
        VALUES($1,$2,$3,$4,TRUE)`,
        ["NEXORE Admin", adminEmail.toLowerCase(), hashed, code]
      );
    } else {
      await pool.query(
        "UPDATE users SET is_admin=TRUE WHERE LOWER(email)=LOWER($1)",
        [adminEmail]
      );
    }
  }
}

app.get("/health", (req, res) => {
  res.json({ status: "ok", app: "NEXORE" });
});

app.get("/", (req, res) => {
  const user = req.session.user;

  res.send(page("Home", `
    <section class="hero">
      <p>WELCOME TO NEXORE</p>
      <h1>CONNECT. SHARE. EARN.</h1>
      <p>Discover affiliate campaigns, share referral links and track your commissions in one place.</p>
      <a class="btn" href="${user ? "/dashboard" : "/register"}">
        ${user ? "Open Dashboard" : "Get Started"}
      </a>
      <a class="btn secondary" href="/campaigns">Explore Campaigns</a>
    </section>
    <div class="grid">
      <div class="card"><h2>Affiliate Links</h2><p>Get your own referral link and share it with your audience.</p></div>
      <div class="card"><h2>Track Results</h2><p>View your referrals, commissions and account activity.</p></div>
      <div class="card"><h2>Withdrawals</h2><p>Submit withdrawal requests and follow their status.</p></div>
    </div>
    <p class="small">Commissions depend on eligible activity and campaign terms. Earnings are not guaranteed.</p>
  `, user));
});

app.get("/register", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");

  const ref = String(req.query.ref || "").replace(/[^a-zA-Z0-9]/g, "");

  res.send(page("Register", `
    <div class="card">
      <h1>Create your NEXORE account</h1>
      ${req.query.error ? message(req.query.error, "error") : ""}
      <form method="POST" action="/register">
        <label>Full name</label>
        <input name="name" required maxlength="100" placeholder="Your full name">
        <label>Email address</label>
        <input type="email" name="email" required placeholder="you@example.com">
        <label>Password</label>
        <input type="password" name="password" required minlength="8" placeholder="At least 8 characters">
        <input type="hidden" name="ref" value="${escapeHTML(ref)}">
        <button class="btn" type="submit">Create Account</button>
      </form>
      <p>Already registered? <a href="/login">Login here</a></p>
    </div>
  `));
});

app.post("/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const ref = String(req.body.ref || "").trim();

    if (!name || !email || password.length < 8) {
      return res.redirect("/register?error=" +
        encodeURIComponent("Enter your name, a valid email and a password of at least 8 characters."));
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (existing.rowCount) {
      return res.redirect("/register?error=" +
        encodeURIComponent("An account with this email already exists."));
    }

    let referrerId = null;

    if (ref) {
      const referral = await pool.query(
        "SELECT id FROM users WHERE referral_code=$1",
        [ref]
      );
      if (referral.rowCount) referrerId = referral.rows[0].id;
    }

    const hashed = await bcrypt.hash(password, 12);
    const code = crypto.randomBytes(5).toString("hex").toUpperCase();

    const result = await pool.query(
      `INSERT INTO users(name,email,password,referral_code,referred_by)
       VALUES($1,$2,$3,$4,$5)
       RETURNING id,name,email,is_admin`,
      [name, email, hashed, code, referrerId]
    );

    req.session.user = result.rows[0];
    res.redirect("/dashboard");
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).send(page("Registration error",
      "<h1>Could not create your account</h1><p>Please try again.</p>"));
  }
});

app.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");

  res.send(page("Login", `
    <div class="card">
      <h1>Login to NEXORE</h1>
      ${req.query.error ? message(req.query.error, "error") : ""}
      <form method="POST" action="/login">
        <label>Email address</label>
        <input type="email" name="email" required>
        <label>Password</label>
        <input type="password" name="password" required>
        <button class="btn" type="submit">Login</button>
      </form>
      <p>New here? <a href="/register">Create an account</a></p>
    </div>
  `));
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT id,name,email,password,is_admin FROM users WHERE email=$1",
      [email]
    );

    if (!result.rowCount ||
        !(await bcrypt.compare(password, result.rows[0].password))) {
      return res.redirect("/login?error=" +
        encodeURIComponent("Incorrect email or password."));
    }

    const user = result.rows[0];
    delete user.password;
    req.session.regenerate(error => {
      if (error) return res.status(500).send("Session error");
      req.session.user = user;
      res.redirect("/dashboard");
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).send("Login failed. Please try again.");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const userId = req.session.user.id;

  const [userResult, referralResult, commissionResult, withdrawalResult] =
    await Promise.all([
      pool.query("SELECT * FROM users WHERE id=$1", [userId]),
      pool.query("SELECT COUNT(*) FROM users WHERE referred_by=$1", [userId]),
      pool.query("SELECT COALESCE(SUM(amount),0) AS total FROM commissions WHERE user_id=$1 AND status='approved'", [userId]),
      pool.query("SELECT COUNT(*) FROM withdrawals WHERE user_id=$1 AND status='pending'", [userId])
    ]);

  const user = userResult.rows[0];
  const referralCount = referralResult.rows[0].count;
  const totalCommission = commissionResult.rows[0].total;
  const pendingWithdrawals = withdrawalResult.rows[0].count;
  const referralLink = `${req.protocol}://${req.get("host")}/register?ref=${user.referral_code}`;

  res.send(page("Dashboard", `
    <h1>Welcome, ${escapeHTML(user.name)}</h1>
    <div class="grid">
      <div class="card"><p>Available Balance</p><div class="stat">${money(user.balance)}</div></div>
      <div class="card"><p>Total Referrals</p><div class="stat">${referralCount}</div></div>
      <div class="card"><p>Approved Commissions</p><div class="stat">${money(totalCommission)}</div></div>
      <div class="card"><p>Pending Withdrawals</p><div class="stat">${pendingWithdrawals}</div></div>
    </div>
    <div class="card">
      <h2>Your Referral Link</h2>
      <input id="refLink" readonly value="${escapeHTML(referralLink)}">
      <button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('refLink').value).then(()=>alert('Referral link copied'))">Copy Link</button>
      <p class="small">Share this link. Referrals do not automatically generate commissions; eligible activity must be reviewed and approved.</p>
    </div>
    <div class="grid">
      <a class="btn" href="/campaigns">View Campaigns</a>
      <a class="btn secondary" href="/wallet">My Wallet</a>
      <a class="btn secondary" href="/history">Transaction History</a>
      ${user.is_admin ? '<a class="btn secondary" href="/admin">Admin Panel</a>' : ""}
    </div>
  `, user));
});

app.get("/campaigns", requireAuth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM campaigns WHERE active=TRUE ORDER BY created_at DESC"
  );

  const cards = result.rows.map(c => `
    <div class="card">
      <h2>${escapeHTML(c.title)}</h2>
      <p>${escapeHTML(c.description)}</p>
      <div class="stat">${money(c.commission)}</div>
      <p class="small">Advertised commission per eligible approved conversion. Terms apply.</p>
    </div>
  `).join("");

  res.send(page("Campaigns", `
    <h1>Affiliate Campaigns</h1>
    ${cards || "<p>No active campaigns are available right now.</p>"}
  `, req.session.user));
});

app.get("/wallet", requireAuth, async (req, res) => {
  const result = await pool.query(
    "SELECT balance FROM users WHERE id=$1",
    [req.session.user.id]
  );

  res.send(page("Wallet", `
    <h1>My Wallet</h1>
    <div class="card">
      <p>Available Balance</p>
      <div class="stat">${money(result.rows[0].balance)}</div>
    </div>
    ${req.query.error ? message(req.query.error, "error") : ""}
    ${req.query.success ? message(req.query.success) : ""}
    <div class="card">
      <h2>Request Withdrawal</h2>
      <p>Minimum withdrawal: ${money(1000)}</p>
      <form method="POST" action="/withdraw">
        <label>Amount (NGN)</label>
        <input type="number" name="amount" min="1000" step="0.01" required>
        <label>Payment method</label>
        <select name="method" required>
          <option value="">Choose method</option>
          <option value="Bank Transfer">Bank Transfer</option>
        </select>
        <label>Bank name, account name and account number</label>
        <textarea name="details" required maxlength="500" placeholder="Enter your bank details"></textarea>
        <button class="btn" type="submit">Submit Request</button>
      </form>
    </div>
    <a href="/history">View transaction history</a>
  `, req.session.user));
});

app.post("/withdraw", requireAuth, async (req, res) => {
  const amount = Number(req.body.amount);
  const method = String(req.body.method || "").trim();
  const details = String(req.body.details || "").trim();
  const userId = req.session.user.id;

  if (!Number.isFinite(amount) || amount < 1000 ||
      !method || !details || details.length > 500) {
    return res.redirect("/wallet?error=" +
      encodeURIComponent("Check your withdrawal details. Minimum withdrawal is ₦1,000."));
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [userId]
    );

    if (!result.rowCount || Number(result.rows[0].balance) < amount) {
      await client.query("ROLLBACK");
      return res.redirect("/wallet?error=" +
        encodeURIComponent("Insufficient available balance."));
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [amount, userId]
    );

    await client.query(
      `INSERT INTO withdrawals(user_id,amount,method,account_details)
       VALUES($1,$2,$3,$4)`,
      [userId, amount, method, details]
    );

    await client.query("COMMIT");
    res.redirect("/wallet?success=" +
      encodeURIComponent("Withdrawal request submitted for admin review."));
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Withdrawal error:", error);
    res.status(500).send("Could not submit withdrawal.");
  } finally {
    client.release();
  }
});

app.get("/history", requireAuth, async (req, res) => {
  const userId = req.session.user.id;

  const [commissions, withdrawals] = await Promise.all([
    pool.query(
      "SELECT amount,description,status,created_at FROM commissions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50",
      [userId]
    ),
    pool.query(
      "SELECT amount,method,status,created_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50",
      [userId]
    )
  ]);

  const commissionRows = commissions.rows.map(item => `
    <tr>
      <td>Commission</td>
      <td>${money(item.amount)}</td>
      <td>${escapeHTML(item.description)}</td>
      <td>${escapeHTML(item.status)}</td>
      <td>${new Date(item.created_at).toLocaleDateString()}</td>
    </tr>
  `).join("");

  const withdrawalRows = withdrawals.rows.map(item => `
    <tr>
      <td>Withdrawal</td>
      <td>${money(item.amount)}</td>
      <td>${escapeHTML(item.method)}</td>
      <td>${escapeHTML(item.status)}</td>
      <td>${new Date(item.created_at).toLocaleDateString()}</td>
    </tr>
  `).join("");

  res.send(page("History", `
    <h1>Transaction History</h1>
    <div class="card table-wrap">
      <table>
        <tr><th>Type</th><th>Amount</th><th>Description</th><th>Status</th><th>Date</th></tr>
        ${commissionRows}${withdrawalRows}
      </table>
      ${!commissionRows && !withdrawalRows ? "<p>No transactions yet.</p>" : ""}
    </div>
  `, req.session.user));
});

app.get("/admin", requireAuth, requireAdmin, async (req, res) => {
  const [users, campaigns, withdrawals] = await Promise.all([
    pool.query("SELECT id,name,email,balance,referral_code,created_at FROM users ORDER BY created_at DESC LIMIT 100"),
    pool.query("SELECT * FROM campaigns ORDER BY created_at DESC"),
    pool.query(
      `SELECT w.*,u.name,u.email FROM withdrawals w
       JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC LIMIT 100`
    )
  ]);

  const userRows = users.rows.map(u => `
    <tr>
      <td>${u.id}</td><td>${escapeHTML(u.name)}</td>
      <td>${escapeHTML(u.email)}</td><td>${money(u.balance)}</td>
      <td>${escapeHTML(u.referral_code)}</td>
    </tr>
  `).join("");

  const campaignRows = campaigns.rows.map(c => `
    <tr>
      <td>${c.id}</td><td>${escapeHTML(c.title)}</td>
      <td>${money(c.commission)}</td><td>${c.active ? "Active" : "Inactive"}</td>
      <td>
        <form method="POST" action="/admin/campaign-toggle">
          <input type="hidden" name="id" value="${c.id}