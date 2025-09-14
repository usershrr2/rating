// backend/server.js
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

// -------------------- Validation middleware --------------------
function validateUserPayload(req, res, next) {
  const { name, email, password, address } = req.body;
  if (!name || !email || !password || !address) {
    return res.status(400).json({ message: "All fields are required." });
  }

  // Name: min 20, max 60
  if (typeof name !== "string" || name.trim().length < 20 || name.trim().length > 60) {
    return res.status(400).json({ message: "Name must be between 20 and 60 characters." });
  }

  // Address: max 400
  if (typeof address !== "string" || address.length > 400) {
    return res.status(400).json({ message: "Address must be at most 400 characters." });
  }

  // Password: 8-16 chars, at least 1 uppercase, at least 1 special char
  const passwordRegex = /^(?=.{8,16}$)(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).*$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      message:
        "Password must be 8-16 characters, include at least one uppercase letter and one special character.",
    });
  }

  // Simple email format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email address." });
  }

  next();
}

// -------------------- Auth middleware --------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// authorizeRoles: admin always allowed, otherwise must match one of required roles
function authorizeRoles(...roles) {
  return (req, res, next) => {
    const role = req.user && req.user.role;
    if (!role) return res.status(401).json({ message: "Unauthorized" });

    if (role === "admin") return next(); // admin override

    for (const r of roles) {
      if (r === role) return next();
    }
    return res.status(403).json({ message: "Access denied" });
  };
}

// -------------------- Helpers --------------------
function normalizeRole(inputRole) {
  if (!inputRole) return "normal";
  const r = String(inputRole).toLowerCase();
  if (r === "admin") return "admin";
  if (r === "store_owner" || r === "owner" || r === "storeowner") return "store_owner";
  return "normal";
}

const ALLOWED_USER_SORT = ["id", "name", "email", "address", "user_role", "created_at"];
const ALLOWED_STORE_SORT = ["id", "name", "address", "owner_id", "created_at"];

// -------------------- Routes --------------------

// Signup (public)
app.post("/signup", validateUserPayload, async (req, res) => {
  const { name, email, password, address, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const roleValue = normalizeRole(role);
    const result = await pool.query(
      "INSERT INTO users (name, email, password, user_role, address) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, user_role",
      [name.trim(), email.toLowerCase(), hashedPassword, roleValue, address.trim()]
    );
    const user = result.rows[0];
    res.status(201).json({ ...user, role: user.user_role });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ message: "Email already exists." });
    }
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email and password required." });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: "Invalid credentials." });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Invalid credentials." });

    const token = jwt.sign({ id: user.id, role: user.user_role }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.user_role } });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// Admin-only: Add user
app.post("/users", authenticateToken, authorizeRoles("admin"), validateUserPayload, async (req, res) => {
  const { name, email, password, address, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const roleValue = normalizeRole(role);
    const result = await pool.query(
      "INSERT INTO users (name, email, password, user_role, address) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, user_role, address",
      [name.trim(), email.toLowerCase(), hashedPassword, roleValue, address.trim()]
    );
    const user = result.rows[0];
    res.status(201).json({ ...user, role: user.user_role });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ message: "Email already exists." });
    }
    console.error("Add user error:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// Admin-only: Add store
app.post("/stores", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { name, address, owner_id } = req.body;
  if (!name || !address || !owner_id) {
    return res.status(400).json({ message: "All fields are required." });
  }
  try {
    const result = await pool.query(
      "INSERT INTO stores (name, address, owner_id) VALUES ($1, $2, $3) RETURNING *",
      [name.trim(), address.trim(), owner_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Add store error:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// Admin dashboard stats
app.get("/admin/dashboard", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const usersResult = await pool.query("SELECT COUNT(*) FROM users");
    const storesResult = await pool.query("SELECT COUNT(*) FROM stores");
    const ratingsResult = await pool.query("SELECT COUNT(*) FROM ratings");
    res.json({
      totalUsers: parseInt(usersResult.rows[0].count, 10),
      totalStores: parseInt(storesResult.rows[0].count, 10),
      totalRatings: parseInt(ratingsResult.rows[0].count, 10),
    });
  } catch (err) {
    console.error("Admin dashboard error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Update user password
app.put("/users/:id/password", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;

  if (req.user.id !== parseInt(id) && req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied" });
  }

  if (!password) {
    return res.status(400).json({ message: "Password is required" });
  }

  const passwordRegex = /^(?=.{8,16}$)(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).*$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      message:
        "Password must be 8-16 characters, include at least one uppercase letter and one special character.",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, id]);
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Password update error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// List & filter users
app.get("/users", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { name, email, address, role, sortBy = "id", order = "asc" } = req.query;
  let sBy = String(sortBy || "id");
  let ord = String(order || "asc").toLowerCase() === "desc" ? "DESC" : "ASC";
  if (!ALLOWED_USER_SORT.includes(sBy)) sBy = "id";

  let query = `SELECT id, name, email, address, user_role FROM users WHERE 1=1`;
  const params = [];
  let idx = 1;

  if (name) { query += ` AND name ILIKE $${idx++}`; params.push(`%${name}%`); }
  if (email) { query += ` AND email ILIKE $${idx++}`; params.push(`%${email}%`); }
  if (address) { query += ` AND address ILIKE $${idx++}`; params.push(`%${address}%`); }
  if (role) { query += ` AND user_role = $${idx++}`; params.push(role); }

  query += ` ORDER BY ${sBy} ${ord}`;

  try {
    const result = await pool.query(query, params);
    res.json(result.rows.map(u => ({ ...u, role: u.user_role })));
  } catch (err) {
    console.error("Users list error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// List & filter stores
app.get("/stores", authenticateToken, async (req, res) => {
  const { name, address, owner_id, sortBy = "id", order = "asc" } = req.query;
  let sBy = String(sortBy || "id");
  let ord = String(order || "asc").toLowerCase() === "desc" ? "DESC" : "ASC";
  if (!ALLOWED_STORE_SORT.includes(sBy)) sBy = "id";

  let query = "SELECT * FROM stores WHERE 1=1";
  const params = [];
  let idx = 1;

  if (name) { query += ` AND name ILIKE $${idx++}`; params.push(`%${name}%`); }
  if (address) { query += ` AND address ILIKE $${idx++}`; params.push(`%${address}%`); }
  if (owner_id) { query += ` AND owner_id = $${idx++}`; params.push(owner_id); }

  query += ` ORDER BY ${sBy} ${ord}`;

  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error("Stores list error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Add or Update rating
app.post("/ratings", authenticateToken, async (req, res) => {
  const { store_id, rating } = req.body;
  const user_id = req.user.id;

  if (!store_id || rating == null) {
    return res.status(400).json({ message: "Store and rating required" });
  }
  if (rating < 1 || rating > 5) {
    return res.status(400).json({ message: "Rating must be between 1 and 5" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO ratings (store_id, user_id, rating)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, store_id)
       DO UPDATE SET rating = EXCLUDED.rating, updated_at = NOW()
       RETURNING *`,
      [store_id, user_id, rating]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Ratings upsert error:", err);
    res.status(500).json({ error: "Database insert/update failed" });
  }
});

// Fetch ratings by store
app.get("/ratings/:store_id", async (req, res) => {
  try {
    const ratings = await pool.query(
      "SELECT r.*, u.name AS user_name FROM ratings r JOIN users u ON r.user_id = u.id WHERE r.store_id = $1",
      [req.params.store_id]
    );

    const avg = await pool.query(
      "SELECT AVG(rating)::numeric(10,2) AS avg_rating, COUNT(*) AS total_ratings FROM ratings WHERE store_id = $1",
      [req.params.store_id]
    );

    res.json({ ratings: ratings.rows, stats: avg.rows[0] });
  } catch (err) {
    console.error("Ratings fetch error:", err);
    res.status(500).json({ error: "Database fetch failed" });
  }
});

// Average rating for a store
app.get("/stores/:id/average-rating", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT AVG(rating)::numeric(10,2) AS avg_rating, COUNT(*) AS total_ratings FROM ratings WHERE store_id = $1",
      [req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Average rating error:", err);
    res.status(500).json({ error: "Database fetch failed" });
  }
});

// Owner dashboard
app.get("/owner/:id/ratings", authenticateToken, authorizeRoles("store_owner"), async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.id !== parseInt(id) && req.user.role !== "admin") {
      return res.status(403).json({ message: "Access denied" });
    }

    const ratings = await pool.query(
      `SELECT u.name, u.email, r.rating, r.created_at, s.name AS store_name
       FROM ratings r
       JOIN users u ON r.user_id = u.id
       JOIN stores s ON r.store_id = s.id
       WHERE s.owner_id = $1`,
      [id]
    );

    const averages = await pool.query(
      `SELECT s.name AS store_name, AVG(r.rating)::numeric(10,2) AS avg_rating
       FROM stores s
       LEFT JOIN ratings r ON s.id = r.store_id
       WHERE s.owner_id = $1
       GROUP BY s.name`,
      [id]
    );

    res.json({ ratings: ratings.rows, averages: averages.rows });
  } catch (err) {
    console.error("Owner dashboard error:", err);
    res.status(500).json({ error: "Owner dashboard fetch failed" });
  }
});

// Root
app.get("/", (req, res) => {
  res.send("Backend is running ✅");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
