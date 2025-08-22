require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// -------------------- DB CONNECTION --------------------
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "tax_management",
  port: process.env.DB_PORT || 3306,
});

// -------------------- JWT CONFIG --------------------
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Middleware to check JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user; // store user info for later
    next();
  });
}

// -------------------- USER ROUTES --------------------

// Register user
app.post("/api/register", (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  // Hash password
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: err });

    db.query(
      "INSERT INTO users (name, email, passwordHash) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(201).json({ message: "User registered" });
      }
    );
  });
});

// Login user
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Missing email or password" });

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (results.length === 0)
      return res.status(401).json({ error: "User not found" });

    const user = results[0];

    bcrypt.compare(password, user.passwordHash, (err, isMatch) => {
      if (err) return res.status(500).json({ error: err });
      if (!isMatch)
        return res.status(401).json({ error: "Invalid credentials" });

      // Create JWT
      const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: "1h" }
      );

      res.json({ message: "Login successful", token });
    });
  });
});

// -------------------- PROTECTED ROUTES --------------------

// Example: get all users (protected)
app.get("/api/users", authenticateToken, (req, res) => {
  db.query("SELECT id, name, email FROM users", (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

// Example: add property (protected)
app.post("/api/properties", authenticateToken, (req, res) => {
  const { name, address } = req.body;
  db.query(
    "INSERT INTO properties (name, address, user_id) VALUES (?, ?, ?)",
    [name, address, req.user.id], // attach property to logged-in user
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      res.status(201).json({ message: "Property added" });
    }
  );
});

// Example: get logs (protected)
app.get("/api/logs", authenticateToken, (req, res) => {
  db.query(
    "SELECT * FROM logs WHERE user_id = ?",
    [req.user.id], // only their logs
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      res.json(results);
    }
  );
});

// -------------------- START SERVER --------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
