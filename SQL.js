const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');

const jwt = require('jsonwebtoken');

const bcrypt = require('bcrypt'); //bcypt for hashing passwords
const saltRounds = 10;

require("dotenv").config(); //dotenv for .env file to be accessible using process.env

const app = express();
app.use(cors());
app.use(express.json());

// -------------------- MySQL Connection --------------------
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "tax_management_db",
  port: process.env.DB_PORT || 3306,
});

// Test connection
db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ MySQL connection error:', err);
    } else {
        console.log('✅ Connected to MySQL database');
        connection.release();
    }
});

// -------------------- JWT CONFIG --------------------
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// -------------------- JWT MIDDLEWARE --------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user; // { id, email }

    if (req.params.id) {
      if (Number(req.params.id) !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
      return next();
    } else if (req.params.email) {
      if (req.params.email !== req.user.email) return res.status(403).json({ error: 'Forbidden' });
      return next();
    } else if (req.params.propertyId) {
      // Query DB to make sure this property belongs to req.user.id
      return db.query(
        'SELECT user_id FROM properties WHERE id = ?',
        [Number(req.params.propertyId)],
        (err, results) => {
          if (err) return res.status(500).json({ error: err });
          if (!results.length || results[0].user_id !== req.user.id) {
            return res.status(403).json({ error: 'Forbidden' });
          }
          return next();
        }
      );
    }

    // If no relevant param, just continue
    return next();
  });
};

// Apply JWT auth middleware globally, except login & signup
app.use((req, res, next) => {
  // Public routes that don't need a token
  if (
    req.path === '/api/login' || 
    req.path === '/api/add-user'
  ) {
    return next();
  }

  // Everything else requires authentication
  authenticateToken(req, res, next);
});

// -------------------- USERS --------------------

// Get all users
app.get('/api/users', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json(results);
    });
});

// Add user
app.post('/api/add-user', (req, res) => {
    const { email, password } = req.body; // send raw password from frontend

    // Check if user already exists
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) return res.status(500).json({ error: err });

        if (results.length > 0) {
            return res.status(400).json({ error: 'An account with this email already exists.' });
        }

        // Hash password
        bcrypt.hash(password, saltRounds, (err, hash) => {
            if (err) return res.status(500).json({ error: err });

            // Insert new user with hashed password
            db.query('INSERT INTO users (email, passwordHash) VALUES (?, ?)', [email, hash], (err, results) => {
                if (err) return res.status(500).json({ error: err });

                const token = jwt.sign({ id: results.insertId, email }, JWT_SECRET, { expiresIn: '1h' });
                res.json({ id: results.insertId, email, token });
            });
        });
    });
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body; // raw password from frontend

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        if (!results.length) return res.status(401).json({ error: 'User not found' });

        const user = results[0];

        // Compare password with hash
        bcrypt.compare(password, user.passwordHash, (err, match) => {
            if (err) return res.status(500).json({ error: err });
            if (!match) return res.status(401).json({ error: 'Invalid password' });

            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ id: user.id, email: user.email, token });
        });
    });
});

// Delete user and related data
app.delete('/api/users/delete', (req, res) => {
    const userId = req.user.id;
    db.query('DELETE FROM logs WHERE property_id IN (SELECT id FROM properties WHERE user_id = ?)', [userId], (err) => {
        if (err) return res.status(500).json({ error: err });
        db.query('DELETE FROM properties WHERE user_id = ?', [userId], (err) => {
            if (err) return res.status(500).json({ error: err });
            db.query('DELETE FROM users WHERE id = ?', [userId], (err) => {
                if (err) return res.status(500).json({ error: err });
                res.json({ success: true });
            });
        });
    });
});

// -------------------- PROPERTIES --------------------

// Get properties of the authenticated user
app.get('/api/user/properties', (req, res) => {
    const userId = req.user.id; // From JWT

    db.query(
        'SELECT id, name, address, distance, propertyType FROM properties WHERE user_id = ?',
        [userId],
        (err, properties) => {
            if (err) return res.status(500).json({ error: err });
            res.json({ properties });
        }
    );
});

// Get property names and ids for a user
app.get('/api/properties/names', (req, res) => {
    const userId = req.user.id;
    db.query('SELECT id, name FROM properties WHERE user_id = ?', [userId], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        const names = results.map(r => r.name);
        const idList = results.map(r => r.id);
        res.json({ names, idList });
    });
});

// Add property
app.post('/api/properties', (req, res) => {
    const user_id = req.user.id;
    const { newCard } = req.body;
    if (!newCard || !user_id) return res.status(400).json({ error: "Missing data" });

    const { name, distance, address, propertyType } = newCard;
    db.query('INSERT INTO properties (user_id, name, distance, address, propertyType) VALUES (?, ?, ?, ?, ?)',
        [user_id, name, distance, address, propertyType], (err, results) => {
            if (err) return res.status(500).json({ error: err });
            res.json({ id: results.insertId, user_id, name, distance, address, propertyType });
        });
});

// Edit property
app.put('/api/properties/:propertyId', (req, res) => {
    const { name, distance, address, propertyType } = req.body;
    db.query('UPDATE properties SET name = ?, distance = ?, address = ?, propertyType = ? WHERE id = ?',
        [name, distance, address, propertyType, Number(req.params.propertyId)], (err) => {
            if (err) return res.status(500).json({ error: err });
            res.json({ success: true });
        });
});

// Delete property and related logs
app.delete('/api/properties/:propertyId', (req, res) => {
    const propertyId = Number(req.params.propertyId);
    db.query('DELETE FROM logs WHERE property_id = ?', [propertyId], (err) => {
        if (err) return res.status(500).json({ error: err });
        db.query('DELETE FROM properties WHERE id = ?', [propertyId], (err) => {
            if (err) return res.status(500).json({ error: err });
            res.json({ success: true });
        });
    });
});

// -------------------- LOGS --------------------

/*
id: log.id,
"Property Id": property.id,
"Property Name": property.name,
Distance: Number(property.distance),
Date: log.date,
"Travel Reason": log.reason
*/

// Get all logs for all properties of a user (formatted for frontend)
app.get('/api/logs/user', (req, res) => {
  const userId = req.user.id;

  const sql = `
    SELECT 
      logs.id AS id,
      properties.id AS propertyId,
      properties.name AS propertyName,
      properties.distance AS distance,
      DATE_FORMAT(logs.date, '%Y-%m-%d') AS date,
      logs.reason AS travelReason
    FROM logs
    JOIN properties ON logs.property_id = properties.id
    WHERE properties.user_id = ?
  `;

  db.query(sql, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: err });

    // Transform into desired client format
    const formatted = results.map(row => ({
      id: row.id,
      'Property Id': row.propertyId,
      'Property Name': row.propertyName,
      Distance: Number(row.distance),
      Date: row.date,
      'Travel Reason': row.travelReason
    }));

    res.json({ logs: formatted });
  });
});

app.post('/api/user/add-log-and-get-all', (req, res) => {
  const userId = req.user.id;
  const { log, propertyId } = req.body;

  // Verify property ownership before inserting
  const checkSql = `SELECT id FROM properties WHERE id = ? AND user_id = ?`;
  db.query(checkSql, [Number(propertyId), userId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (!results.length) return res.status(403).json({ error: "Forbidden" });

    const insertSql = `INSERT INTO logs (property_id, date, reason) VALUES (?, ?, ?)`;
    db.query(insertSql, [propertyId, log.date, log.reason], (err) => {
      if (err) return res.status(500).json({ error: err });

      // Return updated logs (only user’s)
      const getLogsSql = `
        SELECT logs.id, properties.id AS propertyId, properties.name AS propertyName,
               properties.distance, DATE_FORMAT(logs.date, '%Y-%m-%d') AS date,
               logs.reason AS travelReason
        FROM logs
        JOIN properties ON logs.property_id = properties.id
        WHERE properties.user_id = ?
      `;
      db.query(getLogsSql, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        const formatted = results.map(row => ({
          id: row.id,
          'Property Id': row.propertyId,
          'Property Name': row.propertyName,
          Distance: Number(row.distance),
          Date: row.date,
          'Travel Reason': row.travelReason
        }));
        res.json({ logs: formatted });
      });
    });
  });
});

app.put('/api/user/edit-log-and-get-all', (req, res) => {
  const userId = req.user.id;
  const { log, propertyId } = req.body;

  // Verify both property and log ownership in one query
  const checkSql = `
    SELECT logs.id 
    FROM logs
    JOIN properties ON logs.property_id = properties.id
    WHERE logs.id = ? AND properties.user_id = ?
  `;
  db.query(checkSql, [log.id, userId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (!results.length) return res.status(403).json({ error: "Forbidden" });

    const updateSql = `UPDATE logs SET property_id = ?, date = ?, reason = ? WHERE id = ?`;
    db.query(updateSql, [propertyId, log.date, log.reason, log.id], (err) => {
      if (err) return res.status(500).json({ error: err });

      const getLogsSql = `
        SELECT logs.id, properties.id AS propertyId, properties.name AS propertyName,
               properties.distance, DATE_FORMAT(logs.date, '%Y-%m-%d') AS date,
               logs.reason AS travelReason
        FROM logs
        JOIN properties ON logs.property_id = properties.id
        WHERE properties.user_id = ?
      `;
      db.query(getLogsSql, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        const formatted = results.map(row => ({
          id: row.id,
          'Property Id': row.propertyId,
          'Property Name': row.propertyName,
          Distance: Number(row.distance),
          Date: row.date,
          'Travel Reason': row.travelReason
        }));
        res.json({ logs: formatted });
      });
    });
  });
});

app.delete('/api/user/delete-log-and-get-all', (req, res) => {
  const userId = req.user.id;
  const { logId } = req.body;

  // Verify ownership of log
  const checkSql = `
    SELECT logs.id 
    FROM logs
    JOIN properties ON logs.property_id = properties.id
    WHERE logs.id = ? AND properties.user_id = ?
  `;
  db.query(checkSql, [logId, userId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (!results.length) return res.status(403).json({ error: "Forbidden" });

    db.query('DELETE FROM logs WHERE id = ?', [logId], (err) => {
      if (err) return res.status(500).json({ error: err });

      const getLogsSql = `
        SELECT logs.id, properties.id AS propertyId, properties.name AS propertyName,
               properties.distance, DATE_FORMAT(logs.date, '%Y-%m-%d') AS date,
               logs.reason AS travelReason
        FROM logs
        JOIN properties ON logs.property_id = properties.id
        WHERE properties.user_id = ?
      `;
      db.query(getLogsSql, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        const formatted = results.map(row => ({
          id: row.id,
          'Property Id': row.propertyId,
          'Property Name': row.propertyName,
          Distance: Number(row.distance),
          Date: row.date,
          'Travel Reason': row.travelReason
        }));
        res.json({ logs: formatted });
      });
    });
  });
});

// -------------------- START SERVER --------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

