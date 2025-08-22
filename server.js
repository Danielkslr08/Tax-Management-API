const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const saltRounds = 10;
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// -------------------- PostgreSQL Connection --------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log('✅ Connected to PostgreSQL database'))
  .catch(err => console.error('❌ PostgreSQL connection error:', err));

// -------------------- JWT CONFIG --------------------
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// -------------------- JWT MIDDLEWARE --------------------
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;

    if (req.params.id && Number(req.params.id) !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (req.params.email && req.params.email !== req.user.email) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (req.params.propertyId) {
      try {
        const result = await pool.query(
          'SELECT user_id FROM properties WHERE id = $1',
          [Number(req.params.propertyId)]
        );
        if (!result.rows.length || result.rows[0].user_id !== req.user.id) {
          return res.status(403).json({ error: 'Forbidden' });
        }
      } catch (err) {
        return res.status(500).json({ error: err });
      }
    }
    return next();
  });
};

// Apply JWT middleware except login/signup
app.use((req, res, next) => {
  if (req.path === '/api/login' || req.path === '/api/add-user') return next();
  authenticateToken(req, res, next);
});

// -------------------- USERS --------------------

// Get all users
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// Add user
app.post('/api/add-user', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'An account with this email already exists.' });
    }

    const hash = await bcrypt.hash(password, saltRounds);
    const insert = await pool.query(
      'INSERT INTO users (email, passwordHash) VALUES ($1, $2) RETURNING id',
      [email, hash]
    );
    const userId = insert.rows[0].id;
    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ id: userId, email, token });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!result.rows.length) return res.status(401).json({ error: 'User not found' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.passwordhash);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ id: user.id, email: user.email, token });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// Delete user and related data
app.delete('/api/users/delete', async (req, res) => {
  const userId = req.user.id;
  try {
    await pool.query('DELETE FROM logs WHERE property_id IN (SELECT id FROM properties WHERE user_id = $1)', [userId]);
    await pool.query('DELETE FROM properties WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// -------------------- PROPERTIES --------------------

app.get('/api/user/properties', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, address, distance, propertyType FROM properties WHERE user_id = $1',
      [req.user.id]
    );
    res.json({ properties: result.rows });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.get('/api/properties/names', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM properties WHERE user_id = $1', [req.user.id]);
    const names = result.rows.map(r => r.name);
    const idList = result.rows.map(r => r.id);
    res.json({ names, idList });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.post('/api/properties', async (req, res) => {
  const user_id = req.user.id;
  const { newCard } = req.body;
  if (!newCard) return res.status(400).json({ error: "Missing data" });

  const { name, distance, address, propertyType } = newCard;
  try {
    const result = await pool.query(
      'INSERT INTO properties (user_id, name, distance, address, propertyType) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [user_id, name, distance, address, propertyType]
    );
    res.json({ id: result.rows[0].id, user_id, name, distance, address, propertyType });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.put('/api/properties/:propertyId', async (req, res) => {
  const { name, distance, address, propertyType } = req.body;
  try {
    await pool.query(
      'UPDATE properties SET name=$1, distance=$2, address=$3, propertyType=$4 WHERE id=$5',
      [name, distance, address, propertyType, Number(req.params.propertyId)]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.delete('/api/properties/:propertyId', async (req, res) => {
  const propertyId = Number(req.params.propertyId);
  try {
    await pool.query('DELETE FROM logs WHERE property_id=$1', [propertyId]);
    await pool.query('DELETE FROM properties WHERE id=$1', [propertyId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// -------------------- LOGS --------------------

app.get('/api/logs/user', async (req, res) => {
  const userId = req.user.id;
  const sql = `
    SELECT 
      logs.id AS id,
      properties.id AS "propertyId",
      properties.name AS "propertyName",
      properties.distance AS distance,
      TO_CHAR(logs.date, 'YYYY-MM-DD') AS date,
      logs.reason AS "travelReason"
    FROM logs
    JOIN properties ON logs.property_id = properties.id
    WHERE properties.user_id = $1
  `;
  try {
    const result = await pool.query(sql, [userId]);
    const formatted = result.rows.map(row => ({
      id: row.id,
      'Property Id': row.propertyId,
      'Property Name': row.propertyName,
      Distance: Number(row.distance),
      Date: row.date,
      'Travel Reason': row.travelReason
    }));
    res.json({ logs: formatted });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.post('/api/user/add-log-and-get-all', async (req, res) => {
  const userId = req.user.id;
  const { log, propertyId } = req.body;
  try {
    const check = await pool.query('SELECT id FROM properties WHERE id=$1 AND user_id=$2', [propertyId, userId]);
    if (!check.rows.length) return res.status(403).json({ error: "Forbidden" });

    await pool.query('INSERT INTO logs (property_id, date, reason) VALUES ($1, $2, $3)', [propertyId, log.date, log.reason]);

    const getLogs = await pool.query(`
      SELECT logs.id, properties.id AS "propertyId", properties.name AS "propertyName",
             properties.distance, TO_CHAR(logs.date, 'YYYY-MM-DD') AS date,
             logs.reason AS "travelReason"
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE properties.user_id = $1
    `, [userId]);

    const formatted = getLogs.rows.map(row => ({
      id: row.id,
      'Property Id': row.propertyId,
      'Property Name': row.propertyName,
      Distance: Number(row.distance),
      Date: row.date,
      'Travel Reason': row.travelReason
    }));
    res.json({ logs: formatted });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.put('/api/user/edit-log-and-get-all', async (req, res) => {
  const userId = req.user.id;
  const { log, propertyId } = req.body;
  try {
    const check = await pool.query(`
      SELECT logs.id 
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE logs.id=$1 AND properties.user_id=$2
    `, [log.id, userId]);
    if (!check.rows.length) return res.status(403).json({ error: "Forbidden" });

    await pool.query('UPDATE logs SET property_id=$1, date=$2, reason=$3 WHERE id=$4',
      [propertyId, log.date, log.reason, log.id]);

    const getLogs = await pool.query(`
      SELECT logs.id, properties.id AS "propertyId", properties.name AS "propertyName",
             properties.distance, TO_CHAR(logs.date, 'YYYY-MM-DD') AS date,
             logs.reason AS "travelReason"
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE properties.user_id = $1
    `, [userId]);

    const formatted = getLogs.rows.map(row => ({
      id: row.id,
      'Property Id': row.propertyId,
      'Property Name': row.propertyName,
      Distance: Number(row.distance),
      Date: row.date,
      'Travel Reason': row.travelReason
    }));
    res.json({ logs: formatted });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.delete('/api/user/delete-log-and-get-all', async (req, res) => {
  const userId = req.user.id;
  const { logId } = req.body;
  try {
    const check = await pool.query(`
      SELECT logs.id 
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE logs.id=$1 AND properties.user_id=$2
    `, [logId, userId]);
    if (!check.rows.length) return res.status(403).json({ error: "Forbidden" });

    await pool.query('DELETE FROM logs WHERE id=$1', [logId]);

    const getLogs = await pool.query(`
      SELECT logs.id, properties.id AS "propertyId", properties.name AS "propertyName",
             properties.distance, TO_CHAR(logs.date, 'YYYY-MM-DD') AS date,
             logs.reason AS "travelReason"
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE properties.user_id = $1
    `, [userId]);

    const formatted = getLogs.rows.map(row => ({
      id: row.id,
      'Property Id': row.propertyId,
      'Property Name': row.propertyName,
      Distance: Number(row.distance),
      Date: row.date,
      'Travel Reason': row.travelReason
    }));
    res.json({ logs: formatted });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// -------------------- START SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
