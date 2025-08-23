// -------------------- IMPORTS --------------------
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const saltRounds = 10;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// -------------------- POSTGRESQL CONNECTION --------------------
const pool = new Pool({
  connectionString: 'postgresql://postgres:DanielKessler2008!@db.taqaztieujyshpmzzejw.supabase.co:5432/postgres',
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log('✅ Connected to PostgreSQL database'))
  .catch(err => console.error('❌ PostgreSQL connection error:', err));

// -------------------- JWT MIDDLEWARE --------------------
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;

    // Optional ownership checks
    if (req.params.id && Number(req.params.id) !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    if (req.params.email && req.params.email !== req.user.email) return res.status(403).json({ error: 'Forbidden' });
    if (req.params.propertyId) {
      const result = await pool.query('SELECT user_id FROM properties WHERE id=$1', [Number(req.params.propertyId)]);
      if (!result.rows.length || result.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    }

    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Apply middleware except login/signup
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
    res.status(500).json({ error: err.message });
  }
});

// Add user
app.post('/api/add-user', async (req, res) => {
  try {
    const { email, password } = req.body;
    const existing = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Email already exists' });

    const hash = await bcrypt.hash(password, saltRounds);
    const insert = await pool.query(
      'INSERT INTO users (email, passwordhash) VALUES ($1, $2) RETURNING id',
      [email, hash]
    );

    const userId = insert.rows[0].id;
    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ id: userId, email, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!result.rows.length) return res.status(401).json({ error: 'User not found' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.passwordhash);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ id: user.id, email: user.email, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete user and cascade delete properties/logs
app.delete('/api/users/delete', async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------- PROPERTIES --------------------

// Get user's properties
app.get('/api/user/properties', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, address, distance, propertytype FROM properties WHERE user_id=$1',
      [req.user.id]
    );
    res.json({ properties: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get property names for dropdown
app.get('/api/properties/names', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM properties WHERE user_id=$1', [req.user.id]);
    res.json({
      names: result.rows.map(r => r.name),
      idList: result.rows.map(r => r.id)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add property
app.post('/api/properties', async (req, res) => {
  try {
    const { name, distance, address, propertyType } = req.body.newCard;
    const result = await pool.query(
      'INSERT INTO properties (user_id, name, distance, address, propertytype) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [req.user.id, name, distance, address, propertyType]
    );
    res.json({ id: result.rows[0].id, user_id: req.user.id, name, distance, address, propertyType });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update property
app.put('/api/properties/:propertyId', async (req, res) => {
  try {
    const { name, distance, address, propertyType } = req.body;
    await pool.query(
      'UPDATE properties SET name=$1, distance=$2, address=$3, propertytype=$4 WHERE id=$5',
      [name, distance, address, propertyType, Number(req.params.propertyId)]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete property (logs auto-deleted via ON DELETE CASCADE)
app.delete('/api/properties/:propertyId', async (req, res) => {
  try {
    await pool.query('DELETE FROM properties WHERE id=$1', [Number(req.params.propertyId)]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------- LOGS --------------------

// Get all logs for user
app.get('/api/logs/user', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT logs.id, properties.id AS "propertyId", properties.name AS "propertyName",
             properties.distance, TO_CHAR(logs.date, 'YYYY-MM-DD') AS date, logs.reason AS "travelReason"
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE properties.user_id = $1
    `, [req.user.id]);

    res.json({
      logs: result.rows.map(row => ({
        id: row.id,
        'Property Id': row.propertyId,
        'Property Name': row.propertyName,
        Distance: Number(row.distance),
        Date: row.date,
        'Travel Reason': row.travelReason
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add log and return all logs
app.post('/api/user/add-log-and-get-all', async (req, res) => {
  try {
    const { log, propertyId } = req.body;
    const check = await pool.query('SELECT id FROM properties WHERE id=$1 AND user_id=$2', [propertyId, req.user.id]);
    if (!check.rows.length) return res.status(403).json({ error: "Forbidden" });

    await pool.query('INSERT INTO logs (property_id, date, reason) VALUES ($1,$2,$3)', [propertyId, log.date, log.reason]);

    // Return all logs
    const getLogs = await pool.query(`
      SELECT logs.id, properties.id AS "propertyId", properties.name AS "propertyName",
             properties.distance, TO_CHAR(logs.date,'YYYY-MM-DD') AS date, logs.reason AS "travelReason"
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE properties.user_id=$1
    `, [req.user.id]);

    res.json({
      logs: getLogs.rows.map(row => ({
        id: row.id,
        'Property Id': row.propertyId,
        'Property Name': row.propertyName,
        Distance: Number(row.distance),
        Date: row.date,
        'Travel Reason': row.travelReason
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Edit log and return all logs
app.put('/api/user/edit-log-and-get-all', async (req, res) => {
  try {
    const { log, propertyId } = req.body;
    const check = await pool.query(`
      SELECT logs.id FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE logs.id=$1 AND properties.user_id=$2
    `, [log.id, req.user.id]);
    if (!check.rows.length) return res.status(403).json({ error: "Forbidden" });

    await pool.query('UPDATE logs SET property_id=$1, date=$2, reason=$3 WHERE id=$4', [propertyId, log.date, log.reason, log.id]);

    const getLogs = await pool.query(`
      SELECT logs.id, properties.id AS "propertyId", properties.name AS "propertyName",
             properties.distance, TO_CHAR(logs.date,'YYYY-MM-DD') AS date, logs.reason AS "travelReason"
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE properties.user_id=$1
    `, [req.user.id]);

    res.json({
      logs: getLogs.rows.map(row => ({
        id: row.id,
        'Property Id': row.propertyId,
        'Property Name': row.propertyName,
        Distance: Number(row.distance),
        Date: row.date,
        'Travel Reason': row.travelReason
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete log and return all logs
app.delete('/api/user/delete-log-and-get-all', async (req, res) => {
  try {
    const { logId } = req.body;
    const check = await pool.query(`
      SELECT logs.id FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE logs.id=$1 AND properties.user_id=$2
    `, [logId, req.user.id]);
    if (!check.rows.length) return res.status(403).json({ error: "Forbidden" });

    await pool.query('DELETE FROM logs WHERE id=$1', [logId]);

    const getLogs = await pool.query(`
      SELECT logs.id, properties.id AS "propertyId", properties.name AS "propertyName",
             properties.distance, TO_CHAR(logs.date,'YYYY-MM-DD') AS date, logs.reason AS "travelReason"
      FROM logs
      JOIN properties ON logs.property_id = properties.id
      WHERE properties.user_id=$1
    `, [req.user.id]);

    res.json({
      logs: getLogs.rows.map(row => ({
        id: row.id,
        'Property Id': row.propertyId,
        'Property Name': row.propertyName,
        Distance: Number(row.distance),
        Date: row.date,
        'Travel Reason': row.travelReason
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------- START SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
