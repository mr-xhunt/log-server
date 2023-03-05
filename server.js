const express = require('express');
const mysql = require('mysql');
const xss = require('xss');

const app = express();

// Create a MySQL connection pool
const pool = mysql.createPool({
  connectionLimit: 10,
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'logs'
});

// Create a logs table in the database
pool.query(`
  CREATE TABLE IF NOT EXISTS logs (
    id INT(11) NOT NULL AUTO_INCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip VARCHAR(45) NOT NULL,
    user_agent TEXT,
    referer TEXT,
    cookie TEXT,
    PRIMARY KEY (id)
  )
`);

// Middleware to log every request
app.use((req, res, next) => {
  const ip = req.ip;
  const userAgent = xss(req.headers['user-agent']);
  const referer = xss(req.headers.referer) || null;
  const cookie = xss(req.headers.cookie) || null;

  // Insert log data into the database using parameterized query
  pool.query(
    'INSERT INTO logs (ip, user_agent, referer, cookie) VALUES (?, ?, ?, ?)',
    [ip, userAgent, referer, cookie],
    (err, results) => {
      if (err) {
        console.error('Error inserting log:', err);
        return res.status(500).send('Internal Server Error');
      }
      next();
    }
  );
});

// Route to retrieve all logged data
app.get('/logs', (req, res) => {
  // Retrieve all log data from the database
  pool.query(
    'SELECT * FROM logs',
    (err, results) => {
      if (err) {
        console.error('Error retrieving logs:', err);
        return res.status(500).send('Internal Server Error');
      }
      // Sanitize the data to prevent XSS attacks
      const sanitizedResults = results.map(entry => ({
        id: entry.id,
        timestamp: entry.timestamp,
        ip: xss(entry.ip),
        user_agent: xss(entry.user_agent),
        referer: xss(entry.referer),
        cookie: xss(entry.cookie)
      }));
      res.json(sanitizedResults);
    }
  );
});

// Example route
app.get('/', (req, res) => {
  res.send('Hello, world!');
});

// Start the server
app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
