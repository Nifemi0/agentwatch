const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../models/database');

// List agents
router.get('/', (req, res) => {
  const agents = db.prepare('SELECT * FROM agents ORDER BY created_at DESC').all();
  res.json(agents);
});

// Add agent
router.post('/', (req, res) => {
  const { name, type, config } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'Name and type required' });

  const id = uuidv4();
  db.prepare(`
    INSERT INTO agents (id, name, type, status, config)
    VALUES (?, ?, ?, 'idle', ?)
  `).run(id, name, type, config ? JSON.stringify(config) : null);

  res.json({ id, name, type, status: 'idle' });
});

// Update agent status
router.patch('/:id', (req, res) => {
  const { status, config } = req.body;
  const updates = [];
  const params = [];

  if (status) { updates.push('status = ?'); params.push(status); }
  if (config) { updates.push('config = ?'); params.push(JSON.stringify(config)); }

  updates.push('last_seen = unixepoch()');
  params.push(req.params.id);

  db.prepare(`UPDATE agents SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  res.json({ status: 'updated' });
});

// Get agent stats
router.get('/stats', (req, res) => {
  const stats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
      SUM(CASE WHEN status = 'idle' THEN 1 ELSE 0 END) as idle,
      SUM(CASE WHEN type = 'security_scanner' THEN 1 ELSE 0 END) as scanners
    FROM agents
  `).get();
  res.json(stats);
});

module.exports = router;
