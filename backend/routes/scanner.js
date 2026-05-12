const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../models/database');
const { analyzeToken } = require('../services/ollama');

// Scan a token
router.post('/scan', async (req, res) => {
  const { contract, chain = 'solana', name, symbol, description } = req.body;

  if (!contract && !name) {
    return res.status(400).json({ error: 'Contract address or token name required' });
  }

  const scanId = uuidv4();
  const io = req.app.get('io');

  // Create scan record
  db.prepare(`
    INSERT INTO scans (id, contract_address, chain, token_name, token_symbol, status)
    VALUES (?, ?, ?, ?, ?, 'pending')
  `).run(scanId, contract || 'unknown', chain, name || null, symbol || null);

  res.json({ scan_id: scanId, status: 'pending', message: 'Scan started' });

  // Run analysis asynchronously
  try {
    // Emit progress
    io.to(`scan:${scanId}`).emit('scan:progress', { scan_id: scanId, progress: 10, message: 'Analyzing token...' });

    const result = await analyzeToken({
      contract: contract,
      chain: chain,
      name: name,
      symbol: symbol,
      description: description
    });

    io.to(`scan:${scanId}`).emit('scan:progress', { scan_id: scanId, progress: 80, message: 'Processing results...' });

    // Store results in DB
    const insertCheck = db.prepare(`
      INSERT INTO scan_results (id, scan_id, category, severity, title, description, passed, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    let totalChecks = 0;
    let passedChecks = 0;

    for (const check of (result.checks || [])) {
      insertCheck.run(
        uuidv4(), scanId,
        check.category || 'general',
        check.severity || 'info',
        check.title || 'Unknown check',
        check.description || '',
        check.passed ? 1 : 0,
        check.details || ''
      );
      totalChecks++;
      if (check.passed) passedChecks++;
    }

    // Update scan record
    db.prepare(`
      UPDATE scans SET
        status = 'completed',
        risk_score = ?,
        risk_level = ?,
        summary = ?,
        details = ?,
        completed_at = unixepoch()
      WHERE id = ?
    `).run(
      result.risk_score || 50,
      result.risk_level || 'medium',
      result.summary || '',
      result.detailed_analysis || '',
      scanId
    );

    io.to(`scan:${scanId}`).emit('scan:complete', {
      scan_id: scanId,
      risk_score: result.risk_score,
      risk_level: result.risk_level,
      summary: result.summary,
      checks: result.checks,
      recommendations: result.recommendations
    });

  } catch (error) {
    console.error('Scan error:', error);
    db.prepare(`
      UPDATE scans SET status = 'failed', details = ?, completed_at = unixepoch()
      WHERE id = ?
    `).run(error.message, scanId);

    io.to(`scan:${scanId}`).emit('scan:error', {
      scan_id: scanId,
      error: error.message
    });
  }
});

// Get scan result
router.get('/scan/:id', (req, res) => {
  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const results = db.prepare('SELECT * FROM scan_results WHERE scan_id = ? ORDER BY severity DESC').all(req.params.id);

  res.json({ scan, results });
});

// List recent scans
router.get('/scans', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const scans = db.prepare('SELECT * FROM scans ORDER BY created_at DESC LIMIT ?').all(limit);
  res.json(scans);
});

// Get scan stats
router.get('/stats', (req, res) => {
  const stats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
      SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
      AVG(CASE WHEN risk_score IS NOT NULL THEN risk_score ELSE NULL END) as avg_risk,
      SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical_count,
      SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_count
    FROM scans
    WHERE date(created_at, 'unixepoch') = date('now')
  `).get();

  res.json(stats);
});

module.exports = router;
