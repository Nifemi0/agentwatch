/**
 * Learn Routes — API endpoints for AgentWatch's self-learning system.
 * 
 * Endpoints:
 *   POST /learn/update    — Run the learning pipeline (scrape + extract)
 *   GET  /learn/status    — Current learning status and stats
 *   POST /learn/reload    — Reload patterns from disk (no scrape)
 *   GET  /learn/patterns  — Export all current patterns
 *   POST /learn/prompt    — Generate updated AI security prompt
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { runLearningPipeline, getStatus, generateAIPrompt, loadCurrentPatterns } = require('../learn/threat_scraper');

const PATTERNS_PATH = path.resolve(__dirname, '..', 'learn', 'patterns.json');

// Store a reference to the security router so we can hot-reload
let securityRouter = null;

/**
 * Register the security router for hot-reload.
 */
function setSecurityRouter(router) {
  securityRouter = router;
}

/**
 * Run learning pipeline (scrape internet + generate patterns).
 */
router.post('/update', async (req, res) => {
  const includeScraping = req.body.scrape !== false;
  const includeSeed = req.body.seed !== false;
  
  // Don't wait too long — run in background if scraping
  if (includeScraping) {
    res.json({ status: 'started', message: 'Learning pipeline running in background. Check /learn/status for results.' });
    
    try {
      const report = await runLearningPipeline({ includeScraping, includeSeed });
      console.log(`[LEARN] Update complete: ${report.summary.total_patterns} total patterns`);
      
      // Auto-reload patterns into security engine
      if (securityRouter && typeof securityRouter.hotReloadPatterns === 'function') {
        securityRouter.hotReloadPatterns();
      }
    } catch (e) {
      console.error('[LEARN] Update failed:', e.message);
    }
  } else {
    // Fast path — seed only, no scraping
    try {
      const report = await runLearningPipeline({ includeScraping, includeSeed });
      
      if (securityRouter && typeof securityRouter.hotReloadPatterns === 'function') {
        securityRouter.hotReloadPatterns();
      }
      
      res.json({ status: 'complete', ...report });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
});

/**
 * Get current learning status.
 */
router.get('/status', (req, res) => {
  const status = getStatus();
  res.json(status);
});

/**
 * Reload patterns from disk (no scrape).
 */
router.post('/reload', (req, res) => {
  try {
    const patterns = loadCurrentPatterns();
    if (!patterns) {
      return res.status(404).json({ error: 'No patterns.json found. Run /learn/update first.' });
    }
    
    // Hot-reload into security engine
    if (securityRouter && typeof securityRouter.hotReloadPatterns === 'function') {
      const result = securityRouter.hotReloadPatterns();
      res.json({ status: 'reloaded', patterns_loaded: patterns.meta.total_patterns, ...result });
    } else {
      res.json({ status: 'patterns_loaded', patterns: patterns.meta.total_patterns, warning: 'Security router not registered for hot-reload' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * Export all current patterns.
 */
router.get('/patterns', (req, res) => {
  try {
    const patterns = loadCurrentPatterns();
    if (!patterns) {
      return res.status(404).json({ error: 'No patterns found' });
    }
    res.json(patterns);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * Generate updated AI security prompt from current patterns.
 */
router.post('/prompt', (req, res) => {
  try {
    const prompt = generateAIPrompt();
    if (!prompt) {
      return res.status(404).json({ error: 'No patterns found to generate prompt from' });
    }
    res.json({ prompt, length: prompt.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
module.exports.setSecurityRouter = setSecurityRouter;
