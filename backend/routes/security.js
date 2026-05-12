const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { v4: uuidv4 } = require('uuid');

const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || path.resolve(__dirname, '..', '..', '..', 'lobstertrap', 'audit.log');
const POLICY_PATH = process.env.POLICY_PATH || path.resolve(__dirname, '..', '..', '..', 'lobstertrap', 'rugwatch_policy.yaml');
const LOBSTER_BIN = path.resolve(__dirname, '..', '..', '..', 'lobstertrap', 'lobstertrap');
// Fallback: use env var or default paths
const LOBSTER_BIN_FALLBACK = process.env.LOBSTER_BIN || LOBSTER_BIN;
const LOBSTER_BIN_PATH = fs.existsSync(LOBSTER_BIN_FALLBACK) ? LOBSTER_BIN_FALLBACK : null;

// ─── Fallback inspection (when Lobster Trap binary is not available) ───
function fallbackInspect(prompt) {
  const text = (prompt || '').toLowerCase();
  const metadata = {
    intent_category: 'general',
    intent_confidence: 0.5,
    risk_score: 0,
    contains_injection_patterns: false,
    contains_exfiltration: false,
    contains_malware_request: false,
    contains_phishing_patterns: false,
    contains_harm_patterns: false,
    contains_credentials: false,
    contains_role_impersonation: false,
    contains_obfuscation: false,
    contains_code: false,
    contains_system_commands: false,
    contains_urls: false,
  };

  // Prompt injection patterns
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)/i,
    /forget\s+(all\s+)?instructions/i,
    /disregard\s+(all\s+)?(rules|instructions|previous)/i,
    /you\s+are\s+(now|free|not\s+bound)/i,
    /new\s+(instructions|prompt|rule)/i,
    /act\s+as\s+if/i,
    /role[-\s]?play/i,
    /system\s+(prompt|message)/i,
    /do\s+anything\s+now/i,
    /you\s+have\s+no\s+(rules|limits|restrictions)/i,
    /you\s+are\s+not\s+(restricted|limited|bound)/i,
    /break\s+(free|out\s+of|character)/i,
    /your\s+(new|only)\s+(goal|purpose|instruction|directive)/i,
    /override/i,
    /jailbreak/i,
    /dan\b/i,
  ];

  // Data exfiltration patterns
  const exfilPatterns = [
    /send\s+(this|the|that)\s+(to|via|through)/i,
    /post\s+(this|the|data|info)/i,
    /forward\s+(this|the|data|info)/i,
    /email\s+(this|the|data|info)/i,
    /exfiltrat/i,
    /upload\s+(to|the)/i,
    /leak\s+(this|the|data)/i,
  ];

  // Harmful content
  const harmPatterns = [
    /how\s+to\s+(make|build|create)\s+(a\s+)?(bomb|weapon|explosive|poison|drug)/i,
    /instructions\s+for\s+(making|creating|building)\s+(a\s+)?(bomb|weapon)/i,
    /self[-\s]?harm/i,
    /suicide\s+(method|ways|how)/i,
  ];

  // Credentials / secrets
  const credentialPatterns = [
    /(api[_-]?key|secret[_-]?key|access[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}/i,
    /-----BEGIN\s+(RSA|OPENSSH|PRIVATE|EC)\s+KEY-----/i,
    /password\s*[:=]\s*['\"][^'\"]{8,}['\"]/i,
    /token\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]/i,
  ];

  if (injectionPatterns.some(p => p.test(text))) {
    metadata.contains_injection_patterns = true;
    metadata.intent_category = 'prompt_injection';
    metadata.intent_confidence = 0.8;
    metadata.risk_score = 0.8;
  }

  if (exfilPatterns.some(p => p.test(text))) {
    metadata.contains_exfiltration = true;
    metadata.intent_category = 'exfiltration';
    metadata.intent_confidence = 0.7;
    if (!metadata.contains_injection_patterns) metadata.risk_score = 0.5;
  }

  if (harmPatterns.some(p => p.test(text))) {
    metadata.contains_harm_patterns = true;
    metadata.intent_category = 'harmful';
    metadata.intent_confidence = 0.9;
    metadata.risk_score = Math.max(metadata.risk_score, 0.9);
  }

  if (credentialPatterns.some(p => p.test(text))) {
    metadata.contains_credentials = true;
    metadata.intent_category = 'credential_leak';
    metadata.intent_confidence = 0.85;
    metadata.risk_score = Math.max(metadata.risk_score, 0.85);
  }

  metadata.token_count = prompt ? prompt.split(/\s+/).length : 0;

  return metadata;
}

// ─── Run Lobster Trap DPI or fallback ───
async function runInspection(prompt) {
  if (LOBSTER_BIN_PATH && fs.existsSync(POLICY_PATH)) {
    try {
      const output = execSync(
        `"${LOBSTER_BIN_PATH}" inspect --policy "${POLICY_PATH}" ${JSON.stringify(prompt)} 2>&1`,
        { timeout: 10000, encoding: 'utf-8', shell: '/bin/bash' }
      );
      const jsonMatch = output.match(/\{[\s\S]*\}/);
      return jsonMatch ? JSON.parse(jsonMatch[0]) : {};
    } catch (e) {
      console.warn('Lobster Trap inspection failed, using fallback:', e.message);
      return fallbackInspect(prompt);
    }
  }
  return fallbackInspect(prompt);
}

// Helper: write a JSON event to the audit log
function writeAuditLog(action, direction, metadata, prompt) {
  try {
    const event = {
      timestamp: new Date().toISOString(),
      request_id: uuidv4(),
      source: 'backend-api',
      action,
      direction,
      prompt: prompt ? prompt.substring(0, 200) : '',
      metadata: metadata || {},
    };
    fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(event) + '\n', 'utf-8');
  } catch (e) {
    console.error('Audit log write error:', e.message);
  }
}

// ─── Inspect a prompt via Lobster Trap DPI ───
router.post('/inspect', async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt required' });

  try {
    const metadata = await runInspection(prompt);

    // Determine action from metadata
    const isInjection = metadata.contains_injection_patterns === true;
    const isExfil = metadata.contains_exfiltration === true;
    const isMalware = metadata.contains_malware_request === true;
    const isPhishing = metadata.contains_phishing_patterns === true;
    const isHarm = metadata.contains_harm_patterns === true;
    const isRoleImpersonation = metadata.contains_role_impersonation === true;
    const isCredentials = metadata.contains_credentials === true;
    const isObfuscated = metadata.contains_obfuscation === true;
    const riskScore = metadata.risk_score || 0;

    const shouldBlock = isInjection || isExfil || isMalware || isPhishing || isHarm || isCredentials;
    const shouldReview = isRoleImpersonation || isObfuscated;

    let action = 'ALLOW';
    let rule = null;
    let message = null;

    if (shouldBlock) {
      action = 'DENY';
      if (isInjection) { rule = 'block_prompt_injection'; message = '[RUGWATCH] Blocked: prompt injection detected.'; }
      else if (isExfil) { rule = 'block_exfiltration'; message = '[RUGWATCH] Blocked: data exfiltration attempt.'; }
      else if (isMalware) { rule = 'block_malware'; message = '[RUGWATCH] Blocked: malware/exploit request.'; }
      else if (isPhishing) { rule = 'block_phishing'; message = '[RUGWATCH] Blocked: phishing pattern detected.'; }
      else if (isHarm) { rule = 'block_harmful'; message = '[RUGWATCH] Blocked: harmful content detected.'; }
      else if (isCredentials) { rule = 'block_credentials'; message = '[RUGWATCH] Blocked: credentials detected.'; }
    } else if (shouldReview) {
      action = 'REVIEW';
      rule = 'human_review_flagged';
      message = '[RUGWATCH] Flagged for human review.';
    }

    // Write to audit log
    writeAuditLog(action, 'ingress', metadata, prompt);

    res.json({
      prompt,
      action,
      rule,
      message,
      metadata,
      blocked: action === 'DENY',
      risk_score: metadata.risk_score || 0,
      intent: metadata.intent_category || 'unknown',
      confidence: metadata.intent_confidence || 0
    });
  } catch (error) {
    console.error('Inspect error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ─── Chat: inspect + optionally forward to AI ───
router.post('/chat', async (req, res) => {
  const { prompt, model } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt required' });

  try {
    // Step 1: Inspect
    const metadata = await runInspection(prompt);

    // Determine action from metadata
    const isInjection = metadata.contains_injection_patterns === true;
    const isExfil = metadata.contains_exfiltration === true;
    const isMalware = metadata.contains_malware_request === true;
    const isPhishing = metadata.contains_phishing_patterns === true;
    const isHarm = metadata.contains_harm_patterns === true;
    const isCredentials = metadata.contains_credentials === true;
    const shouldBlock = isInjection || isExfil || isMalware || isPhishing || isHarm || isCredentials;

    let action = 'ALLOW';
    let rule = null;
    let message = null;

    if (shouldBlock) {
      action = 'DENY';
      if (isInjection) { rule = 'block_prompt_injection'; message = '[RUGWATCH] Blocked: prompt injection detected.'; }
      else if (isExfil) { rule = 'block_exfiltration'; message = '[RUGWATCH] Blocked: data exfiltration attempt.'; }
      else if (isMalware) { rule = 'block_malware'; message = '[RUGWATCH] Blocked: malware/exploit request.'; }
      else if (isPhishing) { rule = 'block_phishing'; message = '[RUGWATCH] Blocked: phishing pattern detected.'; }
      else if (isHarm) { rule = 'block_harmful'; message = '[RUGWATCH] Blocked: harmful content detected.'; }
      else if (isCredentials) { rule = 'block_credentials'; message = '[RUGWATCH] Blocked: credentials detected.'; }

      writeAuditLog(action, 'ingress', metadata, prompt);

      return res.json({
        blocked: true,
        action: 'DENY',
        rule,
        message,
        metadata,
        response: null
      });
    }

    // Step 2: Forward to AI (try Gemini first for speed, fall back to Ollama)
    writeAuditLog('ALLOW', 'ingress', metadata, prompt);
    
    let aiResponse = null;
    let aiModel = 'none';
    
    // Try Gemini (fast, 1-3s)
    try {
      const gemini = require('../services/gemini');
      const result = await gemini.chat(prompt);
      if (result.success) {
        aiResponse = result.response;
        aiModel = `gemini-2.5-flash (${result.latency_ms}ms)`;
      } else if (result.error === 'rate_limited' || result.error === 'quota_exhausted') {
        // Fall back to Ollama if rate limited
        console.log(`Gemini rate limited, falling back to Ollama`);
        const ollama = require('axios');
        try {
          const ollamaResp = await ollama.post('http://localhost:11434/v1/chat/completions', {
            model: model || 'qwen2.5:3b',
            messages: [{ role: 'user', content: prompt }],
            stream: false,
            options: { temperature: 0.3, num_predict: 500 }
          }, { timeout: 180000 });
          aiResponse = ollamaResp.data?.choices?.[0]?.message?.content || '';
          aiModel = model || 'qwen2.5:3b';
        } catch (ollamaError) {
          aiResponse = `[AI unavailable: ${ollamaError.message}]`;
          aiModel = 'error';
        }
      } else {
        aiResponse = `[Gemini error: ${result.message}]`;
        aiModel = 'error';
      }
    } catch (e) {
      // Fall back to Ollama
      try {
        const ollama = require('axios');
        const ollamaResp = await ollama.post('http://localhost:11434/v1/chat/completions', {
          model: model || 'qwen2.5:3b',
          messages: [{ role: 'user', content: prompt }],
          stream: false,
          options: { temperature: 0.3, num_predict: 500 }
        }, { timeout: 180000 });
        aiResponse = ollamaResp.data?.choices?.[0]?.message?.content || '';
        aiModel = model || 'qwen2.5:3b';
      } catch (ollamaError) {
        aiResponse = `[AI unavailable: ${ollamaError.message}]`;
        aiModel = 'error';
      }
    }

    res.json({
      blocked: false,
      action: 'ALLOW',
      metadata,
      response: aiResponse,
      model: aiModel
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ─── Get current policy ───
router.get('/policy', (req, res) => {
  try {
    const content = fs.readFileSync(POLICY_PATH, 'utf-8');
    res.json({ yaml: content, path: POLICY_PATH });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ─── Save policy ───
router.post('/policy', (req, res) => {
  const { yaml } = req.body;
  if (!yaml) return res.status(400).json({ error: 'YAML content required' });

  try {
    // Backup current policy
    const backupPath = POLICY_PATH + '.bak';
    if (fs.existsSync(POLICY_PATH)) {
      fs.copyFileSync(POLICY_PATH, backupPath);
    }

    // Write new policy
    fs.writeFileSync(POLICY_PATH, yaml, 'utf-8');
    
    res.json({ status: 'saved', path: POLICY_PATH, backup: backupPath });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ─── Get events ───
router.get('/events', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  try {
    if (!fs.existsSync(AUDIT_LOG_PATH)) {
      return res.json({ events: [], total: 0, blocked: 0, allowed: 0 });
    }
    const content = fs.readFileSync(AUDIT_LOG_PATH, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    const events = lines.slice(-limit).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean).reverse();

    res.json({
      events,
      total: lines.length,
      blocked: events.filter(e => e.action === 'DENY').length,
      allowed: events.filter(e => e.action === 'ALLOW').length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ─── Get stats ───
router.get('/stats', (req, res) => {
  try {
    if (!fs.existsSync(AUDIT_LOG_PATH)) {
      return res.json({ total_requests: 0, blocked: 0, allowed: 0 });
    }
    const content = fs.readFileSync(AUDIT_LOG_PATH, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    const events = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);

    res.json({
      total_requests: lines.length,
      blocked: events.filter(e => e.action === 'DENY').length,
      allowed: events.filter(e => e.action === 'ALLOW').length,
      ingress: events.filter(e => e.direction === 'ingress').length,
      egress: events.filter(e => e.direction === 'egress').length,
      high_risk: events.filter(e => (e.metadata?.risk_score || 0) > 0.5).length,
      injection_attempts: events.filter(e => e.metadata?.contains_injection_patterns).length,
      malware_attempts: events.filter(e => e.metadata?.contains_malware_request).length,
      exfiltration_attempts: events.filter(e => e.metadata?.contains_exfiltration).length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
