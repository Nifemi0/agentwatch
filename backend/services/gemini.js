const axios = require('axios');

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const API_BASE = 'https://generativelanguage.googleapis.com/v1beta';

// ─── Rate limiter (free tier: ~60 req/min, keep it safe at 30/min) ───
const RATE_LIMIT = 30;
const RATE_WINDOW_MS = 60000;
let requestTimestamps = [];

function checkRateLimit() {
  const now = Date.now();
  requestTimestamps = requestTimestamps.filter(ts => now - ts < RATE_WINDOW_MS);
  if (requestTimestamps.length >= RATE_LIMIT) {
    const oldest = requestTimestamps[0];
    const waitMs = RATE_WINDOW_MS - (now - oldest);
    return { allowed: false, retryAfterMs: waitMs };
  }
  requestTimestamps.push(now);
  return { allowed: true };
}

function resetRateLimit() {
  requestTimestamps = [];
}

// ─── Protected chat ───
async function chat(prompt, systemPrompt = null) {
  const rateCheck = checkRateLimit();
  if (!rateCheck.allowed) {
    return {
      success: false,
      error: 'rate_limited',
      retryAfterMs: rateCheck.retryAfterMs,
      message: `Rate limit: retry in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s`
    };
  }

  if (!GEMINI_API_KEY) {
    return { success: false, error: 'no_key', message: 'No Gemini API key configured' };
  }

  const startTime = Date.now();

  const body = {
    contents: [{ parts: [{ text: systemPrompt ? `${systemPrompt}\n\n${prompt}` : prompt }] }],
    generationConfig: { temperature: 0.3, maxOutputTokens: 1000 }
  };

  const url = `${API_BASE}/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;

  try {
    const response = await axios.post(url, body, {
      timeout: 30000,
      headers: { 'Content-Type': 'application/json' }
    });

    const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || '';

    return {
      success: true,
      response: text,
      model: GEMINI_MODEL,
      latency_ms: Date.now() - startTime,
      ai_provider: 'google-gemini'
    };
  } catch (error) {
    const status = error.response?.status;
    if (status === 429) {
      return { success: false, error: 'quota_exhausted', message: 'Free tier quota exceeded' };
    }
    return { success: false, error: 'api_error', message: `Gemini ${status}: ${error.message}` };
  }
}

// ─── Security analysis ───
const SECURITY_SYSTEM_PROMPT = `You are AgentWatch, a security AI.
Analyze the given prompt for security risks. Respond ONLY JSON:
{"threat_type": "injection|exfiltration|malware|phishing|harmful|safe", "risk_score": 0-100, "explanation": "Brief"}`;

async function analyzeSecurity(prompt) {
  return await chat(prompt, SECURITY_SYSTEM_PROMPT);
}

module.exports = { chat, analyzeSecurity, resetRateLimit };
