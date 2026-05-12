const axios = require('axios');

const OLLAMA_BASE_URL = 'http://localhost:8080';  // Via Lobster Trap proxy
const OLLAMA_MODEL = 'qwen2.5:3b';

const SYSTEM_PROMPT = `You are RugWatch, an AI security analyst specialized in detecting crypto token scams, rugs, and honeypots.

Given token contract details or a token name/description, analyze it for security risks.

Respond in this JSON format:
{
  "risk_score": 0-100,
  "risk_level": "low|medium|high|critical",
  "summary": "Brief one-line summary",
  "detailed_analysis": "Detailed explanation",
  "checks": [
    {
      "category": "liquidity|ownership|code|social|pattern",
      "severity": "info|warning|critical",
      "title": "Check title",
      "description": "What was found",
      "passed": true/false,
      "details": "Extra details"
    }
  ],
  "recommendations": ["rec1", "rec2"]
}

Be thorough. A score of 0-30 is low risk, 30-60 medium, 60-85 high, 85-100 critical.
Only return valid JSON. No markdown. No code fences.`;

async function analyzeToken(tokenInfo) {
  const startTime = Date.now();

  const payload = {
    model: OLLAMA_MODEL,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: formatTokenInfo(tokenInfo) }
    ],
    stream: false,
    options: {
      temperature: 0.3,
      num_predict: 1500
    }
  };

  try {
    const response = await axios.post(
      `${OLLAMA_BASE_URL}/v1/chat/completions`,
      payload,
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 180000
      }
    );

    const content = response.data.choices?.[0]?.message?.content || '';
    let result;

    try {
      result = JSON.parse(content);
    } catch (e) {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        result = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error('Model returned non-JSON: ' + content.substring(0, 100));
      }
    }

    return {
      ...result,
      model: OLLAMA_MODEL,
      latency_ms: Date.now() - startTime,
      ai_provider: 'ollama'
    };
  } catch (error) {
    console.error('Ollama error:', error.message);
    if (error.response) {
      console.error('Ollama response:', error.response.status, error.response.data?.error || JSON.stringify(error.response.data).substring(0, 200));
    }
    return {
      risk_score: 50,
      risk_level: 'medium',
      summary: 'AI analysis unavailable — basic checks applied',
      detailed_analysis: 'Could not connect to AI. Try again.',
      checks: [
        {
          category: 'ai',
          severity: 'warning',
          title: 'AI analysis service error',
          description: `Error: ${error.message}`,
          passed: false,
          details: 'The AI service is temporarily unavailable'
        }
      ],
      recommendations: ['Retry analysis', 'Check AI configuration']
    };
  }
}

function formatTokenInfo(info) {
  const parts = [];
  if (info.name) parts.push(`Token Name: ${info.name}`);
  if (info.symbol) parts.push(`Symbol: ${info.symbol}`);
  if (info.contract) parts.push(`Contract: ${info.contract}`);
  if (info.chain) parts.push(`Chain: ${info.chain}`);
  if (info.description) parts.push(`Description: ${info.description}`);
  if (info.holders) parts.push(`Holders: ${info.holders}`);
  if (info.liquidity) parts.push(`Liquidity: ${info.liquidity}`);
  if (info.supply) parts.push(`Supply: ${info.supply}`);
  if (info.owner) parts.push(`Owner: ${info.owner}`);
  if (info.mint) parts.push(`Mint Authority: ${info.mint}`);
  if (info.freeze) parts.push(`Freeze Authority: ${info.freeze}`);

  parts.push(`\nAnalyze this token for rug potential, scam patterns, and security risks.`);

  return parts.join('\n');
}

module.exports = { analyzeToken };
