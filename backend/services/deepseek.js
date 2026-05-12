const axios = require('axios');

const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY || '';
const DEEPSEEK_BASE_URL = 'https://api.deepseek.com/v1';
const DEEPSEEK_MODEL = 'deepseek-chat';

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
Only return valid JSON. No markdown.`;

async function analyzeToken(tokenInfo) {
  const startTime = Date.now();

  const payload = {
    model: DEEPSEEK_MODEL,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: formatTokenInfo(tokenInfo) }
    ],
    temperature: 0.3,
    max_tokens: 2000,
    response_format: { type: 'json_object' }
  };

  try {
    const response = await axios.post(
      `${DEEPSEEK_BASE_URL}/chat/completions`,
      payload,
      {
        headers: {
          'Authorization': `Bearer ${DEEPSEEK_API_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 45000
      }
    );

    const content = response.data.choices[0].message.content;
    const result = JSON.parse(content);

    return {
      ...result,
      model: DEEPSEEK_MODEL,
      latency_ms: Date.now() - startTime,
      ai_provider: 'deepseek'
    };
  } catch (error) {
    console.error('DeepSeek analysis error:', error.message);
    // Fallback analysis
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
      recommendations: ['Retry analysis', 'Check API configuration']
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
