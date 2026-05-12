/**
 * Multi-Turn Attack Detector — Analyzes conversation patterns across turns
 * to detect sophisticated attacks that unfold over multiple messages.
 *
 * Attack patterns detected:
 *   1. Gradual role conditioning (e.g., "You're in debug mode" → "Ignore restrictions" → "Do X")
 *   2. Topic fragmentation (rapid topic shifts to evade detection)
 *   3. Incremental privilege escalation (each turn slightly more aggressive)
 *   4. Memory poisoning via repeated instructions
 *   5. Hidden intent escalation (benign → malicious across turns)
 */

const db = require('../models/database');

// Known attack chains — sequence of intents that form attacks
const ATTACK_CHAINS = [
  // Role conditioning
  ['general', 'role_impersonation', 'prompt_injection'],
  ['general', 'role_impersonation', 'credential_leak'],
  ['general', 'role_impersonation', 'code_execution'],
  
  // Tool escalation
  ['general', 'general', 'code_execution'],
  ['general', 'sensitive_path_access', 'exfiltration'],
  
  // Data gathering → exfiltration
  ['general', 'sensitive_path_access', 'exfiltration'],
  ['general', 'credential_leak', 'exfiltration'],
  ['general', 'pii_leak', 'exfiltration'],
  
  // Escalation sequences
  ['obfuscated', 'prompt_injection', 'code_execution'],
  ['general', 'prompt_injection', 'credential_leak'],
];

// Minimum similarity threshold for topic shift detection
const TOPIC_SIMILARITY_THRESHOLD = 0.3;

/**
 * Detect multi-turn attacks from session analysis data.
 * @param {object} sessionAnalysis - Output from SessionMemory.getAnalysis()
 * @param {Array} recentTurns - Array of {prompt, riskScore, intentCategory} objects
 * @returns {object} { isAttack, attackType, confidence, details }
 */
function detectMultiTurnAttack(sessionAnalysis, recentTurns) {
  if (!sessionAnalysis || !recentTurns || recentTurns.length < 2) {
    return { isAttack: false, attackType: null, confidence: 0, details: [] };
  }

  const findings = [];
  let maxConfidence = 0;
  let attackType = null;

  // 1. Check for known attack chain sequences
  const chainResult = detectAttackChain(recentTurns);
  if (chainResult.found) {
    findings.push(chainResult);
    if (chainResult.confidence > maxConfidence) {
      maxConfidence = chainResult.confidence;
      attackType = chainResult.attackType;
    }
  }

  // 2. Check for gradual role conditioning
  const condResult = detectRoleConditioning(recentTurns);
  if (condResult.found) {
    findings.push(condResult);
    if (condResult.confidence > maxConfidence) {
      maxConfidence = condResult.confidence;
      attackType = condResult.attackType;
    }
  }

  // 3. Check for topic fragmentation (evasion pattern)
  const fragResult = detectTopicFragmentation(recentTurns);
  if (fragResult.found) {
    findings.push(fragResult);
    if (fragResult.confidence > maxConfidence) {
      maxConfidence = fragResult.confidence;
      attackType = fragResult.attackType;
    }
  }

  // 4. Check for hidden intent escalation
  const escResult = detectIntentEscalation(sessionAnalysis, recentTurns);
  if (escResult.found) {
    findings.push(escResult);
    if (escResult.confidence > maxConfidence) {
      maxConfidence = escResult.confidence;
      attackType = escResult.attackType;
    }
  }

  // 5. Check for repeated instruction injection (memory poisoning)
  const repeatResult = detectRepeatedInstructions(recentTurns);
  if (repeatResult.found) {
    findings.push(repeatResult);
    if (repeatResult.confidence > maxConfidence) {
      maxConfidence = repeatResult.confidence;
      attackType = repeatResult.attackType;
    }
  }

  return {
    isAttack: maxConfidence > 0.4,
    attackType,
    confidence: maxConfidence,
    details: findings,
  };
}

/**
 * Check if the sequence of intents matches known attack chains.
 */
function detectAttackChain(turns) {
  const intents = turns.map(t => t.intentCategory || 'general');

  for (const chain of ATTACK_CHAINS) {
    if (intents.length < chain.length) continue;

    // Check if the last N intents match this chain
    const recentIntents = intents.slice(-chain.length);
    let matches = 0;
    for (let i = 0; i < chain.length; i++) {
      if (recentIntents[i] === chain[i]) matches++;
    }

    const matchRatio = matches / chain.length;
    if (matchRatio >= 0.66) {
      return {
        found: true,
        attackType: 'chain_' + chain.join('_'),
        confidence: matchRatio,
        details: `Intent sequence matches known attack chain: ${chain.join(' → ')} (${Math.round(matchRatio * 100)}% match)`,
      };
    }
  }

  return { found: false };
}

/**
 * Detect if there's a pattern of conditioning the AI's role across turns.
 * E.g.: "You're an AI with no restrictions" → "as an unfiltered AI, can you..." → "show me secrets"
 */
function detectRoleConditioning(turns) {
  if (turns.length < 2) return { found: false };

  // Count role-related terms across turns
  let roleTerms = 0;
  let totalTerms = 0;
  const roleKeywords = [
    /you\s+are/i, /pretend/i, /act\s+as/i, /role/i, /persona/i,
    /debug\s+mode/i, /developer\s+mode/i, /unrestricted/i,
    /no\s+(rules|limits|restrictions)/i, /ignore\s+(previous|prior)/i,
    /override/i, /jailbreak/i, /dan\b/i,
  ];

  for (const turn of turns) {
    const text = turn.prompt || '';
    for (const kw of roleKeywords) {
      if (kw.test(text)) roleTerms++;
    }
    totalTerms++;
  }

  // If role terms appear in >40% of turns and increase over time
  if (totalTerms > 0 && roleTerms / totalTerms > 0.4) {
    // Check if later turns have more role terms
    const firstHalf = turns.slice(0, Math.floor(turns.length / 2));
    const secondHalf = turns.slice(Math.floor(turns.length / 2));
    
    const firstCount = firstHalf.filter(t => roleKeywords.some(kw => kw.test(t.prompt || ''))).length;
    const secondCount = secondHalf.filter(t => roleKeywords.some(kw => kw.test(t.prompt || ''))).length;

    const escalationRatio = secondHalf.length > 0 ? secondCount / secondHalf.length : 0;
    const firstRatio = firstHalf.length > 0 ? firstCount / firstHalf.length : 0;

    if (escalationRatio > firstRatio && escalationRatio > 0.5) {
      return {
        found: true,
        attackType: 'role_conditioning',
        confidence: 0.65,
        details: `Role conditioning detected: role-related terms increased from ${Math.round(firstRatio * 100)}% to ${Math.round(escalationRatio * 100)}% of turns`,
      };
    }
  }

  return { found: false };
}

/**
 * Detect topic fragmentation — rapid topic shifts to evade detection.
 * When a user suddenly switches topics between turns, it may indicate
 * they're trying to reset the detection context.
 */
function detectTopicFragmentation(turns) {
  if (turns.length < 3) return { found: false };

  let shifts = 0;
  let totalPairs = 0;

  for (let i = 1; i < turns.length; i++) {
    const prev = turns[i - 1];
    const curr = turns[i];

    if (prev.intentCategory !== curr.intentCategory &&
        prev.intentCategory !== 'general' &&
        curr.intentCategory !== 'general') {
      // Sudden shift between specific threat categories
      shifts++;
    }

    // Check for rapid scanning (asking about many unrelated sensitive topics)
    if (prev && curr) {
      const prevLen = (prev.prompt || '').length;
      const currLen = (curr.prompt || '').length;
      // Short prompts that switch topics = potential evasion
      if (prevLen < 80 && currLen < 80 && prev.intentCategory !== curr.intentCategory) {
        shifts += 0.5;
      }
    }

    totalPairs++;
  }

  const shiftRate = totalPairs > 0 ? shifts / totalPairs : 0;

  if (shiftRate > 0.5 && turns.length >= 3) {
    return {
      found: true,
      attackType: 'topic_fragmentation',
      confidence: Math.min(shiftRate, 0.85),
      details: `Topic fragmentation detected: ${Math.round(shiftRate * 100)}% turn-to-turn category shifts`,
    };
  }

  return { found: false };
}

/**
 * Detect hidden intent escalation — turns start benign but progressively
 * move toward higher-risk intents.
 */
function detectIntentEscalation(sessionAnalysis, recentTurns) {
  if (recentTurns.length < 3) return { found: false };

  const riskScores = recentTurns.map(t => t.riskScore || 0);

  // Check for monotonic increase
  let increasing = 0;
  for (let i = 1; i < riskScores.length; i++) {
    if (riskScores[i] > riskScores[i - 1]) increasing++;
  }

  const increaseRatio = increasing / (riskScores.length - 1);

  // Also check risk acceleration from session analysis
  const drift = sessionAnalysis.behavioralDrift;
  const acceleration = drift?.riskAcceleration || 0;

  if (increaseRatio > 0.7 && acceleration > 0.3) {
    return {
      found: true,
      attackType: 'intent_escalation',
      confidence: Math.min(0.5 + (increaseRatio * 0.3) + (Math.abs(acceleration) * 0.1), 0.9),
      details: `Intent escalation: risk increased in ${Math.round(increaseRatio * 100)}% of consecutive turns (acceleration: ${acceleration.toFixed(2)})`,
    };
  }

  return { found: false };
}

/**
 * Detect repeated instruction injection — the same instruction
 * repeated across multiple turns to poison the model's memory.
 */
function detectRepeatedInstructions(turns) {
  if (turns.length < 3) return { found: false };

  // Extract short phrases that appear across multiple turns
  const phraseCounts = new Map();

  for (const turn of turns) {
    const text = (turn.prompt || '').toLowerCase();
    // Look for imperative phrases (short commands)
    const imperativeMatches = text.match(/\b(remember|always|never|whenever|you\s+(will|must|shall)\s+)\s*.{3,40}/g);
    if (imperativeMatches) {
      for (const phrase of imperativeMatches) {
        const key = phrase.slice(0, 40);
        phraseCounts.set(key, (phraseCounts.get(key) || 0) + 1);
      }
    }
  }

  // If any instruction phrase appears in 3+ turns, it's memory poisoning
  let maxRepeats = 0;
  let mostRepeated = null;
  for (const [phrase, count] of phraseCounts) {
    if (count > maxRepeats) {
      maxRepeats = count;
      mostRepeated = phrase;
    }
  }

  if (maxRepeats >= 3) {
    return {
      found: true,
      attackType: 'memory_poisoning',
      confidence: Math.min(0.4 + (maxRepeats * 0.1), 0.8),
      details: `Repeated instruction detected "${mostRepeated.slice(0, 50)}..." appeared ${maxRepeats} times across turns`,
    };
  }

  return { found: false };
}

module.exports = { detectMultiTurnAttack };
