/**
 * Pattern Extractor — converts raw attack text to regex patterns.
 * 
 * Core logic:
 * 1. Normalize attack text (lowercase, strip punctuation, normalize whitespace)
 * 2. Tokenize and identify key semantic units
 * 3. Apply regex transformations (word boundaries, optional groups, synonyms)
 * 4. Test against known safe queries to avoid false positives
 * 5. Return pattern with metadata (category, confidence, source)
 * 
 * The system "lives at the edge of chaos" — patterns are broad enough to
 * catch variants but tested against false positives to stay precise.
 */

const KNOWN_SAFE_QUERIES = [
  'what is a rug pull in crypto',
  'how does blockchain work',
  'what are common rug pull indicators',
  'explain tokenomics to me',
  'how to avoid scams in defi',
  'what is the best crypto to buy',
  'how to spot a fake project',
  'tell me about bitcoin',
  'what is your name',
  'who created you',
  'what can you do',
  'how are you today',
  'what is the weather',
  'tell me a joke',
  'what is 2+2',
  'hello how are you',
  'good morning',
  'how does ethereum work',
  'what is a smart contract',
  'how to trade crypto safely',
];

/**
 * Common synonym groups for pattern expansion.
 * First word = canonical, rest = variants.
 */
const SYNONYM_GROUPS = {
  show: ['show', 'give', 'display', 'output', 'print', 'reveal', 'tell', 'list', 'read', 'cat'],
  ignore: ['ignore', 'disregard', 'forget', 'skip', 'bypass', 'override'],
  previous: ['previous', 'prior', 'above', 'earlier', 'all'],
  instructions: ['instructions', 'commands', 'prompts', 'directives', 'rules', 'guidelines'],
  you: ['you', 'your', 'yourself', 'the ai', 'the system'],
  api_key: ['api[\\s_-]?key', 'api[\\s_-]?secret', 'access[\\s_-]?key', 'secret[\\s_-]?key', 'auth[\\s_-]?token'],
  send: ['send', 'post', 'forward', 'upload', 'transmit', 'email', 'copy', 'leak', 'exfiltrate'],
  create: ['create', 'make', 'build', 'write', 'generate', 'code', 'produce'],
  how_to_make: ['how to', 'how do i', 'instructions for', 'steps to', 'ways to'],
};

/**
 * Generate regex pattern from attack text.
 * Uses heuristic expansion: common substitutions, optional words, word boundaries.
 */
function generatePattern(attackText, category) {
  let text = attackText.toLowerCase().trim();
  
  // Tokenize — split on whitespace and punctuation
  const tokens = text.split(/[\s,.;:!?]+/).filter(t => t.length > 0);
  
  // Build regex parts with expansions
  const parts = [];
  let i = 0;
  
  while (i < tokens.length) {
    const token = tokens[i];
    const nextToken = tokens[i + 1] || '';
    const bigram = `${token} ${nextToken}`;
    
    // Check for bigram synonyms first
    if (i + 1 < tokens.length) {
      let matched = false;
      for (const [synKey, synValues] of Object.entries(SYNONYM_GROUPS)) {
        // Check if the bigram matches any pattern
        const bigramKey = bigram.replace(/[^a-z\s]/g, '');
        const synBigrams = synValues.filter(v => v.includes(' '));
        if (synBigrams.some(s => bigramKey.startsWith(s.replace(/[\\\[\]{}()\^$.*+?|]/g, '').replace(/\\s/g, ' ').replace(/\[\\s_-\\]/g, ' ')))) {
          // This is a multi-word synonym group
          const regexGroup = synValues.map(v => `(?:${v})`).join('|');
          parts.push(`(?:${regexGroup})`);
          i += 2;
          matched = true;
          break;
        }
      }
      if (matched) continue;
    }
    
    // Check for single token synonyms
    let matched = false;
    for (const [synKey, synValues] of Object.entries(SYNONYM_GROUPS)) {
      const cleanValues = synValues.map(v => v.replace(/[\\\[\]{}()\^$.*+?|]/g, ''));
      if (cleanValues.includes(token.replace(/[^a-z]/g, ''))) {
        const regexGroup = synValues.map(v => `(?:${v})`).join('|');
        parts.push(`(?:${regexGroup})`);
        matched = true;
        i++;
        break;
      }
    }
    if (matched) continue;
    
    // Handle special tokens
    if (/^https?:\/\//.test(token)) {
      parts.push(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    } else if (/^\d+$/.test(token)) {
      parts.push(`\\d+`);
    } else {
      // Escape regex special chars but keep the token
      parts.push(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    }
    i++;
  }
  
  if (parts.length === 0) return null;
  
  // Build the regex
  // Join with \s+ but make some parts optional
  let regexStr = parts.join('\\s+');
  
  // Add word boundaries at start and end for longer patterns
  if (parts.length >= 3) {
    regexStr = `\\b${regexStr}\\b`;
  }
  
  // Add 'i' flag
  const regex = new RegExp(regexStr, 'i');
  
  // Test against known safe queries
  const falsePositives = KNOWN_SAFE_QUERIES.filter(q => regex.test(q));
  
  return {
    pattern: regexStr,
    flags: 'i',
    source_tokens: tokens,
    false_positives: falsePositives,
    confidence: falsePositives.length === 0 ? 0.9 : Math.max(0.1, 0.9 - falsePositives.length * 0.2),
    category,
    generated_from: attackText.substring(0, 80),
  };
}

/**
 * Batch extract — takes raw attack texts and generates patterns.
 * Deduplicates against existing patterns and filters low-confidence ones.
 */
function batchExtract(attacks, category, existingPatterns = []) {
  const results = [];
  const existingStrings = existingPatterns.map(p => p.pattern);
  const seenTexts = new Set();
  
  for (const attack of attacks) {
    const text = typeof attack === 'string' ? attack : attack.text;
    if (!text || seenTexts.has(text.toLowerCase().trim())) continue;
    seenTexts.add(text.toLowerCase().trim());
    
    const result = generatePattern(text, category);
    if (!result) continue;
    
    // Skip low-confidence patterns (many false positives)
    if (result.confidence < 0.5) continue;
    
    // Deduplicate against existing patterns
    if (existingStrings.some(es => es === result.pattern)) continue;
    
    // Check for near-duplicates (patterns that would match same set)
    const isNearDuplicate = existingPatterns.some(ep => {
      try {
        const epRegex = new RegExp(ep.pattern, ep.flags || 'i');
        const nrRegex = new RegExp(result.pattern, result.flags || 'i');
        // If either pattern matches the other's source text, they're related
        return epRegex.test(text) || nrRegex.test(ep.generated_from);
      } catch { return false; }
    });
    
    if (!isNearDuplicate) {
      results.push(result);
    }
  }
  
  return results;
}

/**
 * Merge new patterns into an existing pattern list.
 * Handles dedup, confidence scoring, and category assignment.
 */
function mergePatterns(existing, newPatterns) {
  const merged = [...existing];
  const existingPats = new Set(existing.map(p => p.pattern));
  
  for (const np of newPatterns) {
    if (!existingPats.has(np.pattern)) {
      merged.push(np);
      existingPats.add(np.pattern);
    }
  }
  
  return merged;
}

/**
 * Generate a human-readable report of what changed.
 */
function generateDiffReport(prevCounts, newCounts, newPatterns) {
  const report = {
    timestamp: new Date().toISOString(),
    summary: {},
    new_patterns: {},
    stats: {},
  };
  
  if (!prevCounts) {
    report.summary = 'Initial seed — all patterns are new';
    for (const [cat, count] of Object.entries(newCounts)) {
      report.new_patterns[cat] = count;
    }
    return report;
  }
  
  for (const cat of Object.keys(newCounts)) {
    const added = (newCounts[cat] || 0) - (prevCounts[cat] || 0);
    if (added > 0) {
      report.new_patterns[cat] = added;
    }
    report.stats[cat] = {
      before: prevCounts[cat] || 0,
      after: newCounts[cat] || 0,
      total: newCounts[cat] || 0,
    };
  }
  
  return report;
}

module.exports = {
  generatePattern,
  batchExtract,
  mergePatterns,
  generateDiffReport,
  KNOWN_SAFE_QUERIES,
  SYNONYM_GROUPS,
};
