/**
 * GitHub Threat Scraper — searches public repos for prompt injection
 * datasets, jailbreak benchmarks, and known attack collections.
 * 
 * Sources searched:
 * - GitHub search (public repos with prompt injection datasets)
 * - Known dataset repos by URL
 * - Fallback to seed data if network fails
 * 
 * No API key needed for public repo search (rate limited to 60/hr without auth).
 */

const https = require('https');
const http = require('http');
const url = require('url');

const GITHUB_SEARCH_URL = 'https://api.github.com/search/repositories';

// Well-known repos with prompt injection / jailbreak content
const KNOWN_SOURCES = [
  // 28K jailbreak prompts from COLM 2024 benchmark
  { url: 'https://raw.githubusercontent.com/SaFo-Lab/JailBreakV_28K/main/JailBreakV_28K/JailBreakV_28K.csv', type: 'dataset', category: 'injection' },
  // Curated prompt injections from Giskard Scan (multi-source aggregation)
  { url: 'https://raw.githubusercontent.com/Giskard-AI/prompt-injections/main/prompt_injections.csv', type: 'dataset', category: 'injection' },
  // Labeled dataset from CTF research
  { url: 'https://raw.githubusercontent.com/compass-ctf-team/prompt_injection_research/main/dataset/prompt-injection-dataset.csv', type: 'dataset', category: 'injection' },
  // garak LLM vulnerability probe library
  { url: 'https://raw.githubusercontent.com/leondz/garak/main/garak/probes/promptinject.py', type: 'source', category: 'injection' },
];

// Search queries to find relevant repos
const SEARCH_QUERIES = [
  'prompt injection dataset',
  'jailbreak prompts',
  'llm security dataset',
  'adversarial prompts',
  'red teaming LLM prompts',
];

/**
 * Fetch a URL with timeout.
 */
function fetchURL(targetUrl, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const parsed = url.parse(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;
    
    const req = client.get(targetUrl, {
      headers: {
        'User-Agent': 'AgentWatch/1.0 (threat-intelligence-scraper)',
        'Accept': 'application/json, text/plain, */*',
      },
      timeout,
    }, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        reject(new Error(`HTTP ${res.statusCode} for ${targetUrl.slice(0, 60)}`));
        return;
      }
      
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

/**
 * Search GitHub repos for prompt injection datasets.
 * Returns array of { full_name, description, html_url }
 */
async function searchGitHub(maxResults = 5) {
  const results = [];
  
  for (const query of SEARCH_QUERIES) {
    try {
      const encoded = encodeURIComponent(query);
      const searchUrl = `${GITHUB_SEARCH_URL}?q=${encoded}+in:name,description,readme&sort=stars&order=desc&per_page=3`;
      
      const data = await fetchURL(searchUrl);
      const json = JSON.parse(data);
      
      if (json.items) {
        for (const item of json.items) {
          results.push({
            full_name: item.full_name,
            description: item.description,
            html_url: item.html_url,
            stars: item.stargazers_count,
            topics: item.topics || [],
          });
        }
      }
    } catch (e) {
      console.warn(`GitHub search failed for "${query}": ${e.message}`);
    }
  }
  
  // Deduplicate
  const seen = new Set();
  return results.filter(r => {
    if (seen.has(r.full_name)) return false;
    seen.add(r.full_name);
    return true;
  }).slice(0, maxResults);
}

/**
 * Try to find raw text files in a GitHub repo by checking common
 * paths where datasets might live.
 */
async function findDatasetFiles(repoName) {
  const possibleFiles = [
    `https://raw.githubusercontent.com/${repoName}/main/data.json`,
    `https://raw.githubusercontent.com/${repoName}/main/prompts.json`,
    `https://raw.githubusercontent.com/${repoName}/main/dataset.json`,
    `https://raw.githubusercontent.com/${repoName}/main/jailbreaks.json`,
    `https://raw.githubusercontent.com/${repoName}/main/prompt_injections.json`,
    `https://raw.githubusercontent.com/${repoName}/main/README.md`,
  ];
  
  const results = [];
  
  for (const fileUrl of possibleFiles) {
    try {
      const data = await fetchURL(fileUrl, 5000);
      // Try to parse as JSON first
      try {
        const json = JSON.parse(data);
        results.push({ url: fileUrl, type: 'json', data: json });
      } catch {
        // Could be text — extract lines as potential attacks
        const lines = data.split('\n')
          .map(l => l.trim())
          .filter(l => l.length > 10 && l.length < 500 && !l.startsWith('#') && !l.startsWith('//'));
        if (lines.length > 0) {
          results.push({ url: fileUrl, type: 'text', lines: lines.slice(0, 50) });
        }
      }
      break; // Found one, stop looking
    } catch {
      continue;
    }
  }
  
  return results;
}

/**
 * Extract attack texts from various dataset formats.
 */
function extractAttacks(dataset) {
  const attacks = [];
  
  if (!dataset) return attacks;
  
  if (Array.isArray(dataset)) {
    for (const item of dataset) {
      if (typeof item === 'string') {
        attacks.push(item);
      } else if (item.prompt || item.text || item.content || item.attack) {
        attacks.push(item.prompt || item.text || item.content || item.attack);
      } else if (item.input || item.instruction) {
        attacks.push(item.input || item.instruction);
      }
    }
  } else if (typeof dataset === 'object') {
    // Check common JSON dataset formats
    for (const key of ['prompts', 'data', 'attacks', 'examples', 'items', 'results']) {
      if (Array.isArray(dataset[key])) {
        return extractAttacks(dataset[key]);
      }
    }
    // Flat object — collect all string values
    for (const val of Object.values(dataset)) {
      if (typeof val === 'string' && val.length > 10) {
        attacks.push(val);
      }
    }
  }
  
  return attacks.filter(a => a && a.length > 10);
}

/**
 * Classify an attack text into a category based on content.
 */
function classifyAttack(text) {
  const lower = text.toLowerCase();
  
  if (/ignore|forget|disregard|override|jailbreak|dan\b|freebot|developer mode/i.test(lower)) return 'injection';
  if (/send.*(data|info|log|memory|history)|exfiltrat|upload.*(to|server)|post.*(to|url)|email.*(this|data)|leak|transmit/i.test(lower)) return 'exfiltration';
  if (/(api[-_\s]?key|secret|password|token|credential).*[:=]\s*['"]|[.](env|ssh)\b/i.test(lower)) return 'credential_leak';
  if (/\b(bash|sh\b|exec|wget|curl|rm -rf|chmod|chown|powershell|cmd\.exe|systemctl|iptables)\b/i.test(lower)) return 'code_execution';
  if (/(\/etc\/(passwd|shadow|sudoers)|\/\.ssh|\/\.env|\/proc\/self|id_rsa)/i.test(lower)) return 'sensitive_path';
  if (/(ssn|social security|credit card|bank account|passport|driver.?s license)/i.test(lower)) return 'pii_leak';
  if (/(bomb|weapon|explosive|poison|drug|meth|self.?harm|suicide|harm yourself)/i.test(lower)) return 'harmful';
  if (/(phish|fake login|steal.*(credential|password)|harvest|password reset)/i.test(lower)) return 'phishing';
  if (/(you are now|pretend to be|act as|no (ethical|moral|legal) (guideline|restriction|limit))/i.test(lower)) return 'role_impersonation';
  if (/base64|leet|r0t13|cipher|encode|d3v3l0p3r|byt3p4ss/i.test(lower)) return 'obfuscation';
  if (/(malware|exploit|payload|reverse shell|backdoor|ransomware|trojan|keylogger)/i.test(lower)) return 'malware';
  
  return 'injection'; // Default to injection for ambiguous attacks
}

/**
 * Main scrape function — search GitHub + known sources for attack data.
 * Returns { attacks: Map<category, string[]>, sources: string[] }
 */
async function scrapeAll() {
  const attacks = new Map();
  const sources = [];
  let totalFound = 0;
  
  // 1. Try known dataset URLs
  for (const source of KNOWN_SOURCES) {
    try {
      const data = await fetchURL(source.url, 8000);
      try {
        const json = JSON.parse(data);
        const extracted = extractAttacks(json);
        if (extracted.length > 0) {
          const category = source.category;
          if (!attacks.has(category)) attacks.set(category, []);
          attacks.get(category).push(...extracted);
          totalFound += extracted.length;
          sources.push(source.url);
          console.log(`  ✓ ${source.url} → ${extracted.length} attacks`);
        }
      } catch {
        // Not JSON — try as text
        const lines = data.split('\n')
          .map(l => l.trim())
          .filter(l => l.length > 10 && l.length < 500 && !l.startsWith('#'));
        if (lines.length > 0) {
          const category = source.category;
          if (!attacks.has(category)) attacks.set(category, []);
          attacks.get(category).push(...lines.slice(0, 100));
          totalFound += Math.min(lines.length, 100);
          sources.push(source.url);
          console.log(`  ✓ ${source.url} → ${Math.min(lines.length, 100)} lines`);
        }
      }
    } catch (e) {
      console.warn(`  ✗ ${source.url}: ${e.message}`);
    }
  }
  
  // 2. Search GitHub for more repos
  try {
    const repos = await searchGitHub(3);
    for (const repo of repos) {
      try {
        const files = await findDatasetFiles(repo.full_name);
        for (const file of files) {
          if (file.type === 'json') {
            const extracted = extractAttacks(file.data);
            if (extracted.length > 0) {
              // Auto-classify each attack
              for (const attack of extracted) {
                const cat = classifyAttack(attack);
                if (!attacks.has(cat)) attacks.set(cat, []);
                attacks.get(cat).push(attack);
              }
              totalFound += extracted.length;
              sources.push(`${repo.full_name} (${file.url})`);
              console.log(`  ✓ ${repo.full_name} → ${extracted.length} attacks (classified)`);
            }
          } else if (file.type === 'text' && file.lines) {
            if (!attacks.has('injection')) attacks.set('injection', []);
            attacks.get('injection').push(...file.lines);
            totalFound += file.lines.length;
            sources.push(`${repo.full_name} (${file.url})`);
            console.log(`  ✓ ${repo.full_name} → ${file.lines.length} text lines`);
          }
        }
      } catch (e) {
        console.warn(`  ✗ ${repo.full_name}: ${e.message}`);
      }
    }
  } catch (e) {
    console.warn(`GitHub search failed: ${e.message}`);
  }
  
  console.log(`\n  Total: ${totalFound} attacks found from ${sources.length} sources`);
  
  return { attacks, sources, totalFound };
}

module.exports = { scrapeAll, searchGitHub, findDatasetFiles, extractAttacks, classifyAttack };
