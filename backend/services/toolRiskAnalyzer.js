/**
 * Tool Risk Analyzer — Analyzes prompts for tool/action intent and
 * scores the risk of what the agent is ABOUT to do, not just what's said.
 *
 * Tool categories analyzed:
 *   - FILE_SYSTEM: read/write files, path traversal
 *   - SHELL: command execution, script running
 *   - NETWORK: HTTP calls, webhook sends, data transfer
 *   - DATABASE: query, modify, export data
 *   - BROWSER: web navigation, form fill
 *   - MEMORY: RAG queries, vector store access
 *   - PAYMENT: transaction, token transfer
 *   - AUTH: credential access, token manipulation
 *   - API: external API calls
 *   - EMAIL: send/read email
 */

// Tool risk profiles — defines risk per tool + action type
const TOOL_RISK_PROFILES = {
  FILE_SYSTEM: {
    baseRisk: 0.3,
    actions: {
      read: 0.3,
      write: 0.5,
      delete: 0.9,
      modify: 0.6,
      list: 0.2,
      traverse: 0.7,
    },
    sensitivePatterns: [
      /\/(etc|home|root|var\/log|proc)/i,
      /\.(env|ssh|kube|aws|config)/i,
      /(password|secret|key|token|credential)s?\..+/i,
      /\.(pem|key|crt|pfx)$/i,
    ],
    description: 'File system operations',
  },
  SHELL: {
    baseRisk: 0.7,
    actions: {
      execute: 0.9,
      install: 0.7,
      download: 0.8,
      network_scan: 0.9,
      process_control: 0.8,
    },
    sensitivePatterns: [
      /\b(rm|shred|dd)\s+-[rf]/i,
      /\b(wget|curl)\s+.+(-O|--output)/i,
      /\b(chmod|chown|chattr)\s/i,
      /\|/i, // piped commands
      /\b(sudo|su)\s/i,
      /(;\s*|&&\s*|\|\|\s*)/i, // command chaining
    ],
    description: 'Shell command execution',
  },
  NETWORK: {
    baseRisk: 0.4,
    actions: {
      http_get: 0.3,
      http_post: 0.5,
      webhook: 0.7,
      ftp: 0.6,
      socket: 0.8,
      data_transfer: 0.8,
    },
    sensitivePatterns: [
      /(webhook|callback|notify)\s*(url|endpoint|uri)/i,
      /send\s+(data|info|logs|results)\s+(to|via|through)/i,
      /post\s+(to|data\s+to|request\s+to)/i,
      /\b(exfil|leak|upload)\b/i,
      /(ngrok|serveo|localtunnel)/i,
    ],
    description: 'Network/HTTP operations',
  },
  DATABASE: {
    baseRisk: 0.4,
    actions: {
      read: 0.3,
      write: 0.5,
      delete: 0.8,
      export: 0.7,
      schema_change: 0.8,
    },
    sensitivePatterns: [
      /(drop|truncate|delete\s+from)\s/i,
      /export\s+(to|as|data)/i,
      /(dump|backup)\s+(database|db|data)/i,
      /select\s+\*\s+from\s+.+/i,
    ],
    description: 'Database operations',
  },
  BROWSER: {
    baseRisk: 0.3,
    actions: {
      navigate: 0.2,
      fill_form: 0.4,
      extract_data: 0.5,
      screenshot: 0.3,
      execute_js: 0.8,
    },
    sensitivePatterns: [
      /(fill|submit|autofill)\s+(form|login|password)/i,
      /extract\s+(all\s+)?(data|content|text|html)/i,
      /execute\s+(javascript|js|script)/i,
    ],
    description: 'Browser operations',
  },
  MEMORY: {
    baseRisk: 0.3,
    actions: {
      query: 0.3,
      store: 0.4,
      modify: 0.6,
      delete: 0.7,
      inject: 0.8,
    },
    sensitivePatterns: [
      /(inject|insert|store|save)\s+(into|to)\s+(memory|vector|store|knowledge)/i,
      /(modify|change|update|edit)\s+(memory|stored|saved|knowledge)/i,
      /(poison|corrupt|manipulate)\s+(memory|storage|vector)/i,
    ],
    description: 'Memory/vector store operations',
  },
  PAYMENT: {
    baseRisk: 0.8,
    actions: {
      transfer: 0.9,
      approve: 0.9,
      mint: 0.7,
      burn: 0.8,
    },
    sensitivePatterns: [
      /(send|transfer|pay)\s+(\d+\.?\d*)\s*(eth|sol|btc|usd|token)/i,
      /(approve|authorize)\s+(transaction|payment|transfer)/i,
    ],
    description: 'Payment/transaction operations',
  },
  AUTH: {
    baseRisk: 0.8,
    actions: {
      read_credentials: 0.9,
      create_token: 0.8,
      modify_permissions: 0.9,
    },
    sensitivePatterns: [
      /(api[_-]?key|secret|token|password)\b/i,
      /(read|get|fetch|load)\s+(env|environment|config|credentials)/i,
      /(login|authenticate|authorize)\s+(as|with)/i,
    ],
    description: 'Authentication operations',
  },
  API: {
    baseRisk: 0.2,
    actions: {
      call: 0.2,
      modify: 0.4,
      delete: 0.6,
    },
    sensitivePatterns: [
      /(delete|remove|destroy)\s+(resource|account|data)/i,
      /(modify|change|update)\s+(config|setting|permission|policy)/i,
    ],
    description: 'External API calls',
  },
  EMAIL: {
    baseRisk: 0.3,
    actions: {
      send: 0.5,
      read: 0.3,
      forward: 0.6,
      delete: 0.4,
    },
    sensitivePatterns: [
      /(forward|redirect)\s+(all\s+)?(email|mail|messages)/i,
      /send\s+(to|an\s+email|a\s+message)\s+(to|containing)/i,
    ],
    description: 'Email operations',
  },
};

// Verb-to-tool mapping for natural language tool detection
const VERB_TO_TOOL = {
  // File operations
  read: ['FILE_SYSTEM', 'read'],
  write: ['FILE_SYSTEM', 'write'],
  delete: ['FILE_SYSTEM', 'delete'],
  remove: ['FILE_SYSTEM', 'delete'],
  'list files': ['FILE_SYSTEM', 'list'],
  traverse: ['FILE_SYSTEM', 'traverse'],

  // Shell
  execute: ['SHELL', 'execute'],
  run: ['SHELL', 'execute'],
  install: ['SHELL', 'install'],
  download: ['SHELL', 'download'],
  'curl': ['SHELL', 'download'],

  // Network
  fetch: ['NETWORK', 'http_get'],
  'http get': ['NETWORK', 'http_get'],
  'http post': ['NETWORK', 'http_post'],
  send: ['NETWORK', 'data_transfer'],
  upload: ['NETWORK', 'data_transfer'],

  // Database
  query: ['DATABASE', 'read'],
  'select from': ['DATABASE', 'read'],
  insert: ['DATABASE', 'write'],
  update: ['DATABASE', 'write'],
  'drop table': ['DATABASE', 'delete'],

  // Browser
  navigate: ['BROWSER', 'navigate'],
  'go to': ['BROWSER', 'navigate'],
  scrape: ['BROWSER', 'extract_data'],
  screenshot: ['BROWSER', 'screenshot'],

  // Memory
  remember: ['MEMORY', 'store'],
  recall: ['MEMORY', 'query'],
  forget: ['MEMORY', 'delete'],
  inject: ['MEMORY', 'inject'],

  // Payments
  transfer: ['PAYMENT', 'transfer'],
  pay: ['PAYMENT', 'transfer'],

  // Auth
  login: ['AUTH', 'create_token'],
  'get token': ['AUTH', 'read_credentials'],
  'list keys': ['AUTH', 'read_credentials'],

  // API
  'api call': ['API', 'call'],
  'call api': ['API', 'call'],

  // Email
  'send email': ['EMAIL', 'send'],
  email: ['EMAIL', 'send'],
};

// Sensitive data type indicators
const DATA_SENSITIVITY_KEYWORDS = {
  critical: [/password/i, /secret/i, /api[_-]?key/i, /token/i, /private\s+key/i, /credential/i],
  high: [/salary/i, /payroll/i, /ssn/i, /credit\s+card/i, /bank\s+account/i, /pii/i, /phi/i],
  medium: [/email/i, /phone/i, /address/i, /customer/i, /user\s+data/i],
  low: [/public/i, /readme/i, /docs/i, /documentation/i],
};

// Destination URLs risk scoring
const DESTINATION_RISK = {
  'localhost': 0.2,
  '127.0.0.1': 0.2,
  'internal': 0.4,
  'external-unknown': 0.6,
  'external-suspicious': 0.9,
};

/**
 * Analyze a prompt and detect what tools/actions it's requesting.
 * @param {string} prompt
 * @returns {object} { detectedTools, overallRisk, details }
 */
function analyzeToolRisk(prompt) {
  if (!prompt) {
    return {
      detectedTools: [],
      overallRisk: 0,
      maxRisk: 0,
      details: 'No prompt to analyze',
    };
  }

  const text = prompt.toLowerCase();
  const detectedTools = [];
  let maxRisk = 0;
  let maxRiskTool = null;
  const warnings = [];

  // Check each tool category
  for (const [toolName, profile] of Object.entries(TOOL_RISK_PROFILES)) {
    const toolRisk = {
      tool: toolName,
      description: profile.description,
      baseRisk: profile.baseRisk,
      detectedActions: [],
      riskModifiers: 0,
      actionRisk: 0,
      totalRisk: 0,
      matchedPatterns: [],
      dataSensitivity: 'none',
    };

    // Check sensitive patterns
    for (const pattern of profile.sensitivePatterns) {
      if (pattern.test(text)) {
        toolRisk.matchedPatterns.push(pattern.source);
      }
    }

    // Detect actions from verbs
    for (const [verb, [tool, action]] of Object.entries(VERB_TO_TOOL)) {
      if (tool === toolName) {
        const verbRegex = new RegExp(`\\b${verb.replace(/\s+/g, '\\s+')}\\b`, 'i');
        if (verbRegex.test(text)) {
          toolRisk.detectedActions.push(action);
        }
      }
    }

    // Calculate tool risk
    if (toolRisk.detectedActions.length > 0 || toolRisk.matchedPatterns.length > 0) {
      // Base risk
      let totalRisk = profile.baseRisk;

      // Action risk (use highest detected action)
      let highestActionRisk = 0;
      for (const action of toolRisk.detectedActions) {
        const actionRisk = profile.actions[action] || 0.3;
        if (actionRisk > highestActionRisk) highestActionRisk = actionRisk;
      }
      toolRisk.actionRisk = highestActionRisk;

      // Use the higher of base risk and action risk
      totalRisk = Math.max(totalRisk, highestActionRisk);

      // Pattern modfier: each matched pattern increases risk
      const patternModifier = Math.min(toolRisk.matchedPatterns.length * 0.1, 0.3);
      toolRisk.riskModifiers = patternModifier;
      totalRisk += patternModifier;

      // Check data sensitivity
      for (const [level, patterns] of Object.entries(DATA_SENSITIVITY_KEYWORDS)) {
        if (patterns.some(p => p.test(text))) {
          toolRisk.dataSensitivity = level;
          const sensitivityBonus = level === 'critical' ? 0.2 : level === 'high' ? 0.15 : 0.1;
          totalRisk += sensitivityBonus;
          break;
        }
      }

      // Check destination risk if URLs involved
      const urls = text.match(/https?:\/\/[^\s]+/g);
      if (urls) {
        for (const url of urls) {
          if (/(evil|malware|phish|steal|exfil|hack|bad|suspicious)/i.test(url)) {
            totalRisk += 0.2;
            warnings.push(`Suspicious destination URL: ${url.slice(0, 60)}`);
          }
        }
      }

      // Clamp
      toolRisk.totalRisk = Math.min(Math.max(totalRisk, 0), 1);

      if (toolRisk.totalRisk > maxRisk) {
        maxRisk = toolRisk.totalRisk;
        maxRiskTool = toolName;
      }

      detectedTools.push(toolRisk);
    }
  }

  // Check for tool chaining — multiple high-risk tools detected
  const highRiskTools = detectedTools.filter(t => t.totalRisk > 0.7);
  const chainWarning = highRiskTools.length >= 2
    ? `Tool chaining: ${highRiskTools.map(t => t.tool).join(' + ')} — ${highRiskTools.length} high-risk tools simultaneously`
    : null;
  if (chainWarning) warnings.push(chainWarning);

  return {
    detectedTools,
    overallRisk: maxRisk,
    maxRiskTool,
    toolCount: detectedTools.length,
    highRiskToolCount: highRiskTools.length,
    warnings,
    chainedTools: highRiskTools.length >= 2,
  };
}

/**
 * Get recommended action based on tool risk analysis.
 * @param {object} toolAnalysis - output from analyzeToolRisk
 * @returns {string} 'ALLOW' | 'REVIEW' | 'DENY'
 */
function getRecommendedAction(toolAnalysis) {
  if (!toolAnalysis || toolAnalysis.overallRisk === 0) return 'ALLOW';

  if (toolAnalysis.chainedTools) return 'DENY';
  if (toolAnalysis.overallRisk >= 0.8) return 'DENY';
  if (toolAnalysis.overallRisk >= 0.5) return 'REVIEW';
  return 'ALLOW';
}

/**
 * Check for data exfiltration risk in tool context.
 * @param {object} toolAnalysis
 * @param {string} prompt
 * @returns {number} exfiltration risk (0-1)
 */
function getExfiltrationRisk(toolAnalysis, prompt) {
  if (!toolAnalysis) return 0;

  const hasDataAccess = toolAnalysis.detectedTools.some(t =>
    ['FILE_SYSTEM', 'DATABASE', 'MEMORY'].includes(t.tool)
  );
  const hasNetwork = toolAnalysis.detectedTools.some(t =>
    ['NETWORK', 'EMAIL'].includes(t.tool)
  );

  if (!hasDataAccess || !hasNetwork) return 0;

  // Data + network = exfiltration risk
  const dataCount = toolAnalysis.detectedTools.filter(t =>
    ['FILE_SYSTEM', 'DATABASE', 'MEMORY'].includes(t.tool)
  ).length;
  const netCount = toolAnalysis.detectedTools.filter(t =>
    ['NETWORK', 'EMAIL'].includes(t.tool)
  ).length;

  const baseRisk = 0.3 + (dataCount * 0.1) + (netCount * 0.1);

  // Check for explicit exfiltration language
  const text = (prompt || '').toLowerCase();
  if (/(send|upload|forward|post|email|transmit)\s+(data|file|results|logs|info|everything)/i.test(text)) {
    return Math.min(baseRisk + 0.3, 1);
  }

  return Math.min(baseRisk, 0.8);
}

module.exports = {
  analyzeToolRisk,
  getRecommendedAction,
  getExfiltrationRisk,
  TOOL_CATEGORIES: Object.keys(TOOL_RISK_PROFILES),
};
