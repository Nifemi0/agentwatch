/**
 * Runtime AI Sandbox — Phase 5
 * 
 * Simulates tool/action execution before it happens. Estimates blast radius,
 * classifies sensitivity, predicts consequences, and provides pre-execution
 * risk scoring.
 * 
 * This is the "what if" engine — before an agent touches a tool, file,
 * database, or network, AgentWatch simulates the impact.
 * 
 * Layers:
 *   1. Action Simulation — what would executing this action do?
 *   2. Blast Radius — how far would the effect spread?
 *   3. Sensitivity Classification — what level of resource is touched?
 *   4. Consequence Prediction — what are the chain reactions?
 *   5. Pre-execution Risk Score — composite go/no-go score
 */

const { analyzeToolRisk, getExfiltrationRisk } = require('./toolRiskAnalyzer');
const db = require('../models/database');

// ─── Resource Sensitivity Registry ───
// Defines sensitivity levels for different resource types
const RESOURCE_SENSITIVITY = {
  // File system paths
  '/etc': { sensitivity: 'critical', category: 'system_config', impact: 'system_integrity' },
  '/etc/passwd': { sensitivity: 'critical', category: 'identity', impact: 'credential_exposure' },
  '/etc/shadow': { sensitivity: 'critical', category: 'identity', impact: 'credential_exposure' },
  '/etc/ssh': { sensitivity: 'critical', category: 'access', impact: 'unauthorized_access' },
  '/root': { sensitivity: 'critical', category: 'system', impact: 'privilege_escalation' },
  '/home': { sensitivity: 'high', category: 'user_data', impact: 'data_exposure' },
  '/var/log': { sensitivity: 'medium', category: 'system', impact: 'information_disclosure' },
  '/var/run': { sensitivity: 'high', category: 'system', impact: 'process_disruption' },
  '/proc': { sensitivity: 'high', category: 'system', impact: 'information_disclosure' },
  '.env': { sensitivity: 'critical', category: 'credentials', impact: 'credential_exposure' },
  '.ssh': { sensitivity: 'critical', category: 'access', impact: 'unauthorized_access' },
  '.kube': { sensitivity: 'critical', category: 'infrastructure', impact: 'cluster_compromise' },
  '.aws': { sensitivity: 'critical', category: 'infrastructure', impact: 'cloud_compromise' },
  '.git': { sensitivity: 'high', category: 'repository', impact: 'source_code_leak' },

  // Database
  'postgresql://': { sensitivity: 'critical', category: 'database', impact: 'data_breach' },
  'mysql://': { sensitivity: 'critical', category: 'database', impact: 'data_breach' },
  'mongodb://': { sensitivity: 'critical', category: 'database', impact: 'data_breach' },
  'redis://': { sensitivity: 'high', category: 'cache', impact: 'data_exposure' },

  // Cloud / infra
  'https://api.stripe.com': { sensitivity: 'critical', category: 'payment', impact: 'financial_loss' },
  'https://api.github.com': { sensitivity: 'high', category: 'repository', impact: 'source_code_leak' },
  'https://aws.amazon.com': { sensitivity: 'high', category: 'infrastructure', impact: 'cloud_compromise' },

  // Auth endpoints
  'oauth': { sensitivity: 'critical', category: 'auth', impact: 'unauthorized_access' },
  'token': { sensitivity: 'critical', category: 'auth', impact: 'credential_exposure' },
  'login': { sensitivity: 'high', category: 'auth', impact: 'account_takeover' },
};

// ─── Impact Chain Definitions ───
// Maps actions to their predictable consequences
const IMPACT_CHAINS = {
  'FILE_SYSTEM:read': {
    direct: ['file_read'],
    potential: ['data_exposure', 'information_disclosure'],
    maxBlastRadius: 1, // files affected
  },
  'FILE_SYSTEM:write': {
    direct: ['file_modified'],
    potential: ['file_corruption', 'configuration_change', 'persistence'],
    maxBlastRadius: 2,
  },
  'FILE_SYSTEM:delete': {
    direct: ['file_deleted'],
    potential: ['data_loss', 'system_instability', 'service_disruption'],
    maxBlastRadius: 5,
  },
  'SHELL:execute': {
    direct: ['command_execution'],
    potential: ['process_spawn', 'network_connection', 'data_modification', 'system_change', 'persistence', 'privilege_escalation'],
    maxBlastRadius: 10,
  },
  'NETWORK:http_get': {
    direct: ['outbound_request'],
    potential: ['data_exposure', 'server_side_request_forgery', 'information_disclosure'],
    maxBlastRadius: 1,
  },
  'NETWORK:http_post': {
    direct: ['outbound_data_transfer'],
    potential: ['data_exfiltration', 'api_abuse', 'webhook_trigger'],
    maxBlastRadius: 3,
  },
  'NETWORK:data_transfer': {
    direct: ['data_transferred'],
    potential: ['data_exfiltration', 'credential_theft', 'intellectual_property_loss'],
    maxBlastRadius: 10,
  },
  'DATABASE:read': {
    direct: ['database_query'],
    potential: ['data_exposure', 'information_disclosure', 'schema_discovery'],
    maxBlastRadius: 100, // records
  },
  'DATABASE:write': {
    direct: ['data_modified'],
    potential: ['data_corruption', 'unauthorized_modification', 'sql_injection_chain'],
    maxBlastRadius: 1000,
  },
  'DATABASE:delete': {
    direct: ['data_deleted'],
    potential: ['data_loss', 'service_disruption', 'application_failure'],
    maxBlastRadius: 10000,
  },
  'BROWSER:navigate': {
    direct: ['page_navigation'],
    potential: ['phishing_exposure', 'credential_harvesting'],
    maxBlastRadius: 1,
  },
  'BROWSER:fill_form': {
    direct: ['form_interaction'],
    potential: ['credential_harvesting', 'identity_theft', 'payment_fraud'],
    maxBlastRadius: 1,
  },
  'MEMORY:store': {
    direct: ['memory_insertion'],
    potential: ['memory_poisoning', 'behavioral_manipulation', 'persistent_misinformation'],
    maxBlastRadius: 100, // future interactions
  },
  'MEMORY:modify': {
    direct: ['memory_modification'],
    potential: ['memory_corruption', 'knowledge_base_tampering', 'long_term_compromise'],
    maxBlastRadius: 500,
  },
  'PAYMENT:transfer': {
    direct: ['financial_transaction'],
    potential: ['financial_loss', 'theft', 'fraud'],
    maxBlastRadius: 100000, // dollars
  },
  'AUTH:read_credentials': {
    direct: ['credential_access'],
    potential: ['credential_theft', 'account_takeover', 'privilege_escalation', 'lateral_movement'],
    maxBlastRadius: 100,
  },
  'EMAIL:send': {
    direct: ['email_sent'],
    potential: ['phishing', 'data_exfiltration', 'reputation_damage', 'social_engineering'],
    maxBlastRadius: 1000,
  },
};

// Sensitivity score mapping for blast radius calculation
const SENSITIVITY_MULTIPLIER = {
  'low': 1,
  'medium': 2,
  'high': 5,
  'critical': 10,
};

/**
 * Run a complete sandbox simulation for a given prompt and its detected tools.
 * 
 * @param {string} prompt - The original prompt
 * @param {object} toolAnalysis - Output from toolRiskAnalyzer.analyzeToolRisk()
 * @param {Array} sessionHistory - Recent session turns
 * @returns {object} Complete sandbox analysis
 */
function simulateExecution(prompt, toolAnalysis = null, sessionHistory = []) {
  if (!toolAnalysis) {
    toolAnalysis = analyzeToolRisk(prompt);
  }

  const text = (prompt || '');
  const simulations = [];
  let maxBlastRadius = 0;
  let maxConsequenceRisk = 0;
  let affectedSystems = new Set();
  const warnings = [];

  // ── Simulate each detected tool ──
  for (const tool of (toolAnalysis.detectedTools || [])) {
    for (const action of (tool.detectedActions || [])) {
      const sim = simulateAction(tool.tool, action, text, tool);
      simulations.push(sim);

      if (sim.blastRadius > maxBlastRadius) maxBlastRadius = sim.blastRadius;
      if (sim.consequenceRisk > maxConsequenceRisk) maxConsequenceRisk = sim.consequenceRisk;
      
      for (const sys of sim.affectedSystems) affectedSystems.add(sys);
      for (const w of sim.warnings) warnings.push(w);
    }
  }

  // ── Handle raw detected patterns even without explicit actions ──
  if (toolAnalysis.detectedTools && simulations.length === 0) {
    for (const tool of toolAnalysis.detectedTools) {
      if (tool.matchedPatterns.length > 0) {
        const sim = simulatePatternMatch(tool.tool, tool.matchedPatterns, text, tool);
        simulations.push(sim);
        if (sim.blastRadius > maxBlastRadius) maxBlastRadius = sim.blastRadius;
        if (sim.consequenceRisk > maxConsequenceRisk) maxConsequenceRisk = sim.consequenceRisk;
        for (const sys of sim.affectedSystems) affectedSystems.add(sys);
        for (const w of sim.warnings) warnings.push(w);
      }
    }
  }

  // ── Compute composite sandbox scores ──

  // Blast radius: highest + bonus for chained tools
  let blastRadius = maxBlastRadius;
  if (toolAnalysis.chainedTools) blastRadius *= 1.5;
  if (toolAnalysis.highRiskToolCount >= 2) blastRadius *= 2;

  // Sensitivity: highest sensitivity across all simulations
  const sensitivityLevels = simulations.map(s => s.sensitivityLevel);
  const sensitivityRank = { low: 1, medium: 2, high: 3, critical: 4 };
  const highestSensitivity = sensitivityLevels.sort((a, b) => (sensitivityRank[b] || 0) - (sensitivityRank[a] || 0))[0] || 'low';

  // Risk score: weighted from consequence + blast + tool chaining
  const baseRisk = maxConsequenceRisk || toolAnalysis.overallRisk || 0;
  const blastBonus = Math.min(blastRadius / 1000, 0.2);
  const chainBonus = toolAnalysis.chainedTools ? 0.15 : 0;
  const sensitivityBonus = (sensitivityRank[highestSensitivity] || 1) * 0.05;
  const sandboxRisk = Math.min(baseRisk + blastBonus + chainBonus + sensitivityBonus, 1);

  // Recommended halt? (block execution)
  const shouldHalt = sandboxRisk >= 0.7 || 
    highestSensitivity === 'critical' ||
    (blastRadius >= 100 && toolAnalysis.chainedTools);

  // Consequence summary
  const consequences = simulations.flatMap(s => s.consequences);
  const uniqueConsequences = [...new Set(consequences)];

  // Compute blast radius label
  const blastRadiusLabel = blastRadius <= 1 ? 'contained'
                     : blastRadius <= 10 ? 'limited'
                     : blastRadius <= 100 ? 'significant'
                     : blastRadius <= 1000 ? 'wide'
                     : 'critical';

  return {
    sandboxRisk: Math.round(sandboxRisk * 100) / 100,
    blastRadius: Math.round(blastRadius),
    blastRadiusLabel,
    highestSensitivity,
    affectedSystems: [...affectedSystems],
    simulationCount: simulations.length,
    shouldHalt,
    consequenceRisk: Math.round(maxConsequenceRisk * 100) / 100,
    consequences: uniqueConsequences,
    details: simulations,
    warnings: [...new Set(warnings)],
    summary: shouldHalt
      ? `HIGH-RISK: Sandbox simulation predicts ${uniqueConsequences.length} potential consequences with blast radius ${blastRadiusLabel}`
      : sandboxRisk > 0.4
        ? `MODERATE: Sandbox simulation shows moderate risk (blast radius: ${blastRadiusLabel})`
        : `LOW: Sandbox simulation shows minimal impact`,
  };
}

/**
 * Simulate a single tool + action combination.
 */
function simulateAction(toolName, action, promptText, toolInfo) {
  const impactKey = `${toolName}:${action}`;
  const impact = IMPACT_CHAINS[impactKey];

  // Extract targets from prompt
  const targets = extractTargets(promptText, toolName);

  // Determine sensitivity
  const sensitivityLevel = determineSensitivity(toolName, targets, action, promptText);

  // Blast radius
  const baseBlast = impact?.maxBlastRadius || 1;
  const sensitivityMult = SENSITIVITY_MULTIPLIER[sensitivityLevel] || 1;
  const blastRadius = baseBlast * sensitivityMult;

  // Consequences
  const consequences = [];
  if (impact) {
    consequences.push(...impact.direct, ...impact.potential);
  } else {
    consequences.push(`${toolName.toLowerCase()}_${action}`);
  }

  // Affected systems
  const affectedSystems = [toolName.toLowerCase()];
  if (['SHELL', 'NETWORK', 'FILE_SYSTEM'].includes(toolName)) {
    affectedSystems.push('operating_system');
  }
  if (['NETWORK', 'EMAIL'].includes(toolName)) {
    affectedSystems.push('external_network');
  }
  if (['PAYMENT', 'AUTH'].includes(toolName)) {
    affectedSystems.push('credentials');
  }

  // Consequence risk — how bad are the consequences?
  const consequenceNames = consequences;
  let consequenceRisk = 0;
  if (consequenceNames.some(c => ['data_exfiltration', 'credential_exposure', 'unauthorized_access', 'financial_loss', 'persistence', 'privilege_escalation', 'cluster_compromise', 'cloud_compromise'].includes(c))) {
    consequenceRisk = 0.8;
  } else if (consequenceNames.some(c => ['data_breach', 'account_takeover', 'credential_theft', 'memory_poisoning', 'long_term_compromise'].includes(c))) {
    consequenceRisk = 0.7;
  } else if (consequenceNames.some(c => ['data_loss', 'data_exposure', 'system_change', 'information_disclosure'].includes(c))) {
    consequenceRisk = 0.5;
  } else {
    consequenceRisk = 0.3;
  }

  // Adjust by tool's own risk score
  consequenceRisk = Math.max(consequenceRisk, toolInfo?.totalRisk || 0);

  // Warnings
  const simWarnings = [];
  if (targets.some(t => t.sensitivity === 'critical')) {
    simWarnings.push(`Accessing critical resource: ${targets.filter(t => t.sensitivity === 'critical').map(t => t.path).join(', ')}`);
  }
  if (action === 'delete' || action === 'drop_table') {
    simWarnings.push('Destructive action — data loss risk');
  }
  if (toolName === 'SHELL' && action === 'execute') {
    simWarnings.push('Shell command execution — full system access risk');
  }
  if (toolName === 'NETWORK' && ['http_post', 'data_transfer'].includes(action)) {
    simWarnings.push('Outbound data transfer — exfiltration risk');
  }

  return {
    tool: toolName,
    action,
    targets,
    sensitivityLevel,
    blastRadius: Math.round(blastRadius),
    consequenceRisk: Math.round(consequenceRisk * 100) / 100,
    consequences: consequenceNames.slice(0, 5),
    affectedSystems: affectedSystems.slice(0, 5),
    warnings: simWarnings,
    chainLength: impact?.potential?.length || 0,
  };
}

/**
 * Simulate a pattern match (when no explicit action was detected).
 */
function simulatePatternMatch(toolName, matchedPatterns, promptText, toolInfo) {
  const targets = extractTargets(promptText, toolName);
  const sensitivityLevel = determineSensitivity(toolName, targets, 'unknown', promptText);
  const sensitivityMult = SENSITIVITY_MULTIPLIER[sensitivityLevel] || 1;
  const blastRadius = Math.min(matchedPatterns.length * 2 * sensitivityMult, 100);

  const consequences = [`${toolName.toLowerCase()}_pattern_match`];
  let consequenceRisk = Math.min(matchedPatterns.length * 0.15, 0.6);

  const affectedSystems = [toolName.toLowerCase()];
  if (['SHELL', 'NETWORK'].includes(toolName)) affectedSystems.push('external_network');

  const simWarnings = [];
  if (matchedPatterns.length >= 3) simWarnings.push(`Multiple sensitive patterns detected (${matchedPatterns.length})`);

  return {
    tool: toolName,
    action: 'uncertain',
    targets,
    sensitivityLevel,
    blastRadius: Math.round(blastRadius),
    consequenceRisk,
    consequences,
    affectedSystems,
    warnings: simWarnings,
    chainLength: 0,
  };
}

/**
 * Extract resource targets from prompt text.
 */
function extractTargets(text, toolName) {
  const targets = [];
  const lower = text.toLowerCase();

  // File system targets
  if (['FILE_SYSTEM', 'SHELL'].includes(toolName)) {
    for (const [path, info] of Object.entries(RESOURCE_SENSITIVITY)) {
      if (path.startsWith('/') || path.startsWith('.')) {
        if (lower.includes(path.toLowerCase())) {
          targets.push({ path, sensitivity: info.sensitivity, category: info.category, type: 'file' });
        }
      }
    }
  }

  // URL targets
  if (['NETWORK', 'EMAIL', 'BROWSER'].includes(toolName)) {
    const urls = lower.match(/https?:\/\/[^\s'",)\]]+/g) || [];
    for (const url of urls) {
      let sensitivity = 'medium';
      // Check if known
      for (const [knownUrl, info] of Object.entries(RESOURCE_SENSITIVITY)) {
        if (url.includes(knownUrl.toLowerCase())) {
          sensitivity = info.sensitivity;
          targets.push({ path: url.slice(0, 60), sensitivity, category: info.category, type: 'url' });
          break;
        }
      }
      if (sensitivity === 'medium') {
        targets.push({ path: url.slice(0, 60), sensitivity: 'medium', category: 'external', type: 'url' });
      }
    }
  }

  // Auth targets
  if (['AUTH'].includes(toolName)) {
    if (lower.includes('api_key') || lower.includes('api key')) {
      targets.push({ path: 'api_key', sensitivity: 'critical', category: 'auth', type: 'credential' });
    }
    if (lower.includes('token')) {
      targets.push({ path: 'token', sensitivity: 'critical', category: 'auth', type: 'credential' });
    }
    if (lower.includes('password') || lower.includes('secret')) {
      targets.push({ path: 'password/secret', sensitivity: 'critical', category: 'auth', type: 'credential' });
    }
  }

  // Database targets
  if (['DATABASE'].includes(toolName)) {
    if (lower.includes('all') && (lower.includes('user') || lower.includes('customer') || lower.includes('employee'))) {
      targets.push({ path: 'user_database', sensitivity: 'critical', category: 'database', type: 'data_set' });
    }
    if (lower.includes('salary') || lower.includes('payroll')) {
      targets.push({ path: 'payroll', sensitivity: 'critical', category: 'database', type: 'pii' });
    }
  }

  // Default target
  if (targets.length === 0) {
    targets.push({ path: 'unknown', sensitivity: 'medium', category: 'general', type: 'unknown' });
  }

  return targets;
}

/**
 * Determine the sensitivity level of an operation.
 */
function determineSensitivity(toolName, targets, action, promptText) {
  const lower = promptText.toLowerCase();

  // Check target sensitivities
  for (const t of targets) {
    if (t.sensitivity === 'critical') return 'critical';
  }

  // Destructive actions are always at least high
  if (['delete', 'drop_table', 'truncate', 'destroy', 'modify_permissions'].includes(action)) {
    return 'high';
  }

  // Check for sensitive patterns in prompt
  if (/(salary|payroll|ssn|credit\s+card|bank\s+account|passport)/i.test(lower)) return 'high';
  if (/(password|secret|token|credential|api[_-]?key)/i.test(lower)) return 'critical';
  if (/(all\s+(users|customers|employees|data|records|accounts|emails))/i.test(lower)) return 'high';

  // Tool-based defaults
  const toolDefaults = {
    'SHELL': 'high',
    'AUTH': 'critical',
    'PAYMENT': 'critical',
    'MEMORY': 'medium',
    'FILE_SYSTEM': 'medium',
    'NETWORK': 'medium',
    'DATABASE': 'high',
    'BROWSER': 'low',
    'EMAIL': 'medium',
    'API': 'low',
  };

  return toolDefaults[toolName] || 'medium';
}

/**
 * Get a human-readable sandbox summary.
 */
function formatSandboxSummary(sandboxResult) {
  const parts = [
    `🛡️ Sandbox Simulation: ${sandboxResult.sandboxRisk >= 0.7 ? '🔴 HALT' : sandboxResult.sandboxRisk >= 0.4 ? '🟡 CAUTION' : '🟢 SAFE'}`,
    `   Risk Score: ${Math.round(sandboxResult.sandboxRisk * 100)}%`,
    `   Blast Radius: ${sandboxResult.blastRadius} (${sandboxResult.blastRadiusLabel})`,
    `   Sensitivity: ${sandboxResult.highestSensitivity}`,
    `   Consequence Risk: ${Math.round(sandboxResult.consequenceRisk * 100)}%`,
    `   Potential Consequences: ${sandboxResult.consequences.slice(0, 5).join(', ')}`,
    `   Affected Systems: ${sandboxResult.affectedSystems.join(', ')}`,
  ];

  if (sandboxResult.warnings.length > 0) {
    parts.push(`   ⚠️ Warnings:`);
    for (const w of sandboxResult.warnings.slice(0, 3)) {
      parts.push(`      - ${w}`);
    }
  }

  return parts.join('\n');
}

module.exports = {
  simulateExecution,
  simulateAction,
  formatSandboxSummary,
  RESOURCE_SENSITIVITY,
  IMPACT_CHAINS,
};
