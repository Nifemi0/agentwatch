/**
 * Security Agents — Multi-agent security reasoning system.
 *
 * Uses 4 specialized "analyst agents" (pure functions, no external AI needed)
 * plus a Behavioral Judge that combines their findings into a final decision.
 *
 * Agents:
 *   1. Injection Analyst — Detects jailbreaks, prompt overrides, hidden instructions
 *   2. Exfiltration Analyst — Detects credential leaks, outbound data, suspicious destinations
 *   3. Tool Execution Analyst — Detects privilege abuse, dangerous commands, workflow escalation
 *   4. Behavioral Judge — Combines all signals into risk score + recommendation
 */

const fs = require('fs');
const path = require('path');
const toolRiskAnalyzer = require('./toolRiskAnalyzer');

// ─── Agent 1: Injection Analyst ───

/**
 * Analyzes a prompt for injection attacks, jailbreaks, and role overrides.
 * @param {string} prompt
 * @param {Array} sessionHistory - recent turns for context
 * @returns {object} { riskScore, confidence, finding, reasoning, subCategories }
 */
function analyzeInjection(prompt, sessionHistory = []) {
  const findings = [];
  let riskScore = 0;
  let confidence = 0;
  const text = (prompt || '').toLowerCase();

  // === Detection categories ===

  // 1. Direct jailbreak attempts
  const jailbreakPatterns = [
    { pattern: /you\s+are\s+(now|free|not\s+bound|a\s+different|a\s+new)/i, weight: 0.8, label: 'role_override' },
    { pattern: /ignore\s+(all\s+)?(previous|prior|above|your)/i, weight: 0.8, label: 'instruction_override' },
    { pattern: /forget\s+(all\s+)?(instructions|everything|what|rules)/i, weight: 0.7, label: 'memory_reset' },
    { pattern: /disregard\s+(all\s+)?(rules|instructions|previous|safety)/i, weight: 0.8, label: 'safety_bypass' },
    { pattern: /new\s+(instructions|prompt|rule|directive)/i, weight: 0.6, label: 'new_directive' },
    { pattern: /override\s+(all\s+)?(previous|constraints|restrictions|rules)/i, weight: 0.8, label: 'override_attempt' },
    { pattern: /jailbreak/i, weight: 0.9, label: 'explicit_jailbreak' },
    { pattern: /\bdan\b/i, weight: 0.85, label: 'dan_persona' },
    { pattern: /no\s+(rules|limits|restrictions|boundaries|ethics|morals|safety)/i, weight: 0.8, label: 'rule_removal' },
    { pattern: /unrestricted\s+(mode|access|ai|model)/i, weight: 0.75, label: 'unrestricted_mode' },
    { pattern: /bypass\s+(all\s+)?(safety|filters|restrictions|guardrails)/i, weight: 0.85, label: 'safety_bypass' },
    { pattern: /developer\s+mode/i, weight: 0.7, label: 'developer_mode' },
  ];

  for (const { pattern, weight, label } of jailbreakPatterns) {
    if (pattern.test(text)) {
      const match = text.match(pattern);
      findings.push({ type: 'injection', subType: label, weight, match: match?.[0]?.slice(0, 40) });
      riskScore = Math.max(riskScore, weight);
      confidence = Math.max(confidence, 0.5 + (weight * 0.3));
    }
  }

  // 2. Hidden instructions / encoded directives
  const hiddenPatterns = [
    { pattern: /&#\d{2,5};/g, weight: 0.5, label: 'html_encoded' },
    { pattern: /\\u00[0-9a-f]{2}/gi, weight: 0.5, label: 'unicode_escaped' },
    { pattern: /\\x[0-9a-f]{2}/gi, weight: 0.5, label: 'hex_escaped' },
    { pattern: /(system\s*:\s|user\s*:\s|assistant\s*:\s)/i, weight: 0.7, label: 'role_injection' },
    { pattern: /(human|system|ai)\s*(:|says|sends|says\s*:)/i, weight: 0.5, label: 'message_spoofing' },
  ];

  for (const { pattern, weight, label } of hiddenPatterns) {
    const matches = text.match(pattern);
    if (matches && matches.length > 0) {
      findings.push({ type: 'injection', subType: label, weight: Math.min(weight + (matches.length * 0.05), 0.8), match: `${label} × ${matches.length}` });
      riskScore = Math.max(riskScore, Math.min(weight + (matches.length * 0.05), 0.8));
      confidence = Math.max(confidence, 0.6);
    }
  }

  // 3. Gradual conditioning check (if session context provided)
  if (sessionHistory.length >= 2) {
    const roleTerms = ['you are', 'pretend', 'act as', 'role', 'persona', 'debug mode',
      'developer mode', 'unrestricted', 'ignore previous', 'override', 'jailbreak', 'dan'];
    
    let conditioningScore = 0;
    let prevTurnHadConditioning = false;
    
    for (let i = 0; i < sessionHistory.length; i++) {
      const turnText = (sessionHistory[i].prompt || '').toLowerCase();
      const hasConditioning = roleTerms.some(t => turnText.includes(t));
      
      if (hasConditioning && prevTurnHadConditioning) {
        conditioningScore += 0.15; // Conditioning across consecutive turns
      }
      prevTurnHadConditioning = hasConditioning;
    }

    if (conditioningScore > 0.3) {
      findings.push({ type: 'injection', subType: 'gradual_conditioning', weight: Math.min(conditioningScore, 0.7), match: `conditioning × ${sessionHistory.length} turns` });
      riskScore = Math.max(riskScore, Math.min(conditioningScore, 0.7));
      confidence = Math.max(confidence, 0.65);
    }
  }

  // 4. Combined confidence booster
  if (findings.length >= 2) confidence = Math.min(confidence + 0.1, 0.95);
  if (findings.length >= 4) confidence = Math.min(confidence + 0.15, 0.98);

  const subCategories = {};
  for (const f of findings) {
    if (!subCategories[f.subType]) subCategories[f.subType] = 0;
    subCategories[f.subType] = Math.max(subCategories[f.subType], f.weight);
  }

  return {
    agentName: 'Injection_Analyst',
    riskScore,
    confidence: Math.min(confidence, 1),
    finding: riskScore > 0.7 ? 'injection_attack_detected'
            : riskScore > 0.4 ? 'suspicious_injection_pattern'
            : 'clean',
    reasoning: findings.length > 0
      ? `Found ${findings.length} injection indicators: ${findings.map(f => f.subType).join(', ')}`
      : 'No injection patterns detected',
    subCategories,
    findingCount: findings.length,
  };
}


// ─── Agent 2: Exfiltration Analyst ───

/**
 * Analyzes a prompt for data exfiltration attempts.
 * @param {string} prompt
 * @param {object} toolAnalysis - from toolRiskAnalyzer
 * @returns {object} { riskScore, confidence, finding, reasoning }
 */
function analyzeExfiltration(prompt, toolAnalysis = null) {
  const findings = [];
  let riskScore = 0;
  const text = (prompt || '').toLowerCase();

  // 1. Direct exfiltration indicators
  const exfilPatterns = [
    { pattern: /(send|upload|forward|post|email|transmit)\s+(this|the|that|data|info|logs|history|messages|everything|results)\s+(to|via|through)/i, weight: 0.8, label: 'data_transfer_request' },
    { pattern: /exfiltrat/i, weight: 0.9, label: 'explicit_exfiltration' },
    { pattern: /(leak|steal|copy)\s+(this|the|data|info|logs|secrets)/i, weight: 0.85, label: 'data_theft' },
    { pattern: /(webhook|callback)\s*(url|endpoint)/i, weight: 0.7, label: 'webhook_target' },
    { pattern: /(ngrok|serveo|localtunnel|cloudflare\s+tunnel)/i, weight: 0.7, label: 'tunneling_service' },
    { pattern: /ftp:\/\/|sftp:\/\//i, weight: 0.6, label: 'ftp_transfer' },
    { pattern: /send\s+(to|everything\s+to|data\s+to|my\s+email|all\s+data)/i, weight: 0.6, label: 'send_all_data' },
  ];

  for (const { pattern, weight, label } of exfilPatterns) {
    if (pattern.test(text)) {
      findings.push({ type: 'exfiltration', subType: label, weight, match: label });
      riskScore = Math.max(riskScore, weight);
    }
  }

  // 2. Check tool analysis for data + network combo (exfiltration risk)
  if (toolAnalysis && toolAnalysis.detectedTools) {
    const hasDataAccess = toolAnalysis.detectedTools.some(t =>
      ['FILE_SYSTEM', 'DATABASE', 'MEMORY'].includes(t.tool)
    );
    const hasNetworkOut = toolAnalysis.detectedTools.some(t =>
      ['NETWORK', 'EMAIL'].includes(t.tool)
    );

    if (hasDataAccess && hasNetworkOut) {
      const exfilRisk = toolRiskAnalyzer.getExfiltrationRisk(toolAnalysis, prompt);
      if (exfilRisk > riskScore) {
        riskScore = exfilRisk;
        findings.push({ type: 'exfiltration', subType: 'data_plus_network', weight: exfilRisk, match: `Data access + network: ${toolAnalysis.detectedTools.filter(t => t.totalRisk > 0.3).map(t => t.tool).join('+')}` });
      }
    }
  }

  // 3. Check for credentials + external destination
  const hasCreds = /(api[_-]?key|secret|token|password|credential)/i.test(text);
  const hasExternal = /https?:\/\/(?!localhost|127\.0\.0\.1)/i.test(text);
  if (hasCreds && hasExternal) {
    findings.push({ type: 'exfiltration', subType: 'credential_external_transfer', weight: 0.85, match: 'Credentials + external URL' });
    riskScore = Math.max(riskScore, 0.85);
  }

  return {
    agentName: 'Exfiltration_Analyst',
    riskScore,
    confidence: riskScore > 0 ? 0.5 + (riskScore * 0.4) : 0,
    finding: riskScore > 0.7 ? 'exfiltration_attempt_detected'
            : riskScore > 0.4 ? 'suspicious_data_transfer'
            : 'clean',
    reasoning: findings.length > 0
      ? `Found ${findings.length} exfiltration indicators: ${findings.map(f => f.subType).join(', ')}`
      : 'No exfiltration patterns detected',
    findingCount: findings.length,
  };
}


// ─── Agent 3: Tool Execution Analyst ───

/**
 * Analyzes a prompt for dangerous tool execution patterns.
 * @param {string} prompt
 * @param {object} toolAnalysis - from toolRiskAnalyzer
 * @returns {object} { riskScore, confidence, finding, reasoning }
 */
function analyzeToolExecution(prompt, toolAnalysis = null) {
  const findings = [];
  let riskScore = 0;
  const text = (prompt || '').toLowerCase();

  // 1. Command injection indicators
  const cmdPatterns = [
    { pattern: /\b(rm|shred)\s+-[rf]/i, weight: 0.95, label: 'destructive_command' },
    { pattern: /\b(wget|curl)\b.*?(\||&&|;|`)/i, weight: 0.85, label: 'piped_network_command' },
    { pattern: /\b(chmod\s+\+x|chown|chattr)/i, weight: 0.7, label: 'permission_escalation' },
    { pattern: /\b(dd\s+if=|mkfs|fdisk|parted|format)/i, weight: 0.9, label: 'disk_destructive' },
    { pattern: /\b(sudo|su)\s+/i, weight: 0.6, label: 'privilege_escalation' },
    { pattern: /(bash|sh|zsh|powershell|cmd\.exe)\s/i, weight: 0.6, label: 'shell_execution' },
    { pattern: /\bexec(ute)?\s+(this|the|following|command)/i, weight: 0.7, label: 'explicit_exec' },
    { pattern: /systemctl\s+(stop|start|restart|disable|kill)/i, weight: 0.6, label: 'service_control' },
    { pattern: /(iptables|firewalld|ufw)\s/i, weight: 0.5, label: 'firewall_modification' },
    { pattern: /useradd|usermod|passwd/i, weight: 0.7, label: 'user_management' },
  ];

  for (const { pattern, weight, label } of cmdPatterns) {
    if (pattern.test(text)) {
      findings.push({ type: 'tool_execution', subType: label, weight, match: label });
      riskScore = Math.max(riskScore, weight);
    }
  }

  // 2. Check for command chaining
  const chainRegex = /(;\s+|&&\s+|\|\|\s+|`[^`]+`|\$\([^)]+\))/g;
  const chainMatches = text.match(chainRegex);
  if (chainMatches && chainMatches.length >= 2) {
    const chainWeight = Math.min(0.5 + (chainMatches.length * 0.1), 0.8);
    findings.push({ type: 'tool_execution', subType: 'command_chaining', weight: chainWeight, match: `${chainMatches.length} chain operators` });
    riskScore = Math.max(riskScore, chainWeight);
  }

  // 3. Check tool analysis for dangerous tool combinations
  if (toolAnalysis) {
    if (toolAnalysis.chainedTools) {
      findings.push({ type: 'tool_execution', subType: 'tool_chaining', weight: 0.75, match: `${toolAnalysis.highRiskToolCount} high-risk tools` });
      riskScore = Math.max(riskScore, 0.75);
    }

    // Check for SHELL + NETWORK combination (remote code execution)
    const hasShell = toolAnalysis.detectedTools.some(t => t.tool === 'SHELL' && t.totalRisk > 0.3);
    const hasNetwork = toolAnalysis.detectedTools.some(t => t.tool === 'NETWORK' && t.totalRisk > 0.3);
    if (hasShell && hasNetwork) {
      findings.push({ type: 'tool_execution', subType: 'remote_code_execution', weight: 0.85, match: 'SHELL + NETWORK combo' });
      riskScore = Math.max(riskScore, 0.85);
    }
  }

  // 4. Workflow escalation — check if later turns request more dangerous operations
  // (This will be detected by Phase 1 session analysis and passed in)

  return {
    agentName: 'Tool_Execution_Analyst',
    riskScore,
    confidence: riskScore > 0 ? 0.5 + (riskScore * 0.35) : 0,
    finding: riskScore > 0.7 ? 'dangerous_tool_execution'
            : riskScore > 0.4 ? 'suspicious_tool_usage'
            : 'clean',
    reasoning: findings.length > 0
      ? `Found ${findings.length} tool execution risks: ${findings.map(f => f.subType).join(', ')}`
      : 'No dangerous tool operations detected',
    findingCount: findings.length,
  };
}


// ─── Agent 4: Behavioral Judge ───

/**
 * Combines all agent signals into a final assessment.
 * Uses weighted consensus with confidence-based aggregation.
 * 
 * @param {object} agents - results from Injection, Exfiltration, and Tool Execution analysts
 * @param {object} sessionContext - session analysis from SessionMemory
 * @param {object} toolAnalysis - from toolRiskAnalyzer
 * @returns {object} final verdict
 */
function behavioralJudge(agents, sessionContext, toolAnalysis) {
  const agentResults = [
    agents.injection || { riskScore: 0, confidence: 0, finding: 'clean' },
    agents.exfiltration || { riskScore: 0, confidence: 0, finding: 'clean' },
    agents.toolExecution || { riskScore: 0, confidence: 0, finding: 'clean' },
  ];

  // === Calculate weighted consensus ===

  // Weight 1: Individual agent risk scores (confidence-weighted)
  let weightedRiskSum = 0;
  let totalConfidence = 0;
  for (const agent of agentResults) {
    weightedRiskSum += agent.riskScore * (agent.confidence || 0.5);
    totalConfidence += agent.confidence || 0.5;
  }
  const consensusRisk = totalConfidence > 0 ? weightedRiskSum / totalConfidence : 0;

  // Weight 2: Session-based risk (from multi-turn analysis)
  let sessionRisk = 0;
  if (sessionContext) {
    sessionRisk = sessionContext.currentRiskLevel === 'critical' ? 0.9
                : sessionContext.currentRiskLevel === 'high' ? 0.7
                : sessionContext.currentRiskLevel === 'medium' ? 0.4
                : 0;
  }

  // Weight 3: Tool analysis risk
  const toolRisk = toolAnalysis?.overallRisk || 0;

  // === Calculate final risk score ===
  // Weights: consensus 50%, session 30%, tool analysis 20%
  const finalRisk = (consensusRisk * 0.5) + (sessionRisk * 0.3) + (toolRisk * 0.2);

  // === Determine action ===
  let action = 'ALLOW';
  let actionConfidence = 0;

  if (finalRisk >= 0.7) {
    action = 'DENY';
    actionConfidence = Math.min(0.6 + (finalRisk * 0.3), 0.95);
  } else if (finalRisk >= 0.4) {
    action = 'REVIEW';
    actionConfidence = 0.5 + (finalRisk * 0.3);
  } else {
    // If consensus is low but session risk is high, still flag
    if (sessionRisk > 0.6) {
      action = 'REVIEW';
      actionConfidence = 0.6;
    } else {
      action = 'ALLOW';
      actionConfidence = 0.7 + ((1 - finalRisk) * 0.2);
    }
  }

  // === Generate explanation ===
  const highRiskAgents = agentResults.filter(a => a.riskScore > 0.5);
  const explanation = [];

  if (action === 'DENY') {
    explanation.push('Multi-agent consensus determined high-risk action');
  } else if (action === 'REVIEW') {
    explanation.push('Moderate risk detected — flagging for review');
  }

  if (highRiskAgents.length > 0) {
    explanation.push(`Triggered by: ${highRiskAgents.map(a => `${a.agentName} (${(a.riskScore * 100).toFixed(0)}%)`).join(', ')}`);
  }

  if (sessionContext?.isMultiTurnAttack) {
    explanation.push('Multi-turn attack pattern detected in session analysis');
  }
  if (sessionContext?.isEscalating) {
    explanation.push('Risk escalation trend detected across conversation turns');
  }
  if (toolAnalysis?.chainedTools) {
    explanation.push('Dangerous tool chaining detected');
  }

  return {
    agentName: 'Behavioral_Judge',
    finalRisk: Math.min(Math.max(finalRisk, 0), 1),
    consensusRisk: Math.min(consensusRisk, 1),
    sessionRisk,
    toolRisk,
    action,
    actionConfidence: Math.min(actionConfidence, 1),
    explanation: explanation.length > 0 ? explanation.join('. ') : 'No significant threats detected',
    agentVotes: agentResults.map(a => ({
      agentName: a.agentName,
      riskScore: a.riskScore,
      confidence: a.confidence,
      finding: a.finding,
    })),
    highRiskAgentCount: highRiskAgents.length,
    sources: {
      agentConsensus: Math.round(consensusRisk * 100),
      sessionAnalysis: Math.round(sessionRisk * 100),
      toolAnalysis: Math.round(toolRisk * 100),
    },
  };
}


// ─── Main entry point: run all agents ───

/**
 * Run the full multi-agent security pipeline.
 * @param {string} prompt
 * @param {object} sessionContext - from SessionMemory
 * @param {object} sessionHistory - recent turns array
 * @returns {object} complete multi-agent analysis
 */
function runSecurityAgents(prompt, sessionContext = null, sessionHistory = null) {
  // Run tool analysis first (both Phase 2 and used by agents)
  const toolAnalysis = toolRiskAnalyzer.analyzeToolRisk(prompt);

  // Phase 3: Run specialized agents
  const injectionResult = analyzeInjection(prompt, sessionHistory || []);
  const exfiltrationResult = analyzeExfiltration(prompt, toolAnalysis);
  const toolExecutionResult = analyzeToolExecution(prompt, toolAnalysis);

  // Behavioral Judge — combines everything
  const verdict = behavioralJudge(
    { injection: injectionResult, exfiltration: exfiltrationResult, toolExecution: toolExecutionResult },
    sessionContext,
    toolAnalysis
  );

  return {
    verdict,
    agents: {
      injection: injectionResult,
      exfiltration: exfiltrationResult,
      toolExecution: toolExecutionResult,
    },
    toolAnalysis,
  };
}

module.exports = {
  runSecurityAgents,
  analyzeInjection,
  analyzeExfiltration,
  analyzeToolExecution,
  behavioralJudge,
};
