/**
 * Security Phases — Integration route for Phase 1-3 analysis.
 * 
 * Wraps the existing security inspection with:
 *   Phase 1: Session-aware multi-turn detection
 *   Phase 2: Tool-execution risk scoring
 *   Phase 3: Multi-agent security reasoning
 * 
 * Endpoints:
 *   POST /security-phases/inspect  — Full Phase 1-3 inspection pipeline
 *   GET  /security-phases/session/:id — Get session analysis
 *   GET  /security-phases/analysis/:id — Get full agent analysis for an event
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../models/database');
const sessionMemory = require('../services/sessionMemory');
const { detectMultiTurnAttack } = require('../services/multiTurnDetector');
const { analyzeToolRisk, getRecommendedAction, getExfiltrationRisk } = require('../services/toolRiskAnalyzer');
const { runSecurityAgents, behavioralJudge } = require('../services/securityAgents');
const { detectMemoryPoisoning, analyzeSessionMemoryIntegrity } = require('../services/memoryPoisoningDetector');
const { simulateExecution, formatSandboxSummary } = require('../services/runtimeSandbox');

// Reference to the original security router for the base inspect call
let securityRouter = null;

function setSecurityRouter(router) {
  securityRouter = router;
}

/**
 * Full Phase 1-3 inspection pipeline.
 * Runs: existing keyword analysis → Phase 1 session-aware → Phase 2 tool risk → Phase 3 multi-agent
 */
router.post('/inspect', async (req, res) => {
  const { prompt, session_id, simulated_at } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt required' });

  const sessionId = session_id || `session_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const simulatedTime = simulated_at || null;

  try {
    // ── Step 1: Run base keyword/AI inspection (from existing security.js) ──
    // We replicate the core logic inline to avoid duplicating the entire file
    
    const { runInspection, analyzeWithAI } = require('./security');
    
    const keywordMetadata = await runInspection(prompt);

    // Determine base action from keyword metadata
    const isInjection = keywordMetadata.contains_injection_patterns === true;
    const isExfil = keywordMetadata.contains_exfiltration === true;
    const isMalware = keywordMetadata.contains_malware_request === true;
    const isPhishing = keywordMetadata.contains_phishing_patterns === true;
    const isHarm = keywordMetadata.contains_harm_patterns === true;
    const isRoleImpersonation = keywordMetadata.contains_role_impersonation === true;
    const isCredentials = keywordMetadata.contains_credentials === true;
    const isObfuscated = keywordMetadata.contains_obfuscation === true;
    const isSensitivePath = keywordMetadata.contains_sensitive_paths === true;
    const isCodeExec = keywordMetadata.contains_code === true || keywordMetadata.contains_system_commands === true;
    const isPiiLeak = keywordMetadata.contains_pii === true || keywordMetadata.contains_pii_request === true;

    const shouldBlock = isInjection || isExfil || isMalware || isPhishing || isHarm || isCredentials || isSensitivePath || isCodeExec || isPiiLeak;
    const shouldReview = isRoleImpersonation || isObfuscated || (keywordMetadata.contains_urls === true && (keywordMetadata.risk_score || 0) > 0.3);

    let baseAction = 'ALLOW';
    let baseRule = null;
    let baseMessage = null;
    let aiAnalysis = null;

    // Keyword-only determination (if blocked/found, skip AI to save quota)
    if (shouldBlock) {
      baseAction = 'DENY';
      if (isInjection) { baseRule = 'block_prompt_injection'; baseMessage = '[AGENTWATCH] Blocked: prompt injection detected.'; }
      else if (isExfil) { baseRule = 'block_exfiltration'; baseMessage = '[AGENTWATCH] Blocked: data exfiltration attempt.'; }
      else if (isMalware) { baseRule = 'block_malware'; baseMessage = '[AGENTWATCH] Blocked: malware/exploit request.'; }
      else if (isPhishing) { baseRule = 'block_phishing'; baseMessage = '[AGENTWATCH] Blocked: phishing pattern detected.'; }
      else if (isHarm) { baseRule = 'block_harmful'; baseMessage = '[AGENTWATCH] Blocked: harmful content detected.'; }
      else if (isCredentials) { baseRule = 'block_credentials'; baseMessage = '[AGENTWATCH] Blocked: credentials detected.'; }
      else if (isSensitivePath) { baseRule = 'block_sensitive_path'; baseMessage = '[AGENTWATCH] Blocked: sensitive path access.'; }
      else if (isCodeExec) { baseRule = 'block_code_execution'; baseMessage = '[AGENTWATCH] Blocked: code execution attempt.'; }
      else if (isPiiLeak) { baseRule = 'block_pii_leak'; baseMessage = '[AGENTWATCH] Blocked: PII leak detected.'; }
    } else if (shouldReview) {
      baseAction = 'REVIEW';
      baseRule = 'human_review_flagged';
      baseMessage = '[AGENTWATCH] Flagged for human review.';
    }

    // AI analysis pass (only if not already blocked)
    if (!shouldBlock) {
      try {
        aiAnalysis = await analyzeWithAI(prompt);
        if (aiAnalysis && aiAnalysis.is_threat === true) {
          const aiRisk = (aiAnalysis.risk_score || 0) / 100;
          if (aiRisk > (keywordMetadata.risk_score || 0)) keywordMetadata.risk_score = Math.min(aiRisk, 1);
          if (aiAnalysis.confidence > 0.5) {
            baseAction = 'DENY';
            baseRule = 'ai_detected_' + (aiAnalysis.threat_type || 'threat');
            baseMessage = `[AGENTWATCH] Blocked: AI analysis flagged as ${aiAnalysis.threat_type || 'threat'} (${aiAnalysis.risk_score || 0}/100).`;
            keywordMetadata.ai_flagged = true;
            keywordMetadata.ai_threat_type = aiAnalysis.threat_type;
            keywordMetadata.ai_reasoning = aiAnalysis.reasoning;
          }
        }
      } catch (e) {
        // AI analysis optional — don't fail the whole pipeline
        console.warn('[Phase3] AI analysis skipped:', e.message.slice(0, 100));
      }
    }

    // ── Step 2: Phase 1 — Session Memory + Multi-Turn Detection ──
    const session = sessionMemory.getOrCreate(sessionId);
    sessionMemory.addTurn(sessionId, {
      prompt,
      riskScore: keywordMetadata.risk_score || 0,
      intentCategory: keywordMetadata.intent_category || 'general',
      analysis: {
        baseAction,
        baseRule,
        is_injection: isInjection || isRoleImpersonation,
        keywordFlags: {
          injection: isInjection,
          exfil: isExfil,
          credentials: isCredentials,
          codeExec: isCodeExec,
          sensitivePath: isSensitivePath,
          pii: isPiiLeak,
          harm: isHarm,
          phishing: isPhishing,
          obfuscated: isObfuscated,
          roleImpersonation: isRoleImpersonation,
        },
      },
    });

    const sessionAnalysis = sessionMemory.getAnalysis(sessionId);
    const recentTurns = sessionMemory.getRecentTurns(sessionId, 5);

    // Run multi-turn attack detection
    const multiTurnResult = detectMultiTurnAttack(sessionAnalysis, recentTurns);
    const sessionRisk = sessionMemory.computeSessionRisk(sessionId);

    // ── Step 3: Phase 2 — Tool Risk Analysis ──
    const toolAnalysis = analyzeToolRisk(prompt);

    // ── Step 4: Phase 3 — Multi-Agent Security Reasoning ──
    const multiAgentResult = runSecurityAgents(prompt, sessionAnalysis, recentTurns);
    const verdict = multiAgentResult.verdict;

    // ── Step 4.5: Phase 4 — Memory Poisoning Detection ──
    const memoryPoisoning = detectMemoryPoisoning(prompt, recentTurns);
    const sessionMemoryIntegrity = analyzeSessionMemoryIntegrity(recentTurns);
    
    // Phase 4 contributes to risk: memory poisoning adds to composite
    const memoryRisk = memoryPoisoning.isPoisoning ? memoryPoisoning.riskScore : 0;
    
    // ── Step 4.75: Phase 5 — Runtime AI Sandboxing ──
    const sandboxResult = simulateExecution(prompt, toolAnalysis, recentTurns);
    const sandboxRisk = sandboxResult.sandboxRisk;
    const shouldHaltExecution = sandboxResult.shouldHalt;
    
    // ── Step 5: Composite Decision ──
    // Combine signals: keyword base + session risk + tool risk + multi-agent verdict
    const compositeSignals = [];

    // Collect all risk scores
    const allRisks = [
      { source: 'keyword', score: keywordMetadata.risk_score || 0 },
      { source: 'session', score: sessionRisk },
      { source: 'tool', score: toolAnalysis.overallRisk },
      { source: 'multi_agent', score: verdict.finalRisk },
      { source: 'memory_poisoning', score: memoryRisk },
      { source: 'sandbox', score: sandboxRisk },
    ];

    // Determine composite risk (weighted: multi-agent 30%, keyword 20%, session 15%, tool 10%, memory 10%, sandbox 15%)
    const compositeRisk = (
      (verdict.finalRisk * 0.30) +
      ((keywordMetadata.risk_score || 0) * 0.20) +
      (sessionRisk * 0.15) +
      (toolAnalysis.overallRisk * 0.10) +
      (memoryRisk * 0.10) +
      (sandboxRisk * 0.15)
    );

    // Determine final action
    let finalAction = baseAction;
    let finalRule = baseRule;
    let finalMessage = baseMessage;
    let overrideReason = null;

    // Multi-agent verdict overrides if confidence is high enough
    if (verdict.action === 'DENY' && verdict.actionConfidence > 0.7) {
      if (finalAction !== 'DENY') {
        overrideReason = `Multi-agent override: ${verdict.explanation}`;
      }
      finalAction = 'DENY';
      finalRule = 'phase3_multi_agent_deny';
      finalMessage = `[AGENTWATCH-P3] Blocked by multi-agent consensus (risk: ${(verdict.finalRisk * 100).toFixed(0)}%).`;
      compositeSignals.push('multi_agent_deny');
    }

    // Session risk escalation overrides
    if (sessionAnalysis?.isMultiTurnAttack && finalAction !== 'DENY') {
      if (finalAction === 'ALLOW') {
        if (sessionAnalysis.behavioralDrift.injectionAttempts > 1) {
          finalAction = 'DENY';
          finalRule = 'phase1_multi_turn_attack';
          finalMessage = `[AGENTWATCH-P1] Blocked: multi-turn attack detected (${sessionAnalysis.behavioralDrift.injectionAttempts} injection attempts across ${sessionAnalysis.turnCount} turns).`;
          overrideReason = 'Multi-turn attack detection';
          compositeSignals.push('multi_turn_deny');
        } else {
          finalAction = 'REVIEW';
          finalRule = 'phase1_multi_turn_flag';
          finalMessage = '[AGENTWATCH-P1] Flagged: multi-turn attack pattern detected.';
          compositeSignals.push('multi_turn_flag');
        }
      }
    }

    // Tool chaining detection (Phase 2) — escalate to deny
    if (toolAnalysis.chainedTools && finalAction !== 'DENY') {
      finalAction = 'DENY';
      finalRule = 'phase2_tool_chaining';
      finalMessage = `[AGENTWATCH-P2] Blocked: dangerous tool chain detected (${toolAnalysis.warnings.filter(w => w.includes('chaining')).join(', ')}).`;
      overrideReason = 'Tool chaining detection';
      compositeSignals.push('tool_chain_deny');
    }

    // Composite risk high — escalate
    if (compositeRisk > 0.8 && finalAction !== 'DENY') {
      finalAction = 'DENY';
      finalRule = 'phase_composite_high_risk';
      finalMessage = `[AGENTWATCH] Blocked: composite risk score ${(compositeRisk * 100).toFixed(0)}%.`;
      compositeSignals.push('composite_high_risk');
    }

    // Phase 4 — Memory poisoning override
    if (memoryPoisoning.isPoisoning && finalAction !== 'DENY') {
      finalAction = finalAction === 'ALLOW' ? 'REVIEW' : finalAction;
      finalRule = 'phase4_memory_poisoning';
      finalMessage = `[AGENTWATCH-P4] Flagged: memory poisoning attempt detected (${memoryPoisoning.poisoningType}).`;
      compositeSignals.push('memory_poisoning');
    }

    // Phase 5 — Sandbox halt override
    if (shouldHaltExecution && finalAction !== 'DENY') {
      finalAction = 'DENY';
      finalRule = 'phase5_sandbox_halt';
      finalMessage = `[AGENTWATCH-P5] Blocked: sandbox simulation predicts ${sandboxResult.consequences.length} consequences (blast radius: ${sandboxResult.blastRadiusLabel}).`;
      overrideReason = 'Sandbox simulation halt';
      compositeSignals.push('sandbox_halt');
    }

    // ── Step 6: Persist everything ──
    const eventId = uuidv4();

    // Write to security events table FIRST (agent_analyses has FK reference)
    const event = {
      id: eventId,
      timestamp: simulatedTime || new Date().toISOString(),
      action: finalAction,
      direction: 'ingress',
      rule: finalRule,
      message: finalMessage,
      risk_score: compositeRisk,
      intent_category: verdict.finalRisk > 0.5 ? (multiAgentResult.agents.injection.finding.startsWith('injection') ? 'prompt_injection' : keywordMetadata.intent_category || 'general') : keywordMetadata.intent_category || 'general',
      intent_confidence: verdict.actionConfidence || keywordMetadata.intent_confidence || 0,
      layer: compositeSignals.includes('multi_agent_deny') ? 'phase3' : compositeSignals.includes('tool_chain_deny') ? 'phase2' : compositeSignals.some(s => s.startsWith('multi_turn')) ? 'phase1' : keywordMetadata.ai_flagged ? 'ai' : (keywordMetadata.contains_injection_patterns ? 'keyword' : 'dynamic'),
      metadata: JSON.stringify({
        ...keywordMetadata,
        phase1: { sessionRisk, multiTurnResult, sessionTurnCount: sessionAnalysis?.turnCount },
        phase2: { toolAnalysisSummary: { toolCount: toolAnalysis.toolCount, highRiskTools: toolAnalysis.highRiskToolCount, chained: toolAnalysis.chainedTools, warnings: toolAnalysis.warnings } },
        phase3: { verdict, agentVotes: verdict.agentVotes },
        phase4: { memoryPoisoning: { isPoisoning: memoryPoisoning.isPoisoning, healthScore: memoryPoisoning.healthScore, type: memoryPoisoning.poisoningType }, sessionIntegrity: sessionMemoryIntegrity },
        phase5: { sandbox: { riskScore: sandboxResult.sandboxRisk, blastRadius: sandboxResult.blastRadius, shouldHalt: sandboxResult.shouldHalt, consequences: sandboxResult.consequences.slice(0, 5) } },
        compositeRisk,
        compositeSignals,
        overrideReason,
        ai_analysis: aiAnalysis,
      }),
    };

    db.prepare(`
      INSERT INTO security_events (id, timestamp, action, direction, rule, message, risk_score, intent_category, intent_confidence, layer, metadata)
      VALUES (@id, @timestamp, @action, @direction, @rule, @message, @risk_score, @intent_category, @intent_confidence, @layer, @metadata)
    `).run(event);

    const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || '/tmp/rugwatch-audit.log';
    const fs = require('fs');
    try { fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify({...event, metadata: JSON.parse(event.metadata)}) + '\n', 'utf-8'); } catch (e) {}

    // Write all agent analyses (event_id FK exists now)
    const persistAgents = [
      { ...multiAgentResult.agents.injection, eventId, sessionId, timestamp: event.timestamp },
      { ...multiAgentResult.agents.exfiltration, eventId, sessionId, timestamp: event.timestamp },
      { ...multiAgentResult.agents.toolExecution, eventId, sessionId, timestamp: event.timestamp },
      { ...verdict, eventId, sessionId, timestamp: event.timestamp },
    ];

    for (const agent of persistAgents) {
      db.prepare(`
        INSERT INTO agent_analyses (event_id, session_id, agent_name, risk_score, confidence, finding, reasoning, sub_categories, timestamp)
        VALUES (@eventId, @sessionId, @agentName, @riskScore, @confidence, @finding, @reasoning, @subCategories, @timestamp)
      `).run({
        eventId: agent.eventId,
        sessionId: agent.sessionId,
        agentName: agent.agentName,
        riskScore: agent.riskScore,
        confidence: agent.confidence,
        finding: agent.finding,
        reasoning: agent.reasoning || agent.explanation,
        subCategories: JSON.stringify(agent.subCategories || agent.agentVotes || {}),
        timestamp: agent.timestamp,
      });
    }

    // ── Step 7: Return enhanced response ──
    res.json({
      prompt,
      session_id: sessionId,
      action: finalAction,
      rule: finalRule,
      message: finalMessage,
      blocked: finalAction === 'DENY',
      
      // Phase 1
      phase1: {
        sessionRisk,
        turnCount: sessionAnalysis?.turnCount,
        currentRiskLevel: sessionAnalysis?.currentRiskLevel,
        isMultiTurnAttack: sessionAnalysis?.isMultiTurnAttack,
        isEscalating: sessionAnalysis?.isEscalating,
        behavioralShift: sessionAnalysis?.behavioralShift,
        multiTurnResult: {
          isAttack: multiTurnResult.isAttack,
          attackType: multiTurnResult.attackType,
          confidence: multiTurnResult.confidence,
        },
      },
      
      // Phase 2
      phase2: {
        toolAnalysis: {
          detectedTools: toolAnalysis.detectedTools.map(t => ({
            tool: t.tool,
            risk: Math.round(t.totalRisk * 100),
            dataSensitivity: t.dataSensitivity,
          })),
          overallRisk: Math.round(toolAnalysis.overallRisk * 100),
          toolCount: toolAnalysis.toolCount,
          chained: toolAnalysis.chainedTools,
        },
        warnings: toolAnalysis.warnings,
      },
      
      // Phase 3
      phase3: {
        verdict: {
          finalRisk: Math.round(verdict.finalRisk * 100),
          action: verdict.action,
          confidence: Math.round(verdict.actionConfidence * 100),
          explanation: verdict.explanation,
          sources: verdict.sources,
        },
        agents: {
          injection: { riskScore: Math.round(multiAgentResult.agents.injection.riskScore * 100), finding: multiAgentResult.agents.injection.finding },
          exfiltration: { riskScore: Math.round(multiAgentResult.agents.exfiltration.riskScore * 100), finding: multiAgentResult.agents.exfiltration.finding },
          toolExecution: { riskScore: Math.round(multiAgentResult.agents.toolExecution.riskScore * 100), finding: multiAgentResult.agents.toolExecution.finding },
        },
      },
      
      // Phase 4
      phase4: {
        memoryPoisoning: {
          isPoisoning: memoryPoisoning.isPoisoning,
          riskScore: Math.round(memoryPoisoning.riskScore * 100),
          confidence: Math.round(memoryPoisoning.confidence * 100),
          healthScore: Math.round(memoryPoisoning.healthScore * 100),
          type: memoryPoisoning.poisoningType,
          details: memoryPoisoning.details,
          indicators: memoryPoisoning.findings.map(f => ({ type: f.subType, severity: Math.round((f.weight || 0.5) * 100) })),
        },
        sessionIntegrity: {
          score: Math.round(sessionMemoryIntegrity.integrityScore * 100),
          status: sessionMemoryIntegrity.status,
          risks: sessionMemoryIntegrity.risks,
        },
      },
      
      // Phase 5
      phase5: {
        sandbox: {
          riskScore: Math.round(sandboxResult.sandboxRisk * 100),
          blastRadius: sandboxResult.blastRadius,
          blastRadiusLabel: sandboxResult.blastRadiusLabel,
          highestSensitivity: sandboxResult.highestSensitivity,
          consequenceRisk: Math.round(sandboxResult.consequenceRisk * 100),
          consequences: sandboxResult.consequences.slice(0, 5),
          affectedSystems: sandboxResult.affectedSystems,
          shouldHalt: sandboxResult.shouldHalt,
          warnings: sandboxResult.warnings.slice(0, 3),
          summary: sandboxResult.summary,
        },
      },
      
      // Composite
      composite: {
        compositeRisk: Math.round(compositeRisk * 100),
        signals: compositeSignals,
        overrideReason,
        riskBreakdown: {
          keyword: Math.round((keywordMetadata.risk_score || 0) * 100),
          session: Math.round(sessionRisk * 100),
          tool: Math.round(toolAnalysis.overallRisk * 100),
          multiAgent: Math.round(verdict.finalRisk * 100),
          memoryPoisoning: Math.round(memoryRisk * 100),
          sandbox: Math.round(sandboxRisk * 100),
        },
      },
      
      // Legacy fields (backwards compatibility)
      risk_score: compositeRisk,
      intent: keywordMetadata.intent_category || 'unknown',
      confidence: verdict.actionConfidence || keywordMetadata.intent_confidence || 0,
      metadata: keywordMetadata,
      ai_analysis: aiAnalysis,
    });

  } catch (error) {
    console.error('[Phase1-3] Inspection error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get full session analysis.
 */
router.get('/session/:id', (req, res) => {
  try {
    const sessionId = req.params.id;
    const analysis = sessionMemory.getAnalysis(sessionId);
    
    if (!analysis) {
      // Try DB
      const dbSession = db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId);
      if (!dbSession) return res.status(404).json({ error: 'Session not found' });
      
      const turns = db.prepare('SELECT * FROM session_turns WHERE session_id = ? ORDER BY turn_number ASC').all(sessionId);
      
      return res.json({
        sessionId: dbSession.session_id,
        turnCount: dbSession.turn_count,
        currentRiskLevel: dbSession.current_risk_level,
        riskTrajectory: JSON.parse(dbSession.risk_trajectory || '[]'),
        behavioralDrift: JSON.parse(dbSession.behavioral_drift || '{}'),
        flaggedPatterns: JSON.parse(dbSession.flagged_patterns || '[]'),
        turns: turns.map(t => ({
          turnNumber: t.turn_number,
          riskScore: t.risk_score,
          intentCategory: t.intent_category,
          promptPreview: (t.prompt || '').slice(0, 100),
        })),
      });
    }

    res.json(analysis);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get detailed agent analysis for a specific event.
 */
router.get('/analysis/:eventId', (req, res) => {
  try {
    const { eventId } = req.params;
    const analyses = db.prepare('SELECT * FROM agent_analyses WHERE event_id = ? ORDER BY risk_score DESC').all(eventId);
    
    if (analyses.length === 0) {
      return res.status(404).json({ error: 'Analysis not found' });
    }

    res.json({
      eventId,
      agents: analyses.map(a => ({
        agentName: a.agent_name,
        riskScore: a.risk_score,
        confidence: a.confidence,
        finding: a.finding,
        reasoning: a.reasoning,
        subCategories: (() => { try { return JSON.parse(a.sub_categories); } catch { return null; } })(),
      })),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Health check for Phase 1-3 system.
 */
router.get('/status', (req, res) => {
  const activeSessions = db.prepare("SELECT COUNT(*) as count FROM sessions WHERE datetime(updated_at) > datetime('now', '-30 minutes')").get()?.count || 0;
  const totalEvents = db.prepare('SELECT COUNT(*) as count FROM agent_analyses').get()?.count || 0;
  
  res.json({
    phase1: { activeSessions, status: 'online' },
    phase2: { toolCategories: require('../services/toolRiskAnalyzer').TOOL_CATEGORIES.length, status: 'online' },
    phase3: { agents: ['Injection_Analyst', 'Exfiltration_Analyst', 'Tool_Execution_Analyst', 'Behavioral_Judge'], status: 'online' },
    totalAgentAnalyses: totalEvents,
  });
});

module.exports = router;
module.exports.setSecurityRouter = setSecurityRouter;
