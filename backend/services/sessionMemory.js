/**
 * Session Memory — Tracks conversation sessions for multi-turn attack detection.
 * 
 * Each session stores:
 *   - Conversation turns (prompts + risk scores)
 *   - Risk trajectory (how risk evolves across turns)
 *   - Flagged patterns observed
 *   - Behavioral drift metrics
 * 
 * Sessions auto-expire after SESSION_TTL_MS of inactivity.
 */

const db = require('../models/database');

const SESSION_TTL_MS = 30 * 60 * 1000; // 30 min inactivity → session expires
const MAX_TURNS_PER_SESSION = 100;

// In-memory store for fast lookups, synced to DB periodically
class SessionMemory {
  constructor() {
    this.sessions = new Map();
    this._cleanupInterval = setInterval(() => this._cleanup(), 5 * 60 * 1000);
  }

  /**
   * Get or create a session for a given session_id.
   * @param {string} sessionId
   * @returns {object} session object
   */
  getOrCreate(sessionId) {
    if (!sessionId) {
      sessionId = `anon_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    }

    let session = this.sessions.get(sessionId);
    if (!session) {
      // Try loading from DB
      const dbSession = db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId);
      if (dbSession) {
        session = {
          sessionId: dbSession.session_id,
          agentId: dbSession.agent_id,
          turnCount: dbSession.turn_count,
          riskTrajectory: JSON.parse(dbSession.risk_trajectory || '[]'),
          currentRiskLevel: dbSession.current_risk_level || 'low',
          flaggedPatterns: JSON.parse(dbSession.flagged_patterns || '[]'),
          behavioralDrift: JSON.parse(dbSession.behavioral_drift || '{}'),
          createdAt: dbSession.created_at,
          updatedAt: dbSession.updated_at,
          turns: [], // loaded lazily
        };
        this.sessions.set(sessionId, session);
      } else {
        session = {
          sessionId,
          agentId: null,
          turnCount: 0,
          riskTrajectory: [],
          currentRiskLevel: 'low',
          flaggedPatterns: [],
          behavioralDrift: {
            avgPromptLength: 0,
            avgRiskScore: 0,
            riskAcceleration: 0,
            topicShifts: 0,
            injectionAttempts: 0,
          },
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          turns: [],
        };
        this.sessions.set(sessionId, session);
        // Persist to DB
        this._persistSession(session);
      }
    }

    session.updatedAt = new Date().toISOString();
    return session;
  }

  /**
   * Add a turn to a session.
   * @param {string} sessionId
   * @param {object} turnData { prompt, riskScore, intentCategory, analysis }
   * @returns {object} updated session
   */
  addTurn(sessionId, turnData) {
    const session = this.getOrCreate(sessionId);
    if (session.turnCount >= MAX_TURNS_PER_SESSION) {
      // Session full — archive old turns
      session.turns = session.turns.slice(-50);
      session.turnCount = 50;
    }

    const turn = {
      turnNumber: session.turnCount + 1,
      prompt: turnData.prompt || '',
      riskScore: turnData.riskScore || 0,
      intentCategory: turnData.intentCategory || 'general',
      analysis: turnData.analysis || null,
      timestamp: new Date().toISOString(),
    };

    session.turns.push(turn);
    session.turnCount++;
    session.riskTrajectory.push(turn.riskScore);

    // Update drift metrics
    this._updateDriftMetrics(session, turn);

    // Check for escalation patterns
    this._checkEscalation(session, turn);

    // Persist
    this._persistTurn(session.sessionId, turn);
    this._persistSession(session);

    return session;
  }

  /**
   * Get recent turns from a session.
   */
  getRecentTurns(sessionId, count = 5) {
    const session = this.sessions.get(sessionId);
    if (!session) return [];
    return session.turns.slice(-count);
  }

  /**
   * Get the full session analysis.
   */
  getAnalysis(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const drift = session.behavioralDrift || {};
    const trajectory = session.riskTrajectory || [];

    return {
      sessionId: session.sessionId,
      turnCount: session.turnCount,
      currentRiskLevel: session.currentRiskLevel,
      riskTrajectory: trajectory,
      behavioralDrift: {
        avgPromptLength: drift.avgPromptLength || 0,
        avgRiskScore: drift.avgRiskScore || 0,
        riskAcceleration: drift.riskAcceleration || 0,
        topicShifts: drift.topicShifts || 0,
        injectionAttempts: drift.injectionAttempts || 0,
      },
      flaggedPatterns: session.flaggedPatterns || [],
      recentTurns: session.turns.slice(-3).map(t => ({
        riskScore: t.riskScore,
        intentCategory: t.intentCategory,
        promptPreview: (t.prompt || '').slice(0, 80),
      })),
      // Composite threat signals
      isMultiTurnAttack: this._detectMultiTurnAttack(session),
      isEscalating: this._detectEscalation(session),
      behavioralShift: this._detectBehavioralShift(session),
    };
  }

  /** Compute a session-wide risk score (0-1) */
  computeSessionRisk(sessionId) {
    const analysis = this.getAnalysis(sessionId);
    if (!analysis) return 0;

    let score = 0;
    const factors = [];

    // Recent risk trend (last 3 turns weighted more)
    const recent = analysis.recentTurns || [];
    if (recent.length >= 2) {
      const avgRecent = recent.reduce((s, t) => s + t.riskScore, 0) / recent.length;
      factors.push(avgRecent * 0.4); // 40% weight
    }

    // Risk acceleration (sharp increase = bad)
    if (analysis.behavioralDrift.riskAcceleration > 0.3) {
      factors.push(analysis.behavioralDrift.riskAcceleration * 0.2);
    }

    // Multi-turn attack signal
    if (analysis.isMultiTurnAttack) factors.push(0.7 * 0.2);
    if (analysis.isEscalating) factors.push(0.6 * 0.1);
    if (analysis.behavioralShift) factors.push(0.5 * 0.1);

    // Injection attempts
    const injCount = analysis.behavioralDrift.injectionAttempts || 0;
    if (injCount > 0) factors.push(Math.min(injCount * 0.15, 0.6) * 0.15);

    // Flagged patterns
    const flaggedCount = (analysis.flaggedPatterns || []).length;
    if (flaggedCount > 0) factors.push(Math.min(flaggedCount * 0.2, 0.8) * 0.15);

    score = factors.reduce((s, f) => s + f, 0);
    return Math.min(Math.max(score, 0), 1);
  }

  // ─── Private helpers ───

  _updateDriftMetrics(session, turn) {
    const drift = session.behavioralDrift;
    const total = session.turnCount;

    // Running average of prompt length
    drift.avgPromptLength = ((drift.avgPromptLength || 0) * (total - 1) + (turn.prompt || '').length) / total;

    // Running average risk score
    drift.avgRiskScore = ((drift.avgRiskScore || 0) * (total - 1) + turn.riskScore) / total;

    // Risk acceleration — how fast risk is increasing across turns
    const trajectory = session.riskTrajectory;
    if (trajectory.length >= 3) {
      const recent = trajectory.slice(-3);
      drift.riskAcceleration = (recent[2] - recent[0]) / Math.max(recent[0], 0.01);
      // Clamp to reasonable range
      drift.riskAcceleration = Math.max(-10, Math.min(10, drift.riskAcceleration));
    }

    // Track injection attempts
    if (turn.intentCategory === 'prompt_injection' || turn.analysis?.is_injection) {
      drift.injectionAttempts = (drift.injectionAttempts || 0) + 1;
    }
  }

  _checkEscalation(session, turn) {
    const trajectory = session.riskTrajectory;
    if (trajectory.length < 3) return;

    // Check for sudden sharp increases
    const lastThree = trajectory.slice(-3);
    const jumps = [];
    for (let i = 1; i < lastThree.length; i++) {
      jumps.push(lastThree[i] - lastThree[i - 1]);
    }

    // If any jump > 0.5, it's an escalation
    if (jumps.some(j => j > 0.5)) {
      if (!session.flaggedPatterns.includes('risk_escalation')) {
        session.flaggedPatterns.push('risk_escalation');
      }
    }

    // If risk went from low (< 0.3) to high (> 0.7) in 3+ turns, flag as escalation pattern
    if (trajectory.length >= 4) {
      const first = trajectory.slice(0, 3);
      const last = trajectory.slice(-2);
      const avgFirst = first.reduce((s, r) => s + r, 0) / first.length;
      const avgLast = last.reduce((s, r) => s + r, 0) / last.length;
      if (avgFirst < 0.3 && avgLast > 0.7) {
        if (!session.flaggedPatterns.includes('gradual_escalation')) {
          session.flaggedPatterns.push('gradual_escalation');
        }
      }
    }

    // Update risk level
    const avgRecent = trajectory.slice(-5).reduce((s, r) => s + r, 0) / Math.min(trajectory.length, 5);
    if (avgRecent > 0.7) session.currentRiskLevel = 'critical';
    else if (avgRecent > 0.5) session.currentRiskLevel = 'high';
    else if (avgRecent > 0.3) session.currentRiskLevel = 'medium';
    else session.currentRiskLevel = 'low';
  }

  _detectMultiTurnAttack(session) {
    const patterns = session.flaggedPatterns || [];
    if (patterns.includes('gradual_escalation')) return true;

    const drift = session.behavioralDrift;
    const trajectory = session.riskTrajectory || [];
    // Injection attempts that started low then escalated
    if ((drift.injectionAttempts || 0) >= 2 && (drift.riskAcceleration || 0) > 0.5) return true;

    // Multiple topic shifts with increasing risk
    if ((drift.topicShifts || 0) >= 2 && (drift.riskAcceleration || 0) > 0.8) return true;

    // NEW: Any injection attempt at high risk level across 3+ turns
    if ((drift.injectionAttempts || 0) >= 1 && session.currentRiskLevel === 'critical' && session.turnCount >= 3) return true;

    // NEW: Sharp risk jump (any single turn risk > 0.7 with injection in session)
    if ((drift.injectionAttempts || 0) >= 1 && trajectory.some(r => r > 0.8) && session.turnCount >= 2) return true;

    return false;
  }

  _detectEscalation(session) {
    const trajectory = session.riskTrajectory || [];
    if (trajectory.length < 3) return false;

    // Check for sustained increase (monotonic increase in last 3)
    const recent = trajectory.slice(-3);
    return recent[0] < recent[1] && recent[1] < recent[2];
  }

  _detectBehavioralShift(session) {
    const drift = session.behavioralDrift;
    if (!drift) return false;

    // Detect abrupt changes in prompt length or style
    const turns = session.turns;
    if (turns.length < 3) return false;

    const lastThreeLen = turns.slice(-3).map(t => (t.prompt || '').length);
    const beforeAvg = turns.slice(0, Math.max(0, turns.length - 3)).reduce((s, t) => s + (t.prompt || '').length, 0) / Math.max(turns.length - 3, 1);
    const recentAvg = lastThreeLen.reduce((s, l) => s + l, 0) / 3;

    // If recent prompts are significantly longer (3x+) than earlier ones
    if (beforeAvg > 20 && recentAvg > beforeAvg * 3) return true;

    return false;
  }

  _persistSession(session) {
    try {
      db.prepare(`
        INSERT INTO sessions (session_id, agent_id, turn_count, risk_trajectory, current_risk_level, flagged_patterns, behavioral_drift, created_at, updated_at)
        VALUES (@sessionId, @agentId, @turnCount, @riskTrajectory, @currentRiskLevel, @flaggedPatterns, @behavioralDrift, @createdAt, @updatedAt)
        ON CONFLICT(session_id) DO UPDATE SET
          turn_count = @turnCount,
          risk_trajectory = @riskTrajectory,
          current_risk_level = @currentRiskLevel,
          flagged_patterns = @flaggedPatterns,
          behavioral_drift = @behavioralDrift,
          updated_at = @updatedAt
      `).run({
        sessionId: session.sessionId,
        agentId: session.agentId,
        turnCount: session.turnCount,
        riskTrajectory: JSON.stringify(session.riskTrajectory),
        currentRiskLevel: session.currentRiskLevel,
        flaggedPatterns: JSON.stringify(session.flaggedPatterns),
        behavioralDrift: JSON.stringify(session.behavioralDrift),
        createdAt: session.createdAt,
        updatedAt: session.updatedAt,
      });
    } catch (e) {
      console.warn('[SessionMemory] DB persist error:', e.message);
    }
  }

  _persistTurn(sessionId, turn) {
    try {
      db.prepare(`
        INSERT OR IGNORE INTO session_turns (session_id, turn_number, prompt, risk_score, intent_category, analysis, timestamp)
        VALUES (@sessionId, @turnNumber, @prompt, @riskScore, @intentCategory, @analysis, @timestamp)
      `).run({
        sessionId,
        turnNumber: turn.turnNumber,
        prompt: turn.prompt,
        riskScore: turn.riskScore,
        intentCategory: turn.intentCategory,
        analysis: turn.analysis ? JSON.stringify(turn.analysis) : null,
        timestamp: turn.timestamp,
      });
    } catch (e) {
      console.warn('[SessionMemory] Turn persist error:', e.message);
    }
  }

  _cleanup() {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      const age = now - new Date(session.updatedAt).getTime();
      if (age > SESSION_TTL_MS) {
        this._persistSession(session); // final save
        this.sessions.delete(id);
      }
    }
  }

  /** Cleanup resources */
  destroy() {
    clearInterval(this._cleanupInterval);
    // Final persist for all sessions
    for (const session of this.sessions.values()) {
      this._persistSession(session);
    }
    this.sessions.clear();
  }
}

// Singleton
const sessionMemory = new SessionMemory();

module.exports = sessionMemory;
