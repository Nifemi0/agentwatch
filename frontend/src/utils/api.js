import { io } from 'socket.io-client';

const API = '/api';

const socket = io('/', { autoConnect: false, transports: ['websocket', 'polling'] });

/* ─── Scanner ─── */
export async function scanToken(data) {
  const r = await fetch(`${API}/scanner/scan`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(data)
  });
  return r.json();
}
export async function getScan(id) {
  const r = await fetch(`${API}/scanner/scan/${id}`);
  return r.json();
}
export async function getRecentScans(limit=50) {
  const r = await fetch(`${API}/scanner/scans?limit=${limit}`);
  return r.json();
}
export async function getScannerStats() {
  const r = await fetch(`${API}/scanner/stats`);
  return r.json();
}
export async function getHealth() {
  const r = await fetch(`${API}/health`);
  return r.json();
}

/* ─── Security / Lobster Trap ─── */
export async function getSecurityEvents(limit=100) {
  const r = await fetch(`${API}/security/events?limit=${limit}`);
  return r.json();
}
export async function getSecurityStats() {
  const r = await fetch(`${API}/security/stats`);
  return r.json();
}
export async function inspectPrompt(prompt) {
  const r = await fetch(`${API}/security/inspect`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ prompt })
  });
  return r.json();
}
export async function chatAgent(prompt) {
  const r = await fetch(`${API}/security/chat`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ prompt })
  });
  return r.json();
}
export async function getPolicy() {
  const r = await fetch(`${API}/security/policy`);
  return r.json();
}
export async function savePolicy(yaml) {
  const r = await fetch(`${API}/security/policy`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ yaml })
  });
  return r.json();
}

/* ─── Agents ─── */
export async function getAgents() {
  const r = await fetch(`${API}/agents`);
  return r.json();
}

export { socket };
