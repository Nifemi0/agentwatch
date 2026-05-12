
```
 █████╗  ██████╗ ███████╗███╗   ██╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

# AgentWatch: AI Agent Security Observatory

**Real-time threat detection, policy enforcement, and compliance auditing for production AI agents.**

---

## The Problem

AI agents are being deployed in production without security guardrails. Prompt injection, data exfiltration, credential theft — the attack surface is expanding fast. Existing security tools are either **cloud-locked** (requiring your sensitive data to leave your network for scanning) or simply don't inspect traffic at the **deep packet inspection (DPI)** level. You're flying blind.

## The Solution

**AgentWatch** uses [Lobster Trap](https://github.com/nousresearch/lobstertrap), a local deep packet inspection proxy, to inspect **every prompt and response** passing between users and AI agents. It runs entirely **on-premises** with zero external API calls for security scanning. Your data never leaves your network.

```
User/Agent → AgentWatch Dashboard → Lobster Trap DPI Proxy → Local LLM (Ollama/Qwen)
                    ↓                        ↓
              SQLite Audit Log        Policy YAML Engine
                    ↓
            Real-time Alerts (Telegram)
```

---

## Key Features

- 🛡️ **Deep Packet Inspection** — Scans every prompt for 13 signal categories: injection attempts, credential leaks, data exfiltration, malware patterns, phishing, PII disclosure, and more
- 📊 **Live Dashboard** — 7-page React dashboard: Overview, Threat Feed, Agent Console, Audit Log, Policy Editor, Analytics
- 🤖 **Agent Console** — Test any prompt through the security pipeline in real-time with 6 preset attack vectors
- ⚙️ **Policy Engine** — YAML-based policy rules with a visual builder. Save, test, and hot-reload policies without restarting
- 📋 **Audit Log** — Complete traceability with CSV export, pagination, and detailed event modals
- 📈 **Analytics** — Attack patterns by hour, threat type breakdown, intent distribution charts
- 🔔 **Telegram Alerts** — Real-time security notifications sent straight to your chat (optional)
- 🏠 **100% Local** — No cloud dependency. Everything runs on-premises, including the LLM

---

## Quick Start

```bash
git clone https://github.com/yourusername/agentwatch
cd agentwatch

# Start Lobster Trap DPI proxy
cd lobstertrap && ./lobstertrap serve \
  --policy rugwatch_policy.yaml \
  --backend http://localhost:11434 \
  --listen :8080 \
  --audit-log audit.log &

# Start the backend API server
cd ../backend && npm install && node server.js &

# Open the dashboard
# → http://localhost:3001
```

**Prerequisites:** [Ollama](https://ollama.com) with Qwen 2.5:3b (`ollama pull qwen2.5:3b`), Node.js 18+, Go 1.22+

---

## Deployment Guide

### Sidecar Pattern (Recommended for Production)

Run AgentWatch **alongside your existing AI bot** on the same server. Your bot continues talking to the AI, but routes all traffic through Lobster Trap for inspection.

```
Your Bot (Telegram/Discord/API) → Lobster Trap (:8080) → AI Provider (OpenAI/Gemini/Ollama)
                                          ↓
                                    AgentWatch Dashboard (:3001)
```

**Zero code changes** — just tell your bot to point API calls to `http://localhost:8080` instead of the AI provider directly. Same payload format, same responses. AgentWatch just inspects, logs, and blocks threats in between.

### Local LLM vs Cloud API

| Setup | When to use | Performance |
|-------|-------------|-------------|
| **Local LLM** (Ollama + Qwen 3B) | Your server has 4+ cores, you want 100% offline | ~2-3 min per response on 2 cores |
| **Cloud API** (OpenRouter, OpenAI, Gemini) | Low-end server, want fast responses, hackathon deploys | ~1-3 seconds per response |
| **Hybrid** | Default to fast cloud API, fallback to local on network errors | Best of both |

For **hackathon deployment** (Render, Railway, etc.): use cloud APIs. The free tiers of OpenRouter ($1 credit) and Gemini Flash (60 req/min free) are enough for a demo.

### Deploy to Render

```bash
# 1. Push to GitHub
git push origin main

# 2. On Render:
#    - New Web Service → connect your repo
#    - Build command: cd backend && npm install
#    - Start command: cd backend && node server.js
#    - Add env vars: OPENROUTER_API_KEY, GEMINI_API_KEY

# 3. Your dashboard is live at https://your-app.onrender.com
```

The frontend (React build) is served directly by the Express backend — no separate static hosting needed.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React, Socket.io, Chart.js |
| **Backend** | Express (Node.js) |
| **Database** | SQLite |
| **DPI Proxy** | Lobster Trap (Go) |
| **LLM** | Ollama + Qwen 2.5:3b |
| **Alerts** | Telegram Bot API |

---

## Screenshots

> *Screenshots coming soon — check back after the hackathon demo!*

---

## Hackathon

Built for the **Veea / Google Hackathon 2026**.

- **Track 1** — Agent Security
- **Track 2** — AI Agents

---

## License

[MIT](LICENSE)
