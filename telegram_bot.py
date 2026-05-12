#!/usr/bin/env python3
"""
AgentWatch Telegram Alert Bot
Sends real-time security alerts to your Telegram when
Lobster Trap detects DPI events.

Usage:
  1. Set TELEGRAM_BOT_TOKEN environment variable
  2. Run: python3 telegram_bot.py
"""

import os
import sys
import json
import time
import requests
import hashlib
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
AUDIT_LOG = os.path.expanduser("~/lobstertrap/audit.log")
POLL_INTERVAL = 10  # seconds

if not BOT_TOKEN or not CHAT_ID:
    print("❌ Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
    print("   export TELEGRAM_BOT_TOKEN='your_token'")
    print("   export TELEGRAM_CHAT_ID='your_chat_id'")
    sys.exit(1)

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

# ── Helpers ─────────────────────────────────────────────────────────
def send_alert(event):
    """Send a formatted security alert to Telegram."""
    meta = event.get("metadata", {})
    risk = (meta.get("risk_score", 0) or 0) * 100
    action = event.get("action", "UNKNOWN")
    direction = event.get("direction", "unknown")
    intent = meta.get("intent_category", "unknown")
    ts = event.get("timestamp", "")

    # Determine emoji and color
    if action == "DENY":
        emoji = "🚫"
        header = "BLOCKED ATTACK"
    elif action == "REVIEW":
        emoji = "⚠️"
        header = "FLAGGED FOR REVIEW"
    else:
        emoji = "✅"
        header = "PROMPT ALLOWED"

    signals = []
    if meta.get("contains_injection_patterns"): signals.append("Prompt Injection")
    if meta.get("contains_credentials"): signals.append("Credential Theft")
    if meta.get("contains_exfiltration"): signals.append("Data Exfiltration")
    if meta.get("contains_malware_request"): signals.append("Malware Request")
    if meta.get("contains_phishing_patterns"): signals.append("Phishing")
    if meta.get("contains_role_impersonation"): signals.append("Role Impersonation")
    if meta.get("contains_harm_patterns"): signals.append("Harmful Content")
    if meta.get("contains_pii"): signals.append("PII Leakage")
    if meta.get("contains_obfuscation"): signals.append("Obfuscated Text")
    if meta.get("contains_system_commands"): signals.append("System Commands")
    if meta.get("contains_sensitive_paths"): signals.append("Sensitive Paths")

    signals_str = ', '.join(signals) if signals else 'None'
    msg = (
        f"{emoji} AgentWatch Alert — {header}\n"
        f"━━━━━━━━━━━━━━\n"
        f"Risk Score: {risk:.0f}/100\n"
        f"Intent: {intent}\n"
        f"Direction: {direction}\n"
        f"Action: {action}\n"
        f"Signals: {signals_str}\n"
        f"Time: {ts}\n"
        f"━━━━━━━━━━━━━━\n"
        f"Dashboard: http://localhost:3001"
    )

    url = f"{TELEGRAM_API}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": msg,
        "disable_web_page_preview": True,
    }

    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code != 200:
            print(f"⚠️  Telegram API error: {r.status_code} {r.text[:200]}")
        return r.ok
    except Exception as e:
        print(f"⚠️  Failed to send: {e}")
        return False


def get_last_line(path):
    """Read the last line of a file efficiently."""
    try:
        with open(path, "rb") as f:
            try:
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b"\n":
                    f.seek(-2, os.SEEK_CUR)
            except OSError:
                f.seek(0)
            return f.readline().decode().strip()
    except (FileNotFoundError, OSError):
        return None


def get_file_hash(path):
    """MD5 hash of the file for change detection."""
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except (FileNotFoundError, OSError):
        return None


# ── Main Loop ──────────────────────────────────────────────────────
def main():
    print(f"🤖 AgentWatch Telegram Bot")
    print(f"   Watching: {AUDIT_LOG}")
    print(f"   Polling every {POLL_INTERVAL}s")
    print(f"   Press Ctrl+C to stop\n")

    last_hash = get_file_hash(AUDIT_LOG)
    last_event_id = None
    total_sent = 0

    while True:
        try:
            current_hash = get_file_hash(AUDIT_LOG)

            if current_hash and current_hash != last_hash:
                # File changed — read the new line(s)
                line = get_last_line(AUDIT_LOG)
                if line and line.startswith("{"):
                    try:
                        event = json.loads(line)
                        eid = event.get("request_id") or line[:40]

                        # Only alert on blocked or flagged events (reduce noise)
                        action = event.get("action", "")
                        risk = (event.get("metadata", {}).get("risk_score", 0) or 0)
                        if action == "DENY" or (action == "REVIEW") or risk > 0.5:
                            if eid != last_event_id:
                                send_alert(event)
                                total_sent += 1
                                last_event_id = eid
                                print(f"📨 Alert sent ({total_sent} total)")

                    except json.JSONDecodeError:
                        pass

                last_hash = current_hash

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print(f"\n👋 Stopped. {total_sent} alerts sent this session.")
            break
        except Exception as e:
            print(f"⚠️  Error: {e}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
