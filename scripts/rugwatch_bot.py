#!/usr/bin/env python3
"""
RugWatch Telegram Bot — Security scanner for memecoins
"""

import os
import json
import logging
import sys
from pathlib import Path
import requests

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

# Config
RUGBOT_TOKEN = os.environ.get("RUGBOT_TOKEN", "")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:3001")

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔍 Scan Token", callback_data="scan")],
        [InlineKeyboardButton("📊 Recent Scans", callback_data="recent")],
        [InlineKeyboardButton("❓ Help", callback_data="help")],
    ])
    await update.message.reply_text(
        f"🦞 *RugWatch — Agent Security Scanner*\n\n"
        f"Hey {user.first_name}! I scan Solana tokens for rug potential, honeypots, and scam patterns.\n\n"
        f"Just send me a contract address or token name to scan!\n\n"
        f"Powered by DeepSeek AI + Lobster Trap",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=keyboard,
    )

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "*RugWatch Commands:*\n\n"
        "• Send any Solana contract address → instant scan\n"
        "• /scan \[address\] — scan a specific token\n"
        "• /recent — view recent scans\n"
        "• /stats — platform statistics\n\n"
        "*How it works:*\n"
        "1. Paste a token address\n"
        "2. AI analyzes contract, holders, liquidity, socials\n"
        "3. Gets a risk score (0-100)\n"
        "4. Detailed breakdown of red flags\n",
        parse_mode=ParseMode.MARKDOWN,
    )

async def scan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = " ".join(context.args) if context.args else ""
    if not text:
        await update.message.reply_text("Usage: /scan \[contract_address\] or just send me the address")
        return
    await perform_scan(update, context, text)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    # Check if it looks like a contract address (base58 for Solana)
    if len(text) >= 32 and len(text) <= 44 and text.isalnum():
        await perform_scan(update, context, text)
    else:
        await update.message.reply_text(
            "Send a Solana contract address to scan, or use /help for commands."
        )

async def perform_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, address):
    msg = await update.message.reply_text(f"🔍 Scanning `{address[:20]}...`\n\nAnalyzing contract...", parse_mode=ParseMode.MARKDOWN)

    try:
        # Call RugWatch backend
        response = requests.post(
            f"{BACKEND_URL}/api/scanner/scan",
            json={"contract": address, "chain": "solana"},
            timeout=30,
        )

        if response.status_code != 200:
            await msg.edit_text(f"❌ Scan failed: {response.json().get('error', 'Unknown error')}")
            return

        data = response.json()
        scan_id = data["scan_id"]

        # Poll for result
        import time
        for _ in range(30):
            time.sleep(1)
            result = requests.get(f"{BACKEND_URL}/api/scanner/scan/{scan_id}", timeout=10)
            if result.status_code == 200:
                scan_data = result.json()
                if scan_data["scan"]["status"] == "completed":
                    await format_scan_result(msg, scan_data)
                    return
                elif scan_data["scan"]["status"] == "failed":
                    await msg.edit_text("❌ Scan failed. Please try again.")
                    return
            await msg.edit_text(f"🔍 Scanning...\n\nAnalyzing contract `{address[:20]}...`\n🔄 Querying blockchain...\n🧠 AI analysis in progress...", parse_mode=ParseMode.MARKDOWN)

        await msg.edit_text("⏱️ Scan timed out. Try again later.")

    except Exception as e:
        await msg.edit_text(f"❌ Error: {str(e)[:200]}")

async def format_scan_result(msg, data):
    scan = data["scan"]
    results = data["results"]
    score = scan["risk_score"]

    # Emoji based on risk level
    if score >= 75:
        emoji = "🚨"
        level = "CRITICAL"
    elif score >= 50:
        emoji = "⚠️"
        level = "HIGH"
    elif score >= 25:
        emoji = "⚡"
        level = "MEDIUM"
    else:
        emoji = "✅"
        level = "LOW"

    summary_text = scan["summary"] or "No summary available"

    # Build result message
    text = (
        f"{emoji} *RugWatch Scan Result*\n\n"
        f"*Risk Score:* {score}/100 — *{level}*\n"
        f"*Summary:* {summary_text[:300]}\n\n"
        f"*Checks: ({sum(1 for r in results if r['passed'])}/{len(results)} passed)*\n"
    )

    # Add top findings
    for r in results[:5]:
        icon = "✅" if r["passed"] else "❌"
        text += f"\n{icon} *{r['title']}* — {r['description'][:100]}"

    if len(results) > 5:
        text += f"\n\n...and {len(results) - 5} more checks"

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Re-scan", callback_data=f"rescan:{scan['contract_address']}")],
        [InlineKeyboardButton("📊 Full Report", callback_data=f"report:{scan['id']}")],
    ])

    await msg.edit_text(text[:4000], parse_mode=ParseMode.MARKDOWN, reply_markup=keyboard)

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "scan":
        await query.message.reply_text("Send me a Solana contract address to scan!")
    elif data == "recent":
        response = requests.get(f"{BACKEND_URL}/api/scanner/scans?limit=5", timeout=10)
        if response.status_code == 200:
            scans = response.json()
            text = "*Recent Scans:*\n"
            for s in scans[:5]:
                risk = f"{s['risk_score']}/100" if s['risk_score'] else "?"
                status = "✅" if s['status'] == 'completed' else "⏳"
                text += f"\n{status} `{s['contract_address'][:16]}...` — {risk}"
            await query.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)
    elif data == "help":
        await help_cmd(update, context)

def main():
    if not RUGBOT_TOKEN:
        logger.error("RUGBOT_TOKEN not set!")
        sys.exit(1)

    app = Application.builder().token(RUGBOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("scan", scan_cmd))
    from telegram.ext import CallbackQueryHandler
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("RugWatch bot running...")
    app.run_polling()

if __name__ == "__main__":
    main()
