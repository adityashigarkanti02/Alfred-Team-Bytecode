#!/usr/bin/env bash
# ALFRED Gmail Access Setup Helper
# Configures your real Gmail credentials for the Gmail MCP connector.

echo "======================================================"
echo "          ALFRED — Gmail MCP Access Setup             "
echo "======================================================"
echo ""
echo "To connect ALFRED to your live Gmail account:"
echo "1. Visit: https://myaccount.google.com/apppasswords"
echo "2. Generate an App Password named 'ALFRED'"
echo "3. Enter your Gmail address and 16-character App Password below:"
echo ""

read -p "Enter your Gmail address (e.g. user@gmail.com): " USER_EMAIL
read -s -p "Enter your 16-character Google App Password: " APP_PASS
echo ""

if [ -z "$USER_EMAIL" ] || [ -z "$APP_PASS" ]; then
    echo "[-] Error: Email and App Password cannot be empty."
    exit 1
fi

ENV_FILE="/home/nool/alfred/.env"

# Save to .env (which is in .gitignore so it will never be committed)
cat <<EOF > "$ENV_FILE"
GMAIL_USER="$USER_EMAIL"
GMAIL_APP_PASSWORD="$APP_PASS"
ALFRED_WORKSPACE_DIR="/home/nool/alfred/workspace"
ALFRED_EXECUTION_MODE="real"
EOF

chmod 600 "$ENV_FILE"

echo ""
echo "[+] Credentials saved securely to $ENV_FILE (mode 600)."
echo "[+] Testing Gmail connection via Gmail MCP..."

python3 -c "
import os
import sys
import smtplib
import imaplib

user = '$USER_EMAIL'
pwd = '$APP_PASS'.replace(' ', '')

# Test IMAP
try:
    mail = imaplib.IMAP4_SSL('imap.gmail.com', 993, timeout=10)
    mail.login(user, pwd)
    status, _ = mail.select('INBOX', readonly=True)
    mail.logout()
    print('[✓] Gmail IMAP (Reading Emails): SUCCESS')
except Exception as e:
    print(f'[-] Gmail IMAP Error: {e}')

# Test SMTP
try:
    smtp = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10)
    smtp.login(user, pwd)
    smtp.quit()
    print('[✓] Gmail SMTP (Sending Emails): SUCCESS')
except Exception as e:
    print(f'[-] Gmail SMTP Error: {e}')
"

echo ""
echo "======================================================"
echo "To start ALFRED with Gmail MCP live access:"
echo "  export \$(cat /home/nool/alfred/.env | xargs)"
echo "  python3 openchat-web/alfred/server.py"
echo "======================================================"
