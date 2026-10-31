#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
for cmd in docker python3; do
  command -v "$cmd" >/dev/null || { echo "Missing: $cmd"; exit 1; }
done
docker compose version >/dev/null || { echo "Docker Compose v2 required"; exit 1; }
if [[ -f .env ]]; then
  echo ".env already exists; refusing to overwrite secrets."
  exit 1
fi
read -r -p "Telegram BotFather token: " BOT_TOKEN
read -r -p "Your numeric Telegram user ID: " OWNER_ID
if [[ ! "$BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ || ! "$OWNER_ID" =~ ^[0-9]+$ || "$OWNER_ID" == "0" ]]; then
  echo "Invalid bot token or Telegram user ID"; exit 1
fi
FKEY="$(python3 - <<'PYCODE'
import base64,secrets
print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
PYCODE
)"
umask 077
printf 'TELEGRAM_BOT_TOKEN=%s\nOWNER_TELEGRAM_ID=%s\nFERNET_KEY=%s\nDATABASE_PATH=/data/accounts.sqlite3\nLOG_LEVEL=INFO\n' "$BOT_TOKEN" "$OWNER_ID" "$FKEY" > .env
chmod 600 .env
unset BOT_TOKEN FKEY
docker compose up -d --build
printf '\nBot installed. Open your Telegram bot and send /start.\n'
docker compose ps
