#!/usr/bin/env bash
# Startar Brave med debug-port för Claude. Egen profil, så den vanliga Brave-sessionen rörs inte.
# Porten lyssnar bara på 127.0.0.1. Ger full kontroll över profilen: logga bara in där det behövs.
set -euo pipefail

PORT="${JARRI_BROWSER_DEBUG_PORT:-9222}"
PROFILE="${JARRI_BROWSER_PROFILE:-$HOME/.brave-claude}"

if curl -fsS "http://127.0.0.1:${PORT}/json/version" >/dev/null 2>&1; then
  echo "Brave kör redan med debug-port ${PORT}"
  exit 0
fi

mkdir -p "$PROFILE"
exec brave-browser \
  --remote-debugging-port="$PORT" \
  --remote-debugging-address=127.0.0.1 \
  --user-data-dir="$PROFILE" \
  --no-first-run \
  --no-default-browser-check
