#!/usr/bin/env bash
set -euo pipefail

# Always run from the folder where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Defaults (can be overridden via env)
: "${HOST:=0.0.0.0}"
: "${PORT:=5173}"

# Install dependencies if node_modules is missing
if [ ! -d "node_modules" ]; then
  echo "Installing dependencies..."
  npm ci || npm install
fi

echo
echo "Starting server on ${HOST}:${PORT}..."
HOST="$HOST" PORT="$PORT" npm start
