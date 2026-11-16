#!/usr/bin/env bash
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$ROOT_DIR/.wsa-runtime"

stop_pid() {
  local name="$1" file="$STATE_DIR/$1.pid"
  if [ -f "$file" ]; then
    local pid
    pid="$(cat "$file")"
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
    rm -f "$file"
    echo "Stopped $name (PID $pid)."
  fi
}

stop_pid frontend
stop_pid backend
stop_pid wpa
stop_pid hostapd

fuser -k 8000/tcp 2>/dev/null || true
fuser -k 5173/tcp 2>/dev/null || true

echo "WSA processes stopped."
