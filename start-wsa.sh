#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$ROOT_DIR/.wsa-runtime"
mkdir -p "$STATE_DIR"

diagnose() {
  echo "WSA environment diagnostics"
  uname -a
  echo "--- mac80211_hwsim"
  modinfo mac80211_hwsim 2>&1 | sed -n '1,8p' || true
  echo "--- wireless interfaces"
  iw dev 2>&1 || true
  echo "--- links"
  ip -br link 2>&1 || true
  echo "--- Scapy"
  "$ROOT_DIR/.venv/bin/python" - <<'PY' 2>&1 || true
try:
    import scapy
    print(f"Scapy available: {getattr(scapy, '__version__', 'unknown')}")
except Exception as exc:
    print(f"Scapy unavailable: {exc}")
PY
  echo "--- WSA processes"
  for pid_file in "$STATE_DIR"/*.pid; do [ -f "$pid_file" ] && echo "$(basename "$pid_file"): $(cat "$pid_file")"; done
}

if [ "${1:-}" = "--diagnose" ]; then diagnose; exit 0; fi

PYTHON="$ROOT_DIR/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then PYTHON="$(command -v python3 || command -v python)"; fi
if [ -z "${PYTHON:-}" ]; then echo "Python 3 is required."; exit 1; fi

if ! command -v iw >/dev/null || ! command -v modprobe >/dev/null; then
  echo "Wireless tooling unavailable: iw and modprobe are required."
else
  if ! lsmod 2>/dev/null | grep -q '^mac80211_hwsim'; then
    echo "Loading mac80211_hwsim (requires CAP_SYS_MODULE/root)..."
    if ! modprobe mac80211_hwsim radios=3; then
      echo "Could not load mac80211_hwsim. WSA will report the exact capture blocker; no fake live data will be used."
    fi
  fi
fi

echo "Detected wireless interfaces:"
iw dev 2>&1 || true

if [ "${WSA_SKIP_LAB_SETUP:-0}" != "1" ] && [ -x "$ROOT_DIR/scripts/setup_virtual_lab.sh" ]; then
  echo "Setting up isolated virtual AP/client lab..."
  "$ROOT_DIR/scripts/setup_virtual_lab.sh" || echo "Virtual lab setup unavailable; Live Monitor will report the actual blocker."
fi

if [ -f "$STATE_DIR/backend.pid" ] && kill -0 "$(cat "$STATE_DIR/backend.pid")" 2>/dev/null; then
  echo "Backend already running (PID $(cat "$STATE_DIR/backend.pid"))."
else
  (cd "$ROOT_DIR" && setsid "$PYTHON" -m wsa.api </dev/null >"$STATE_DIR/backend.log" 2>&1 & echo $! >"$STATE_DIR/backend.pid")
  sleep 1
  echo "Backend started (PID $(cat "$STATE_DIR/backend.pid"))."
fi

if [ -f "$STATE_DIR/frontend.pid" ] && kill -0 "$(cat "$STATE_DIR/frontend.pid")" 2>/dev/null; then
  echo "Frontend already running (PID $(cat "$STATE_DIR/frontend.pid"))."
else
  (cd "$ROOT_DIR/frontend" && setsid npm run dev -- --host 0.0.0.0 </dev/null >"$STATE_DIR/frontend.log" 2>&1 & echo $! >"$STATE_DIR/frontend.pid")
  sleep 1
  echo "Frontend started (PID $(cat "$STATE_DIR/frontend.pid"))."
fi

echo "Frontend: http://localhost:5173  (also accessible on http://127.0.0.1:5173 and VM IP)"
echo "Backend:  http://localhost:8000  (also accessible on http://127.0.0.1:8000 and VM IP)"
echo "Live Monitor uses a selectable wireless interface reported by /api/live/diagnostics."
echo "Run ./start-wsa.sh --diagnose for capability and blocker details."
