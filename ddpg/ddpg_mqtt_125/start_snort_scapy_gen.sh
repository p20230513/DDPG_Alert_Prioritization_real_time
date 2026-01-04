#!/usr/bin/env bash
# ============================================================
# Real-Time DDPG Alert Prioritization Pipeline
# ------------------------------------------------------------
# Starts Snort3 + Scapy traffic generator
# ------------------------------------------------------------
# Author: vikash Kumar
# ============================================================

set -euo pipefail

# --- CONFIGURATION ---
VENV_PATH="${VIRTUAL_ENV:-$HOME/ddpg_workspace/AlertPrioritization/venv37}"
SRC_DIR="$VENV_PATH/../../ddpg_AlertPrioritization/ddpg/ddpg_mqtt_125/src"
LOG_DIR="$VENV_PATH/snort3/var/log/snort"
SNIFF_IFACE="lo"
RATIO="0.4"

# --- Ensure virtualenv is active ---
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    echo "[INFO] Activating Python virtual environment..."
    source "$VENV_PATH/bin/activate"
fi

echo "============================================================"
echo "Starting Real-Time DDPG Alert Prioritization Pipeline"
echo "VENV:    $VENV_PATH"
echo "SRC_DIR: $SRC_DIR"
echo "LOG_DIR: $LOG_DIR"
echo "============================================================"

mkdir -p "$LOG_DIR"
cd "$SRC_DIR"

# --- Step 1: Start Snort3 ---
echo "[1/3] Launching Snort++ ..."
sudo -E "$VENV_PATH/snort3/bin/snort" \
  -c "$VENV_PATH/snort3/etc/snort/snort.lua" \
 -i "$SNIFF_IFACE" -A alert_json \
  -l "$LOG_DIR" \
  > "$LOG_DIR/snort_runtime.log" 2>&1 &

SNORT_PID=$!
echo "[INFO] Snort started with PID: $SNORT_PID"
sleep 3

# --- Step 2: Start Scapy Traffic Generator ---
echo "[2/3] Launching Scapy Traffic Generator ..."
sudo -E "$VENV_PATH/bin/python3.7" "$SRC_DIR/scapy_traffic.py" \
  --iface "$SNIFF_IFACE" --ratio "$RATIO" --continuous \
  --benign-burst 5 --attack-burst 20
  > "$LOG_DIR/traffic_gen.log" 2>&1 &

TRAFFIC_PID=$!
echo "[INFO] Scapy traffic generator PID: $TRAFFIC_PID"
sleep 3

echo "============================================================"
echo "All components launched successfully."
echo "   - Snort Log:   $LOG_DIR/snort_runtime.log"
echo "   - Traffic Log: $LOG_DIR/traffic_gen.log"
echo "============================================================"

# --- Cleanup handler ---
cleanup() {
    echo "Stopping all processes..."
    sudo kill -9 "$SNORT_PID" "$TRAFFIC_PID" 2>/dev/null || true
    echo "All processes stopped."
}
trap cleanup EXIT

# --- Monitor ---
echo "[MONITOR] Press Ctrl+C to stop..."
wait
