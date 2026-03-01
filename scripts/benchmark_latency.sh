#!/usr/bin/env bash
# ────────────────────────────────────────────
# benchmark_latency.sh — Measure end-to-end detection latency
#
# Orchestrates a controlled test:
#   1. Start the controller with timestamping enabled
#   2. Replay attack traffic
#   3. Measure time from first attack packet to first alert
#
# Usage:
#   sudo ./scripts/benchmark_latency.sh
# ────────────────────────────────────────────

set -euo pipefail

INTERFACE="${1:-eth0}"
PCAP="${2:-ml/data/test_traffic.pcap}"
CONFIG="configs/config.yaml"
ALERT_LOG="alerts.log"

echo "═══════════════════════════════════════════"
echo "Detection Latency Benchmark"
echo "═══════════════════════════════════════════"

# Clean previous alerts
> "$ALERT_LOG"

# Record start time
T_START=$(date +%s%N)

echo "Starting controller in background..."
./bin/controller --config "$CONFIG" &
CTRL_PID=$!
sleep 2  # Wait for XDP attachment

echo "Replaying attack traffic..."
T_REPLAY=$(date +%s%N)
tcpreplay --intf1="$INTERFACE" --topspeed "$PCAP" &
REPLAY_PID=$!

# Wait for first alert (timeout: 10 seconds)
echo "Waiting for detection..."
TIMEOUT=10
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ -s "$ALERT_LOG" ]; then
        T_ALERT=$(date +%s%N)
        break
    fi
    sleep 0.1
    ELAPSED=$((ELAPSED + 1))
done

# Calculate latency
if [ -s "$ALERT_LOG" ]; then
    LATENCY_NS=$((T_ALERT - T_REPLAY))
    LATENCY_MS=$((LATENCY_NS / 1000000))
    LATENCY_S=$(echo "scale=3; $LATENCY_NS / 1000000000" | bc)

    echo ""
    echo "═══════════════════════════════════════════"
    echo "RESULT"
    echo "═══════════════════════════════════════════"
    echo "  Detection Latency: ${LATENCY_MS} ms (${LATENCY_S} s)"

    if [ "$LATENCY_MS" -lt 2000 ]; then
        echo "  Status: ✓ PASS (< 2 seconds)"
    else
        echo "  Status: ✗ FAIL (>= 2 seconds)"
    fi

    echo ""
    echo "  First alert:"
    head -1 "$ALERT_LOG"
else
    echo "  Status: ✗ TIMEOUT — No alert detected within ${TIMEOUT}s"
fi

# Cleanup
kill "$CTRL_PID" 2>/dev/null || true
kill "$REPLAY_PID" 2>/dev/null || true
wait "$CTRL_PID" 2>/dev/null || true
wait "$REPLAY_PID" 2>/dev/null || true

echo ""
echo "Done."
