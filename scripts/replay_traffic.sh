#!/usr/bin/env bash
# ────────────────────────────────────────────
# replay_traffic.sh — Replay CIC-DDoS2019 PCAPs against the XDP system
#
# This script uses tcpreplay to send captured traffic at controlled rates
# to benchmark detection latency and throughput.
#
# Usage:
#   sudo ./scripts/replay_traffic.sh [PCAP_FILE] [INTERFACE] [SPEED_MBPS]
#
# Examples:
#   sudo ./scripts/replay_traffic.sh ml/data/friday.pcap eth0 100
#   sudo ./scripts/replay_traffic.sh ml/data/friday.pcap eth0 1000  # 1Gbps
# ────────────────────────────────────────────

set -euo pipefail

PCAP_FILE="${1:-ml/data/test_traffic.pcap}"
INTERFACE="${2:-eth0}"
SPEED_MBPS="${3:-100}"

if [ "$EUID" -ne 0 ]; then
    echo "Error: tcpreplay requires root. Run with sudo."
    exit 1
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file not found: $PCAP_FILE"
    echo ""
    echo "To create a test PCAP from the CIC-DDoS2019 CSV data:"
    echo "  Download PCAPs from https://www.unb.ca/cic/datasets/ddos-2019.html"
    echo "  Or generate synthetic PCAPs with scapy (see docs/architecture.md)"
    exit 1
fi

echo "═══════════════════════════════════════════"
echo "Traffic Replay Configuration"
echo "═══════════════════════════════════════════"
echo "  PCAP:      $PCAP_FILE"
echo "  Interface: $INTERFACE"
echo "  Speed:     ${SPEED_MBPS} Mbps"
echo ""

# ── Pre-flight checks ──
echo "── Pre-flight checks ──"

# Check XDP is loaded
XDP_STATUS=$(ip link show "$INTERFACE" | grep -o "xdp" || true)
if [ -z "$XDP_STATUS" ]; then
    echo "  ⚠ WARNING: No XDP program detected on $INTERFACE"
    echo "  Run the controller first: sudo ./bin/controller --config configs/config.yaml"
fi

# PCAP info
echo "  PCAP stats:"
tcpreplay --stats=0 "$PCAP_FILE" 2>&1 | head -5 || true

echo ""
echo "── Starting replay ──"
echo "Press Ctrl+C to stop"
echo ""

# ── Replay at specified speed ──
# --mbps: target throughput
# --stats=1: print stats every second
# --loop=1: play once (change for continuous testing)
tcpreplay \
    --intf1="$INTERFACE" \
    --mbps="$SPEED_MBPS" \
    --stats=1 \
    --loop=1 \
    "$PCAP_FILE"

echo ""
echo "✓ Replay complete."
echo "Check alerts.log for detection events."
