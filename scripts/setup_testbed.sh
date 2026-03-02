#!/usr/bin/env bash
# ────────────────────────────────────────────
# setup_testbed.sh — Prepare the testing environment
#
# This script sets up an Ubuntu 22.04/24.04 machine with all
# required dependencies for the DDoS Early Warning System.
#
# Usage:
#   chmod +x scripts/setup_testbed.sh
#   sudo ./scripts/setup_testbed.sh
# ────────────────────────────────────────────

set -euo pipefail

echo "═══════════════════════════════════════════"
echo "DDoS Early Warning System — Testbed Setup"
echo "═══════════════════════════════════════════"

# ── Check root ──
if [ "$EUID" -ne 0 ]; then
    echo "Error: Run this script as root (sudo)."
    exit 1
fi

# ── Check kernel version (need 6.x+ for modern eBPF) ──
KVER=$(uname -r | cut -d. -f1)
echo "Kernel version: $(uname -r)"
if [ "$KVER" -lt 5 ]; then
    echo "WARNING: Kernel $KVER.x detected. eBPF/XDP requires kernel 5.x+ (6.x+ recommended)."
    echo "Consider upgrading: sudo apt install linux-image-generic-hwe-22.04"
fi

echo ""
echo "── Installing system packages ──"
apt-get update
apt-get install -y \
    build-essential \
    clang-15 \
    llvm-15 \
    libbpf-dev \
    linux-tools-$(uname -r) \
    linux-headers-$(uname -r) \
    bpftool \
    tcpreplay \
    tcpdump \
    tshark \
    iproute2 \
    net-tools \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget

# ── Symlink clang/llvm if installed as clang-15 ──
if command -v clang-15 &>/dev/null && ! command -v clang &>/dev/null; then
    ln -sf /usr/bin/clang-15 /usr/bin/clang
    ln -sf /usr/bin/llvm-strip-15 /usr/bin/llvm-strip
    echo "Symlinked clang-15 → clang"
fi

echo ""
echo "── Installing Go 1.21+ ──"
GO_VERSION="1.21.6"
if ! command -v go &>/dev/null; then
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
    export PATH=$PATH:/usr/local/go/bin
    echo "Go ${GO_VERSION} installed."
else
    echo "Go already installed: $(go version)"
fi

echo ""
echo "── Installing ONNX Runtime (C library) ──"
ORT_VERSION="1.16.3"
ORT_DIR="/usr/local/onnxruntime"
if [ ! -d "$ORT_DIR" ]; then
    wget -q "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-x64-${ORT_VERSION}.tgz" \
        -O /tmp/ort.tgz
    mkdir -p "$ORT_DIR"
    tar -C "$ORT_DIR" --strip-components=1 -xzf /tmp/ort.tgz
    echo "${ORT_DIR}/lib" > /etc/ld.so.conf.d/onnxruntime.conf
    ldconfig
    echo "ONNX Runtime ${ORT_VERSION} installed to ${ORT_DIR}"
else
    echo "ONNX Runtime already installed."
fi

echo ""
echo "── Verifying installation ──"
echo "  clang:    $(clang --version | head -1)"
echo "  llvm:     $(llvm-strip --version | head -1)"
echo "  go:       $(go version)"
echo "  bpftool:  $(bpftool version 2>/dev/null || echo 'not found')"
echo "  tcpreplay: $(tcpreplay --version 2>&1 | head -1)"
echo "  python3:  $(python3 --version)"

echo ""
echo "── Kernel eBPF support check ──"
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "  BTF:     ✓ Available (/sys/kernel/btf/vmlinux)"
else
    echo "  BTF:     ✗ Not available (check kernel config)"
fi

if [ -d /sys/fs/bpf ]; then
    echo "  BPF FS:  ✓ Mounted (/sys/fs/bpf)"
else
    echo "  BPF FS:  ✗ Not mounted"
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null && echo "  BPF FS:  ✓ Mounted now" || echo "  BPF FS:  ✗ Failed to mount"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "  1. cd bpf && make"
echo "  2. cd ml && python -m venv .venv && source .venv/bin/activate"
echo "  3. pip install -r requirements.txt"
echo "  4. python scripts/download_dataset.py"
echo "═══════════════════════════════════════════"
