#!/usr/bin/env bash
# One-shot environment setup for ECE 545 HW2 (DPA on AES).
# Reproduces the local environment: builds iverilog from source (no sudo/apt
# needed), installs the Python packages the notebook uses, downloads the
# course-provided RTL/testbench/plaintext files, and registers a Jupyter
# kernel so the notebook can be run from VS Code / Jupyter directly.
set -euo pipefail

HW2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IVERILOG_PREFIX="$HW2_DIR/tools/iverilog"
IVERILOG_VERSION="v12_0"
DPA_AES_DRIVE_ID="1pPd6e4pJM7x8eoPraKG3YzYTP1fGCtPO"

echo "==> Installing Python packages (numpy/matplotlib assumed present already)"
python3 -m pip install --user --quiet scipy pandas gdown vcdvcd ipykernel

echo "==> Registering Jupyter kernel 'ece545-hw2-dpa'"
python3 -m ipykernel install --user --name ece545-hw2-dpa --display-name "ECE545 HW2 (DPA)"

if [ -x "$IVERILOG_PREFIX/bin/iverilog" ]; then
  echo "==> iverilog already built at $IVERILOG_PREFIX, skipping build"
else
  echo "==> Building iverilog $IVERILOG_VERSION from source into $IVERILOG_PREFIX"
  BUILD_DIR="$(mktemp -d)"
  trap 'rm -rf "$BUILD_DIR"' EXIT
  curl -sL -o "$BUILD_DIR/iverilog.tar.gz" \
    "https://github.com/steveicarus/iverilog/archive/refs/tags/${IVERILOG_VERSION}.tar.gz"
  tar xzf "$BUILD_DIR/iverilog.tar.gz" -C "$BUILD_DIR"
  SRC_DIR="$BUILD_DIR/iverilog-${IVERILOG_VERSION#v}"
  (cd "$SRC_DIR" && sh autoconf.sh && ./configure --prefix="$IVERILOG_PREFIX" && make -j"$(nproc)" && make install)
fi

if [ -d "$HW2_DIR/DPA_AES" ]; then
  echo "==> DPA_AES already downloaded, skipping"
else
  echo "==> Downloading DPA_AES RTL/testbench/plaintext files from Google Drive"
  python3 -m gdown --folder "$DPA_AES_DRIVE_ID" -O "$HW2_DIR/DPA_AES"
fi

echo "==> Done. iverilog: $IVERILOG_PREFIX/bin/iverilog"
echo "==> Source tools/iverilog/bin into PATH, e.g.:"
echo "    export PATH=\"$IVERILOG_PREFIX/bin:\$PATH\""
