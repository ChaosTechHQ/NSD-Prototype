#!/usr/bin/env bash
# NSD v19 — Pi install / update script
# Run once after a fresh clone, or again after any deploy change.
# Usage:  bash deploy/install.sh
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_SRC="$PROJECT_DIR/deploy/nsd.service"
SERVICE_DST="/etc/systemd/system/nsd.service"

echo "==> NSD v19 install — project: $PROJECT_DIR"

# 1. Virtual-env
if [ ! -d "$PROJECT_DIR/venv" ]; then
  echo "==> Creating virtualenv..."
  python3 -m venv "$PROJECT_DIR/venv"
fi

echo "==> Installing Python dependencies..."
"$PROJECT_DIR/venv/bin/pip" install --quiet --upgrade pip
"$PROJECT_DIR/venv/bin/pip" install --quiet -r "$PROJECT_DIR/requirements.txt"

# 2. Data directory
DATA_DIR="$HOME/nsd-v19/data"
mkdir -p "$DATA_DIR"
echo "==> Data directory: $DATA_DIR"

# 3. Install / refresh systemd unit
echo "==> Installing systemd unit..."
sudo cp "$SERVICE_SRC" "$SERVICE_DST"
sudo systemctl daemon-reload
sudo systemctl enable nsd
sudo systemctl restart nsd

echo ""
echo "====================================================="
echo " NSD v19 is running."
echo " Status : sudo systemctl status nsd"
echo " Logs   : sudo journalctl -u nsd -f"
echo " Stop   : sudo systemctl stop nsd"
echo " Update : git pull && bash deploy/install.sh"
echo "====================================================="
