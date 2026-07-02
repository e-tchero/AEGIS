#!/bin/bash
# Project AEGIS — Linux / Parrot OS Setup Script
# Lead Architect: ETCHERO / Abdul-Hameed

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║       PROJECT AEGIS — INSTALLER v1.0         ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

echo "[AEGIS] Creating virtual environment..."
python3 -m venv venv

echo "[AEGIS] Activating venv..."
source venv/bin/activate

echo "[AEGIS] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "[AEGIS] Creating log directory..."
mkdir -p logs

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║              INSTALL COMPLETE                ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Run AEGIS:                                  ║"
echo "║  sudo venv/bin/python aegis.py               ║"
echo "║                                              ║"
echo "║  Heartbeat only (no root needed):            ║"
echo "║  venv/bin/python core/heartbeat.py           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
