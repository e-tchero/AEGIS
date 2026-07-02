@echo off
echo.
echo ╔══════════════════════════════════════════════╗
echo ║    PROJECT AEGIS — WINDOWS INSTALLER v1.0    ║
echo ╚══════════════════════════════════════════════╝
echo.

echo [AEGIS] Creating virtual environment...
python -m venv venv

echo [AEGIS] Activating venv...
call venv\Scripts\activate

echo [AEGIS] Installing dependencies...
pip install --upgrade pip
pip install psutil scapy

echo.
echo [AEGIS] Creating log directory...
if not exist logs mkdir logs

echo.
echo ╔══════════════════════════════════════════════╗
echo ║            INSTALL COMPLETE                  ║
echo ╠══════════════════════════════════════════════╣
echo ║  Run AEGIS (Simulation Mode):                ║
echo ║  venv\Scripts\python aegis.py                ║
echo ║                                              ║
echo ║  NOTE: Install Npcap from https://npcap.com  ║
echo ║  to enable packet sniffing on Windows.       ║
echo ╚══════════════════════════════════════════════╝
echo.
pause
