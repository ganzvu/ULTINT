#!/bin/bash
# ULTINT Installer

echo "[*] Setting up ULTINT environment..."

# 1. Check for Python3
if ! command -v python3 &> /dev/null
then
    echo "[!] Python3 could not be found. Please install Python3 before running this."
    exit
fi

# 2. Setup Virtual Environment
echo "[*] Creating Virtual Environment (venv)..."
python3 -m venv venv || { echo "[!] Failed to create venv. Make sure python3-venv is installed."; exit 1; }

# 3. Install Requirements
echo "[*] Installing Python Dependencies..."
./venv/bin/pip install -r requirements.txt || { echo "[!] Pip install failed."; exit 1; }

# 4. Install Playwright Browsers
echo "[*] Installing Stealth Browsers (Playwright)..."
./venv/bin/python3 -m playwright install chromium || { echo "[!] Playwright install failed."; exit 1; }

echo "[+] Installation Complete!"
echo "You can now run ULTINT using: ./venv/bin/python ultint.py"
echo ""
echo "To install globally a symlink, run:"
echo "mkdir -p ~/.local/bin && ln -sf \$(pwd)/ultint.py ~/.local/bin/ultint && chmod +x ultint.py"
