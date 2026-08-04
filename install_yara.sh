#!/bin/bash

echo "=== Installing YARA Dependencies ==="

# Update package list
sudo apt-get update

# Install system dependencies
echo "[*] Installing system dependencies..."
sudo apt-get install -y \
    automake \
    libtool \
    make \
    gcc \
    g++ \
    pkg-config \
    libssl-dev \
    libmagic-dev \
    libjansson-dev \
    python3-dev

# Install YARA from system packages
echo "[*] Installing YARA..."
sudo apt-get install -y yara

# Install Python yara-python module
echo "[*] Installing Python YARA module..."
pip3 install yara-python

# Verify installation
echo -e "\n=== Verifying Installation ==="
yara --version
python3 -c "import yara; print(f'YARA Python version: {yara.YARA_VERSION}')"

echo -e "\n[✓] YARA installation complete!"

