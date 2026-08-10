#!/bin/bash
# Run this once on the Raspberry Pi 5 to install everything needed.

set -e

sudo apt update
sudo apt install -y python3-pip python3-venv swig python3-dev gcc

# lgpio and gpiozero are available as pre-built apt packages on Raspberry Pi
# OS — use those instead of letting pip compile lgpio from source (which
# requires a matching liblgpio C library that isn't installed by default
# and commonly fails to link).
sudo apt install -y python3-lgpio python3-gpiozero

# The libgpiod package name/version varies by Debian release (e.g. libgpiod2
# on Bullseye/Bookworm, libgpiod3 on Trixie). Install whichever is available
# instead of hardcoding a version.
sudo apt install -y libgpiod3 || sudo apt install -y libgpiod2 || \
  echo "No libgpiod system package found by that name — continuing anyway."

# Create the venv with access to system site-packages so it can see the
# apt-installed lgpio/gpiozero above, instead of trying to rebuild them.
python3 -m venv --system-site-packages ~/sensor-env
source ~/sensor-env/bin/activate

pip install --upgrade pip
# gpiozero and lgpio come from apt (via --system-site-packages) — only
# Blinka/DHT libraries and Flask need to come from pip.
pip install adafruit-blinka adafruit-circuitpython-dht flask

echo ""
echo "Done. Before running the sensor scripts, activate the venv each time:"
echo "  source ~/sensor-env/bin/activate"