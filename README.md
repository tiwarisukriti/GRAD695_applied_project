# GRAD695_applied_project
Raspberry Pi 5 IoT sensor system (DHT22 + PIR) with a Flask dashboard, built as a staged cybersecurity project - insecure by design, hardened later

# Raspberry Pi 5 Sensor Logger + Dashboard - DHT22 + PIR

Python scripts to read temperature/humidity from a DHT22 sensor and motion
events from a PIR sensor on a Raspberry Pi 5, with console output, CSV
logging, and a live web dashboard for the DHT22 data.

# HARDWARE
## Hardware Environment

| Hardware | Specification / Configuration | Role in Project |
|---|---|---|
| Raspberry Pi 5 | Broadcom BCM2712 2.4 GHz quad-core 64-bit Arm Cortex-A76 CPU; 4 GB LPDDR4X RAM; 32 GB microSD storage; dual-band 802.11ac Wi-Fi; standard 40-pin GPIO header; USB-C power | Primary IoT platform that runs the Python sensor applications, CSV logging, Flask dashboard, and later cybersecurity controls and monitoring |
| Development/Test Laptop | Dell G5 5505; AMD Ryzen 7 4800H @ 2.90 GHz; 8 cores / 16 logical processors; 16 GB RAM; x64 architecture; Windows 11 Home Single Language | Used for development, Git/GitHub access, SSH administration, dashboard testing, documentation, and authorized cybersecurity assessment of the Raspberry Pi |
| DHT22 Sensor | Digital temperature and humidity sensor; VCC connected to physical Pin 4, data to Pin 11 (GPIO17), and GND to Pin 9 | Collects temperature and humidity data for console output, CSV logging, and dashboard visualization |
| PIR Motion Sensor | Passive infrared motion sensor; VCC connected to physical Pin 2, output to Pin 12 (GPIO18), and GND to Pin 14 | Intended to detect and log motion events; currently undergoing hardware troubleshooting |
| microSD Card | 32 GB | Stores Raspberry Pi OS, application source code, Python environment, sensor logs, configuration files, and project data |
| Network Connection | Home Wi-Fi using the Raspberry Pi 5's integrated dual-band 802.11ac wireless interface | Connects the Raspberry Pi and development laptop on the same local network for dashboard access, SSH administration, and controlled security testing |
| Power Connection | Raspberry Pi powered through its USB-C power interface using a wall-connected USB-C power source | Provides continuous power to the Raspberry Pi and connected sensor environment |
| Prototyping Components | Jumper wires and GPIO connections | Provide power, ground, and signal connections between the Raspberry Pi and sensors |

# SOFTWARE SETUP

Run once, from the project directory:

    chmod +x 00_install.sh
    ./00_install.sh

This installs:
- System packages: python3-pip, python3-venv, swig, python3-dev, gcc,
  python3-lgpio, python3-gpiozero, libgpiod3 (or libgpiod2 on older
  Debian releases)
- A Python virtual environment at ~/sensor-env with access to the
  system-installed lgpio/gpiozero packages
- Python packages inside the venv: adafruit-blinka,
  adafruit-circuitpython-dht, flask

Activate the environment before running any script, in every new
terminal session:

    source ~/sensor-env/bin/activate

# USAGE

DHT22 (temperature + humidity):

    python3 dht22_reader.py --csv dht_log.csv

Prints a reading every 2 seconds and appends it to the CSV file. The
--csv flag is required for the dashboard to have any data to display -
without it, readings only print to the console and nothing is saved.
Occasional "Read error (normal, will retry)" messages are expected -
the DHT22 is a slow sensor that regularly misses individual read
cycles. The script retries automatically.

PIR (motion):

    python3 pir_reader.py --csv pir_log.csv

Prints MOTION_DETECTED / MOTION_STOPPED events as they happen and logs
them to CSV. Omit --csv to print to console only.

Combined logger (both sensors, one CSV):

    python3 combined_logger.py --csv sensor_log.csv --interval 5

Runs both sensors concurrently. --interval sets how often (in seconds)
the DHT22 is polled; the PIR reports events immediately as they occur
regardless of this setting.

Diagnostic script (raw PIR pin state):

    python3 pir_diagnostic.py

Prints the raw GPIO18 pin state directly, bypassing gpiozero's event
system. Useful for confirming whether the sensor is producing any
signal at all. Includes a 60-second warm-up wait, which PIR sensors
need to calibrate to ambient IR before giving reliable readings.

# WEB DASHBOARD

The dashboard is a Flask app that serves a live-updating page showing
the current DHT22 reading, a chart of recent history, and a raw data
table. It reads directly from the CSV file the reader script produces,
so the reader must be running (and logging to CSV) at the same time as
the dashboard for it to show live data.

File layout expected:

project_folder/
  dht_log.csv           (produced by dht22_reader.py --csv dht_log.csv)
  dashboard/
    app.py
    templates/
      index.html

Start the DHT22 reader first, in one terminal:

    source ~/sensor-env/bin/activate
    python3 dht22_reader.py --csv dht_log.csv

In a second terminal, start the dashboard, pointing --csv at the same
file the reader is writing to:

    source ~/sensor-env/bin/activate
    cd dashboard
    python3 app.py --csv ../dht_log.csv --port 5000

Then, from any device on the same network, find the Pi's IP address:

    hostname -I

and visit:

    http://<pi-ip-address>:5000

The page polls for new data every 5 seconds automatically - no need to
refresh manually.

Security note: this dashboard is an intentionally insecure baseline as
part of a staged security project. It has no authentication, no HTTPS,
Flask's debug mode is left on, and it is bound to 0.0.0.0 so any device
on the network can reach it. Security controls (Fail2ban, access
control, logging, TLS) are added in a later phase, then verified
against using Nmap, Wireshark, Nikto, and Hydra. Do not expose this to
the open internet as-is.

# KNOWN ISSUES

PIR sensor is not currently detecting motion. Wiring has been verified
against the official Raspberry Pi 5 GPIO pinout and corrected once
already (an earlier VCC/GND jumper inversion was found and fixed). The
raw pin diagnostic (pir_diagnostic.py) shows the GPIO18 pin remaining
constantly at 0, with no state change observed even with direct motion
in front of the sensor.

Troubleshooting steps identified but not yet completed:
1. Check the onboard sensitivity and time-delay trimpots (may be set
   to minimum sensitivity)
2. Check the trigger-mode jumper (H = repeatable trigger, L = single
   trigger - should be set to H)
3. Reseat and verify all three physical connections (VCC, GND, data)
   for looseness
4. Test the sensor's OUT pin directly with a multimeter, independent
   of the Pi, to confirm whether the sensor itself is producing a
   signal
5. Confirm the Fresnel lens dome is unobstructed (no protective film
   left on, nothing blocking it)

The DHT22 sensor and web dashboard are both confirmed working
correctly as of this submission.

# FILE STRUCTURE

pi_sensors/
  00_install.sh            (One-time dependency installation)
  dht22_reader.py           (Standalone DHT22 reader)
  pir_reader.py             (Standalone PIR reader)
  combined_logger.py        (Runs both sensors together)
  pir_diagnostic.py         (Raw PIR pin-state diagnostic tool)
  dht_log.csv               (Created at runtime by dht22_reader.py)
  dashboard/
    app.py                  (Flask backend serving sensor data)
    templates/
      index.html            (Dashboard frontend)
  README.md                 (This file)
