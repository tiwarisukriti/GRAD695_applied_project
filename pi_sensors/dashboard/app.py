#!/usr/bin/env python3
"""
Basic IoT dashboard for DHT22 sensor readings.

INTENTIONALLY INSECURE BASELINE - part of a staged security project.
No authentication, no HTTPS, no input validation, no rate limiting,
Flask debug mode enabled. Security controls (Fail2ban, TLS, auth,
access control, logging) are added in a later phase, then tested
against with Nmap, Wireshark, Nikto, and Hydra.

Do not expose this to the open internet.

Usage:
    python3 app.py
    python3 app.py --csv /path/to/dht_log.csv --port 5000
"""

import argparse
import csv
import os

from flask import Flask, jsonify, render_template

app = Flask(__name__)

CSV_PATH = "dht_log.csv"
MAX_ROWS_RETURNED = 500


def read_readings():
    """Read all rows from the CSV log. Returns list of dicts, oldest first."""
    if not os.path.isfile(CSV_PATH):
        return []

    readings = []
    with open(CSV_PATH, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            readings.append(row)
    return readings


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/data")
def api_data():
    """Returns the most recent readings as JSON, newest last (for charting)."""
    readings = read_readings()
    trimmed = readings[-MAX_ROWS_RETURNED:]
    latest = trimmed[-1] if trimmed else None
    return jsonify({"latest": latest, "readings": trimmed, "count": len(readings)})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DHT22 sensor dashboard")
    parser.add_argument("--csv", type=str, default="dht_log.csv", help="Path to the DHT22 CSV log file")
    parser.add_argument("--port", type=int, default=5000, help="Port to serve the dashboard on")
    args = parser.parse_args()

    CSV_PATH = args.csv

    # host="0.0.0.0" makes this reachable from other devices on the network,
    # as requested. debug=True is left on for now as part of the intentionally
    # insecure baseline - remember to turn this off once hardening begins.
    app.run(host="0.0.0.0", port=args.port, debug=True)
