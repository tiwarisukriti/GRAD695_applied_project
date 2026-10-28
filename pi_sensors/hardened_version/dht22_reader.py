#!/usr/bin/env python3
"""
Reads temperature and humidity from a DHT22 sensor on GPIO17.

Usage:
    python3 dht22_reader.py                # print readings every 2s
    python3 dht22_reader.py --csv out.csv  # also log to CSV
"""

import argparse
import csv
import os
import time
from datetime import datetime

import board
import adafruit_dht

# --- Config ---
DHT_PIN = board.D17  # GPIO17 (physical pin 11)
READ_INTERVAL_SECONDS = 2


def read_loop(csv_path: str | None):
    dht_device = adafruit_dht.DHT22(DHT_PIN, use_pulseio=False)

    csv_file = None
    writer = None
    if csv_path:
        file_exists = os.path.isfile(csv_path)
        csv_file = open(csv_path, "a", newline="")
        writer = csv.writer(csv_file)
        if not file_exists:
            writer.writerow(["timestamp", "temperature_c", "temperature_f", "humidity_pct"])

    print("Reading DHT22 on GPIO17. Press Ctrl+C to stop.\n")

    try:
        while True:
            try:
                temperature_c = dht_device.temperature
                humidity = dht_device.humidity

                if temperature_c is not None and humidity is not None:
                    temperature_f = temperature_c * 9 / 5 + 32
                    timestamp = datetime.now().isoformat(timespec="seconds")

                    print(
                        f"{timestamp}  Temp: {temperature_c:.1f}C / {temperature_f:.1f}F  "
                        f"Humidity: {humidity:.1f}%"
                    )

                    if writer:
                        writer.writerow(
                            [timestamp, f"{temperature_c:.1f}", f"{temperature_f:.1f}", f"{humidity:.1f}"]
                        )
                        csv_file.flush()
                else:
                    print("Sensor returned no data this cycle, retrying...")

            except RuntimeError as err:
                # DHT22 sensors regularly fail to read — this is normal, just retry.
                print(f"Read error (normal, will retry): {err}")

            time.sleep(READ_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        dht_device.exit()
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read DHT22 temperature/humidity sensor")
    parser.add_argument("--csv", type=str, default=None, help="Path to CSV file to log readings")
    args = parser.parse_args()
    read_loop(args.csv)
