#!/usr/bin/env python3
"""
Runs the DHT22 (GPIO17) and PIR (GPIO18) sensors together, logging
both to console and to a single CSV file.

Usage:
    python3 combined_logger.py
    python3 combined_logger.py --csv sensor_log.csv --interval 5
"""

import argparse
import csv
import os
import threading
import time
from datetime import datetime

import board
import adafruit_dht
from gpiozero import MotionSensor

DHT_PIN = board.D17
PIR_PIN = 18

csv_lock = threading.Lock()


def get_writer(csv_path: str):
    file_exists = os.path.isfile(csv_path)
    csv_file = open(csv_path, "a", newline="")
    writer = csv.writer(csv_file)
    if not file_exists:
        writer.writerow(["timestamp", "sensor", "event_or_temp_c", "temp_f", "humidity_pct"])
    return csv_file, writer


def log_row(writer, csv_file, row):
    if writer is None:
        return
    with csv_lock:
        writer.writerow(row)
        csv_file.flush()


def dht_worker(interval: int, writer, csv_file):
    dht_device = adafruit_dht.DHT22(DHT_PIN, use_pulseio=False)
    while True:
        try:
            temperature_c = dht_device.temperature
            humidity = dht_device.humidity
            if temperature_c is not None and humidity is not None:
                temperature_f = temperature_c * 9 / 5 + 32
                timestamp = datetime.now().isoformat(timespec="seconds")
                print(
                    f"{timestamp}  [DHT22] Temp: {temperature_c:.1f}C / {temperature_f:.1f}F  "
                    f"Humidity: {humidity:.1f}%"
                )
                log_row(
                    writer, csv_file,
                    [timestamp, "DHT22", f"{temperature_c:.1f}", f"{temperature_f:.1f}", f"{humidity:.1f}"],
                )
        except RuntimeError as err:
            print(f"[DHT22] Read error (normal, will retry): {err}")
        time.sleep(interval)


def pir_worker(writer, csv_file):
    pir = MotionSensor(PIR_PIN)

    def on_motion():
        timestamp = datetime.now().isoformat(timespec="seconds")
        print(f"{timestamp}  [PIR] MOTION_DETECTED")
        log_row(writer, csv_file, [timestamp, "PIR", "MOTION_DETECTED", "", ""])

    def on_no_motion():
        timestamp = datetime.now().isoformat(timespec="seconds")
        print(f"{timestamp}  [PIR] MOTION_STOPPED")
        log_row(writer, csv_file, [timestamp, "PIR", "MOTION_STOPPED", "", ""])

    pir.when_motion = on_motion
    pir.when_no_motion = on_no_motion

    # Keep this thread alive
    while True:
        time.sleep(1)


def main(csv_path: str, interval: int):
    csv_file, writer = (None, None)
    if csv_path:
        csv_file, writer = get_writer(csv_path)

    print("Starting DHT22 + PIR logger. Press Ctrl+C to stop.\n")

    dht_thread = threading.Thread(target=dht_worker, args=(interval, writer, csv_file), daemon=True)
    pir_thread = threading.Thread(target=pir_worker, args=(writer, csv_file), daemon=True)

    dht_thread.start()
    pir_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Combined DHT22 + PIR sensor logger")
    parser.add_argument("--csv", type=str, default="sensor_log.csv", help="Path to CSV log file")
    parser.add_argument("--interval", type=int, default=2, help="Seconds between DHT22 readings")
    args = parser.parse_args()
    main(args.csv, args.interval)
