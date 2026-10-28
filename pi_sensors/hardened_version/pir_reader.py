#!/usr/bin/env python3
"""
Detects motion from a PIR sensor on GPIO18.

Usage:
    python3 pir_reader.py                # print motion events
    python3 pir_reader.py --csv out.csv  # also log to CSV
"""

import argparse
import csv
import os
from datetime import datetime
from signal import pause

from gpiozero import MotionSensor

# --- Config ---
PIR_PIN = 18  # GPIO18 (physical pin 12)


def build_logger(csv_path: str | None):
    csv_file = None
    writer = None
    if csv_path:
        file_exists = os.path.isfile(csv_path)
        csv_file = open(csv_path, "a", newline="")
        writer = csv.writer(csv_file)
        if not file_exists:
            writer.writerow(["timestamp", "event"])

    def log(event: str):
        timestamp = datetime.now().isoformat(timespec="seconds")
        print(f"{timestamp}  {event}")
        if writer:
            writer.writerow([timestamp, event])
            csv_file.flush()

    return log, csv_file


def main(csv_path: str | None):
    pir = MotionSensor(PIR_PIN)
    log, csv_file = build_logger(csv_path)

    pir.when_motion = lambda: log("MOTION_DETECTED")
    pir.when_no_motion = lambda: log("MOTION_STOPPED")

    print("Watching PIR sensor on GPIO18. Press Ctrl+C to stop.\n")

    try:
        pause()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read PIR motion sensor")
    parser.add_argument("--csv", type=str, default=None, help="Path to CSV file to log events")
    args = parser.parse_args()
    main(args.csv)
