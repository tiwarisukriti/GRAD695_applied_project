#!/usr/bin/env python3
"""
Run a time-bounded, instrumented DHT22 + PIR sensor trial.

Each DHT22 sampling cycle is written to the CSV, including failed attempts,
so reliability is valid acquisitions divided by all acquisition attempts.
PIR records represent motion-state transitions because gpiozero reports PIR
events asynchronously rather than exposing a comparable polling denominator.

Example 15-minute run:
    python3 combined_logger.py --csv sensor_trial.csv --interval 2 --duration-minutes 15

The CSV uses UTC wall-clock timestamps for cross-process correlation and
monotonic elapsed seconds for measurements within the run. The same run ID
is carried into the Flask API response and dashboard.
"""

import argparse
import csv
import os
import threading
import time
from datetime import datetime, timezone
from uuid import uuid4

import board
import adafruit_dht
from gpiozero import MotionSensor

DHT_PIN = board.D17
PIR_PIN = 18

# These columns preserve the run identity, time base, attempt denominator,
# measurement values, and any diagnostic text needed to interpret each row.
TRIAL_HEADERS = [
    "timestamp_utc",
    "elapsed_seconds",
    "run_id",
    "event_type",
    "sensor",
    "outcome",
    "attempts",
    "successes",
    "failures",
    "reliability_pct",
    "duration_seconds",
    "temperature_c",
    "temperature_f",
    "humidity_pct",
    "pir_event",
    "error",
]


def utc_timestamp():
    """Return a timezone-aware UTC timestamp suitable for trace comparison."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class TrialLogger:
    """Serialize sensor records and keep the attempt counters run-scoped."""

    def __init__(self, csv_path, duration_seconds):
        # Refuse to mix the new schema with an older logger's different CSV
        # header; otherwise DictReader could silently mislabel the evidence.
        if os.path.isfile(csv_path) and os.path.getsize(csv_path) > 0:
            with open(csv_path, newline="", encoding="utf-8") as existing_file:
                existing_header = next(csv.reader(existing_file), [])
            if existing_header != TRIAL_HEADERS:
                raise ValueError(
                    f"{csv_path} has a different CSV schema; choose a new trial CSV path"
                )

        self.csv_file = open(csv_path, "a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.csv_file, fieldnames=TRIAL_HEADERS)
        if os.path.getsize(csv_path) == 0:
            self.writer.writeheader()
            self.csv_file.flush()

        # A unique identifier distinguishes this run from earlier appended trials.
        self.run_id = str(uuid4())
        self.started_monotonic = time.monotonic()
        self.duration_seconds = duration_seconds
        self.attempts = 0
        self.successes = 0
        self.failures = 0
        self.lock = threading.Lock()
        self.record("TRIAL_START", "SYSTEM", duration_seconds=duration_seconds)

    def record(self, event_type, sensor, **values):
        """Write one timestamped record while holding the shared CSV lock."""
        with self.lock:
            timestamp = utc_timestamp()
            reliability = (
                self.successes / self.attempts * 100 if self.attempts else ""
            )
            row = {
                "timestamp_utc": timestamp,
                "elapsed_seconds": f"{time.monotonic() - self.started_monotonic:.3f}",
                "run_id": self.run_id,
                "event_type": event_type,
                "sensor": sensor,
                "outcome": "",
                "attempts": self.attempts,
                "successes": self.successes,
                "failures": self.failures,
                "reliability_pct": (
                    f"{reliability:.2f}" if reliability != "" else ""
                ),
                "duration_seconds": "",
                "temperature_c": "",
                "temperature_f": "",
                "humidity_pct": "",
                "pir_event": "",
                "error": "",
            }
            row.update(values)
            self.writer.writerow(row)
            self.csv_file.flush()
            return timestamp

    def record_dht_attempt(self, outcome, temperature_c=None, humidity=None, error=""):
        """Count and persist every DHT read cycle, successful or not."""
        with self.lock:
            timestamp = utc_timestamp()
            self.attempts += 1
            if outcome == "success":
                self.successes += 1
            else:
                self.failures += 1

            temperature_f = (
                temperature_c * 9 / 5 + 32 if temperature_c is not None else None
            )
            reliability = self.successes / self.attempts * 100
            row = {
                "timestamp_utc": timestamp,
                "elapsed_seconds": f"{time.monotonic() - self.started_monotonic:.3f}",
                "run_id": self.run_id,
                "event_type": "DHT22_ATTEMPT",
                "sensor": "DHT22",
                "outcome": outcome,
                "attempts": self.attempts,
                "successes": self.successes,
                "failures": self.failures,
                "reliability_pct": f"{reliability:.2f}",
                "duration_seconds": "",
                "temperature_c": (
                    f"{temperature_c:.1f}" if temperature_c is not None else ""
                ),
                "temperature_f": (
                    f"{temperature_f:.1f}" if temperature_f is not None else ""
                ),
                "humidity_pct": f"{humidity:.1f}" if humidity is not None else "",
                "pir_event": "",
                "error": error,
            }
            self.writer.writerow(row)
            self.csv_file.flush()
            return timestamp

    def close(self, outcome):
        """Write a final record so an interrupted run is distinguishable."""
        self.record("TRIAL_END", "SYSTEM", outcome=outcome)
        self.csv_file.close()


def dht_worker(interval, logger, stop_event):
    """Sample DHT22 until the trial timer asks the worker to stop."""
    dht_device = adafruit_dht.DHT22(DHT_PIN, use_pulseio=False)
    try:
        while not stop_event.is_set():
            try:
                temperature_c = dht_device.temperature
                humidity = dht_device.humidity
                if temperature_c is not None and humidity is not None:
                    timestamp = logger.record_dht_attempt(
                        "success", temperature_c, humidity
                    )
                    print(
                        f"{timestamp} [DHT22] "
                        f"{temperature_c:.1f}C / {temperature_c * 9 / 5 + 32:.1f}F "
                        f"Humidity: {humidity:.1f}%"
                    )
                else:
                    timestamp = logger.record_dht_attempt("no_data")
                    print(f"{timestamp} [DHT22] No data returned")
            except RuntimeError as err:
                # DHT22 read errors are expected intermittently; preserve each
                # one as a failed attempt while keeping the monitoring loop alive.
                timestamp = logger.record_dht_attempt("error", error=str(err))
                print(f"{timestamp} [DHT22] Read error (will retry): {err}")

            # Event.wait makes the interval interruptible when the trial ends.
            stop_event.wait(interval)
    finally:
        dht_device.exit()


def pir_worker(logger, stop_event):
    """Log asynchronous PIR transitions using the same run clock and ID."""
    pir = MotionSensor(PIR_PIN)

    def record_motion(event):
        timestamp = logger.record("PIR_EVENT", "PIR", pir_event=event)
        print(f"{timestamp} [PIR] {event}")

    pir.when_motion = lambda: record_motion("MOTION_DETECTED")
    pir.when_no_motion = lambda: record_motion("MOTION_STOPPED")
    try:
        while not stop_event.wait(0.25):
            pass
    finally:
        pir.close()


def main(csv_path, interval, duration_minutes):
    """Start both sensors, run for the requested period, then close cleanly."""
    if interval <= 0 or duration_minutes <= 0:
        raise ValueError("interval and duration-minutes must both be positive")

    duration_seconds = duration_minutes * 60
    logger = TrialLogger(csv_path, duration_seconds)
    stop_event = threading.Event()
    workers = [
        threading.Thread(
            target=dht_worker, args=(interval, logger, stop_event), name="dht22"
        ),
        threading.Thread(
            target=pir_worker, args=(logger, stop_event), name="pir"
        ),
    ]
    outcome = "failed"
    print(
        f"Starting {duration_minutes}-minute sensor trial "
        f"(run_id={logger.run_id}, csv={csv_path})"
    )

    try:
        for worker in workers:
            worker.start()

        deadline = time.monotonic() + duration_seconds
        while time.monotonic() < deadline:
            # If a sensor worker exits unexpectedly, stop instead of reporting
            # a complete trial with a missing acquisition or motion stream.
            failed_workers = [worker.name for worker in workers if not worker.is_alive()]
            if failed_workers:
                raise RuntimeError(
                    "Sensor worker stopped unexpectedly: " + ", ".join(failed_workers)
                )
            stop_event.wait(min(0.5, deadline - time.monotonic()))
        failed_workers = [worker.name for worker in workers if not worker.is_alive()]
        if failed_workers:
            raise RuntimeError(
                "Sensor worker stopped unexpectedly: " + ", ".join(failed_workers)
            )
        outcome = "completed"
    except KeyboardInterrupt:
        outcome = "interrupted"
        print("\nTrial interrupted by user.")
    finally:
        stop_event.set()
        for worker in workers:
            if worker.ident is not None:
                worker.join()
        logger.close(outcome)
        print(
            f"Trial {outcome}: attempts={logger.attempts}, "
            f"successes={logger.successes}, failures={logger.failures}, "
            f"reliability={logger.successes / logger.attempts * 100 if logger.attempts else 0:.2f}%"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Instrumented DHT22 + PIR sensor trial")
    parser.add_argument(
        "--csv",
        type=str,
        default="sensor_trial.csv",
        help="Append-only instrumented trial CSV (default: sensor_trial.csv)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2,
        help="Seconds between DHT22 acquisition attempts (default: 2)",
    )
    parser.add_argument(
        "--duration-minutes",
        type=int,
        default=15,
        help="Trial duration in minutes (default: 15)",
    )
    args = parser.parse_args()
    main(args.csv, args.interval, args.duration_minutes)
