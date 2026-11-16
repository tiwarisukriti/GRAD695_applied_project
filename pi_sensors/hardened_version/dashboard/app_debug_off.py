#!/usr/bin/env python3
"""
Flask dashboard for a Raspberry Pi 5 using DHT22 (GPIO17) and PIR (GPIO18).

The dashboard supports TWO alternative CSV logging arrangements:

MODE 1 — Two separate CSV files (existing setup):
    dht22_reader.py -> dht_log.csv
        timestamp,temperature_c,temperature_f,humidity_pct
    pir_reader.py -> pir_log.csv
        timestamp,event

MODE 2 — One combined CSV file (combined_logger.py):
    combined_logger.py -> sensor_trial.csv
        timestamp_utc,elapsed_seconds,run_id,event_type,...,error

The Flask app only reads CSV files. It never accesses GPIO pins, so it can
run alongside EITHER logging setup without competing for the sensor pins.
The browser calls /api/data every five seconds. The instrumented combined
mode adds trial counters and synchronized logger/API/browser timestamps.

HARDENED-VARIANT SERVER SETTINGS:
- Flask debug mode is disabled and HTTP Basic authentication is required.
- Loopback is the default; non-loopback binds require a TLS certificate/key.
- Gunicorn serves the application as a production WSGI server.
- Keep the dashboard on the authorized private test network.

Examples (run from ~/pi_sensors/hardened_version/dashboard/):
    # Separate logs:
    RESULTS_DIR="../../results/pi/$(date -u +%F)"
    python3 app_debug_off.py --csv "$RESULTS_DIR/hardened_dht_log.csv" \
        --pir-csv "$RESULTS_DIR/hardened_pir_log.csv" --port 5001

    # Instrumented 15-minute trial output:
    python3 app_debug_off.py --combined-csv "$RESULTS_DIR/hardened_sensor_trial.csv" --port 5001
"""

# argparse reads optional file paths and HTTP port from the command line.
import argparse
import csv
import getpass
import hmac
import ipaddress
import math
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Flask serves the HTML page and converts Python dictionaries into JSON.
from flask import Flask, Response, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


# Create the web application; templates/index.html is loaded by Flask.
app = Flask(__name__)
_original_wsgi_app = app.wsgi_app


def configure_trusted_proxy():
    """Trust one forwarding hop only when explicitly deployed behind Nginx."""
    app.wsgi_app = _original_wsgi_app
    if os.environ.get("DASHBOARD_TRUST_PROXY", "").strip().lower() == "nginx":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


# Standalone logger defaults use the same dated files as dht22_reader.py and
# pir_reader.py.
RESULTS_DIR = (
    Path(__file__).resolve().parents[2]
    / "results"
    / "pi"
    / datetime.now(timezone.utc).date().isoformat()
)
CSV_PATH = str(RESULTS_DIR / "hardened_dht_log.csv")
PIR_CSV_PATH = str(RESULTS_DIR / "hardened_pir_log.csv")

# None selects the separate-files mode. A path selects combined-files mode.
COMBINED_CSV_PATH = None

# Limit the response size sent to the browser without deleting any CSV data.
MAX_ROWS_RETURNED = 500
MAX_PIR_EVENTS_RETURNED = 100
# A record older than this limit is historical, not live sensor output.
STALE_AFTER_SECONDS = 10

# Credentials are supplied by the service environment rather than stored in
# source control or exposed as command-line arguments.
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "")
DASHBOARD_PASSWORD_HASH = os.environ.get("DASHBOARD_PASSWORD_HASH", "")

FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW_SECONDS = 300
LOGIN_LOCKOUT_SECONDS = 900
MAX_TRACKED_LOGIN_CLIENTS = 1024
_login_failures = {}
_login_failures_lock = threading.Lock()

# The two recognized PIR event strings are produced by pir_reader.py and
# combined_logger.py. Reject other strings rather than displaying bad rows.
VALID_PIR_EVENTS = {"MOTION_DETECTED", "MOTION_STOPPED"}


def _prune_login_failures(now):
    for client_ip, state in tuple(_login_failures.items()):
        if state["locked_until"] > now:
            continue
        if state["locked_until"] or (
            not state["failures"]
            or now - state["failures"][-1] >= FAILED_LOGIN_WINDOW_SECONDS
        ):
            del _login_failures[client_ip]


def _record_failed_login(client_ip, now):
    state = _login_failures.get(client_ip)
    if state is None:
        if len(_login_failures) >= MAX_TRACKED_LOGIN_CLIENTS:
            eligible = [
                address
                for address, entry in _login_failures.items()
                if entry["locked_until"] <= now
            ]
            if not eligible:
                return LOGIN_LOCKOUT_SECONDS
            oldest = min(
                eligible, key=lambda address: _login_failures[address]["last_failure"]
            )
            del _login_failures[oldest]
        state = {"failures": [], "last_failure": now, "locked_until": 0}
        _login_failures[client_ip] = state

    state["failures"] = [
        failed_at
        for failed_at in state["failures"]
        if now - failed_at < FAILED_LOGIN_WINDOW_SECONDS
    ]
    state["failures"].append(now)
    state["last_failure"] = now
    if len(state["failures"]) >= FAILED_LOGIN_LIMIT:
        state["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
        return LOGIN_LOCKOUT_SECONDS
    return None


def _authenticate_request(credentials, client_ip):
    now = time.monotonic()
    with _login_failures_lock:
        _prune_login_failures(now)
        state = _login_failures.get(client_ip)
        if state and state["locked_until"] > now:
            return "locked", math.ceil(state["locked_until"] - now)

    username_valid = bool(
        credentials
        and credentials.username
        and hmac.compare_digest(
            credentials.username.encode("utf-8"),
            DASHBOARD_USERNAME.encode("utf-8"),
        )
    )
    password_valid = bool(
        credentials
        and credentials.password
        and check_password_hash(DASHBOARD_PASSWORD_HASH, credentials.password)
    )

    now = time.monotonic()
    with _login_failures_lock:
        _prune_login_failures(now)
        state = _login_failures.get(client_ip)
        if state and state["locked_until"] > now:
            return "locked", math.ceil(state["locked_until"] - now)
        if username_valid and password_valid:
            _login_failures.pop(client_ip, None)
            return "authenticated", 0

        retry_after = _record_failed_login(client_ip, now)
        if retry_after is not None:
            return "locked", retry_after
        return "invalid", 0


@app.before_request
def require_dashboard_authentication():
    """Protect the dashboard and API with HTTP Basic Auth and login lockout."""
    if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD_HASH:
        return Response(
            "Dashboard credentials are not configured.\n",
            status=503,
            content_type="text/plain; charset=utf-8",
        )

    result, retry_after = _authenticate_request(
        request.authorization, request.remote_addr or "unknown"
    )
    if result == "locked":
        return Response(
            "Too many failed login attempts. Try again later.\n",
            status=429,
            headers={"Retry-After": str(retry_after)},
            content_type="text/plain; charset=utf-8",
        )
    if result != "authenticated":
        return Response(
            "Authentication required.\n",
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="Sensor Dashboard"'},
            content_type="text/plain; charset=utf-8",
        )
    return None


@app.after_request
def add_anti_framing_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response


def is_loopback_host(host):
    """Return whether a bind address is loopback-only."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def load_csv_rows(path):
    """Read one CSV file into dictionaries; return [] when it does not exist."""
    try:
        # Open the file on each API request so new collector writes are visible.
        # newline='' is the Python csv module's recommended file-open option.
        with open(path, newline="", encoding="utf-8") as csv_file:
            return list(csv.DictReader(csv_file))
    except FileNotFoundError:
        # A file may not exist until the collector first creates it. Let the
        # dashboard display empty states instead of failing with an HTTP 500.
        return []


def read_readings():
    """Read DHT22 measurements from the original DHT22-only CSV."""
    readings = []

    # The original file header is:
    # timestamp,temperature_c,temperature_f,humidity_pct
    for row in load_csv_rows(CSV_PATH):
        # Skip incomplete entries and repeated headers if they were appended.
        required_fields = ("timestamp", "temperature_c", "temperature_f", "humidity_pct")
        if not all(row.get(field) for field in required_fields):
            continue
        if row["timestamp"] == "timestamp":
            continue
        readings.append(row)

    # Keep the order written by the logger: oldest first, newest last.
    return readings


def read_pir_events():
    """Read PIR events from the original PIR-only CSV."""
    events = []

    # The original PIR file header is: timestamp,event
    for row in load_csv_rows(PIR_CSV_PATH):
        # Check both columns before accepting a motion transition.
        if not row.get("timestamp") or row.get("event") not in VALID_PIR_EVENTS:
            continue
        events.append({"timestamp": row["timestamp"], "event": row["event"]})

    return events


def numeric_csv_value(value):
    """Parse a numeric CSV field without failing the API on a partial row."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def timestamp_freshness(timestamp, stale_after_seconds, now=None):
    """Classify a CSV timestamp as fresh, stale, future-dated, or unavailable."""
    if not timestamp:
        return {
            "status": "unknown",
            "timestamp_utc": None,
            "age_seconds": None,
            "stale_after_seconds": stale_after_seconds,
        }

    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return {
            "status": "invalid",
            "timestamp_utc": timestamp,
            "age_seconds": None,
            "stale_after_seconds": stale_after_seconds,
        }

    # Older standalone collectors wrote local timestamps without a timezone.
    # Interpret those in the Pi's local timezone instead of silently treating
    # them as UTC; the instrumented trial logger writes explicit UTC offsets.
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    current_time = now or datetime.now(timezone.utc)
    age_seconds = (current_time - parsed.astimezone(timezone.utc)).total_seconds()
    if age_seconds < -5:
        status = "clock_ahead"
    elif age_seconds <= stale_after_seconds:
        status = "fresh"
    else:
        status = "stale"
    return {
        "status": status,
        "timestamp_utc": parsed.astimezone(timezone.utc).isoformat(
            timespec="milliseconds"
        ),
        "age_seconds": round(age_seconds, 2),
        "stale_after_seconds": stale_after_seconds,
    }


def read_instrumented_trial(rows):
    """Return records and attempt metrics for the most recently started trial."""
    dht_readings = []
    pir_events = []

    # Appended trials share a file, so select the latest explicit start record
    # and keep every derived count scoped to that run ID.
    start = next(
        (row for row in reversed(rows) if row.get("event_type") == "TRIAL_START"),
        None,
    )
    if start is None:
        return dht_readings, pir_events, None

    run_id = start.get("run_id")
    if not run_id:
        return dht_readings, pir_events, None
    run_rows = [row for row in rows if row.get("run_id") == run_id]
    attempts = [
        row for row in run_rows if row.get("event_type") == "DHT22_ATTEMPT"
    ]
    # A row counts as a valid acquisition only when its successful outcome
    # and every measurement field are present; all attempt rows stay in the
    # denominator even if a partially written/corrupt row is incomplete.
    valid_attempts = [
        row for row in attempts
        if row.get("outcome") == "success"
        and all(row.get(field) for field in (
            "timestamp_utc", "temperature_c", "temperature_f", "humidity_pct"
        ))
    ]

    # Successful DHT attempts carry the normal dashboard fields; failures
    # remain in the CSV denominator but are not rendered as sensor readings.
    for row in valid_attempts:
        dht_readings.append({
            "timestamp": row["timestamp_utc"],
            "temperature_c": row["temperature_c"],
            "temperature_f": row["temperature_f"],
            "humidity_pct": row["humidity_pct"],
        })

    # PIR remains a transition stream; no synthetic read-attempt denominator
    # is inferred for an asynchronous GPIO sensor.
    for row in run_rows:
        event = row.get("pir_event")
        if (
            row.get("event_type") == "PIR_EVENT"
            and row.get("timestamp_utc")
            and event in VALID_PIR_EVENTS
        ):
            pir_events.append({
                "timestamp": row["timestamp_utc"],
                "event": event,
            })

    end = next(
        (row for row in reversed(run_rows) if row.get("event_type") == "TRIAL_END"),
        None,
    )
    latest_row = run_rows[-1] if run_rows else start
    latest_attempt = attempts[-1] if attempts else None
    elapsed_seconds = numeric_csv_value(latest_row.get("elapsed_seconds"))
    duration_seconds = numeric_csv_value(start.get("duration_seconds"))
    successful_count = len(valid_attempts)
    attempt_count = len(attempts)
    reliability_pct = (
        successful_count / attempt_count * 100 if attempt_count else None
    )
    latest_attempt_timestamp = (
        latest_attempt.get("timestamp_utc") if latest_attempt else None
    )
    activity_freshness = timestamp_freshness(
        latest_attempt_timestamp or start.get("timestamp_utc"),
        STALE_AFTER_SECONDS,
    )
    trial_status = (
        end.get("outcome")
        if end
        else (
            "running"
            if activity_freshness["status"] == "fresh"
            else "stale"
        )
    )
    trial = {
        "run_id": run_id,
        "status": trial_status,
        "started_at_utc": start.get("timestamp_utc"),
        "ended_at_utc": end.get("timestamp_utc") if end else None,
        "duration_seconds": (
            int(duration_seconds) if duration_seconds is not None else None
        ),
        "elapsed_seconds": elapsed_seconds,
        "attempts": attempt_count,
        "successes": successful_count,
        "failures": attempt_count - successful_count,
        "reliability_pct": (
            round(reliability_pct, 2) if reliability_pct is not None else None
        ),
        "latest_attempt": (
            {
                "timestamp_utc": latest_attempt.get("timestamp_utc"),
                "outcome": latest_attempt.get("outcome"),
            }
            if latest_attempt
            else None
        ),
        "logger_timestamp_utc": latest_row.get("timestamp_utc"),
    }
    return dht_readings, pir_events, trial


def read_combined_sensor_data():
    """Read either the instrumented trial schema or the original CSV schema."""
    rows = load_csv_rows(COMBINED_CSV_PATH)
    if any(row.get("event_type") for row in rows):
        return read_instrumented_trial(rows)

    dht_readings = []
    pir_events = []

    # combined_logger.py uses this shared header:
    # timestamp,sensor,event_or_temp_c,temp_f,humidity_pct
    # The 'sensor' column indicates how to interpret event_or_temp_c:
    # DHT22 = Celsius temperature; PIR = motion event text.
    for row in rows:
        timestamp = row.get("timestamp")
        sensor = row.get("sensor")

        # Skip empty/partial rows that could be observed during a file write.
        if not timestamp or timestamp == "timestamp":
            continue

        if sensor == "DHT22":
            # For a DHT22 row, the three measurement columns are all needed.
            temperature_c = row.get("event_or_temp_c")
            temperature_f = row.get("temp_f")
            humidity_pct = row.get("humidity_pct")
            if not all((temperature_c, temperature_f, humidity_pct)):
                continue

            # Rename columns to the same keys returned by read_readings().
            # This lets the existing JS cards and chart display either mode.
            dht_readings.append({
                "timestamp": timestamp,
                "temperature_c": temperature_c,
                "temperature_f": temperature_f,
                "humidity_pct": humidity_pct,
            })

        elif sensor == "PIR":
            # For a PIR row, event_or_temp_c contains the motion event, while
            # temp_f and humidity_pct are intentionally empty CSV fields.
            event = row.get("event_or_temp_c")
            if event not in VALID_PIR_EVENTS:
                continue

            # Match the event dictionary created by read_pir_events().
            pir_events.append({"timestamp": timestamp, "event": event})

        # Any unknown sensor value is ignored; only DHT22 and PIR are shown.

    return dht_readings, pir_events, None


def load_sensor_data():
    """Choose a log format and return readings, events, and optional trial data."""
    if COMBINED_CSV_PATH is not None:
        # When --combined-csv was specified, ignore the separate file paths.
        return read_combined_sensor_data()

    # Default behavior is unchanged: read one CSV per sensor.
    return read_readings(), read_pir_events(), None


@app.route("/")
def index():
    """Serve the preexisting dashboard HTML/CSS/JavaScript."""
    # This route returns the template; the browser fetches readings afterward.
    return render_template("index.html")


@app.route("/api/data")
def api_data():
    """Send one consistent JSON response for either logging arrangement."""
    # Fetch both sensors' histories from whichever mode is configured.
    dht_readings, pir_events, trial = load_sensor_data()

    # Only transmit the newest 500 environmental readings to the browser.
    trimmed_dht = dht_readings[-MAX_ROWS_RETURNED:]
    latest_dht = trimmed_dht[-1] if trimmed_dht else None

    # The last PIR event is the last RECORDED motion state. It does not prove
    # that the sensor or the collector process is currently operating.
    trimmed_pir = pir_events[-MAX_PIR_EVENTS_RETURNED:]
    latest_pir = pir_events[-1] if pir_events else None

    # A motion episode has a DETECTED and often a STOPPED event. Only count
    # DETECTED events so that one episode is not counted twice.
    motion_detections = sum(
        1 for event in pir_events if event["event"] == "MOTION_DETECTED"
    )

    # Expose one UTC API timestamp alongside the logger's UTC timestamp and
    # run ID; the browser adds its own receipt timestamp for a three-point trace.
    api_timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    logger_timestamp = (
        trial["logger_timestamp_utc"]
        if trial
        else (latest_dht.get("timestamp") if latest_dht else None)
    )
    latest_attempt_timestamp = (
        trial["latest_attempt"]["timestamp_utc"]
        if trial and trial["latest_attempt"]
        else (latest_dht.get("timestamp") if latest_dht else None)
    )
    latest_pir_timestamp = latest_pir.get("timestamp") if latest_pir else None

    # Keep the original JSON contract: the frontend reads latest, readings,
    # count, and pir regardless of which CSV format supplied the data. New
    # trace keys are additive so older clients continue to work unchanged.
    return jsonify({
        "latest": latest_dht,                  # Most recent DHT22 measurement.
        "readings": trimmed_dht,              # Most recent DHT22 history.
        "count": len(dht_readings),           # Total valid environmental rows.
        "trial": trial,                        # Attempts and reliability for this run.
        "trace": {
            "run_id": trial["run_id"] if trial else None,
            "logger_timestamp_utc": logger_timestamp,
            "api_timestamp_utc": api_timestamp,
        },
        "freshness": {
            "dht_sample": timestamp_freshness(
                latest_dht.get("timestamp") if latest_dht else None,
                STALE_AFTER_SECONDS,
            ),
            "dht_attempt": timestamp_freshness(
                latest_attempt_timestamp, STALE_AFTER_SECONDS
            ),
            "pir_event": timestamp_freshness(
                latest_pir_timestamp, STALE_AFTER_SECONDS
            ),
        },
        "pir": {
            "latest": latest_pir,             # Last PIR event, if any.
            "events": trimmed_pir,            # Latest 100 PIR transitions.
            "count": len(pir_events),         # Number of all PIR events.
            "detections": motion_detections,  # Number of MOTION_DETECTED rows.
        },
    })


def serve_with_gunicorn(host, port, tls_context):
    try:
        from gunicorn.app.base import BaseApplication
    except ImportError as exc:
        raise RuntimeError(
            "Gunicorn is required; run pi_sensors/00_install.sh first"
        ) from exc

    bind_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    options = {
        "bind": f"{bind_host}:{port}",
        "workers": 1,
        "worker_class": "gthread",
        "threads": 4,
        "accesslog": "-",
        "errorlog": "-",
        "loglevel": "info",
    }
    if tls_context:
        options["certfile"], options["keyfile"] = tls_context

    class DashboardApplication(BaseApplication):
        def __init__(self, application, server_options):
            self.application = application
            self.server_options = server_options
            super().__init__()

        def load_config(self):
            for key, value in self.server_options.items():
                if key in self.cfg.settings and value is not None:
                    self.cfg.set(key.lower(), value)

        def load(self):
            return self.application

    DashboardApplication(app, options).run()


def main():
    global CSV_PATH, PIR_CSV_PATH, COMBINED_CSV_PATH, STALE_AFTER_SECONDS

    parser = argparse.ArgumentParser(
        description="DHT22 + PIR dashboard (separate or combined CSV logs)"
    )
    parser.add_argument(
        "--generate-password-hash",
        action="store_true",
        help="Prompt for a dashboard password and print its Werkzeug hash",
    )

    # These two options are for independent sensor logger scripts.
    parser.add_argument(
        "--csv", type=str, default=CSV_PATH,
        help="Separate-mode DHT22 file (default: today's dated hardened log)",
    )
    parser.add_argument(
        "--pir-csv", type=str, default=PIR_CSV_PATH,
        help="Separate-mode PIR file (default: today's dated hardened log)",
    )

    # This option switches to the combined_logger.py file instead; the
    # --csv/--pir-csv arguments are ignored while this mode is active.
    parser.add_argument(
        "--combined-csv", type=str, default=None,
        help="Use one CSV generated by combined_logger.py instead of separate files",
    )

    # Bind loopback by default; remote access requires HTTPS and valid credentials.
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Bind address (default: 127.0.0.1; non-loopback binds require TLS)",
    )
    parser.add_argument(
        "--port", type=int, default=5001,
        help="Port for loopback HTTP or remote HTTPS (default: 5001)",
    )
    parser.add_argument(
        "--tls-cert", type=str, default=None,
        help="TLS certificate PEM path (required for non-loopback bind addresses)",
    )
    parser.add_argument(
        "--tls-key", type=str, default=None,
        help="TLS private key PEM path (required for non-loopback bind addresses)",
    )
    parser.add_argument(
        "--stale-after-seconds", type=float, default=10,
        help="Age after which the latest sensor record is marked stale (default: 10)",
    )
    args = parser.parse_args()
    if args.generate_password_hash:
        password = getpass.getpass("Dashboard password (minimum 12 characters): ")
        confirmation = getpass.getpass("Confirm dashboard password: ")
        if len(password) < 12:
            parser.error("dashboard password must be at least 12 characters")
        if not hmac.compare_digest(password, confirmation):
            parser.error("passwords do not match")
        print(generate_password_hash(password))
        return

    if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD_HASH:
        parser.error(
            "set DASHBOARD_USERNAME and DASHBOARD_PASSWORD_HASH in the environment"
        )
    if ":" in DASHBOARD_USERNAME:
        parser.error("DASHBOARD_USERNAME must not contain a colon")
    try:
        check_password_hash(DASHBOARD_PASSWORD_HASH, "configuration-validation")
    except (TypeError, ValueError):
        parser.error(
            "DASHBOARD_PASSWORD_HASH must be generated by "
            "--generate-password-hash"
        )
    if args.stale_after_seconds <= 0:
        parser.error("--stale-after-seconds must be greater than zero")
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be provided together")
    if not is_loopback_host(args.host) and not args.tls_cert:
        parser.error("non-loopback bind addresses require --tls-cert and --tls-key")
    if args.tls_cert and (
        not os.path.isfile(args.tls_cert) or not os.path.isfile(args.tls_key)
    ):
        parser.error("TLS certificate and key files must both exist")

    # Save the selected paths for the reading functions above.
    CSV_PATH = args.csv
    PIR_CSV_PATH = args.pir_csv
    COMBINED_CSV_PATH = args.combined_csv
    STALE_AFTER_SECONDS = args.stale_after_seconds

    # Echo the selected data source so a path mistake is easier to diagnose.
    if COMBINED_CSV_PATH is not None:
        print(f"Dashboard source: combined CSV {COMBINED_CSV_PATH}")
    else:
        print(f"Dashboard source: DHT22 CSV {CSV_PATH}; PIR CSV {PIR_CSV_PATH}")

    tls_context = (
        (args.tls_cert, args.tls_key) if args.tls_cert and args.tls_key else None
    )
    configure_trusted_proxy()
    scheme = "https" if tls_context else "http"
    print(
        f"Dashboard starting with Gunicorn at {scheme}://{args.host}:{args.port}",
        flush=True,
    )
    serve_with_gunicorn(args.host, args.port, tls_context)


if __name__ == "__main__":
    main()
