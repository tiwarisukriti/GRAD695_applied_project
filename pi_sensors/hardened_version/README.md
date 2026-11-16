# Hardened-Version Sensor System

This folder contains the project's hardened-variant sensor collector and
dashboard. The dashboard entry point, `dashboard/app_debug_off.py`, disables
Flask debug mode, uses a Gunicorn WSGI server, verifies a Werkzeug-hashed
password, and binds to loopback by default. Five failed logins from one
address within five minutes trigger a 15-minute lockout. Any non-loopback bind
requires a TLS certificate and private key. The lockout is process-local and
resets on restart; this project does not configure firewall rules, SSH
protections, or intrusion monitoring. Verify those controls separately on the
Raspberry Pi.

For shared hardware setup and evidence context, see the [project README](../../README.md).
The date-wise sensor and security evidence archive is documented in
[`../results/README.md`](../results/README.md).

## Components

- `combined_logger.py` — instrumented, time-bounded DHT22 and PIR collection.
- `dht22_reader.py` / `pir_reader.py` — standalone legacy collectors.
- `dashboard/app_debug_off.py` — Flask API and dashboard server with debug
  mode disabled, served by Gunicorn.
- `dashboard/templates/index.html` — browser dashboard.

## Run a 15-minute instrumented trial

Run on the Raspberry Pi, activate the shared environment, and start from this
version directory:

```bash
cd ~/GRAD695_applied_project/pi_sensors/hardened_version
source ~/sensor-env/bin/activate
python3 combined_logger.py --interval 2 --duration-minutes 15
```

The defaults are a two-second DHT22 interval and a 15-minute trial. The logger
creates or appends to `../results/pi/<UTC-date>/hardened_sensor_trial.csv`.
Use `--csv` to choose another path. Runs on the same UTC date share the file
and remain distinguishable by their run IDs. It refuses to append the
instrumented schema to a nonmatching existing CSV.

The CSV contains explicit trial start/end rows, every DHT22 attempt, and
asynchronous PIR motion events. Each row has a UUID run ID, UTC timestamp with
millisecond precision, monotonic elapsed seconds, and cumulative DHT22
attempt/success/failure counts. Reliability is complete valid acquisitions
divided by all attempts. PIR detections/stops are event counts, not a periodic
attempt denominator. Worker-thread exits before the duration expires are
reported as a failed trial rather than a completed run.

In another terminal, launch the matching dashboard:

```bash
cd ~/GRAD695_applied_project/pi_sensors/hardened_version/dashboard
source ~/sensor-env/bin/activate
RESULTS_DIR="../../results/pi/$(date -u +%F)"
read -r -p "Dashboard username: " DASHBOARD_USERNAME
export DASHBOARD_USERNAME
DASHBOARD_PASSWORD_HASH="$(python3 app_debug_off.py --generate-password-hash)"
export DASHBOARD_PASSWORD_HASH
python3 app_debug_off.py --combined-csv "$RESULTS_DIR/hardened_sensor_trial.csv"
```

The hash-generation command prompts twice for a password and requires at least
12 characters. Only the Werkzeug password hash is stored in the environment;
the plaintext is not saved by the application.

The default server URL is `http://127.0.0.1:5001`; the browser prompts for
credentials. This loopback mode is useful for local checks on the Pi. For
authorized remote dashboard access, use a certificate whose subject
alternative name matches the Pi's DNS name or IP address, then bind with TLS:

```bash
python3 app_debug_off.py \
  --host 0.0.0.0 --port 5001 \
  --tls-cert /path/to/pi-dashboard.crt \
  --tls-key /path/to/pi-dashboard.key \
  --combined-csv "$RESULTS_DIR/hardened_sensor_trial.csv"
```

The app refuses remote binds without both TLS files, and returns an error if
dashboard credentials are missing or wrong. Invalid credentials are rejected
with HTTP 401; after five failures from one source address within five minutes,
requests from that address receive HTTP 429 with `Retry-After` for 15 minutes.
The address comes from the direct connection; this app does not trust forwarded
IP headers. Behind a reverse proxy, all clients may appear to share the proxy's
address. Use proxy-side lockout or add explicitly trusted proxy handling before
relying on per-client lockout. The single-worker Gunicorn configuration keeps
lockout state consistent, but that state is in memory and resets when the
process restarts. Do not commit credentials or private keys. Open
`https://<pi-name-or-ip>:5001` from the authorized network and verify the
certificate.

The dashboard also sends `X-Frame-Options: DENY` and
`Content-Security-Policy: frame-ancestors 'none'` to prevent framing.

The dashboard refreshes every five seconds and shows the trial status, run ID,
elapsed/duration, attempt counts, reliability percentage, logger/API/browser
UTC timestamps, and API HTTP status. Sensor data older than 10 seconds is
marked stale by default; change the threshold with `--stale-after-seconds`.
This is timestamp freshness, not a process-health heartbeat. An abrupt
termination may leave the trial without `TRIAL_END`; stale timestamps now
change an open trial's API status to `stale` rather than implying it is
running. Always review CSV and API freshness together.

## Capture comparable evidence

For this run, retain the original `hardened_sensor_trial.csv`, a saved
`/api/data` response, and a dashboard capture with the matching run ID in the
same dated results folder. Name additional evidence with the `hardened_` prefix.
Also record the Git revision, run date/time, hardware/configuration notes, and
final trial status. When reviewing an older trial, set `RESULTS_DIR` to its UTC
date folder. Check that the run ID matches across all artifacts before
calculating or reporting results. The 15-minute ≥95% reliability criterion
requires an actual completed hardware run; source code or historical
successful rows alone do not establish that it passed.

## Hardening and evidence boundary

The instrumented behavior addresses measurement traceability: millisecond UTC
timestamps (while preserving row order), persistent DHT22 attempt counts,
per-run IDs and monotonic elapsed time, and explicit worker-exit detection.
The dashboard labels historical sensor records stale based on their timestamp,
but does not independently monitor the collector process.

The October 25 historical analysis reported 5,161 successful DHT22 records and
2,626 PIR events across five combined CSVs, including PIR transitions sharing
whole-second timestamps. These are historical record counts and cannot
establish failed-attempt rates because those older files do not record every
DHT22 failure. Rapid PIR transitions also need controlled hardware testing
before assigning a physical cause.

For a valid baseline comparison, use the same hardware, interval, duration,
and observation setup in each version, and preserve each version's trial CSV
separately. The added authentication and TLS behavior are application-level
controls; do not infer that the whole host or network service is secure.
Document and verify each additional security control independently.
