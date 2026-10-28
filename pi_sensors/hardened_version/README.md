# Hardened-Version Sensor System

This folder contains the project's hardened-variant sensor collector and
dashboard. The dashboard entry point, `dashboard/app_debug_off.py`, disables
Flask debug mode, requires environment-provided HTTP Basic credentials, and
binds to loopback by default. Any non-loopback bind requires a TLS certificate
and private key. This is still a trial/development server, not a production
WSGI deployment; it does not configure firewall rules, SSH protections, or
intrusion monitoring. Verify those controls separately on the Raspberry Pi.

For shared hardware setup and evidence context, see the [project README](../../README.md).

## Components

- `combined_logger.py` — instrumented, time-bounded DHT22 and PIR collection.
- `dht22_reader.py` / `pir_reader.py` — standalone legacy collectors.
- `dashboard/app_debug_off.py` — Flask API and dashboard server with debug
  mode disabled.
- `dashboard/templates/index.html` — browser dashboard.

## Run a 15-minute instrumented trial

Run on the Raspberry Pi, activate the shared environment, and start from this
version directory so its trial CSV remains separate from the baseline:

```bash
cd ~/GRAD695_applied_project/pi_sensors/hardened_version
source ~/sensor-env/bin/activate
python3 combined_logger.py --csv sensor_trial.csv --interval 2 --duration-minutes 15
```

The defaults are a two-second DHT22 interval and a 15-minute trial. The logger
creates or appends to `sensor_trial.csv`; choose a new filename to preserve a
separate run artifact. It refuses to append the instrumented schema to a
nonmatching existing CSV.

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
read -r -p "Dashboard username: " DASHBOARD_USERNAME
export DASHBOARD_USERNAME
read -r -s -p "Dashboard password: " DASHBOARD_PASSWORD
echo
export DASHBOARD_PASSWORD
python3 app_debug_off.py --combined-csv ../sensor_trial.csv
```

Choose a unique dashboard password of at least 12 characters. The application
refuses to start without both credentials or with a shorter password.

The default server URL is `http://127.0.0.1:5001`; the browser prompts for
credentials. This loopback mode is useful for local checks on the Pi. For
authorized remote dashboard access, use a certificate whose subject
alternative name matches the Pi's DNS name or IP address, then bind with TLS:

```bash
python3 app_debug_off.py \
  --host 0.0.0.0 --port 5001 \
  --tls-cert /path/to/pi-dashboard.crt \
  --tls-key /path/to/pi-dashboard.key \
  --combined-csv ../sensor_trial.csv
```

The app refuses remote binds without both TLS files, and returns an error if
dashboard credentials are missing or wrong. Do not commit credentials or
private keys. Open `https://<pi-name-or-ip>:5001` from the authorized network
and verify the certificate. For anything beyond a controlled project trial,
use a production WSGI server and a properly managed TLS/reverse-proxy setup.

The dashboard refreshes every five seconds and shows the trial status, run ID,
elapsed/duration, attempt counts, reliability percentage, logger/API/browser
UTC timestamps, and API HTTP status. Sensor data older than 10 seconds is
marked stale by default; change the threshold with `--stale-after-seconds`.
This is timestamp freshness, not a process-health heartbeat. An abrupt
termination may leave the trial without `TRIAL_END`; stale timestamps now
change an open trial's API status to `stale` rather than implying it is
running. Always review CSV and API freshness together.

## Capture comparable evidence

For this run, retain the original `sensor_trial.csv`, a saved `/api/data`
response, and a dashboard capture with the matching run ID. Also record the
Git revision, run date/time, hardware/configuration notes, and final trial
status. Check that the run ID matches across all artifacts before calculating
or reporting results. The 15-minute ≥95% reliability criterion requires an
actual completed hardware run; source code or historical successful rows alone
do not establish that it passed.

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
