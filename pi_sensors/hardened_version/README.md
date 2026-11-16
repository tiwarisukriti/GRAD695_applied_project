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
credentials. This loopback mode is useful for local checks on the Pi.

## Deploy behind Nginx with HTTPS

The deployment examples in `deploy/` keep Gunicorn on loopback and terminate
TLS at Nginx on port 443. Use a certificate trusted by the client and whose
subject alternative name matches the hostname or IP address used to reach the
Pi. Do not expose Gunicorn directly.

Install Nginx, disable its packaged default site, and install the supplied
reverse-proxy configuration after placing the certificate and private key at
the configured paths:

```bash
cd ~/GRAD695_applied_project/pi_sensors/hardened_version
sudo apt update
sudo apt install -y nginx
sudo systemctl disable --now nginx
sudo unlink /etc/nginx/sites-enabled/default
sudo install -m 0644 deploy/nginx-dashboard.conf /etc/nginx/sites-available/sensor-dashboard
sudo ln -sfn /etc/nginx/sites-available/sensor-dashboard /etc/nginx/sites-enabled/sensor-dashboard
sudo nginx -t
```

The configuration expects `/etc/ssl/certs/pi-dashboard.crt` and
`/etc/ssl/private/pi-dashboard.key`; change those paths if needed. Keep the key
root-owned and readable only by root. Install and start the per-user Gunicorn
service (replace `pi` with the Pi account that owns the checkout):

```bash
sudo install -m 0644 deploy/sensor-dashboard@.service /etc/systemd/system/
sudo install -o root -g root -m 0600 /dev/null /etc/default/sensor-dashboard-pi
sudoedit /etc/default/sensor-dashboard-pi
```

Set `DASHBOARD_USERNAME` and a `DASHBOARD_PASSWORD_HASH` generated with
`python3 app_debug_off.py --generate-password-hash` in that environment file.
Run the hash generator from the dashboard directory with the sensor
environment active. Do not put the plaintext password in the environment file.
Start the dashboard and proxy:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sensor-dashboard@pi.service
sudo systemctl enable --now nginx
```

For this service instance, the dashboard reads
`results/pi/live/hardened_sensor_trial.csv`. Create that directory and run the
logger with `--csv` pointing to the same file when you want the deployed
dashboard to display a trial:

```bash
RESULTS_DIR="../results/pi/live"
mkdir -p "$RESULTS_DIR"
python3 combined_logger.py --csv "$RESULTS_DIR/hardened_sensor_trial.csv" \
  --interval 2 --duration-minutes 15
```

The `DASHBOARD_TRUST_PROXY=nginx` setting trusts one forwarding hop. Nginx
overwrites `X-Forwarded-For` with the connected client's address; Gunicorn must
remain bound to `127.0.0.1:5001`. This lets the application's per-client
lockout distinguish remote clients. It is not safe to expose the Gunicorn
listener beyond loopback.

Do not apply firewall changes until you have verified which client source
address the Pi sees and have a recovery path for SSH. The intended inbound
policy is default-deny with TCP/22 and TCP/443 allowed only from the authorized
client source. The collector can compare observed UFW rules with a Pi-visible
source CIDR that you enter; it never changes firewall settings. Nmap results
from the authorized test client are still needed to verify actual exposure.

The direct-TLS command below is an optional standalone test mode, not the
Nginx deployment:

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
Without `DASHBOARD_TRUST_PROXY=nginx`, the address comes from the direct
connection and forwarded IP headers are ignored. The single-worker Gunicorn
configuration keeps lockout state consistent, but that state is in memory and
resets when the process restarts. Do not commit credentials or private keys.
For the Nginx deployment, open `https://<pi-name-or-ip>/` and verify the
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

### One-run evidence collection from WSL

[`../collect_hardened_evidence.py`](../collect_hardened_evidence.py) runs on
the authorized WSL client and connects to the Pi over SSH; it does not need to
be copied to or run on the Pi. It starts a temporary dashboard against a new
trial CSV and packages the collected results into a ZIP. It does not update
packages or change Pi configuration. It separately records Nginx/Gunicorn
service and listener facts and probes the deployed HTTPS endpoint without
sending credentials; this is distinct from its temporary trial dashboard. For
example, from WSL:

```bash
python3 /mnt/c/Users/<windows-user>/OneDrive/Documents/GitHub/GRAD695_applied_project/pi_sensors/collect_hardened_evidence.py
```

The collector prompts for an optional existing TLS certificate/key. Without a
trusted remote TLS endpoint, HTTPS and packet-capture checks are reported as
not run; loopback HTTP through SSH is not represented as an HTTPS test. It
does not run Nmap, Nikto, or Hydra, generate SSH failures for Fail2ban, trigger
the web lockout threshold, or reboot the Pi. Those checks can affect access or
availability and require separately controlled evidence. The collector asks
for a dashboard screenshot while its temporary dashboard is live, but does not
independently validate screenshot contents. It checks UFW's active state but
compares rules with the Pi-visible source CIDR entered at runtime; package
update status is a read-only APT simulation, and permission checks cover the
project source paths only. Review and sanitize its ZIP before publishing.

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
