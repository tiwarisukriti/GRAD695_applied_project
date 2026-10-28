# GRAD695 Applied Project

Raspberry Pi 5 sensor-monitoring prototype and staged security comparison.
The project reads temperature and humidity from a DHT22 and motion events
from a PIR sensor, records data to CSV, and presents the records in a Flask
dashboard.

## Project versions

The two implementations are maintained separately so their behavior and
evidence can be compared:

- [Security baseline](./pi_sensors/security_baseline/README.md) — intentionally
  retains the baseline dashboard's Flask debug setting for controlled,
  authorized testing.
- [Hardened version](./pi_sensors/hardened_version/README.md) — the dashboard
  entry point disables Flask debug mode. This is one hardening step, not a
  claim that the application has authentication, HTTPS, or complete host and
  network protections.

Run only one version at a time: both use GPIO17 and GPIO18 on the same
Raspberry Pi. Each version's README has its launch commands, CSV schema,
security notes, and current evidence limitations.

## Hardware

| Component | Connection / purpose |
|---|---|
| Raspberry Pi 5 | Runs sensor collection, CSV logging, and the dashboard. |
| DHT22 | Data to GPIO17 (physical pin 11); VCC to physical pin 4; GND to physical pin 9. |
| PIR motion sensor | Output to GPIO18 (physical pin 12); VCC to physical pin 2; GND to physical pin 14. |
| Local network | Connects the Pi and an authorized observation device for dashboard access. |

Verify wiring against the actual sensor and Raspberry Pi pinout before
powering the hardware.

## Install dependencies

The shared setup script is at `pi_sensors/00_install.sh`. On Raspberry Pi OS,
run it once from the sensor directory:

```bash
cd ~/GRAD695_applied_project/pi_sensors
chmod +x 00_install.sh
./00_install.sh
```

The script installs the system GPIO prerequisites and creates
`~/sensor-env` with the DHT22 and Flask packages. Activate that environment
in every terminal used to run project Python scripts:

```bash
source ~/sensor-env/bin/activate
```

## Sensor trial and data interpretation

Each version provides an instrumented combined logger. Its default run is a
continuous 15-minute trial with a two-second DHT22 polling interval. The CSV
records every DHT22 attempt, including failures and empty results, so the
attempt-based reliability is:

```text
100 × complete valid DHT22 acquisitions / all DHT22 acquisition attempts
```

PIR is event-driven. Its motion transitions are logged and counted as events;
they are not treated as periodic read attempts. Trial records include a UUID
run ID, UTC timestamps with millisecond precision, monotonic elapsed seconds,
and per-run counters. The logger serializes CSV writes with a lock and flushes
each record. A worker that exits unexpectedly causes the trial to be marked
failed rather than silently continuing as a complete run. An abrupt process
termination or power loss can prevent the final record from being written;
therefore, a missing `TRIAL_END` or a dashboard status of `running` is not
proof that collection is still active. Check the latest logger timestamp
against the API and browser timestamps.

An instrumented run can provide evidence for the 15-minute reliability
criterion, but the code alone does not establish that the threshold was met.
Run the trial on the Raspberry Pi, retain its CSV, capture the matching
`/api/data` response, and save a dashboard capture showing the same run ID.
Compare the displayed logger, API, and browser UTC timestamps. A CSV containing
successful historical rows without recorded failed attempts cannot establish
an attempt-based reliability percentage.

The Oct. 25 historical analysis reported 5,161 successful DHT22 records and
2,626 PIR events across five combined CSV files, including many PIR transitions
sharing a whole-second timestamp. Those historical totals demonstrate logged
activity, not an attempt-based reliability rate. The new instrumented logger
uses millisecond timestamps, but timestamps are not guaranteed unique; CSV row
order and the run ID remain important when correlating close events.

## Security and evidence boundaries

The baseline and hardened variants are comparison conditions, not production
deployment recommendations. Keep both on an owner-controlled private network;
do not expose the baseline development server to the public internet. The
hardened dashboard requires environment-provided HTTP Basic credentials and
disables debug mode. By default it binds to loopback; a non-loopback bind
requires a TLS certificate and private key. This does not replace a production
WSGI server, reverse proxy, firewall policy, SSH hardening, or intrusion
monitoring. The dashboard marks sensor rows stale after 10 seconds by default
(configurable with `--stale-after-seconds`); stale display status is based on
timestamps and is not an independent process-health monitor. Report only
controls and results that have actually been configured and measured on the Pi.

## Repository layout

```text
pi_sensors/
  00_install.sh
  security_baseline/
    README.md
    combined_logger.py
    dashboard/
  hardened_version/
    README.md
    combined_logger.py
    dashboard/
```
