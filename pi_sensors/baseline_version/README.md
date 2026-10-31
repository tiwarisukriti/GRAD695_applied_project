# Security Baseline Sensor System

This folder contains the project's baseline Raspberry Pi sensor collector
and Flask dashboard. It is intentionally the less-secure comparison
condition: `dashboard/app.py` runs Flask with debug mode enabled. Use it only
on the owner-controlled private test network. Do not port-forward it or expose
it to the public internet.

For shared hardware setup and evidence context, see the [project README](../../README.md).

## Components

- `combined_logger.py` — instrumented, time-bounded DHT22 and PIR collection.
- `dht22_reader.py` / `pir_reader.py` — standalone legacy collectors.
- `dashboard/app.py` — Flask API and dashboard server.
- `dashboard/templates/index.html` — browser dashboard.
- `combined_data*.csv`, `dht_log.csv`, `pir_log.csv`, and `sensor_log.csv` —
  historical evidence; do not treat them as output from a new trial.

## Run a 15-minute instrumented trial

Use the Raspberry Pi, activate the shared environment, and run from this
version directory so the output CSV is kept with this version:

```bash
cd ~/GRAD695_applied_project/pi_sensors/baseline_version
source ~/sensor-env/bin/activate
python3 combined_logger.py --csv sensor_trial.csv --interval 2 --duration-minutes 15
```

The logger defaults to these settings if `--interval` and `--duration-minutes`
are omitted. It creates or appends to `sensor_trial.csv`; select a new filename
if you need a separate evidence artifact. It refuses to append the instrumented
schema to a nonmatching existing CSV.

The CSV records `TRIAL_START`, every `DHT22_ATTEMPT`, each `PIR_EVENT`, and
`TRIAL_END`. DHT22 attempts have `success`, `error`, or `no_data` outcomes.
Reliability uses complete successful measurement rows divided by all attempt
rows. Each record includes a run UUID, UTC timestamp with millisecond
precision, monotonic elapsed seconds, and cumulative counters. The PIR is
callback-driven; motion detections and stops are timestamped events, not
polled acquisition attempts.

In another terminal, launch the matching dashboard against that CSV:

```bash
cd ~/GRAD695_applied_project/pi_sensors/baseline_version/dashboard
source ~/sensor-env/bin/activate
python3 app.py --combined-csv ../sensor_trial.csv --port 5000
```

Open `http://<pi-ip-address>:5000` from the authorized local network.
The page refreshes its data from `/api/data` every five seconds. The trial
panel displays run status and ID, elapsed/duration, attempts, successes,
failures, reliability, logger/API/browser UTC timestamps, and HTTP status.
The baseline API intentionally remains unauthenticated HTTP with Flask debug
enabled.

The dashboard marks the latest DHT22 sample and PIR event stale when their
timestamp is older than 10 seconds by default. Change the threshold with
`--stale-after-seconds`. Historical measurements remain visible with their
timestamps, but the header marks stale DHT22 data rather than presenting it as
live. This timestamp check is not a process-health monitor; an abrupt logger
termination can leave the trial without `TRIAL_END`, so compare freshness
across the CSV, API, and browser.

## Capture comparable evidence

For each trial, preserve:

1. The unedited `sensor_trial.csv`.
2. The `/api/data` JSON response, including `trial.run_id` and `trace`.
3. A browser capture showing that same run ID and the logger/API/browser
   timestamps.
4. The Git revision, run date/time, hardware/configuration notes, and whether
   the run ended as `completed`, `interrupted`, or `failed`.

The logger and API timestamps use UTC. The dashboard records the browser's
UTC receipt time. Confirm the run ID matches before comparing these records.
The dashboard's DHT `LIVE` indicator means data is present; it is not proof
that a separate or historical collector is still running. In instrumented
mode, use the displayed trial status and elapsed time as additional context.
If the process or Pi stops abruptly, there may be no `TRIAL_END` row and the
API can continue to show `running`; compare the latest logger timestamp with
the current API/browser timestamps before calling collection live.

## Findings addressed by instrumented mode

- Whole-second timestamp collisions: new trial records use millisecond UTC
  timestamps and keep CSV row ordering; close PIR transitions can still share
  a timestamp at that precision.
- Missing DHT attempt denominator: every sample cycle, including failures and
  empty results, is stored and counted.
- Silent worker loss: the timed logger checks both worker threads and marks
  an unexpected exit as a failed trial.
- Stopped or delayed logger data: the dashboard classifies records older than
  the configured freshness threshold as stale.
- Run correlation: each record and the API response share one UUID run ID;
  elapsed time uses a monotonic clock.

An abrupt process termination or power loss cannot write a final status row.
The trial status and DHT `LIVE` indicator alone therefore do not establish
collector health; timestamp freshness must be checked.

Historical CSVs do not retroactively gain failed-attempt counts. The Oct. 25
analysis reported 5,161 successful DHT22 rows and 2,626 PIR events across
five combined files. Those counts and multi-event-per-second timestamps do
not prove attempt-based reliability or explain the physical cause of rapid PIR
transitions. The 15-minute ≥95% criterion is not met until a new trial is
completed and its evidence reviewed.
