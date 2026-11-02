# Code Changes Handoff for ChatGPT

**Purpose:** This companion document summarizes the implementation changes
made for the sensor-trial and baseline/hardened comparison work. It is not a
replacement for the source code or a line-by-line patch. To review or modify
the implementation, provide this handoff together with the source files listed
below.

## What changed

### Shared sensor-trial instrumentation

Matching `combined_logger.py` implementations were added to the baseline and
hardened version folders. They support repeatable, time-bounded DHT22/PIR
trials and write trial evidence to an appendable CSV.

- Default trial duration is 15 minutes; the default DHT22 interval is two
  seconds. Both values and the output CSV can be supplied as command-line
  arguments.
- Each trial gets a UUID run ID. Records carry that ID, a timezone-aware UTC
  timestamp with millisecond precision, and elapsed time from a monotonic
  clock.
- The CSV has explicit `TRIAL_START`, `DHT22_ATTEMPT`, `PIR_EVENT`, and
  `TRIAL_END` record types. It records DHT22 outcomes as `success`, `error`,
  or `no_data`, along with cumulative attempt, success, failure, and
  reliability values.
- Attempt-based reliability is calculated as complete successful DHT22
  acquisitions divided by all recorded DHT22 attempts. PIR detections and
  stops are logged as asynchronous events; they are not assigned a
  polling-attempt denominator.
- A thread lock serializes sensor writes to the shared CSV. The logger flushes
  records as they are written and refuses to append to a non-empty CSV whose
  header does not match the instrumented schema.
- Intermittent DHT22 `RuntimeError` readings are recorded and retried. Sensor
  workers are monitored; unexpected worker exit prevents the run from being
  reported as completed. Ctrl+C is recorded as an interrupted run.
- Millisecond timestamps improve event ordering but cannot guarantee unique
  timestamps or prove the physical cause of rapid PIR transitions.

### Dashboard and API updates

Both dashboards can continue to read the legacy separate sensor CSV files and
can also be launched against the instrumented combined trial CSV. The Flask
app reads the files; it does not access GPIO.

- `/api/data` retains the established sensor-data keys and adds trial metrics,
  freshness information, and trace timestamps.
- For an instrumented CSV, the API derives metrics from the latest started
  run ID, counts every DHT22 attempt in the denominator, and treats only
  complete successful measurement rows as valid successes.
- The response includes the run ID and logger/API UTC timestamps. The browser
  adds its receipt timestamp and displays the response HTTP status, enabling
  comparison of logger, API, and browser observations.
- Timestamp freshness is classified as fresh, stale, future/clock-ahead,
  invalid, or unknown. The default stale threshold is ten seconds and can be
  changed at launch.
- A missing `TRIAL_END` is not proof that collection is still running. In an
  open trial, stale latest-attempt data changes the API trial status to
  `stale`; abrupt process or power loss can still prevent a final status row.
- The dashboard displays trial/run status, DHT22 attempts, successes,
  failures, reliability percentage, latest sensor data, freshness, and the
  trace timestamps. PIR remains an event stream.

### Baseline and hardened behavior

- **Baseline:** Kept intentionally basic for the comparison condition. Its
  dashboard remains unauthenticated HTTP, binds to `0.0.0.0`, and runs with
  Flask debug enabled. These are deliberate insecure-baseline settings, not
  recommended deployment settings. Use only on an authorized, owner-controlled
  test network.
- **Hardened variant:** The dashboard requires `DASHBOARD_USERNAME` and
  `DASHBOARD_PASSWORD` from the process environment, checks credentials using
  constant-time comparison, and refuses requests when credentials are absent
  or invalid. Passwords shorter than 12 characters are rejected at startup.
  Flask debug is disabled, loopback is the default bind, and remote binds
  require existing TLS certificate and key files.
- The hardened dashboard still uses Flask's built-in development server. The
  code does not establish that firewall, SSH, egress filtering, intrusion
  monitoring, or other host/network protections are configured on the Pi.

### Documentation and repository organization

- The root `README.md` was made a general project overview with hardware,
  setup, measurement interpretation, security boundaries, and links to the
  variant guides.
- The baseline folder has its own instructions for running the instrumented
  trial, starting the intentionally insecure dashboard, and collecting
  comparable artifacts.
- The hardened folder has its own trial instructions and credential/TLS
  setup guidance.
- The baseline directory was renamed from `security_baseline` to
  `baseline_version`; references and commands were updated.
- The historical CSVs remain historical evidence. They were not rewritten to
  invent missing failed-attempt records.

## Files to provide with this handoff

For code review or future changes, attach these current source files:

1. `pi_sensors/baseline_version/combined_logger.py`
2. `pi_sensors/hardened_version/combined_logger.py`
3. `pi_sensors/baseline_version/dashboard/app.py`
4. `pi_sensors/baseline_version/dashboard/templates/index.html`
5. `pi_sensors/hardened_version/dashboard/app_debug_off.py`
6. `pi_sensors/hardened_version/dashboard/templates/index.html`
7. `README.md`
8. `pi_sensors/baseline_version/README.md`
9. `pi_sensors/hardened_version/README.md`
10. `pi_sensors/baseline_version/combined_data6.csv` (sanitized completed run)
11. `pi_sensors/iot_security_baseline/trial_api_response.json` (sanitized
    mid-run snapshot)

Attach the results memo and the relevant CSV/scan/API evidence separately if
the question concerns project findings rather than code behavior. Do not send
passwords, private keys, or other secrets.

## Public evidence sanitization

The GitHub-facing sensor CSVs and API responses use synthetic date shifts that
preserve relative timing; the latest run ID and scan target addresses are
redacted. Do not replace these with unredacted originals when sharing this
handoff. The memo explains which timestamps are synthetic.

## Validation and evidence boundaries

Earlier work in this conversation reported Python syntax checks and simulated
logger/API checks as passing, including freshness classification and
fail-closed authentication behavior. These were software-level checks, not a
Raspberry Pi hardware run. No completed instrumented 15-minute sensor trial,
matching hardened security scan, reverse-shell-resilience test, or supervisor
review is evidenced by this handoff. Run the tests on the current checkout
again before relying on them.

At the time this handoff was prepared, the source implementation was already
committed in repository history, so a normal `git diff` does not display the
full earlier implementation. The file list above points to the current
implementation itself. Use the current source files rather than relying on a
short commit range as a complete change record.
