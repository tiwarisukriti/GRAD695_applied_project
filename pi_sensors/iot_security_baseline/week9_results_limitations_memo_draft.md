# Results and Limitations Memo — Draft for Supervisor Review

**To:** [Supervisor name]
**From:** [Student name]
**Date:** November 1, 2026
**Subject:** Raspberry Pi DHT22/PIR monitoring prototype: current results, evidence limits, and next comparison

> **Draft status:** This memo includes one completed instrumented 15-minute baseline sensor trial and a mid-run API snapshot. It does not claim that a hardened trial/security scan, reverse-shell-defense test, or supervisor review has been completed. Replace bracketed fields and update this memo after collecting and reviewing those results.

## Executive summary

The project has demonstrated that a Raspberry Pi 5 can collect DHT22 temperature/humidity readings and PIR motion-state events, write combined CSV records, and expose sensor history through a Flask dashboard API. A completed instrumented baseline run lasted 900.001 seconds and recorded 383 successful DHT22 acquisitions from 383 attempts (100.00% for this run), exceeding the project’s ≥95% per-run target. It also recorded 29 PIR transitions. This is a result from one run, not a general estimate of long-term sensor reliability or evidence about the hardened version.

The strongest quantitative web-service evidence remains a separate 20-request API timing sample. All 20 returned HTTP 200; response time averaged 23.31 ms (median 22.64 ms; p95 29.71 ms), with a recorded range of 18.87–31.77 ms. This is not a latency or availability benchmark for the 15-minute run. A redacted API snapshot from the instrumented run records 238 successful DHT22 attempts and 19 PIR events at 557.638 seconds, while the logger CSV documents the completed run and its final counts. The saved JSON retains logger/API timestamp fields, but their absolute values and the run ID were anonymized; it does not include an HTTP status code or browser receipt timestamp, so it is only a partial logger/API/dashboard trace. Security scans show open SSH and rpcbind on the tested IPv4 target and open rpcbind/mDNS UDP ports; however, the full TCP scan recorded port 5000 closed, while later Nikto and API evidence show the dashboard responding at port 5000. The evidence package does not yet explain the difference in target reachability or service state.

The instrumented logger records every DHT22 attempt with its outcome, run ID, UTC timestamp, elapsed time, and cumulative counters; it also checks whether its sensor workers remain alive. The completed baseline CSV verifies that the instrumentation operated for the full target duration in this run. The hardened version still requires its own comparable hardware run, and the dashboard/API trace should be supplemented with a browser capture showing the matching run ID and browser receipt time.

## Results by subsystem and question

### Sensor collection and logging

| Metric / question | Current observation | Evidence and interpretation |
|---|---:|---|
| Historical successful DHT22 records | 5,161 | Recomputed from the five combined CSVs. These files contain successful records, not all read attempts. |
| Historical PIR events | 2,626 | Recomputed from the same five files. PIR records are event-driven transitions, not periodic acquisition attempts. |
| Total historical sensor rows | 7,787 | Sum of the five CSV row counts. This is not a count of DHT22 attempts or unique trial samples. |
| Distinct timestamp seconds containing multiple PIR records | 373 | Recomputed as exact-timestamp PIR groups with at least two rows. Historical timestamps have whole-second precision, so this does not establish subsecond event separation. |
| Completed baseline instrumented run | 900.001 seconds; `TRIAL_END=completed` | [combined_data6.csv](../baseline_version/combined_data6.csv) is a public copy with anonymized timestamps: synthetic range 2026-01-01 12:00:00.000–12:15:00.001 UTC. It records a 900-second target duration and one consistent redacted run ID. |
| DHT22 attempts and outcomes in the completed run | 383 attempts: 383 success, 0 error, 0 no-data | Attempt sequence is contiguous from 1 to 383; final counters agree with the recorded attempt rows. |
| DHT22 attempt-based reliability in the completed run | 100.00% (383/383) | Meets the ≥95% criterion for this single baseline run. Do not generalize this one-run outcome to other sessions or the hardened version. |
| DHT22 observed values | 21.4–22.0 °C; 45.4–47.5% RH | Range across the 383 successful acquisitions; not a calibration or accuracy assessment. |
| PIR events in the completed run | 29 total: 15 `MOTION_DETECTED`, 14 `MOTION_STOPPED` | Event-driven transitions, not polling attempts or a PIR reliability denominator. |
| Attempt-based reliability across historical CSVs | Not measurable | Historical CSVs omit failed-attempt records; their successful-row counts cannot provide the denominator. |
| Required reliability threshold | ≥95% valid attempts | Acceptance target. Met by the observed completed baseline run only; a comparable hardened run and repeated trials remain outstanding. |

*Table 1 caption:* Historical totals come from the five legacy CSVs; the new
trial metrics come from one completed instrumented baseline run. Historical
attempt-based reliability remains unknowable because those files omit failures.

### API and security baseline

| Measure | Observed result | Boundary / interpretation |
|---|---|---|
| API timing sample | 20/20 HTTP 200; mean 23.31 ms; median 22.64 ms; p95 29.71 ms; range 18.87–31.77 ms | Descriptive summary of 20 recorded samples. It does not establish sustained availability, tail latency under load, or performance during a sensor trial. |
| API response snapshot | HTTP 200; count field 798; latest DHT22/PIR event in the sanitized copy has a synthetic timestamp | One response snapshot, not an availability measurement. Its response header identifies Werkzeug 3.1.8 and Python 3.13.5. The sensor timestamp has no timezone, so it cannot be directly reconciled with the HTTP `Date` header without the Pi's timezone/clock configuration. |
| Instrumented-run API snapshot | At 557.638 seconds: 238 DHT22 attempts/successes and 19 PIR events; API trial status was `running` | [trial_api_response.json](./trial_api_response.json) is a redacted mid-run snapshot; absolute timestamps and run ID were anonymized. It is not the final trial result. The JSON has no HTTP status-code or browser receipt-time field; a browser capture is still needed for a complete three-point trace. |
| Full TCP scan | TCP 22/SSH and 111/rpcbind open; 65,533 other ports reported closed | Applies only to the scan's target, source, interface, and timestamp. Port 5000 was reported closed in this scan result. |
| UDP scan | UDP 111/rpcbind and 5353/zeroconf open | Only the recorded ports were scanned; establish whether these services are required and repeat under the documented comparison procedure. |
| IPv6 scan | TCP 22, 111, and 5000 filtered | A filtered result does not by itself establish the cause or represent a complete IPv6 exposure assessment. |
| Nikto web check | Missing `X-Frame-Options`; GET/OPTIONS/HEAD reported | A configuration observation, not proof of exploitability. |
| Baseline app security condition | Unauthenticated HTTP; binds to `0.0.0.0`; Flask debug enabled | Intentional baseline test condition. Restrict testing to the authorized, owner-controlled network; never expose this development configuration to the public Internet. |
| Hardened comparison result | No comparable hardened scan/timing package identified | The hardened code configures credentials, loopback by default, TLS-required remote bind, and debug off; results must be measured on the Pi before claiming risk reduction. |

*Table 2 caption:* Network and application results are observations from
separate evidence files, not a synchronized scan session. The instrumented-run
API entry is a mid-run sensor snapshot. Hardened behavior listed here is based
on source configuration; no matching hardened test result was found.

#### Historical combined CSV breakdown

| File | DHT22 rows | PIR events | Total rows | PIR timestamp groups with multiple events | Recorded timestamp span |
|---|---:|---:|---:|---:|---|
| `combined_data.csv` | 645 | 424 | 1,069 | 44 | Dec. 24 23:40:17 – Dec. 25 00:05:31, 2025 |
| `combined_data2.csv` | 846 | 555 | 1,401 | 37 | Dec. 25 21:14:09 – 21:59:22, 2025 |
| `combined_data3.csv` | 1,593 | 1,102 | 2,695 | 210 | Dec. 25 22:55:34 – 23:58:00, 2025 |
| `combined_data4.csv` | 888 | 41 | 929 | 11 | Jan. 1 13:00:50 – 13:47:39, 2026 |
| `combined_data5.csv` | 1,189 | 504 | 1,693 | 71 | Jan. 1 15:51:35 – 18:12:37, 2026 |
| **Total** | **5,161** | **2,626** | **7,787** | **373** | **Dec. 24, 2025 23:40:17 – Jan. 1, 2026 18:12:37** |

*Table 3 caption:* Per-file counts and timestamp spans were recomputed from
the five historical CSVs. Public copies use a constant date shift; absolute
dates are synthetic, while row order and intervals are preserved. Legacy
timestamps remain timezone-naive. Multi-event groups count exact PIR
timestamps with two or more event rows.

### Figure 1. Evidence path and principal measurement gaps

```text
 DHT22 on GPIO17                         PIR on GPIO18
       |                                       |
       | periodic reads                       | asynchronous callbacks
       v                                       v
 Combined logger (separate worker threads; CSV lock)
       |                                       |
       | DHT success/error/no-data rows        | motion transition rows
       +------------------+--------------------+
                          |
                          v
       CSV evidence: public timestamps are anonymized; legacy rows retain
       whole-second precision, instrumented rows retain millisecond precision
                          |
                          v
           Flask reads CSV and returns /api/data
              |                         |
              v                         v
        API response snapshot      Browser dashboard (5-second polling)
                                       |
                                       v
                       timestamp freshness / displayed measurements
```

*Caption:* Figure 1 shows the logger-to-dashboard path and where evidence can
be lost or misinterpreted. Historical CSV rows do not include failed DHT22
attempts, and an API response can display the latest stored value after the
logger stops. The completed baseline run demonstrates that the instrumented
logger recorded a full trial; it does not retroactively repair historical
data, establish hardened-version performance, or replace a browser capture.

## Focused error analysis: PIR transitions sharing whole-second timestamps

The five historical files contain 373 distinct timestamp seconds containing
multiple PIR records across the five historical combined CSVs. An example
contains `MOTION_STOPPED` and `MOTION_DETECTED` at the same recorded second.
The historical schema records timestamps only to whole seconds. Therefore,
two transitions separated by milliseconds can appear simultaneous; CSV row
order shows which row was written first but cannot establish their physical
time separation.

These clusters should not automatically be classified as false detections or
sensor defects. Plausible explanations include actual rapid signal changes,
PIR module retrigger/timing behavior, environmental conditions, or timestamp
resolution. The existing evidence cannot distinguish these causes. Resolving
them requires a controlled PIR test that records millisecond timestamps,
preserves raw transitions, documents sensor warm-up and module settings, and
compares repeated movement/no-movement intervals. Do not silently debounce or
delete events before preserving the raw trace; if filtering is later tested,
record filtered output separately from raw events.

In the completed instrumented baseline run, the 29 PIR events had
millisecond-resolution timestamps. No exact duplicate PIR timestamp groups
occurred, but three adjacent event pairs were less than one second apart; the
shortest separation was 0.105 seconds. Three event pairs also fell within the
same displayed whole second. These observations distinguish rapid state
changes from exact timestamp collisions: the events are ordered at millisecond
resolution, but the log alone cannot determine whether sensor retriggering,
environmental conditions, or actual movement caused them.

### DHT22 failure and denominator analysis

The legacy CSVs show successful measurements but omit unsuccessful read
attempts. A successful-row total is therefore a numerator without its
denominator. It cannot support an attempt-based reliability percentage. Gaps
between successful-row timestamps are also ambiguous: they could reflect
intentional logger restarts, collection pauses, or read failures; the CSV
alone does not determine which. The supplied project analysis attributes
some historical gaps to intentional restarts, but that attribution should be
documented with the corresponding run notes rather than inferred from the
gap.

As an additional descriptive check, the pooled gaps between consecutive
DHT22 rows *within each file* have a median of 2 seconds and a maximum of
5,669 seconds (1 hour, 34 minutes, 29 seconds). Three within-file gaps exceed
10 seconds: 728 seconds in `combined_data2.csv`, 723 seconds in
`combined_data4.csv`, and 5,669 seconds in `combined_data5.csv`. These are
observed timestamp gaps, not proven sensor failures. The legacy logs do not
include a process heartbeat, pause/restart marker, or failed-attempt
denominator for these periods.

The updated combined logger writes `success`, `error`, or `no_data` outcomes
for every DHT22 acquisition attempt, calculates cumulative reliability, and
marks trial start/end. In the completed baseline run, all 383 attempts
succeeded, with attempt intervals from 2.351 to 2.352 seconds. No DHT22
acquisition failure was observed in this run, so the historical checksum/
read-error class was not reproduced. This result is limited to one trial;
abrupt power loss can still prevent a final end record. A missing
`TRIAL_END` must be interpreted using the latest logger timestamp and other
trial evidence, not treated as proof that a logger remains active.

## Baseline-to-hardened comparison plan

The historical security artifacts provide an initial baseline, but the
results are not yet a controlled before/after comparison. Most importantly,
the full TCP scan says port 5000 was closed, whereas the later Nikto and API
artifacts show a service at that port. The source artifacts were collected at
different times; their published copies use synthetic dates. This may reflect
a changed service state or a difference in target/interface/path; the
artifacts alone do not identify which. Before interpreting exposure
reduction, repeat both scans from the same authorized client, to the same
target address/interface, while confirming the dashboard listener and
recording the exact service state and test time.

For the functional comparison, run each version on the same Pi and sensor
hardware, one at a time, using the same DHT22 interval, 15-minute duration,
dashboard polling interval, network path, and observation client. Retain each
version's unedited trial CSV, run ID, API response, and dashboard capture.
Report attempts, valid readings, failures by outcome, reliability percentage,
trial duration/completion, PIR event counts, API request count/status, and
latency distribution. Repeat trials to expose run-to-run variability. Keep
the sensor collection implementation aligned between versions so measured
differences are not caused by different sampling behavior.

For security testing, compare reachable TCP/UDP services, unauthenticated
dashboard behavior, HTTP/TLS behavior, relevant HTTP headers, and authorized
failed-login response only where such tests are part of the approved scope.
The proposed reverse-shell-resilience assessment should focus on documented
controls and safe, authorized validation of egress policy, detection, and
response. Do not claim reverse-shell prevention from port scans or Nikto
results. Preserve approved test plans, observed telemetry, timestamps, and
limitations; avoid executing an actual shell payload on a shared or
uncontrolled system.

### Table 4. Comparison measures and evidence status

| Comparison dimension | Baseline evidence available | Hardened evidence needed | Status |
|---|---|---|---|
| DHT22 reliability | One completed 15-minute run: 383/383 successes (100.00%) | Repeat the same instrumented trial and retain raw CSV | Initial baseline measured; repeatability and hardened comparison pending |
| PIR behavior | Historical data: 373 same-second groups; new run: 29 events, three sub-second adjacent pairs, minimum 0.105 s | Same controlled motion protocol and higher-resolution event trace | Baseline trace available; physical cause and between-version comparison pending |
| API/dashboard trace | Redacted mid-run API snapshot at 557.638 s; logger CSV has final status and counters | Save final API response, HTTP status, browser timestamp/screenshot, and matching run ID | Partial trace; browser capture missing |
| API performance | 20 HTTP 200 samples; mean 23.31 ms, median 22.64 ms, p95 29.71 ms | Same client, cadence, duration, and sample method | Initial baseline only |
| Service exposure | IPv4 TCP/UDP, IPv6 samples; inconsistent port-5000 evidence | Repeat matching scans with service state recorded | Partial; reconcile baseline first |
| Authentication / TLS | Baseline app is unauthenticated HTTP | Verify denied unauthenticated access and TLS certificate/transport | Code supports a difference; runtime evidence absent |
| Reverse-shell/e-gress resilience | No test result in current evidence folder | Approved safe test plan, expected controls, logs/alerts, response timing | Not measured |

*Caption:* Table 4 distinguishes observed baseline evidence from code
configuration and missing hardened measurements. “Not comparable yet” means
the evidence is incomplete, not that the sensor or security control failed.

## Limitations and threats to validity

1. **No attempt denominator in historical sensor files.** Reliability cannot
   be calculated from successful rows alone.
2. **Historical sessions are heterogeneous.** The five CSVs span different
   collection periods and intentional restarts; they are not one continuous
   15-minute experiment.
3. **Timestamp precision and provenance differ.** Historical combined CSVs
   use timestamps without an explicit timezone and with whole-second
   precision. Instrumented logs use UTC milliseconds. Do not compare their
   event ordering or clock offsets as if their formats were identical.
4. **Only one instrumented baseline trial is available.** It completed for
   900.001 seconds with 383/383 successful DHT22 attempts. One run cannot
   characterize between-run variability, establish long-term reliability, or
   serve as the hardened comparison.
5. **API timing sample is small.** Twenty successful requests do not measure
   availability over time, high-percentile behavior reliably, or service
   performance under load.
6. **Security scan conditions are not fully synchronized.** Port 5000 was
   reported closed in the Nmap full TCP scan, while a later Nikto result and
   API capture show the web service responding. Published timestamps have
   been shifted for privacy; the source artifacts also use different
   timestamp/timezone conventions and do not record a synchronized listener
   check. Target, route, interface, listener state, and test time need to be
   captured together.
7. **Security evidence is incomplete.** Existing scans do not test
   authentication (baseline has none), TLS (baseline is HTTP), host
   configuration, egress filtering, intrusion detection, or reverse-shell
   response.
8. **Implementation and deployment differ.** A code option or configuration
   in the repository does not show that the Pi was launched with that option
   or that a network control was active during a test.
9. **Single-device scope.** Results from one Pi, sensor pair, room, and local
   network do not establish reliability, security, or scalability for other
   devices, environments, users, or deployments.

## Broader-impact considerations

The system collects environmental measurements and PIR activity. Motion
events can reveal room occupancy or activity patterns even though the system
does not identify people. Retain only the data needed for the project, limit
access to raw CSVs and dashboard endpoints, avoid public exposure, and define
when trial data will be deleted or archived. Do not treat absence of a PIR
event as evidence that a room is unoccupied or safe.

Incorrect, stale, or missing measurements could mislead a user making
environmental or safety decisions. The dashboard's stale indicator and
attempt-based reliability help communicate uncertainty, but this prototype
has not been validated as a safety-critical monitor. The Raspberry Pi and
sensors also require continuous power and maintenance; power/network outages,
sensor drift, and replacement calibration affect long-term sustainability
and data continuity. Separate raw evidence from derived summaries to support
reproducibility and future maintenance.

## Conclusions and next actions

The prototype has demonstrated end-to-end sensor logging and API presentation
in historical runs, and initial scans identified exposed services and web
configuration observations. The first completed instrumented baseline trial
recorded 383/383 successful DHT22 attempts (100.00%) over 900.001 seconds,
meeting the ≥95% criterion for that run. It does not establish long-term
reliability, hardened-version performance, or security improvement. The most
important remaining evidence limitation is that no matched hardened run or
repeated trials are available; the legacy files also still cannot yield an
attempt-based reliability rate.

Before the final report:

1. Repeat and archive baseline and hardened 15-minute trials, retaining each
   raw CSV, run ID, final API response and HTTP status, browser receipt
   timestamp, and matching dashboard capture. Compare the variants under the
   same hardware and trial conditions.
2. Reconcile why the full TCP scan showed port 5000 closed while later web
   tests responded; then repeat synchronized baseline and hardened scans.
3. Capture the Pi OS/kernel, services/listeners, firewall (IPv4/IPv6), SSH,
   network, dashboard service configuration, and package versions for each
   comparison state. Redact secrets before sharing.
4. Define the approved reverse-shell-resilience scope and measure only the
   relevant egress-control, detection, and response outcomes.
5. Obtain supervisor feedback and revise this memo. **Supervisor feedback:**
   [Pending; record feedback and revisions here.]

## AI usage disclosure draft

AI assistance was used to organize the existing project evidence, calculate
or summarize descriptive metrics, identify limitations and inconsistencies,
and draft portions of this memo. The student supplied the completed baseline
trial CSV and API snapshot; the counts and interpretations in this memo
should be independently checked against those original artifacts and the
Raspberry Pi runtime configuration, revised in the student's own voice, and
disclosed according to course policy. No new sensor trial or security test
was generated by this memo.
