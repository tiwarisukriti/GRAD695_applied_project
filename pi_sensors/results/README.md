# Results archive

Results are grouped by the platform that produced the evidence (`pi`, `wsl`,
or `windows`), then by `YYYY-MM-DD`. For example:
`pi/2025-11-14/baseline_sensor_trial.csv`. A platform folder identifies where
the evidence was collected, not necessarily the system being tested. Dates
may be synthetic rather than wall-clock dates. Evidence formerly dated in
2026 was shifted by 365 days and three hours; relative event timing was
preserved. See the project README's evidence boundary before interpreting
dates.

## Naming

- `baseline_...` and `hardened_...` distinguish sensor collection variants.
- `pi_security_...` identifies Raspberry Pi security-baseline evidence.
- `wsl_...` identifies WSL IoT security-baseline evidence.
- Sensor logs spanning multiple dates are split into one CSV per date. Their
  headers and row contents are retained, and the original source filename is
  included in the output filename.
- Files without a usable date are stored under `<platform>/undated/` with
  their source name retained.

New sensor logs are written under `pi/` automatically using the current UTC date.
Combined trials use `baseline_sensor_trial.csv` or
`hardened_sensor_trial.csv`; standalone readers use the corresponding
`baseline_` or `hardened_` DHT/PIR log filename. The `--csv` option on each
reader or combined logger can still select a custom path. A combined trial
stays together in `pi/<UTC-start-date>`.

Save each Pi trial's API response, dashboard capture, and run notes under
`pi/<date>/`, using the matching `baseline_` or `hardened_` prefix. The
dashboard command must point to the date folder containing that trial.

## Archived dates

| Platform | Date folder | Contents |
|---|---|---|
| `pi` | `2025-01-01` | Baseline combined sensor readings |
| `pi` | `2025-10-16` | Baseline DHT22 readings |
| `pi` | `2025-10-25` | Raspberry Pi security-baseline evidence |
| `pi` | `2025-11-14` | Pi listeners and environment evidence |
| `pi` | `2025-12-24` | Baseline sensor readings and PIR events |
| `pi` | `2025-12-25` | Baseline combined sensor readings |
| `pi` | `undated` | Historical sensor log without a usable date |
| `wsl` | `2025-01-01` | WSL API, timing, IPv6, TCP/UDP, and Nikto evidence |
| `wsl` | `2025-10-25` | WSL baseline scans |
| `windows` | `2025-10-25` | Windows Nmap and baseline scans; sanitized initial-capture summary |
| `windows` | `2025-11-14` | Laptop HTTP/API checks and sanitized Wireshark summary |

Wireshark metadata identifies both packet captures as collected on Windows.
The raw captures, scan reports, API snapshots, and host/network configuration
outputs may contain private IP/MAC addresses, host details, run IDs, or exact
timestamps. Sanitize public copies before committing them; keep original
captures and unredacted evidence in a private location.
