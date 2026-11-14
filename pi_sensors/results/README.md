# Results archive

Results are grouped in `YYYY-MM-DD` folders under this directory. The folder
date is the recorded UTC date, not necessarily the date when a sanitized copy
was published. Some timestamps in this repository were shifted synthetically;
see the project README's evidence boundary before interpreting dates as
wall-clock dates.

## Naming

- `baseline_...` and `hardened_...` distinguish sensor collection variants.
- `pi_security_...` identifies Raspberry Pi security-baseline evidence.
- `wsl_...` identifies WSL IoT security-baseline evidence.
- Sensor logs spanning multiple dates are split into one CSV per date. Their
  headers and row contents are retained, and the original source filename is
  included in the output filename.
- Files without a usable date are stored under `undated/` with their source
  name retained.

New sensor logs are written here automatically using the current UTC date.
Combined trials use `baseline_sensor_trial.csv` or
`hardened_sensor_trial.csv`; standalone readers use the corresponding
`baseline_` or `hardened_` DHT/PIR log filename. The `--csv` option on each
reader or combined logger can still select a custom path. A combined trial
stays together in the folder for its UTC start date.

Save each trial's API response, dashboard capture, and run notes in the same
date folder, using the matching `baseline_` or `hardened_` prefix. The
dashboard command must point to the date folder containing that trial.

## Archived dates

| Date folder | Contents |
|---|---|
| `2025-10-16` | Baseline DHT22 readings |
| `2025-12-24` | Baseline sensor readings and PIR events |
| `2025-12-25` | Baseline combined sensor readings |
| `2026-01-01` | Baseline combined sensor readings and WSL IoT security evidence |
| `2026-10-25` | Raspberry Pi security-baseline evidence |
| `undated` | Empty historical sensor log |
