#!/usr/bin/env python3
"""Collect defensive evidence for an authorized hardened Pi sensor trial.

Run this script from WSL. It uses only Python's standard library locally and
over SSH on the Pi. It does not install software, change host controls, kill
unowned processes, run Nmap/Nikto/Hydra, or save credentials.
"""

import base64
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import select
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path


VERSION = "1.0"
TRIAL_SECONDS = 900
POLL_SECONDS = 30
STALE_SECONDS = 10
WORKING_TOOLS = {
    "nmap": ["--version"],
    "tshark": ["--version"],
    "tcpdump": ["--version"],
    "nikto": ["-Version"],
    "hydra": ["-h"],
    "curl": ["--version"],
    "ufw": ["version"],
    "fail2ban-client": ["-V"],
    "ssh": ["-V"],
    "scp": ["-V"],
}


REMOTE_DISCOVER = r"""
import json, os, shutil
from pathlib import Path

home = Path.home()
candidates = [
    home / "GRAD695_applied_project" / "pi_sensors",
    home / "pi_sensors",
]
found = [str(p) for p in candidates
         if (p / "hardened_version" / "combined_logger.py").is_file()
         and (p / "hardened_version" / "dashboard" / "app_debug_off.py").is_file()]
print(json.dumps({
    "home": str(home),
    "projects": found,
    "python3": shutil.which("python3"),
}))
"""


REMOTE_INVENTORY = r"""
import hashlib, importlib.metadata, json, os, platform, re, shutil, subprocess
import sys, time
from datetime import datetime, timezone
from pathlib import Path

config = json.load(sys.stdin)
project = Path(config["project"]).expanduser().resolve()

def command(argv, timeout=20, privileged=False):
    executable = shutil.which(argv[0])
    if not executable:
        return {"status": "NOT RUN", "reason": argv[0] + " is not installed"}
    args = [executable] + argv[1:]
    if privileged:
        sudo = shutil.which("sudo")
        if not sudo:
            return {"status": "NOT RUN", "reason": "sudo is unavailable"}
        args = [sudo, "-n"] + args
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=timeout, check=False)
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode and privileged and (
            "password is required" in output.lower()
            or "a password is required" in output.lower()
            or "not allowed" in output.lower()
        ):
            return {"status": "NOT RUN", "reason":
                    "non-interactive elevated permission is unavailable",
                    "exit_code": result.returncode, "output": output[-12000:]}
        return {"status": "COMPLETED" if result.returncode == 0 else "ERROR",
                "exit_code": result.returncode, "output": output[-20000:]}
    except subprocess.TimeoutExpired as exc:
        return {"status": "NOT RUN", "reason": "command timed out",
                "output": str(exc)}
    except OSError as exc:
        return {"status": "NOT RUN", "reason": str(exc)}

def read_text(path):
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError as exc:
        return "NOT RUN: " + str(exc)

def package_versions():
    names = [
        "Flask", "Werkzeug", "gunicorn", "gpiozero",
        "adafruit-circuitpython-dht", "Adafruit-Blinka",
    ]
    result = {}
    for name in names:
        try:
            result[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result[name] = "NOT INSTALLED"
    return result

def code_facts():
    app_path = project / "hardened_version" / "dashboard" / "app_debug_off.py"
    facts = {}
    try:
        source_bytes = app_path.read_bytes()
        source = source_bytes.decode("utf-8", errors="replace")
        facts = {
            "password_hash_source_indicator":
                "DASHBOARD_PASSWORD_HASH" in source
                and "check_password_hash(" in source,
            "web_lockout_source_indicator":
                "FAILED_LOGIN_LIMIT" in source
                and "LOGIN_LOCKOUT_SECONDS" in source,
            "gunicorn_source_indicator":
                "gunicorn.app.base" in source and "BaseApplication" in source,
            "trusted_proxy_source_indicator":
                "ProxyFix" in source and "DASHBOARD_TRUST_PROXY" in source,
            "anti_framing_source_indicator":
                "X-Frame-Options" in source and "frame-ancestors" in source,
            "dedicated_auth_audit_log_source_indicator":
                "AUTH_AUDIT_LOG" in source or "authentication_audit" in source,
            "dashboard_source_sha256":
                hashlib.sha256(source_bytes).hexdigest(),
        }
    except OSError as exc:
        facts["source_read_error"] = str(exc)
    return facts

commands = {
    "date_timezone": command(["date", "--iso-8601=seconds"]),
    "timedatectl": command(["timedatectl", "show", "-p", "Timezone",
                            "-p", "LocalRTC"]),
    "kernel": command(["uname", "-a"]),
    "architecture": command(["uname", "-m"]),
    "python": command([sys.executable, "--version"]),
    "disk_space": command(["df", "-h", str(project)]),
    "package_updates_simulation": command(
        ["apt-get", "-s", "upgrade"], timeout=60),
    "interfaces_ipv4_ipv6": command(["ip", "-details", "address"]),
    "routes_ipv4": command(["ip", "route", "show", "table", "all"]),
    "routes_ipv6": command(["ip", "-6", "route", "show", "table", "all"]),
    "listeners_unprivileged": command(["ss", "-lntup"]),
    "listeners_elevated": command(["ss", "-lntup"], privileged=True),
    "nginx_version": command(["nginx", "-v"]),
    "nginx_config_test": command(["nginx", "-t"], privileged=True),
    "nginx_service": command(["systemctl", "is-active", "nginx"]),
    "dashboard_service": command([
        "systemctl", "is-active",
        "sensor-dashboard@{}.service".format(config.get("ssh_user", "")),
    ]),
    "ufw_status": command(["ufw", "status", "verbose"], privileged=True),
    "ufw_rules": command(["ufw", "status", "numbered"], privileged=True),
    "ufw_version": command(["ufw", "version"]),
    "fail2ban_version": command(["fail2ban-client", "-V"]),
    "fail2ban_status": command(["fail2ban-client", "status"]),
    "fail2ban_sshd_jail": command(["fail2ban-client", "status", "sshd"]),
    "fail2ban_ssh_jail": command(["fail2ban-client", "status", "ssh"]),
    "fail2ban_maxretry": command(["fail2ban-client", "get", "sshd", "maxretry"]),
    "fail2ban_findtime": command(["fail2ban-client", "get", "sshd", "findtime"]),
    "fail2ban_bantime": command(["fail2ban-client", "get", "sshd", "bantime"]),
    "fail2ban_ssh_maxretry": command(["fail2ban-client", "get", "ssh", "maxretry"]),
    "fail2ban_ssh_findtime": command(["fail2ban-client", "get", "ssh", "findtime"]),
    "fail2ban_ssh_bantime": command(["fail2ban-client", "get", "ssh", "bantime"]),
}
for key, argv in (
    ("fail2ban_status", ["fail2ban-client", "status"]),
    ("fail2ban_sshd_jail", ["fail2ban-client", "status", "sshd"]),
    ("fail2ban_ssh_jail", ["fail2ban-client", "status", "ssh"]),
):
    if commands[key].get("status") != "COMPLETED":
        commands[key] = command(argv, privileged=True)
sshd_args = ["sshd", "-T"]
if config.get("ssh_user") and config.get("source_ip"):
    sshd_args.extend([
        "-C", "user={},host={},addr={}".format(
            config["ssh_user"], config["source_ip"], config["source_ip"])
    ])
commands["sshd_effective"] = command(sshd_args)
for jail_name in ("sshd", "ssh"):
    for key, option in (("maxretry", "maxretry"),
                        ("findtime", "findtime"),
                        ("bantime", "bantime")):
        command_name = "fail2ban_{}_{}".format(jail_name, key)
        jail_status = commands["fail2ban_{}_jail".format(jail_name)]
        if jail_status.get("status") == "COMPLETED" and \
                commands[command_name].get("status") != "COMPLETED":
            commands[command_name] = command(
                ["fail2ban-client", "get", jail_name, option], privileged=True)
sshd = commands["sshd_effective"]
if sshd.get("status") != "COMPLETED":
    elevated_args = ["sshd", "-T"]
    if config.get("ssh_user") and config.get("source_ip"):
        elevated_args.extend(["-C", "user={},host={},addr={}".format(
            config["ssh_user"], config["source_ip"], config["source_ip"])])
    commands["sshd_effective"] = command(elevated_args, privileged=True)
    sshd = commands["sshd_effective"]
if sshd.get("output"):
    relevant = ("pubkeyauthentication", "passwordauthentication",
                "kbdinteractiveauthentication", "authenticationmethods",
                "permitrootlogin", "maxauthtries")
    sshd["auth_settings"] = [
        line for line in sshd["output"].splitlines()
        if line.split(" ", 1)[0].lower() in relevant
    ]

ufw_file = read_text("/etc/default/ufw")
nginx_text = ""
nginx_site_dir = Path("/etc/nginx/sites-enabled")
nginx_site_names = []
try:
    for path in sorted(nginx_site_dir.iterdir()):
        if path.is_file():
            nginx_site_names.append(path.name)
            nginx_text += "\n" + path.read_text(errors="replace")
except OSError:
    pass
nginx_facts = {
    "enabled_site_files": nginx_site_names,
    "https_443_listener": bool(re.search(
        r"(?m)^\s*listen\s+(?:\[::\]:)?443\s+ssl\b", nginx_text)),
    "proxy_to_loopback_gunicorn": bool(re.search(
        r"(?m)^\s*proxy_pass\s+http://127\.0\.0\.1:5001\s*;", nginx_text)),
    "forwarded_client_ip_overwritten": bool(re.search(
        r"(?m)^\s*proxy_set_header\s+X-Forwarded-For\s+\$remote_addr\s*;",
        nginx_text)),
}
try:
    model = Path("/proc/device-tree/model").read_bytes().decode(
        "utf-8", errors="replace").strip("\x00\n ")
except OSError:
    model = "NOT AVAILABLE"
try:
    os_release = Path("/etc/os-release").read_text(errors="replace")
except OSError as exc:
    os_release = "NOT RUN: " + str(exc)

file_permissions = []
permission_targets = [
    project,
    project / "hardened_version" / "combined_logger.py",
    project / "hardened_version" / "dashboard" / "app_debug_off.py",
    project / "hardened_version" / "dashboard" / "templates" / "index.html",
]
for path in permission_targets:
    try:
        mode = path.stat().st_mode & 0o777
        file_permissions.append({
            "path": str(path),
            "mode": oct(mode),
            "group_writable": bool(mode & 0o020),
            "world_writable": bool(mode & 0o002),
        })
    except OSError as exc:
        file_permissions.append({"path": str(path), "error": str(exc)})

git = {
    "is_git_checkout": False,
    "revision": None,
    "working_tree": None,
    "status": None,
}
git_root = command(["git", "-C", str(project), "rev-parse", "--show-toplevel"])
if git_root.get("status") == "COMPLETED":
    git["is_git_checkout"] = True
    git["root"] = git_root["output"].strip()
    git["revision"] = command(["git", "-C", str(project), "rev-parse", "HEAD"])
    git["status"] = command(["git", "-C", str(project), "status", "--short"])
    git["working_tree"] = (
        "clean" if git["status"].get("output", "").strip() == ""
        and git["status"].get("status") == "COMPLETED" else "uncommitted changes"
    )
else:
    relevant_files = [
        project / "hardened_version" / "combined_logger.py",
        project / "hardened_version" / "dashboard" / "app_debug_off.py",
        project / "hardened_version" / "dashboard" / "templates" / "index.html",
    ]
    git["hashes"] = {}
    for path in relevant_files:
        try:
            git["hashes"][str(path.relative_to(project))] = hashlib.sha256(
                path.read_bytes()).hexdigest()
        except OSError as exc:
            git["hashes"][str(path.relative_to(project))] = "NOT RUN: " + str(exc)

result = {
    "captured_at_local": datetime.now().astimezone().isoformat(),
    "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    "pi_model": model,
    "os_release": os_release,
    "kernel": platform.release(),
    "architecture": platform.machine(),
    "python_version": platform.python_version(),
    "python_executable": sys.executable,
    "user": command(["id"]),
    "disk_space": command(["df", "-h", str(project)]),
    "network": {
        "interfaces": commands["interfaces_ipv4_ipv6"],
        "routes_ipv4": commands["routes_ipv4"],
        "routes_ipv6": commands["routes_ipv6"],
    },
    "packages": package_versions(),
    "commands": commands,
    "nginx_facts": nginx_facts,
    "file_permissions": file_permissions,
    "ufw_ipv6_setting": [
        line.strip() for line in ufw_file.splitlines()
        if line.strip().startswith("IPV6=")
    ],
    "project": str(project),
    "revision": git,
    "source_facts": code_facts(),
}
print(json.dumps(result))
"""


REMOTE_ORCHESTRATOR = r"""
import csv, importlib.util, json, os, select, shutil, signal, socket
import subprocess, sys, time, traceback
from datetime import datetime, timezone
from pathlib import Path

config = json.loads(sys.stdin.readline())
stopping = False

def on_signal(signum, frame):
    global stopping
    stopping = True

for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(sig, on_signal)

def emit(value):
    print(json.dumps(value), flush=True)

def fail(message, extra=None):
    result = {"event": "error", "reason": message}
    if extra:
        result.update(extra)
    emit(result)
    return 2

def children_collectors():
    found = []
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            args = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode(
                errors="replace")
        except OSError:
            continue
        if any(name in args for name in
               ("combined_logger.py", "dht22_reader.py", "pir_reader.py")):
            found.append({"pid": int(entry.name), "command": args[:500]})
    return found

def find_python(project):
    home = Path.home()
    candidates = [
        home / "sensor-env" / "bin" / "python3",
        home / "sensor-env" / "bin" / "python",
        project / ".venv" / "bin" / "python3",
        project / ".venv" / "bin" / "python",
        Path(sys.executable),
    ]
    code = "import flask,werkzeug,gunicorn,board,adafruit_dht,gpiozero"
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            test = subprocess.run([str(candidate), "-c", code],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=15)
            if test.returncode == 0:
                return str(candidate)
        except (OSError, subprocess.SubprocessError):
            pass
    return None

def csv_number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

def read_trial(csv_path):
    try:
        with open(csv_path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    except OSError as exc:
        return {"error": str(exc)}
    if not rows:
        return {"error": "CSV has no data rows"}
    run_id = next((row.get("run_id") for row in rows
                   if row.get("event_type") == "TRIAL_START"), None)
    run_rows = [row for row in rows if row.get("run_id") == run_id]
    start = next((row for row in run_rows
                  if row.get("event_type") == "TRIAL_START"), None)
    end = next((row for row in reversed(run_rows)
                if row.get("event_type") == "TRIAL_END"), None)
    attempts = [row for row in run_rows
                if row.get("event_type") == "DHT22_ATTEMPT"]
    valid = [row for row in attempts
             if row.get("outcome") == "success"
             and all(row.get(field) for field in
                     ("timestamp_utc", "temperature_c", "temperature_f",
                      "humidity_pct"))]
    start_elapsed = csv_number(start.get("elapsed_seconds")) if start else None
    end_elapsed = csv_number(end.get("elapsed_seconds")) if end else None
    actual_elapsed = (
        round(end_elapsed - start_elapsed, 3)
        if start_elapsed is not None and end_elapsed is not None
        else None
    )
    pir = [row for row in run_rows if row.get("event_type") == "PIR_EVENT"]
    return {
        "run_id": run_id,
        "started_at_utc": start.get("timestamp_utc") if start else None,
        "ended_at_utc": end.get("timestamp_utc") if end else None,
        "end_outcome": end.get("outcome") if end else None,
        "duration_seconds": start.get("duration_seconds") if start else None,
        "actual_elapsed_seconds": actual_elapsed,
        "attempts": len(attempts),
        "successes": len(valid),
        "failures": len(attempts) - len(valid),
        "reliability_pct": round(len(valid) / len(attempts) * 100, 2)
            if attempts else None,
        "pir_transitions": len(pir),
        "pir_motion_detected": sum(1 for row in pir
                                   if row.get("pir_event") == "MOTION_DETECTED"),
        "pir_motion_stopped": sum(1 for row in pir
                                  if row.get("pir_event") == "MOTION_STOPPED"),
    }

project = Path(config["project"]).expanduser().resolve()
if not project.is_dir():
    sys.exit(fail("Pi project directory does not exist"))
conflicts = children_collectors()
if conflicts:
    sys.exit(fail("Existing sensor collector process found; no GPIO process started",
                  {"conflicting_collectors": conflicts}))

python = find_python(project)
if not python:
    sys.exit(fail("No Python environment has Flask, Gunicorn, and sensor packages"))

username = config.get("username", "")
password = config.get("password", "")
if not username or ":" in username:
    sys.exit(fail("Dashboard username is empty or contains a colon"))
if len(password) < 12:
    sys.exit(fail("Dashboard password must contain at least 12 characters"))

hash_code = ("import json,sys; from werkzeug.security import "
             "generate_password_hash; print(generate_password_hash("
             "json.load(sys.stdin)['password']))")
hash_result = subprocess.run(
    [python, "-c", hash_code], input=json.dumps({"password": password}),
    capture_output=True, text=True, timeout=90)
password = None
config.pop("password", None)
if hash_result.returncode:
    sys.exit(fail("Could not generate the dashboard password hash"))
password_hash = hash_result.stdout.strip()
if not password_hash:
    sys.exit(fail("Password hash generator returned no hash"))

env = os.environ.copy()
env["DASHBOARD_USERNAME"] = username
env["DASHBOARD_PASSWORD_HASH"] = password_hash
env.pop("FLASK_DEBUG", None)

dashboard_dir = project / "hardened_version" / "dashboard"
logger_path = project / "hardened_version" / "combined_logger.py"
dashboard_path = dashboard_dir / "app_debug_off.py"
for path in (logger_path, dashboard_path,
             dashboard_dir / "templates" / "index.html"):
    if not path.is_file():
        sys.exit(fail("Required hardened project file is missing"))

debug_code = ("import json,sys; sys.path.insert(0,sys.argv[1]); "
              "import app_debug_off; print(json.dumps("
              "{'debug': bool(app_debug_off.app.config.get('DEBUG', False))}))")
debug_result = subprocess.run(
    [python, "-c", debug_code, str(dashboard_dir)],
    env=env, capture_output=True, text=True, timeout=30)
if debug_result.returncode:
    sys.exit(fail("Could not inspect dashboard runtime configuration"))
try:
    debug_value = json.loads(debug_result.stdout.strip())["debug"]
except (ValueError, KeyError, TypeError):
    sys.exit(fail("Could not parse dashboard debug-mode result"))
package_code = r'''
import importlib.metadata, json
names = ["Flask", "Werkzeug", "gunicorn", "gpiozero",
         "adafruit-circuitpython-dht", "Adafruit-Blinka"]
result = {}
for name in names:
    try:
        result[name] = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        result[name] = "NOT INSTALLED"
print(json.dumps(result))
'''
package_result = subprocess.run(
    [python, "-c", package_code], capture_output=True, text=True, timeout=30)
if package_result.returncode:
    sys.exit(fail("Could not inspect runtime package versions"))
try:
    runtime_packages = json.loads(package_result.stdout)
except ValueError:
    sys.exit(fail("Could not parse runtime package versions"))

now = datetime.now(timezone.utc)
date_folder = now.date().isoformat()
results_dir = project / "results" / "pi" / date_folder
results_dir.mkdir(parents=True, exist_ok=True)
csv_path = results_dir / config["csv_name"]
logger_log = results_dir / (csv_path.stem + ".logger.log")
dashboard_log = results_dir / (csv_path.stem + ".dashboard.log")
if any(path.exists() for path in (csv_path, logger_log, dashboard_log)):
    sys.exit(fail("A generated results filename already exists; refusing to overwrite"))

base_port = int(config.get("port", 5001))
bind_host = "0.0.0.0" if config.get("tls") else "127.0.0.1"
port = None
for candidate in range(base_port, min(base_port + 21, 65536)):
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_host, candidate))
        port = candidate
        break
    except OSError:
        pass
    finally:
        sock.close()
if port is None:
    sys.exit(fail("No free dashboard port was found in the requested range"))
if config.get("tls"):
    cert_path = Path(config["tls_cert"]).expanduser()
    key_path = Path(config["tls_key"]).expanduser()
    if not cert_path.is_file() or not key_path.is_file():
        sys.exit(fail("Remote TLS certificate or key file is unavailable"))

logger_args = [python, str(logger_path), "--csv", str(csv_path),
               "--interval", "2", "--duration-minutes", "15"]
logger_env = env.copy()
logger_env.pop("DASHBOARD_USERNAME", None)
logger_env.pop("DASHBOARD_PASSWORD_HASH", None)
logger_handle = open(logger_log, "a", encoding="utf-8")
dashboard_handle = None
logger = None
dashboard = None
try:
    logger = subprocess.Popen(
        logger_args, cwd=str(project / "hardened_version"), env=logger_env,
        stdin=subprocess.DEVNULL, stdout=logger_handle, stderr=subprocess.STDOUT,
        start_new_session=True)
    run_id = None
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if logger.poll() is not None:
            break
        try:
            with open(csv_path, newline="", encoding="utf-8") as handle:
                run_id = next((row.get("run_id") for row in csv.DictReader(handle)
                               if row.get("event_type") == "TRIAL_START"), None)
        except OSError:
            pass
        if run_id:
            break
        time.sleep(0.25)
    if not run_id:
        if logger.poll() is None:
            os.killpg(logger.pid, signal.SIGINT)
            logger.wait(timeout=10)
        sys.exit(fail("Logger did not write a TRIAL_START record",
                      {"logger_pid": logger.pid,
                       "csv_path": str(csv_path),
                       "logger_log": str(logger_log)}))

    dashboard_args = [
        python, str(dashboard_path), "--combined-csv", str(csv_path),
        "--host", bind_host, "--port", str(port),
    ]
    if config.get("tls"):
        cert = str(Path(config["tls_cert"]).expanduser())
        key = str(Path(config["tls_key"]).expanduser())
        dashboard_args.extend(["--tls-cert", cert, "--tls-key", key])
    dashboard_handle = open(dashboard_log, "a", encoding="utf-8")
    dashboard = subprocess.Popen(
        dashboard_args, cwd=str(dashboard_dir), env=env,
        stdin=subprocess.DEVNULL, stdout=dashboard_handle,
        stderr=subprocess.STDOUT, start_new_session=True)
    time.sleep(2)
    if dashboard.poll() is not None:
        os.killpg(logger.pid, signal.SIGINT)
        logger.wait(timeout=10)
        sys.exit(fail("Dashboard did not remain running; no other process was stopped",
                      {"csv_path": str(csv_path),
                       "logger_log": str(logger_log),
                       "dashboard_log": str(dashboard_log)}))

    logger_handle.close()
    dashboard_handle.close()
    emit({
        "event": "started",
        "run_id": run_id,
        "logger_pid": logger.pid,
        "dashboard_pid": dashboard.pid,
        "csv_path": str(csv_path),
        "logger_log": str(logger_log),
        "dashboard_log": str(dashboard_log),
        "results_dir": str(results_dir),
        "dashboard_port": port,
        "bind_address": bind_host,
        "scheme": "https" if config.get("tls") else "http",
        "debug_mode": debug_value,
        "python": python,
        "runtime_packages": runtime_packages,
        "collector_conflicts": [],
    })
    logger_done_at = None
    hard_deadline = time.monotonic() + 1080
    while not stopping and time.monotonic() < hard_deadline:
        if select.select([sys.stdin], [], [], 1.0)[0]:
            control = sys.stdin.readline().strip()
            if not control or control == "STOP":
                break
        if logger.poll() is not None and logger_done_at is None:
            logger_done_at = time.monotonic()
            emit({"event": "logger_exited", "exit_code": logger.returncode})
        if logger_done_at is not None and time.monotonic() - logger_done_at > 180:
            break
    if logger.poll() is None:
        try:
            os.killpg(logger.pid, signal.SIGINT)
            logger.wait(timeout=12)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(logger.pid, signal.SIGTERM)
                logger.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(logger.pid, signal.SIGKILL)
                except OSError:
                    pass
    if dashboard.poll() is None:
        try:
            os.killpg(dashboard.pid, signal.SIGTERM)
            dashboard.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(dashboard.pid, signal.SIGKILL)
            except OSError:
                pass
    emit({
        "event": "finished",
        "logger_exit_code": logger.poll(),
        "dashboard_exit_code": dashboard.poll(),
        "trial": read_trial(csv_path),
        "csv_path": str(csv_path),
        "logger_log": str(logger_log),
        "dashboard_log": str(dashboard_log),
        "cleaned_up": True,
    })
except SystemExit:
    raise
except Exception as exc:
    if logger and logger.poll() is None:
        try:
            os.killpg(logger.pid, signal.SIGINT)
            logger.wait(timeout=12)
        except Exception:
            pass
    if dashboard and dashboard.poll() is None:
        try:
            os.killpg(dashboard.pid, signal.SIGTERM)
            dashboard.wait(timeout=10)
        except Exception:
            pass
    sys.exit(fail("Trial supervisor error: " + type(exc).__name__))
finally:
    if logger_handle and not logger_handle.closed:
        logger_handle.close()
    if dashboard_handle and not dashboard_handle.closed:
        dashboard_handle.close()
"""


REMOTE_STATUS = r"""
import csv, json, os, shutil, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

data = json.load(sys.stdin)
path = Path(data["csv_path"])
try:
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
except OSError as exc:
    print(json.dumps({"error": str(exc)}))
    sys.exit(0)
run_id = data["run_id"]
rows = [row for row in rows if row.get("run_id") == run_id]
start = next((row for row in rows if row.get("event_type") == "TRIAL_START"), None)
attempts = [row for row in rows if row.get("event_type") == "DHT22_ATTEMPT"]
successes = [row for row in attempts if row.get("outcome") == "success"
             and all(row.get(k) for k in
                     ("timestamp_utc", "temperature_c", "temperature_f",
                      "humidity_pct"))]
end = next((row for row in reversed(rows)
            if row.get("event_type") == "TRIAL_END"), None)
def numeric(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

start_elapsed = numeric(start.get("elapsed_seconds")) if start else None
end_elapsed = numeric(end.get("elapsed_seconds")) if end else None
actual_elapsed = (
    round(end_elapsed - start_elapsed, 3)
    if start_elapsed is not None and end_elapsed is not None
    else None
)
pir = [row for row in rows if row.get("event_type") == "PIR_EVENT"]
ss = shutil.which("ss")
listeners = "NOT RUN: ss is not installed"
if ss:
    result = subprocess.run([ss, "-lntup"], capture_output=True, text=True)
    listeners = (result.stdout or "") + (result.stderr or "")
print(json.dumps({
    "run_id": run_id,
    "captured_at_pi_utc": datetime.now(timezone.utc).isoformat(),
    "duration_seconds": start.get("duration_seconds") if start else None,
    "actual_elapsed_seconds": actual_elapsed,
    "attempts": len(attempts),
    "successes": len(successes),
    "failures": len(attempts) - len(successes),
    "reliability_pct": round(len(successes) / len(attempts) * 100, 2)
        if attempts else None,
    "trial_end": end,
    "pir_transitions": len(pir),
    "pir_motion_detected": sum(1 for row in pir
                               if row.get("pir_event") == "MOTION_DETECTED"),
    "pir_motion_stopped": sum(1 for row in pir
                              if row.get("pir_event") == "MOTION_STOPPED"),
    "listeners": listeners[-20000:],
}))
"""


REMOTE_TEST_LOGS = r"""
import json, shutil, subprocess, sys

data = json.load(sys.stdin)
user = data.get("ssh_user", "")
source = data.get("source_ip", "")
def collect(argv, selectors):
    executable = shutil.which(argv[0])
    if not executable:
        return {"status": "NOT RUN", "reason": argv[0] + " is unavailable"}
    result = subprocess.run([executable] + argv[1:], capture_output=True,
                           text=True, timeout=30)
    if result.returncode and shutil.which("sudo"):
        result = subprocess.run(
            [shutil.which("sudo"), "-n", executable] + argv[1:],
            capture_output=True, text=True, timeout=30)
    if result.returncode:
        return {"status": "NOT RUN", "exit_code": result.returncode,
                "reason": ((result.stderr or result.stdout or
                            "journal command failed")[-2000:])}
    lines = (result.stdout or "").splitlines()
    lines = [line for line in lines if any(
        selector and selector.lower() in line.lower() for selector in selectors
    )] if selectors else []
    return {"status": "COMPLETED" if result.returncode == 0 else "ERROR",
            "exit_code": result.returncode,
            "output": "\n".join(lines[-200:]) if lines else
                "No matching timestamped entries in the requested interval."}

ssh = collect(["journalctl", "--no-pager", "-o", "short-iso",
               "-u", "ssh", "-u", "sshd", "--since", "25 minutes ago"],
              [user, source])
fail2ban = collect(["journalctl", "--no-pager", "-o", "short-iso",
                    "-u", "fail2ban", "--since", "25 minutes ago"],
                   [source] if source else ["__no_source_address__"])
print(json.dumps({"captured_at_local": __import__("datetime").datetime.now().astimezone().isoformat(),
                  "ssh_logs_filtered": ssh,
                  "fail2ban_logs_filtered": fail2ban}))
"""


REMOTE_FETCH = r"""
import base64, json, os, sys
from pathlib import Path

data = json.load(sys.stdin)
root = Path(data["root"]).resolve()
files = []
for value in data["paths"]:
    path = Path(value).resolve()
    try:
        if os.path.commonpath([str(root), str(path)]) != str(root):
            raise ValueError("outside evidence directory")
        content = path.read_bytes()
        files.append({"path": str(path), "data": base64.b64encode(content).decode("ascii")})
    except Exception as exc:
        files.append({"path": str(path), "error": str(exc)})
print(json.dumps({"files": files}))
"""


def now_local():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def read_line(prompt, default=None):
    suffix = " [{}]".format(default) if default else ""
    value = input(prompt + suffix + ": ").strip()
    return value or (default if default is not None else "")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def write_text(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def add_check(checks, name, machine, expected, observed, status,
              tool="Python standard library", version=platform.python_version(),
              exit_code=None, interface=None, reason="", started=None,
              ended=None):
    checks.append({
        "name": name,
        "machine": machine,
        "interface": interface,
        "started_at_local": started or now_local(),
        "ended_at_local": ended or now_local(),
        "tool": tool,
        "tool_version": version,
        "exit_status": exit_code,
        "expected": expected,
        "observed": observed,
        "status": status,
        "explanation": reason,
    })


def normalize_source_cidr(value):
    try:
        return ipaddress.ip_network(value.strip(), strict=False).with_prefixlen
    except ValueError as exc:
        raise ValueError("Expected source must be a valid IP address or CIDR.") from exc


def validate_ufw_policy(status_output, rules_output, expected_source):
    expected_source = normalize_source_cidr(expected_source)
    expected = {("22/tcp", expected_source), ("443/tcp", expected_source)}
    observed = set()
    unparsed_permitting_rules = []
    observed_permitting_rules = []
    for line in rules_output.splitlines():
        match = re.match(
            r"^\s*\[\s*\d+\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+"
            r"(IN|OUT|FWD)\s+(.+?)\s*$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        target, action, direction, source = match.groups()
        action = action.upper()
        if action not in ("ALLOW", "LIMIT") or direction.upper() != "IN":
            continue
        target = re.sub(r"\s+\(v6\)$", "", target.strip(), flags=re.IGNORECASE)
        source = re.sub(r"\s+\(v6\)$", "", source.strip(), flags=re.IGNORECASE)
        if source.lower() == "anywhere":
            normalized_source = "any"
        else:
            try:
                normalized_source = ipaddress.ip_network(
                    source, strict=False
                ).with_prefixlen
            except ValueError:
                normalized_source = "unparsed:" + source
        rule = (target.lower(), normalized_source)
        observed.add(rule)
        observed_permitting_rules.append({
            "action": action,
            "direction": "IN",
            "port_or_service": target,
            "source": normalized_source,
        })
        if normalized_source.startswith("unparsed:"):
            unparsed_permitting_rules.append(line.strip())

    active = bool(re.search(
        r"^Status:\s*active\b", status_output, re.IGNORECASE | re.MULTILINE))
    incoming_default_deny = bool(re.search(
        r"Default:\s*deny\s+\(incoming\)", status_output, re.IGNORECASE))
    compliant = active and incoming_default_deny and observed == expected
    return {
        "compliant": compliant,
        "active": active,
        "incoming_default_deny": incoming_default_deny,
        "expected_allow_rules": sorted(
            "{} from {}".format(port, source) for port, source in expected
        ),
        "observed_inbound_permitting_rules": sorted(
            observed_permitting_rules,
            key=lambda rule: (
                rule["port_or_service"],
                rule["source"],
                rule["action"],
            ),
        ),
        "unparsed_permitting_rules": unparsed_permitting_rules,
        "reason": "" if compliant else
            "Expected exactly TCP/22 and TCP/443 from the entered CIDR, with an active firewall and default-deny incoming policy.",
    }


def add_deployed_service_checks(checks, inventory):
    commands = inventory.get("commands", {})
    nginx_service = commands.get("nginx_service", {})
    nginx_test = commands.get("nginx_config_test", {})
    dashboard_service = commands.get("dashboard_service", {})
    nginx_facts = inventory.get("nginx_facts", {})
    listeners = "\n".join(
        (commands.get(key) or {}).get("output", "")
        for key in ("listeners_unprivileged", "listeners_elevated")
    )
    nginx_active = (
        nginx_service.get("status") == "COMPLETED"
        and nginx_service.get("output", "").strip() == "active"
    )
    nginx_test_passed = (
        nginx_test.get("status") == "COMPLETED"
        and nginx_test.get("exit_code") == 0
    )
    dashboard_active = (
        dashboard_service.get("status") == "COMPLETED"
        and dashboard_service.get("output", "").strip() == "active"
    )
    https_listener = False
    listeners_collected = False
    for key in ("listeners_unprivileged", "listeners_elevated"):
        if (commands.get(key) or {}).get("status") == "COMPLETED":
            listeners_collected = True
    for line in listeners.splitlines():
        fields = line.split()
        if len(fields) < 5 or not fields[4].endswith(":443"):
            continue
        listener_host = fields[4].rsplit(":", 1)[0].strip("[]")
        if listener_host not in ("127.0.0.1", "::1"):
            https_listener = True
            break
    loopback_gunicorn = bool(re.search(r"127\.0\.0\.1:5001\b", listeners))
    wildcard_gunicorn = bool(re.search(
        r"(?:\*|0\.0\.0\.0|\[::\]|::):5001\b", listeners))

    add_check(
        checks, "Deployed Nginx service", "Raspberry Pi",
        "systemd reports Nginx active and nginx -t succeeds",
        json.dumps({"service": nginx_service, "config_test": nginx_test}),
        "PASS" if nginx_active and nginx_test_passed else
        "FAIL" if nginx_service.get("status") == "ERROR"
        or nginx_test.get("status") == "ERROR" else "NOT RUN",
        tool="systemctl + nginx -t", version="Pi-installed version",
        reason="" if nginx_active and nginx_test.get("exit_code") == 0 else
        "This read-only check does not install or start Nginx.",
    )
    expected_proxy = (
        nginx_facts.get("https_443_listener")
        and nginx_facts.get("proxy_to_loopback_gunicorn")
        and nginx_facts.get("forwarded_client_ip_overwritten")
    )
    add_check(
        checks, "Deployed Nginx reverse-proxy configuration", "Raspberry Pi",
        "HTTPS on 443, proxy to 127.0.0.1:5001, overwrite forwarded client IP",
        json.dumps(nginx_facts),
        "PASS" if expected_proxy else
        "FAIL" if nginx_facts.get("enabled_site_files") else "NOT RUN",
        tool="Read-only enabled-site inspection", version="Nginx configuration",
        reason="" if expected_proxy else
        "Only the expected directives are inspected; this is not a full Nginx configuration audit.",
    )
    add_check(
        checks, "Deployed Gunicorn service", "Raspberry Pi",
        "sensor-dashboard@<SSH-user>.service is active",
        dashboard_service.get("output", dashboard_service.get("reason", "unavailable")),
        "PASS" if dashboard_active else
        "FAIL" if dashboard_service.get("status") in ("COMPLETED", "ERROR")
        else "NOT RUN",
        tool="systemctl is-active", version="Pi systemd",
        exit_code=dashboard_service.get("exit_code"),
        reason="" if dashboard_active else
        "The collector checks the documented service template name and does not start it.",
    )
    listeners_status = (
        "PASS" if https_listener and loopback_gunicorn and not wildcard_gunicorn
        else "FAIL" if listeners_collected else "NOT RUN"
    )
    add_check(
        checks, "Deployed listener exposure", "Raspberry Pi",
        "HTTPS listens on port 443; Gunicorn listens only on 127.0.0.1:5001",
        json.dumps({
            "https_443_listener": https_listener,
            "gunicorn_loopback_listener": loopback_gunicorn,
            "gunicorn_wildcard_listener": wildcard_gunicorn,
        }),
        listeners_status, tool="ss -lntup", version="Pi iproute2",
        reason="" if listeners_status == "PASS" else
        "Listener output is observational; confirm the hardened Nmap scan separately.",
    )


def verify_deployed_https(host, checks):
    host_for_url = "[{}]".format(host) if ":" in host and not host.startswith("[") else host
    url = "https://{}/".format(host_for_url)
    started = now_local()
    try:
        request = urllib.request.Request(url, method="GET")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        with opener.open(request, timeout=8) as response:
            status_code = response.status
            headers = response.headers
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        headers = exc.headers
        exc.close()
    except urllib.error.URLError as exc:
        reason = exc.reason
        is_certificate_error = isinstance(reason, ssl.SSLCertVerificationError)
        add_check(
            checks, "Deployed HTTPS endpoint", "WSL -> Pi:443",
            "Trusted TLS certificate and unauthenticated HTTP 401",
            type(reason).__name__ + ": " + str(reason),
            "FAIL" if is_certificate_error else "NOT RUN",
            tool="Python HTTPS client", version=platform.python_version(),
            reason="Certificate verification is required; no verification bypass is used.",
            started=started,
        )
        return
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        add_check(
            checks, "Deployed HTTPS endpoint", "WSL -> Pi:443",
            "Trusted TLS certificate and unauthenticated HTTP 401",
            type(exc).__name__ + ": " + str(exc), "NOT RUN",
            tool="Python HTTPS client", version=platform.python_version(),
            reason="No credentials were sent; the probe does not alter server state.",
            started=started,
        )
        return

    framing_ok = (
        headers.get("X-Frame-Options", "").lower() == "deny"
        and "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")
    )
    passed = status_code == 401 and framing_ok
    add_check(
        checks, "Deployed HTTPS endpoint", "WSL -> Pi:443",
        "Trusted TLS, unauthenticated HTTP 401 and anti-framing headers",
        json.dumps({
            "url": url,
            "http_status": status_code,
            "x_frame_options_deny": headers.get("X-Frame-Options") == "DENY",
            "csp_frame_ancestors_none": framing_ok,
        }),
        "PASS" if passed else "FAIL",
        tool="Python HTTPS client", version=platform.python_version(),
        exit_code=0 if passed else status_code,
        reason="" if passed else
        "The probe sends no credentials; a non-401 response or missing anti-framing headers fails this check.",
        started=started,
    )


def command_output(argv, timeout=15):
    started = now_local()
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=timeout, check=False)
        output = (result.stdout or "") + (result.stderr or "")
        return {
            "argv": argv,
            "started_at_local": started,
            "ended_at_local": now_local(),
            "exit_code": result.returncode,
            "output": output[-20000:],
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "argv": argv,
            "started_at_local": started,
            "ended_at_local": now_local(),
            "exit_code": None,
            "output": "NOT RUN: " + str(exc),
        }


def local_inventory():
    info = {
        "captured_at_local": now_local(),
        "captured_at_utc": now_utc(),
        "platform": platform.platform(),
        "python": sys.version,
        "user": os.environ.get("USER") or os.environ.get("USERNAME", "unknown"),
        "commands": {},
        "tools": {},
    }
    for name, args in [
        ("uname", ["uname", "-a"]),
        ("ip_address", ["ip", "-details", "address"]),
        ("routes_ipv4", ["ip", "route", "show", "table", "all"]),
        ("routes_ipv6", ["ip", "-6", "route", "show", "table", "all"]),
        ("disk_space", ["df", "-h", "."]),
        ("identity", ["id"]),
    ]:
        if shutil.which(args[0]):
            info["commands"][name] = command_output(args)
        else:
            info["commands"][name] = {
                "exit_code": None,
                "output": "NOT RUN: {} is unavailable".format(args[0]),
            }
    for name, args in WORKING_TOOLS.items():
        executable = shutil.which(name)
        if not executable:
            info["tools"][name] = {
                "available": False,
                "version": "NOT INSTALLED",
                "exit_code": None,
            }
            continue
        result = command_output([executable] + args, timeout=20)
        info["tools"][name] = {
            "available": True,
            "version": result["output"][:4000],
            "exit_code": result["exit_code"],
            "started_at_local": result["started_at_local"],
            "ended_at_local": result["ended_at_local"],
        }
    return info


def record_command_checks(checks, inventory):
    for name, result in inventory["commands"].items():
        output = result.get("output", "")
        code = result.get("exit_code")
        status = "INFORMATIONAL" if code == 0 else "NOT RUN"
        add_check(checks, "WSL " + name, "WSL",
                  "Collect local source/system context", output[:1000],
                  status, tool=result.get("argv", ["Python"])[0],
                  exit_code=code,
                  reason="" if code == 0 else output[:500],
                  started=result.get("started_at_local"),
                  ended=result.get("ended_at_local"))


def tool_version(inventory, name):
    entry = inventory.get("tools", {}).get(name, {})
    return entry.get("version", "NOT CHECKED").strip()


class SSHConnection:
    def __init__(self, executable, host, username, port, control_path):
        self.executable = executable
        self.host = host
        self.username = username
        self.port = port
        self.control_path = str(control_path)
        self.active = False
        self.last_trial_event = None
        self.last_trial_process = None

    def start(self):
        args = [
            self.executable, "-M", "-S", self.control_path,
            "-o", "ControlPersist=20m", "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3", "-fN",
            "-p", str(self.port), "-l", self.username, self.host,
        ]
        result = subprocess.run(args, check=False)
        self.active = result.returncode == 0
        return result.returncode

    def close(self):
        if not self.active:
            return
        subprocess.run(
            [self.executable, "-S", self.control_path, "-O", "exit",
             "-p", str(self.port), "-l", self.username, self.host],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, check=False)
        self.active = False

    def run_code(self, code, payload=None, timeout=60):
        if not self.active:
            raise RuntimeError("SSH control connection is not active")
        remote = "python3 -c " + shlex.quote(code)
        args = [
            self.executable, "-S", self.control_path,
            "-o", "BatchMode=yes", "-T", "-p", str(self.port),
            "-l", self.username, self.host, remote,
        ]
        result = subprocess.run(
            args,
            input=(json.dumps(payload) + "\n") if payload is not None else "",
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode:
            raise RuntimeError(
                "Remote command failed (exit {}): {}".format(
                    result.returncode, (result.stderr or result.stdout)[-2000:])
            )
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise RuntimeError("Remote command returned invalid JSON") from exc

    def start_trial(self, payload):
        remote = "python3 -c " + shlex.quote(REMOTE_ORCHESTRATOR)
        args = [
            self.executable, "-S", self.control_path,
            "-o", "BatchMode=yes", "-T", "-p", str(self.port),
            "-l", self.username, self.host, remote,
        ]
        process = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        self.last_trial_process = process
        process.stdin.write(json.dumps(payload) + "\n")
        process.stdin.flush()
        ready, _, _ = select.select([process.stdout], [], [], 45)
        if not ready:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            raise RuntimeError("Timed out waiting for the Pi trial startup response")
        line = process.stdout.readline()
        try:
            event = json.loads(line)
        except ValueError as exc:
            try:
                process.stdin.write("STOP\n")
                process.stdin.close()
                process.wait(timeout=10)
            except (OSError, subprocess.SubprocessError):
                process.terminate()
            raise RuntimeError("Pi trial startup returned no valid status") from exc
        if event.get("event") != "started":
            self.last_trial_event = event
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
            raise RuntimeError(event.get("reason", "Pi trial did not start"))
        self.last_trial_event = event
        return process, event

    def stop_trial(self, process):
        if process.poll() is None:
            try:
                process.stdin.write("STOP\n")
                process.stdin.flush()
                process.stdin.close()
                process.wait(timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        tail = ""
        if process.stdout:
            try:
                tail = process.stdout.read()
            except OSError:
                pass
        events = []
        for line in tail.splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                events.append({"event": "output", "text": line[:1000]})
        return events


def discover_project(ssh):
    return ssh.run_code(REMOTE_DISCOVER, {}, timeout=30)


def select_free_local_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_tunnel(ssh, local_port, remote_port):
    args = [
        ssh.executable, "-S", ssh.control_path, "-o", "BatchMode=yes",
        "-o", "ExitOnForwardFailure=yes", "-T", "-N",
        "-p", str(ssh.port), "-L",
        "127.0.0.1:{}:127.0.0.1:{}".format(local_port, remote_port),
        "-l", ssh.username, ssh.host,
    ]
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            error = process.stderr.read() if process.stderr else ""
            raise RuntimeError("SSH tunnel failed: " + error[-1000:])
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=0.25):
                return process
        except OSError:
            time.sleep(0.1)
    process.terminate()
    raise RuntimeError("SSH tunnel did not become ready")


def stop_tunnel(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def http_request(url, username=None, password=None, timeout=15):
    headers = {"Accept": "application/json"}
    if username is not None and password is not None:
        token = base64.b64encode(
            (username + ":" + password).encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = "Basic " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    started = now_local()
    response_headers = {}
    try:
        if url.lower().startswith("https://"):
            opened = urllib.request.urlopen(
                request, timeout=timeout, context=ssl.create_default_context()
            )
        else:
            opened = urllib.request.urlopen(request, timeout=timeout)
        with opened as response:
            status = response.status
            body = response.read(2_000_000)
            response_headers = {
                key: response.headers.get(key) for key in
                ("Content-Type", "X-Frame-Options",
                 "Content-Security-Policy", "Retry-After")
                if response.headers.get(key) is not None
            }
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read(100_000)
        response_headers = {
            key: exc.headers.get(key) for key in
            ("Content-Type", "X-Frame-Options",
             "Content-Security-Policy", "Retry-After")
            if exc.headers.get(key) is not None
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "started_at_local": started,
            "ended_at_local": now_local(),
            "url": url,
            "status_code": None,
            "headers": response_headers,
            "body": None,
            "error": type(exc).__name__ + ": " + str(exc),
        }
    text = body.decode("utf-8", errors="replace")
    try:
        content = json.loads(text)
    except ValueError:
        content = text[:4000]
    return {
        "started_at_local": started,
        "ended_at_local": now_local(),
        "url": url,
        "status_code": status,
        "headers": response_headers,
        "body": content,
        "error": None,
    }


def curl_authenticated_status(url, username, password, timeout=20):
    executable = shutil.which("curl")
    if not executable:
        return {
            "status_code": None,
            "exit_code": None,
            "error": "curl is not installed",
        }
    token = base64.b64encode(
        (username + ":" + password).encode("utf-8")
    ).decode("ascii")
    config = 'header = "Authorization: Basic {}"\n'.format(token)
    args = [
        executable, "-q", "--config", "-", "--silent", "--show-error",
        "--max-time", str(timeout), "--output", os.devnull,
        "--write-out", "%{http_code}", url,
    ]
    try:
        result = subprocess.run(
            args, input=config, capture_output=True, text=True,
            timeout=timeout + 5, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status_code": None,
            "exit_code": None,
            "error": type(exc).__name__ + ": " + str(exc),
        }
    status_text = result.stdout.strip()
    status_code = int(status_text) if status_text.isdigit() else None
    return {
        "status_code": status_code,
        "exit_code": result.returncode,
        "error": (
            None if result.returncode == 0 else
            (result.stderr or "curl request failed")[-1000:]
        ),
    }


def api_result_path(base_url):
    return base_url.rstrip("/") + "/api/data"


def save_response(work, filename, response):
    path = work / "api" / filename
    write_json(path, response)
    return path


def request_and_record(checks, work, name, url, user=None, password=None,
                       expected=None, interface=None):
    started = now_local()
    response = http_request(url, user, password)
    end = now_local()
    if response["status_code"] is None:
        status = "NOT RUN"
        reason = response["error"] or "No response"
    elif expected is not None and response["status_code"] != expected:
        status = "FAIL"
        reason = "Expected HTTP {}; received {}".format(
            expected, response["status_code"])
    else:
        status = "PASS" if expected is not None else "INFORMATIONAL"
        reason = ""
    add_check(checks, name, "WSL client -> Pi dashboard",
              "HTTP {}".format(expected) if expected is not None else "Observe response",
              "HTTP {}".format(response["status_code"])
              if response["status_code"] is not None else response["error"],
              status, tool="urllib", version=platform.python_version(),
              exit_code=response["status_code"], interface=interface,
              reason=reason, started=started, ended=end)
    return response


def parse_route(route_text):
    interface = None
    source = None
    for token_index, token in enumerate(route_text.split()):
        if token == "dev" and token_index + 1 < len(route_text.split()):
            interface = route_text.split()[token_index + 1]
        if token == "src" and token_index + 1 < len(route_text.split()):
            source = route_text.split()[token_index + 1]
    return interface, source


def resolve_host(host):
    try:
        return sorted(set(
            item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ))
    except OSError:
        return []


def route_to(host):
    route_tool = shutil.which("ip")
    if not route_tool:
        return {"output": "NOT RUN: ip command is unavailable", "exit_code": None}
    ips = resolve_host(host)
    if not ips:
        return {"output": "NOT RUN: target host did not resolve", "exit_code": None}
    route_args = [route_tool, "route", "get", ips[0]]
    if ":" in ips[0]:
        route_args.insert(1, "-6")
    result = command_output(route_args)
    result["target_ip"] = ips[0]
    result["interface"], result["source"] = parse_route(result["output"])
    return result


def capture_https(work, checks, url, username, password, route, target_port,
                  tool_versions):
    machine = "WSL"
    if not url.startswith("https://"):
        add_check(checks, "Wireshark-compatible HTTPS capture", machine,
                  "Capture a successful verified HTTPS request",
                  "No HTTPS dashboard was configured", "NOT RUN",
                  tool="tshark/tcpdump",
                  reason="Remote TLS is not configured; loopback HTTP is tunneled over SSH.")
        return None
    interface = route.get("interface")
    target_ip = route.get("target_ip")
    if not interface or not target_ip:
        add_check(checks, "Wireshark-compatible HTTPS capture", machine,
                  "Capture the Pi HTTPS interface",
                  route.get("output", "No route information"), "NOT RUN",
                  tool="ip route", reason="Could not determine the target interface.")
        return None
    tshark = shutil.which("tshark")
    tcpdump = shutil.which("tcpdump")
    if not tshark and not tcpdump:
        add_check(checks, "Wireshark-compatible HTTPS capture", machine,
                  "Capture a successful verified HTTPS request",
                  "Neither tshark nor tcpdump is installed", "NOT RUN",
                  tool="tshark/tcpdump",
                  reason="Install and configure an approved capture tool before collecting.")
        return None

    tool = "tshark" if tshark else "tcpdump"
    executable = tshark or tcpdump
    capture_suffix = ".pcapng" if tshark else ".pcap"
    capture = work / "packet_capture" / (
        "wsl_https_{}_{}{}".format(
            datetime.now().strftime("%Y%m%dT%H%M%S"),
            secrets.token_hex(3), capture_suffix)
    )
    filter_text = "host {} and tcp port {}".format(target_ip, target_port)
    if tshark:
        base = [executable, "-i", interface, "-f", filter_text,
                "-a", "duration:15", "-w", str(capture)]
    else:
        base = [executable, "-i", interface, "-nn", "-s", "0",
                "-w", str(capture), filter_text]
    if getattr(os, "geteuid", lambda: 1)() != 0 and shutil.which("sudo"):
        command = [shutil.which("sudo"), "-n"] + base
    else:
        command = base
    capture.parent.mkdir(parents=True, exist_ok=True)
    started = now_local()
    proc = None
    response = None
    error = None
    try:
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True)
        time.sleep(1)
        if proc.poll() is not None:
            error = (proc.stderr.read() if proc.stderr else "").strip()
        else:
            response = http_request(url.rstrip("/") + "/api/data",
                                    username, password, timeout=20)
            try:
                proc.wait(timeout=17)
            except subprocess.TimeoutExpired:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        error = type(exc).__name__ + ": " + str(exc)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    successful = bool(response and response.get("status_code") == 200
                      and response.get("error") is None)
    capture_exists = capture.is_file() and capture.stat().st_size > 0
    packet_count = None
    audit_exit_code = None
    if capture_exists:
        analyzer = shutil.which(tool)
        if analyzer and tool == "tshark":
            audit = command_output([
                analyzer, "-r", str(capture), "-Y",
                "tcp.port == {}".format(target_port),
                "-T", "fields", "-e", "frame.number",
            ], timeout=30)
            audit_exit_code = audit.get("exit_code")
            packet_count = sum(
                1 for line in audit.get("output", "").splitlines()
                if line.strip().isdigit()
            )
        elif analyzer:
            audit = command_output([
                analyzer, "-nn", "-r", str(capture), filter_text,
            ], timeout=30)
            audit_exit_code = audit.get("exit_code")
            packet_count = sum(
                1 for line in audit.get("output", "").splitlines()
                if re.search(r"\bIP6?\s", line)
            )
    if successful and capture_exists and audit_exit_code == 0:
        status = "PASS" if packet_count else "FAIL"
    else:
        status = "NOT RUN"
    reason = ""
    if not successful:
        reason = error or (
            "Capture was not paired with a successful HTTPS response"
            if response else "Capture could not start"
        )
    elif not capture_exists:
        reason = error or "No capture file was produced; check capture permissions."
    elif audit_exit_code != 0:
        reason = "The saved capture could not be read and filtered for target-port packets."
    elif not packet_count:
        reason = "The capture file had no packets matching the target port."
    add_check(checks, "Wireshark-compatible HTTPS capture", machine,
              "Successful verified HTTPS API request and relevant TCP packets captured on {}".format(interface),
              "HTTP {}; file {}; relevant packets {}".format(
                  response.get("status_code") if response else "no response",
                  "created" if capture_exists else "not created",
                  packet_count if packet_count is not None else "not verified"),
              status, tool=tool, version=tool_versions.get(tool, "unknown"),
              exit_code=proc.returncode if proc else None, interface=interface,
              reason=reason, started=started, ended=now_local())
    if capture_exists:
        write_json(capture.with_suffix(".metadata.json"), {
            "capture_machine": "WSL",
            "interface": interface,
            "target_ip": target_ip,
            "target_port": target_port,
            "capture_filter": filter_text,
            "successful_request_status": (
                response.get("status_code") if response else None),
            "certificate_verification": "Python default trust store; not disabled",
            "paired_with_successful_request": successful,
            "capture_read_exit_code": audit_exit_code,
            "target_port_packet_count": packet_count,
        })
    if response:
        save_response(work, "verified_https_capture_request.json", response)
    return capture if capture_exists else None


def pi_outputs_text(inventory):
    lines = []
    for key, value in inventory.items():
        if key in ("commands", "network"):
            continue
        lines.extend(["=== {} ===".format(key), json.dumps(value, indent=2)])
    for group in ("network", "commands"):
        lines.extend(["=== {} ===".format(group)])
        value = inventory.get(group, {})
        if group == "network":
            for name, result in value.items():
                lines.extend(["--- {} ---".format(name),
                              result.get("output", json.dumps(result))])
        else:
            for name, result in value.items():
                lines.extend(["--- {} [{}] ---".format(
                    name, result.get("status", "unknown")),
                    result.get("output", result.get("reason", ""))])
                if result.get("auth_settings"):
                    lines.append("Effective SSH auth settings: " +
                                 "; ".join(result["auth_settings"]))
    return "\n".join(lines) + "\n"


def local_route_report(host, work, checks):
    route = route_to(host)
    path = work / "wsl" / "route_to_pi.txt"
    write_text(path, json.dumps(route, indent=2) + "\n")
    status = "INFORMATIONAL" if route.get("exit_code") == 0 else "NOT RUN"
    add_check(checks, "WSL route to Pi", "WSL", "Record source/interface/target",
              route.get("output", ""), status, tool="ip route",
              version="system iproute2", exit_code=route.get("exit_code"),
              interface=route.get("interface"),
              reason="" if status == "INFORMATIONAL" else route.get("output", ""))
    return route


def collect_manual_files(work, checks):
    copies = []
    print("\nOptional: provide paths to existing authorized scan/evidence outputs.")
    print("These files are included as supplied; the script will not validate or rerun them.")
    while True:
        value = input("Existing evidence file path (blank when done): ").strip()
        if not value:
            break
        source = Path(value).expanduser()
        if not source.is_file():
            print("Not a readable regular file; skipped.")
            add_check(checks, "Manual evidence inclusion", "WSL",
                      "Copy a user-supplied evidence file", str(source),
                      "NOT RUN", reason="Path is not a regular file.")
            continue
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", source.name)[:100]
        destination = work / "manual_evidence" / (
            "{:02d}_{}".format(len(copies) + 1, safe_name or "evidence.txt")
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copies.append(str(destination.relative_to(work)))
        add_check(checks, "Manual evidence inclusion", "WSL",
                  "Preserve supplied evidence unchanged",
                  str(source), "INFORMATIONAL",
                  reason="Copied without asserting that the scan ran successfully.")
    return copies


def ask_pir_events(work, checks, trial_started):
    path = work / "pi" / "pir_user_observations.txt"
    if not trial_started:
        write_text(path, "NOT RUN: no instrumented trial was started.\n")
        return
    print("\nIf you performed PIR motion/no-motion observations during the trial,")
    print("enter each self-recorded timestamp and event (one line per event).")
    print("Example: 2026-11-15T18:25:00-08:00 MOTION_DETECTED")
    print("Leave blank when finished; no accuracy/false-positive rate is inferred.")
    rows = []
    while True:
        value = input("PIR observation: ").strip()
        if not value:
            break
        rows.append(value)
    if rows:
        write_text(path, "User-reported, not independently verified:\n"
                   + "\n".join(rows) + "\n")
        status = "INFORMATIONAL"
        observed = "{} self-reported entries".format(len(rows))
    else:
        write_text(path, "No manual PIR event times were provided.\n")
        status = "NOT RUN"
        observed = "No manual PIR event times provided"
    add_check(checks, "Manual PIR observations", "Pi hardware / user",
              "Prompt for motion and no-motion observations",
              observed, status, reason="PIR accuracy and false-positive rates require ground truth.")


def collect_screenshot(work, checks, live_url=None, run_id=None):
    if live_url:
        print("\nTemporary dashboard URL: {}".format(live_url))
        print("Open it now in an authorized browser; sign in with the temporary credentials.")
        print("Capture the page during this trial with its run ID and current metrics visible.")
        print("Enter a WSL-visible path for the image (for example /mnt/c/Users/...).")
        prompt = "Path to that screenshot captured during the live trial (blank to skip): "
    else:
        prompt = "Optional existing browser screenshot path to include (blank to skip): "
    value = input(prompt).strip()
    if not value:
        add_check(checks, "Browser screenshot", "WSL/user",
                  "Include an authentic browser screenshot or mark it manual",
                  "No screenshot path provided", "NOT RUN",
                  reason="No screenshot was fabricated; collect manually if required.")
        return
    source = Path(value).expanduser()
    if not source.is_file():
        add_check(checks, "Browser screenshot", "WSL/user",
                  "Copy a user-provided screenshot",
                  "Path does not exist: " + str(source), "NOT RUN",
                  reason="Provide an existing screenshot file.")
        return
    suffix = source.suffix.lower() if source.suffix else ".png"
    destination = work / "manual" / ("browser_screenshot" + suffix)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    attested = False
    if live_url:
        try:
            attested = read_line(
                "Does it show run ID {} and current metrics? [y/N]".format(run_id),
                "N",
            ).lower() in ("y", "yes")
        except EOFError:
            pass
    add_check(checks, "Browser screenshot", "WSL/user",
              "Preserve user-provided screenshot",
              json.dumps({
                  "path": str(destination.relative_to(work)),
                  "captured_during_trial": bool(live_url),
                  "live_dashboard_url": live_url,
                  "expected_run_id": run_id,
                  "user_attested_run_id_and_metrics_visible": attested,
              }), "INFORMATIONAL",
              reason="Copied as supplied; screenshot pixels and user attestation were not independently verified.")


def transfer_pi_files(ssh, started_event, work, checks, trial_info):
    if not ssh or not ssh.active or not started_event:
        return
    if not started_event.get("csv_path"):
        if any(started_event.get(key) for key in ("logger_log", "dashboard_log")):
            add_check(checks, "Pi evidence transfer", "Raspberry Pi -> WSL",
                      "Copy trial CSV and logger/dashboard output",
                      "No evidence root path was provided", "NOT RUN",
                      tool="SSH + base64",
                      reason="The remote startup failure did not provide a CSV path for safe file scoping.")
        return
    paths = [
        started_event.get("csv_path"),
        started_event.get("logger_log"),
        started_event.get("dashboard_log"),
    ]
    paths = [path for path in paths if path]
    if not paths:
        return
    try:
        response = ssh.run_code(
            REMOTE_FETCH,
            {"root": str(Path(started_event["csv_path"]).parent), "paths": paths},
            timeout=90,
        )
    except Exception as exc:
        add_check(checks, "Pi evidence transfer", "Raspberry Pi -> WSL",
                  "Copy trial CSV and logger/dashboard output",
                  type(exc).__name__, "NOT RUN", tool="SSH + base64",
                  reason=str(exc))
        return
    for entry in response.get("files", []):
        source_path = entry.get("path", "unknown")
        if "data" not in entry:
            add_check(checks, "Pi evidence transfer", "Raspberry Pi -> WSL",
                      "Copy trial CSV and logger/dashboard output",
                      source_path, "NOT RUN", tool="SSH + base64",
                      reason=entry.get("error", "File could not be read on Pi."))
            continue
        data = base64.b64decode(entry["data"])
        name = Path(source_path).name
        destination = work / "pi" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        add_check(checks, "Pi evidence transfer", "Raspberry Pi -> WSL",
                  "Copy trial CSV and logger/dashboard output",
                  str(destination.relative_to(work)), "PASS",
                  tool="SSH + base64", exit_code=0)
        if trial_info is not None and name == Path(started_event["csv_path"]).name:
            trial_info["csv_archive_path"] = str(
                destination.relative_to(work)).replace(os.sep, "/")


def choose_output_path():
    default_dir = Path.home()
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    default = default_dir / ("hardened_pi_evidence_" + stamp + ".zip")
    while True:
        raw = read_line("Output ZIP path (choose the name and location)", str(default))
        path = Path(raw).expanduser().resolve()
        if path.suffix.lower() != ".zip":
            path = path.with_suffix(".zip")
        if path.exists():
            print("That results file already exists. Choose another; it will not be overwritten.")
            default = path.with_name(path.stem + "_new.zip")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


def collect_pir_username_password():
    username = read_line("Temporary dashboard username for this trial")
    if not username or ":" in username:
        raise ValueError("Dashboard username must be nonempty and contain no colon.")
    while True:
        password = getpass.getpass(
            "Temporary dashboard password (12+ characters; not saved): "
        )
        if len(password) >= 12:
            return username, password
        print("Password must contain at least 12 characters.")


def inspect_api_body(response):
    body = response.get("body")
    if not isinstance(body, dict):
        return {}
    return {
        "run_id": (body.get("trial") or {}).get("run_id"),
        "trial_status": (body.get("trial") or {}).get("status"),
        "attempts": (body.get("trial") or {}).get("attempts"),
        "successes": (body.get("trial") or {}).get("successes"),
        "failures": (body.get("trial") or {}).get("failures"),
        "reliability_pct": (body.get("trial") or {}).get("reliability_pct"),
        "dht_attempt_freshness":
            (body.get("freshness", {}).get("dht_attempt") or {}).get("status"),
        "pir_count": (body.get("pir") or {}).get("count"),
    }


def auth_matrix(base_url, username, password, checks, work, interface,
                curl_version="NOT CHECKED"):
    auth = {}
    for path in ("/", "/api/data"):
        key = "page" if path == "/" else "api"
        url = base_url.rstrip("/") + path
        no_cred = request_and_record(
            checks, work, "Authentication without credentials " + key,
            url, expected=401, interface=interface)
        auth[key + "_no_credentials"] = no_cred
        bad_password = secrets.token_urlsafe(24)
        invalid = request_and_record(
            checks, work, "Authentication with incorrect credentials " + key,
            url, username, bad_password, expected=401, interface=interface)
        auth[key + "_incorrect_credentials"] = invalid
        bad_password = None
    page = request_and_record(
        checks, work, "Authenticated dashboard page", base_url.rstrip("/") + "/",
        username, password, expected=200, interface=interface)
    framing_headers = page.get("headers", {})
    x_frame = framing_headers.get("X-Frame-Options")
    csp = framing_headers.get("Content-Security-Policy", "")
    headers_present = (
        x_frame == "DENY" and "frame-ancestors 'none'" in csp
    )
    if page.get("status_code") is None:
        header_status = "NOT RUN"
    else:
        header_status = "PASS" if headers_present else "FAIL"
    add_check(checks, "Anti-framing response headers",
              "WSL -> Pi dashboard",
              "X-Frame-Options DENY and CSP frame-ancestors 'none'",
              json.dumps({"X-Frame-Options": x_frame,
                          "Content-Security-Policy": csp}),
              header_status,
              tool="urllib", version=platform.python_version(),
              exit_code=page.get("status_code"),
              interface=interface,
              reason="" if headers_present else (
                  "No authenticated response was available."
                  if page.get("status_code") is None else
                  "Authenticated dashboard response did not contain both expected headers."
              ))
    api = request_and_record(
        checks, work, "Authenticated dashboard API", api_result_path(base_url),
        username, password, expected=200, interface=interface)
    curl_result = curl_authenticated_status(
        api_result_path(base_url), username, password)
    curl_status = (
        "PASS" if curl_result.get("status_code") == 200
        and curl_result.get("exit_code") == 0
        else "NOT RUN" if curl_result.get("status_code") is None
        else "FAIL"
    )
    add_check(checks, "curl authenticated dashboard API",
              "WSL -> Pi dashboard",
              "curl verifies the authenticated API request without saving credentials",
              "HTTP {}".format(curl_result.get("status_code"))
              if curl_result.get("status_code") is not None
              else curl_result.get("error"),
              curl_status, tool="curl", version=curl_version,
              exit_code=curl_result.get("exit_code"),
              interface=interface,
              reason="" if curl_status == "PASS" else (
                  curl_result.get("error") or "curl did not receive HTTP 200."
              ))
    auth["page_correct_credentials"] = page
    auth["api_correct_credentials"] = api
    api_body = inspect_api_body(api)
    write_json(work / "api" / "authentication_matrix.json", {
        "captured_at_local": now_local(),
        "credential_material_saved": False,
        "responses": auth,
        "authenticated_api_observation": api_body,
    })
    matrix_names = {
        "Authentication without credentials page",
        "Authentication with incorrect credentials page",
        "Authentication without credentials api",
        "Authentication with incorrect credentials api",
        "Authenticated dashboard page",
        "Authenticated dashboard API",
    }
    matrix_checks = [check for check in checks if check["name"] in matrix_names]
    matrix_status = (
        "PASS" if len(matrix_checks) == len(matrix_names)
        and all(check["status"] == "PASS" for check in matrix_checks)
        else "FAIL" if any(check["status"] == "FAIL" for check in matrix_checks)
        else "NOT RUN"
    )
    add_check(checks, "Dashboard authentication matrix", "WSL -> Pi",
              "No credentials and incorrect credentials return 401; valid credentials return 200",
              json.dumps({check["name"]: check["status"] for check in matrix_checks}),
              matrix_status, tool="urllib", version=platform.python_version(),
              interface=interface,
              reason="" if matrix_status == "PASS" else
              "One or more authentication requests failed or could not be completed.")
    return auth, api_body


def add_scan_not_run_checks(checks, inventory):
    notes = {
        "nmap": "Active port scans are not automated by this collector. Attach a separately authorized output file for review.",
        "nikto": "Active web vulnerability scans are not automated by this collector. Attach a separately authorized output file for review.",
        "hydra": "Credential-guessing automation is intentionally not run. The web auth matrix uses one generated incorrect password per route.",
    }
    for name, note in notes.items():
        available = inventory.get("tools", {}).get(name, {}).get("available", False)
        version = tool_version(inventory, name) if available else "NOT INSTALLED"
        add_check(checks, name + " active test", "NOT RUN",
                  "Authorized evidence output", "Tool available" if available
                  else "Tool unavailable", "NOT RUN", tool=name,
                  version=version[:500], reason=note)


def build_summary(checks, context, trial_info, api_comparison):
    lines = [
        "Hardened Pi IoT cybersecurity evidence collection",
        "Generated: " + now_local(),
        "Target: " + context.get("ssh_target", "NOT CONNECTED"),
        "Pi project: " + context.get("project", "NOT DETECTED"),
        "WSL source user: " + context.get("wsl_user", "unknown"),
        "Dashboard scope: " + context.get(
            "dashboard_scope", "Temporary dashboard not started"),
        "",
        "Scope and limitations",
        "- This archive may contain private IPs, usernames, host details, logs,",
        "  timestamps, sensor readings, run IDs, and packet captures. Review and",
        "  sanitize it before publishing.",
        "- Nmap, Nikto, and Hydra were not executed. Supplied scan files, if any,",
        "  are copied as unverified manual evidence.",
        "- Python performs the authentication matrix; one additional curl API",
        "  request uses credentials supplied on stdin, not command-line arguments.",
        "- HTTPS checks and capture run only when a trusted TLS endpoint is",
        "  configured. Capture files are read back and checked for target-port packets.",
        "- SSH Fail2ban ban/recovery, dashboard lockout-threshold, and reboot tests",
        "  were not triggered; each can interrupt access or the trial.",
        "- The dashboard is temporary for this collector run; a separately",
        "  deployed service is checked separately using read-only service/config",
        "  observations and an unauthenticated HTTPS request to port 443.",
        "- UFW policy comparison uses the source CIDR entered for this run;",
        "  inbound ALLOW and LIMIT rules are counted as permitting. Verify the",
        "  Pi-visible source and manually review full UFW output and Nmap results.",
        "- Package updates are simulated only; APT's local index may be stale.",
        "  Project file permissions are checked, not private-key or service permissions.",
        "- A screenshot is requested while the temporary dashboard is live;",
        "  its pixels and any user attestation are not independently verified.",
        "- No SSH, UFW, Fail2ban, certificate, or application configuration was changed.",
        "- No PIR accuracy or false-positive rate is claimed.",
        "",
        "Functional trial",
    ]
    if trial_info:
        lines.extend([
            "Run ID: {}".format(trial_info.get("run_id", "unavailable")),
            "CSV: {}".format(trial_info.get("csv_path", "unavailable")),
            "End outcome: {}".format(trial_info.get("end_outcome", "unknown")),
            "Duration (configured/recorded elapsed): {}/{} seconds".format(
                trial_info.get("duration_seconds", "unknown"),
                trial_info.get("actual_elapsed_seconds", "unknown")),
            "DHT22 attempts/successes/failures: {}/{}/{}".format(
                trial_info.get("attempts"), trial_info.get("successes"),
                trial_info.get("failures")),
            "DHT22 success: {}% (target >=95%)".format(
                trial_info.get("reliability_pct")),
            "PIR transitions: {} (detected {}, stopped {})".format(
                trial_info.get("pir_transitions"),
                trial_info.get("pir_motion_detected"),
                trial_info.get("pir_motion_stopped")),
        ])
    else:
        lines.append("NOT RUN; see checks for the reason.")
    if api_comparison:
        lines.extend([
            "API run ID/counters: " + json.dumps(api_comparison, sort_keys=True),
        ])
    lines.extend(["", "Check results"])
    for check in checks:
        lines.append(
            "[{status}] {name} | machine={machine} | interface={interface} | "
            "tool={tool} {tool_version} | exit={exit_status}".format(
                **{**check, "interface": check.get("interface") or "n/a",
                   "exit_status": check.get("exit_status")}))
        lines.append("  Expected: " + str(check.get("expected")))
        lines.append("  Observed: " + str(check.get("observed"))[:1000])
        if check.get("explanation"):
            lines.append("  Reason: " + str(check["explanation"]))
    return "\n".join(lines) + "\n"


def finalize_archive(work, output_path, checks, context, trial_info,
                     api_comparison, manual_paths):
    write_text(work / "summary.txt",
               build_summary(checks, context, trial_info, api_comparison))
    source_path = Path(__file__).resolve()
    if source_path.is_file():
        shutil.copy2(source_path, work / "collector_script.py")
    known_purposes = {
        "summary.txt": "Readable summary with per-check statuses and limitations",
        "observations.json": "Timestamped structured observation and check records",
        "wsl/system_info.json": "WSL platform and installed-tool inventory",
        "wsl/system_info.txt": "WSL command output",
        "pi/system_inventory.json": "Pi model, OS, network, packages, revision and source facts",
        "pi/system_inventory.txt": "Readable Pi system and command output",
        "pi/revision.json": "Git revision/status or source hashes",
        "pi/security_controls.json": "UFW, Nginx, Gunicorn, Fail2ban, listeners, SSH settings and log evidence",
        "pi/ufw_policy_comparison.json": "Read-only UFW comparison against the user-entered expected source CIDR and TCP ports",
        "pi/file_permissions.json": "Mode bits for hardened project source paths",
        "pi/pir_user_observations.txt": "Optional user-reported PIR event times",
        "pi/test_logs.json": "Timestamped SSH and Fail2ban log excerpts filtered to the test user/source",
        "pi/listeners_during_trial.json": "Listener snapshots taken during the functional trial",
        "pi/runtime_packages.json": "Python package versions from the selected Pi virtual environment",
        "collector_script.py": "Collector used to create this archive",
    }
    def associated_checks(rel):
        names = []
        if rel.startswith("wsl/"):
            names.extend(check["name"] for check in checks
                         if check["name"].startswith("WSL "))
        if rel.startswith("pi/system_inventory"):
            names.extend(("Pi system inventory", "Pi package update status"))
        if rel == "pi/revision.json":
            names.append("Pi project revision")
            names.append("Pi project file hashes")
        if rel == "pi/security_controls.json":
            names.extend(("SSH effective authentication settings",
                          "UFW status collection", "UFW active status",
                          "UFW policy validation", "Fail2ban SSH jail",
                          "Fail2ban SSH ban duration requirement",
                          "Deployed Nginx service",
                          "Deployed Nginx reverse-proxy configuration",
                          "Deployed Gunicorn service",
                          "Deployed listener exposure"))
        if rel == "pi/ufw_policy_comparison.json":
            names.append("UFW policy validation")
        if rel == "pi/file_permissions.json":
            names.append("Hardened project file permissions")
        if rel.startswith("pi/listeners_during_trial"):
            names.append("Nmap comparison with listeners")
        if rel == "pi/test_logs.json":
            names.append("Timestamped SSH/Fail2ban log excerpts")
        if rel.startswith("pi/hardened_sensor_trial_"):
            names.extend(("Recorded trial elapsed duration",
                          "15-minute sensor reliability target",
                          "Pi evidence transfer"))
        if rel.startswith("api/authentication_matrix"):
            names.extend(check["name"] for check in checks
                         if "Authentication" in check["name"]
                         or "Authenticated dashboard" in check["name"]
                         or "Anti-framing" in check["name"]
                         or check["name"].startswith("curl authenticated"))
        if rel.endswith("midpoint.json"):
            names.append("Mid-trial authenticated API observation")
        if rel.endswith("completed.json"):
            names.extend(("Completed-trial API observation",
                          "API/CSV counters correlation"))
        if rel.endswith("post_trial_stale.json"):
            names.extend(("Post-trial stale/freshness API observation",
                          "Post-trial freshness status"))
        if rel.startswith("packet_capture/"):
            names.append("Wireshark-compatible HTTPS capture")
        if rel.startswith("manual/browser_screenshot."):
            names.append("Browser screenshot")
        if rel.startswith("manual_evidence/"):
            names.append("Manual evidence inclusion")
        return [
            {"name": check["name"], "status": check["status"]}
            for check in checks if check["name"] in names
        ]

    entries = []
    for path in sorted(work.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        rel = str(path.relative_to(work)).replace(os.sep, "/")
        purpose = known_purposes.get(rel)
        if not purpose and rel.startswith("api/"):
            purpose = "Saved API response; credentials and authorization headers omitted"
        if not purpose and rel.startswith("manual_evidence/"):
            purpose = "User-supplied evidence copied unchanged; scan completion not independently verified"
        if not purpose and rel.startswith("manual/browser_screenshot."):
            purpose = "User-supplied browser screenshot copied without alteration"
        if not purpose and rel.startswith("packet_capture/"):
            purpose = "Bounded packet capture and metadata; interpret only with paired-request result"
        if not purpose and rel.startswith("pi/") and (
            rel.endswith(".logger.log") or rel.endswith(".dashboard.log")
        ):
            purpose = "Pi-side complete trial logger or dashboard process output"
        if not purpose and rel.startswith("pi/"):
            purpose = "Pi-side trial evidence"
        if not purpose and rel.startswith("wsl/"):
            purpose = "WSL-side evidence output"
        entries.append({
            "path": rel,
            "purpose": purpose or "Supporting evidence",
            "collection_status": "COLLECTED",
            "associated_checks": associated_checks(rel),
            "size_bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    entries.append({
        "path": "manifest.json",
        "purpose": "File inventory with purpose, status, size, and SHA-256",
        "collection_status": "COLLECTED",
        "associated_checks": [],
        "size_bytes": None,
        "sha256": None,
    })
    write_json(work / "manifest.json", {
        "generated_at_local": now_local(),
        "generated_at_utc": now_utc(),
        "archive": str(output_path.name),
        "files": entries,
        "manual_evidence_paths": manual_paths,
        "checks": checks,
    })

    # Exclusive creation prevents overwriting an existing results file.
    with output_path.open("xb") as target:
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(work.rglob("*")):
                if path.is_file():
                    archive.write(path, str(path.relative_to(work)).replace(os.sep, "/"))


def main():
    print("This collector is for an authorized Raspberry Pi you administer.")
    print("It never installs packages or changes SSH/firewall/Fail2ban settings.")
    print("Active Nmap/Nikto scans and Hydra credential guessing are not automated.")
    print("The archive can contain private network and sensor evidence; sanitize before sharing.\n")

    output_path = choose_output_path()
    work = Path(tempfile.mkdtemp(prefix="hardened-pi-evidence-"))
    (work / "wsl").mkdir()
    checks = []
    context = {
        "output_path": str(output_path),
        "working_directory": str(work),
        "wsl_user": os.environ.get("USER") or os.environ.get("USERNAME", "unknown"),
    }
    inventory = local_inventory()
    write_json(work / "wsl" / "system_info.json", inventory)
    local_lines = [
        "Captured local time: " + inventory["captured_at_local"],
        "Captured UTC: " + inventory["captured_at_utc"],
        "Platform: " + inventory["platform"],
        "Python: " + inventory["python"],
    ]
    for name, result in inventory["commands"].items():
        local_lines.extend(["\n=== {} ===".format(name), result.get("output", "")])
    local_lines.append("\n=== tool versions ===")
    for name, result in inventory["tools"].items():
        local_lines.extend(["\n--- {} ---".format(name),
                            "available={}".format(result.get("available")),
                            result.get("version", "")])
    write_text(work / "wsl" / "system_info.txt", "\n".join(local_lines) + "\n")
    record_command_checks(checks, inventory)
    add_scan_not_run_checks(checks, inventory)
    is_wsl = bool(
        os.environ.get("WSL_DISTRO_NAME")
        or "microsoft" in platform.release().lower()
    )
    add_check(checks, "Execution environment", "WSL",
              "Run external-client checks from WSL",
              platform.platform(),
              "INFORMATIONAL" if is_wsl else "NOT RUN",
              reason="" if is_wsl else
              "This process is not identified as WSL; local tool/interface results may not represent the intended client.")

    ssh_path = shutil.which("ssh")
    context["ssh_target"] = "NOT CONNECTED"
    project = None
    ssh = None
    control_dir = None
    supervisor = None
    tunnel = None
    started_event = None
    trial_info = None
    api_comparison = {}
    manual_paths = []
    route = {}
    dashboard_base_url = None
    trial_started = False
    screenshot_prompted = False
    dashboard_user = None
    dashboard_password = None
    trial_not_started_reason = "SSH connection or trial startup was unavailable."
    capture_tool_versions = {
        name: tool_version(inventory, name) for name in ("tshark", "tcpdump")
    }
    try:
        host = read_line("Raspberry Pi SSH address")
        username = read_line("SSH username")
        ssh_port_text = read_line("SSH port", "22")
        if not host or not username:
            raise ValueError("Pi SSH address and username are required.")
        if any(char.isspace() for char in host) or host.startswith("-"):
            raise ValueError("SSH address must be a hostname or IP without spaces.")
        if any(char.isspace() for char in username) or username.startswith("-"):
            raise ValueError("SSH username must not contain spaces or start with a hyphen.")
        try:
            ssh_port = int(ssh_port_text)
            if not 1 <= ssh_port <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError("SSH port must be between 1 and 65535.")
        expected_firewall_source = read_line(
            "Expected Pi-visible source IP/CIDR allowed for TCP/22 and TCP/443 (blank skips UFW policy comparison)"
        )
        if expected_firewall_source:
            expected_firewall_source = normalize_source_cidr(
                expected_firewall_source
            )
        context["expected_firewall_source"] = (
            expected_firewall_source or "NOT PROVIDED"
        )
        context["ssh_target"] = "{}@{}:{}".format(username, host, ssh_port)
        route = local_route_report(host, work, checks)
        manual_paths = collect_manual_files(work, checks)

        if not ssh_path:
            add_check(checks, "SSH connection", "WSL -> Pi",
                      "Connect over SSH", "ssh executable unavailable",
                      "NOT RUN", tool="ssh", version="NOT INSTALLED",
                      reason="Install/configure OpenSSH in WSL; the collector does not install it.")
        else:
            control_dir = Path(tempfile.mkdtemp(prefix="hpe-"))
            control_path = control_dir / "c"
            ssh = SSHConnection(ssh_path, host, username, ssh_port, control_path)
            started = now_local()
            rc = ssh.start()
            if rc:
                add_check(checks, "SSH connection", "WSL -> Pi",
                          "Authorized SSH connection", "SSH connection failed",
                          "NOT RUN", tool="OpenSSH", version=tool_version(inventory, "ssh"),
                          exit_code=rc,
                          reason="Check address, username, network reachability, host key, and existing SSH authorization.",
                          started=started)
            else:
                add_check(checks, "SSH connection", "WSL -> Pi",
                          "Authorized SSH connection", "SSH control connection established",
                          "PASS", tool="OpenSSH", version=tool_version(inventory, "ssh"),
                          exit_code=0, started=started)
                discovery = None
                discovery_error = ""
                try:
                    discovery = discover_project(ssh)
                except Exception as exc:
                    discovery_error = str(exc)
                add_check(checks, "Pi Python 3 availability", "Raspberry Pi",
                          "Python 3 available for read-only collection",
                          (discovery or {}).get("python3") or "Not detected",
                          "PASS" if (discovery or {}).get("python3") else "NOT RUN",
                          tool="python3", version="Pi system",
                          exit_code=0 if (discovery or {}).get("python3") else None,
                          reason=discovery_error or (
                              "" if (discovery or {}).get("python3") else
                              "Remote Python could not be detected.")
                          )
                project_candidates = (discovery or {}).get("projects", [])
                project = project_candidates[0] if project_candidates else None
                if not (discovery or {}).get("python3"):
                    raise RuntimeError("Python 3 is unavailable on the Pi; remote checks cannot run.")
                if not project:
                    project = read_line(
                        "Could not detect the Pi project directory; enter its pi_sensors path"
                    )
                if not project:
                    raise ValueError("Pi project directory was not provided.")
                context["project"] = project
                inv = ssh.run_code(
                    REMOTE_INVENTORY,
                    {
                        "project": project,
                        "ssh_user": username,
                        "source_ip": route.get("source", ""),
                    },
                    timeout=90,
                )
                write_json(work / "pi" / "system_inventory.json", inv)
                write_text(work / "pi" / "system_inventory.txt", pi_outputs_text(inv))
                write_json(work / "pi" / "revision.json", inv.get("revision", {}))
                write_json(work / "pi" / "file_permissions.json",
                           inv.get("file_permissions", []))
                write_json(work / "pi" / "security_controls.json", {
                    "captured_at_local": inv.get("captured_at_local"),
                    "ssh_effective_auth_settings":
                        inv.get("commands", {}).get("sshd_effective", {}).get("auth_settings"),
                    "ufw_ipv6_setting": inv.get("ufw_ipv6_setting"),
                    "ufw_status": inv.get("commands", {}).get("ufw_status"),
                    "ufw_rules": inv.get("commands", {}).get("ufw_rules"),
                    "fail2ban": {
                        key: value for key, value in inv.get("commands", {}).items()
                        if key.startswith("fail2ban_")
                    },
                    "listeners_before_trial":
                        inv.get("commands", {}).get("listeners_unprivileged"),
                    "nginx_facts": inv.get("nginx_facts"),
                    "nginx_service":
                        inv.get("commands", {}).get("nginx_service"),
                    "nginx_config_test":
                        inv.get("commands", {}).get("nginx_config_test"),
                    "dashboard_service":
                        inv.get("commands", {}).get("dashboard_service"),
                    "package_update_simulation":
                        inv.get("commands", {}).get("package_updates_simulation"),
                    "source_facts": inv.get("source_facts"),
                })
                pi_packages = inv.get("packages", {})
                add_check(checks, "Pi system inventory", "Raspberry Pi",
                          "Record OS, kernel, model, Python, packages, network and disk",
                          "Inventory captured at {}".format(inv.get("captured_at_local")),
                          "PASS", tool="SSH + Python standard library",
                          version=inv.get("python_version", "unknown"), exit_code=0)
                add_deployed_service_checks(checks, inv)
                verify_deployed_https(host, checks)
                update_result = inv.get("commands", {}).get(
                    "package_updates_simulation", {})
                update_match = re.search(
                    r"^(\d+)\s+upgraded,", update_result.get("output", ""),
                    re.MULTILINE)
                if update_result.get("status") != "COMPLETED" or not update_match:
                    update_status = "NOT RUN"
                    update_observed = update_result.get(
                        "output", update_result.get("reason", "No APT simulation result"))
                    update_reason = (
                        "A read-only APT simulation could not determine available updates."
                    )
                else:
                    pending_updates = int(update_match.group(1))
                    update_status = "PASS" if pending_updates == 0 else "INFORMATIONAL"
                    update_observed = "{} package update(s) available".format(
                        pending_updates)
                    update_reason = (
                        "Simulation only; packages were not installed and the local APT index may be stale."
                    )
                add_check(checks, "Pi package update status",
                          "Raspberry Pi",
                          "Record available updates without changing installed packages",
                          update_observed, update_status,
                          tool="apt-get -s upgrade", version="Pi APT",
                          exit_code=update_result.get("exit_code"),
                          reason=update_reason)

                permission_records = inv.get("file_permissions", [])
                if not permission_records or any(
                    "error" in record for record in permission_records
                ):
                    permission_status = "NOT RUN"
                    permission_reason = "One or more project paths could not be inspected."
                elif any(record.get("group_writable")
                         or record.get("world_writable")
                         for record in permission_records):
                    permission_status = "FAIL"
                    permission_reason = "At least one inspected project path is writable by group or other users."
                else:
                    permission_status = "PASS"
                    permission_reason = (
                        "Checks project source paths only; TLS private-key permissions and deployed-service paths are not included."
                    )
                add_check(checks, "Hardened project file permissions",
                          "Raspberry Pi",
                          "Project directory and source files are not group/world writable",
                          json.dumps(permission_records), permission_status,
                          tool="Python stat", version=inv.get("python_version", "unknown"),
                          reason=permission_reason)
                rev = inv.get("revision", {})
                if rev.get("is_git_checkout"):
                    add_check(checks, "Pi project revision", "Raspberry Pi",
                              "Record revision and working tree status",
                              "{}; {}".format(
                                  (rev.get("revision") or {}).get("output", "").strip(),
                                  rev.get("working_tree")),
                              "INFORMATIONAL", tool="git",
                              version="Pi-installed version",
                              exit_code=(rev.get("revision") or {}).get("exit_code"))
                else:
                    add_check(checks, "Pi project file hashes", "Raspberry Pi",
                              "Hash logger, dashboard and template",
                              json.dumps(rev.get("hashes", {})),
                              "INFORMATIONAL", tool="Python hashlib")

                sshd_settings = (
                    inv.get("commands", {}).get("sshd_effective", {}).get("auth_settings")
                    or []
                )
                ssh_text = " ".join(sshd_settings).lower()
                key_enabled = "pubkeyauthentication yes" in ssh_text
                password_disabled = "passwordauthentication no" in ssh_text
                keyboard_disabled = (
                    "kbdinteractiveauthentication no" in ssh_text
                    or "challengeresponseauthentication no" in ssh_text
                )
                ssh_auth_observation = {
                    "pubkeyauthentication_enabled": key_enabled,
                    "passwordauthentication_disabled": password_disabled,
                    "keyboard_interactive_disabled": keyboard_disabled,
                    "actual_allowed_denied_login_behavior": "NOT independently tested",
                }
                write_json(work / "pi" / "ssh_auth_settings.json", ssh_auth_observation)
                ssh_status = "PASS" if key_enabled and password_disabled and keyboard_disabled else "INFORMATIONAL"
                add_check(checks, "SSH effective authentication settings",
                          "Raspberry Pi", "Public key enabled; password and keyboard-interactive disabled",
                          json.dumps(ssh_auth_observation), ssh_status,
                          tool="sshd -T", version="Pi OpenSSH",
                          exit_code=(inv.get("commands", {}).get("sshd_effective") or {}).get("exit_code"),
                          reason="Server settings are observed; no additional failed-login behavior test was attempted.")

                f2b_commands = inv.get("commands", {})
                ssh_jail = (
                    "sshd" if f2b_commands.get("fail2ban_sshd_jail", {}).get("status") == "COMPLETED"
                    else "ssh" if f2b_commands.get("fail2ban_ssh_jail", {}).get("status") == "COMPLETED"
                    else "sshd"
                )
                ufw_status = f2b_commands.get("ufw_status", {})
                ufw_rules = f2b_commands.get("ufw_rules", {})
                ufw_commands_completed = (
                    ufw_status.get("status") == "COMPLETED"
                    and ufw_rules.get("status") == "COMPLETED"
                )
                ufw_output = (ufw_status.get("output") or "") + "\n" + (
                    ufw_rules.get("output") or "")
                ufw_active = bool(re.search(
                    r"^Status:\s*active\b", ufw_output, re.IGNORECASE | re.MULTILINE))
                add_check(checks, "UFW status collection", "Raspberry Pi",
                          "Collect current firewall status and rules",
                          json.dumps({"status": ufw_status, "rules": ufw_rules}),
                          "INFORMATIONAL" if ufw_commands_completed else "NOT RUN",
                          tool="ufw", version="Pi-installed version",
                          exit_code=0 if ufw_commands_completed else None,
                          reason="Command success records output only; it does not establish policy compliance.")
                add_check(checks, "UFW active status", "Raspberry Pi",
                          "UFW reports Status: active",
                          "active" if ufw_active else (
                              "inactive" if ufw_commands_completed else "unavailable"),
                          ("PASS" if ufw_active else "FAIL")
                          if ufw_commands_completed else "NOT RUN",
                          tool="ufw status", version="Pi-installed version",
                          exit_code=(0 if ufw_active else 1)
                          if ufw_commands_completed else None,
                          reason="" if ufw_active else
                          "UFW did not report active, or status could not be read.")
                if expected_firewall_source and ufw_commands_completed:
                    policy = validate_ufw_policy(
                        ufw_status.get("output", ""),
                        ufw_rules.get("output", ""),
                        expected_firewall_source,
                    )
                    policy_status = "PASS" if policy["compliant"] else "FAIL"
                    policy_reason = policy["reason"]
                else:
                    policy = {
                        "expected_source": expected_firewall_source or "NOT PROVIDED",
                        "observed": "NOT RUN",
                    }
                    policy_status = "NOT RUN"
                    policy_reason = (
                        "Enter the Pi-visible expected source CIDR and make both UFW commands readable to compare policy."
                    )
                write_json(work / "pi" / "ufw_policy_comparison.json", policy)
                add_check(checks, "UFW policy validation", "Raspberry Pi",
                          "Default-deny incoming; only TCP/22 and TCP/443 allowed from the entered CIDR",
                          json.dumps(policy), policy_status,
                          tool="ufw status verbose + numbered",
                          reason=policy_reason)
                for item, keys, expected in [
                    ("Fail2ban SSH jail", (
                        "fail2ban_status", "fail2ban_{}_jail".format(ssh_jail),
                        "fail2ban_{}_maxretry".format(ssh_jail),
                        "fail2ban_{}_findtime".format(ssh_jail),
                        "fail2ban_{}_bantime".format(ssh_jail)),
                     "Record active jails, threshold, window and ban duration"),
                ]:
                    values = {key: inv.get("commands", {}).get(key)
                              for key in keys}
                    completed = all(value and value.get("status") == "COMPLETED"
                                    for value in values.values())
                    observed = json.dumps(values)
                    add_check(checks, item, "Raspberry Pi", expected, observed,
                              "PASS" if completed else "NOT RUN",
                              tool="ufw/fail2ban-client",
                              version="Pi-installed version",
                              exit_code=0 if completed else None,
                              reason=(
                                  "Effective settings are recorded; no source was deliberately banned or tested for recovery."
                                  if completed else
                                  "One or more commands were unavailable or lacked permission."
                              ))

                ban_result = inv.get("commands", {}).get(
                    "fail2ban_{}_bantime".format(ssh_jail), {})
                ban_match = re.search(r"-?\d+", ban_result.get("output", ""))
                if ban_result.get("status") != "COMPLETED" or not ban_match:
                    add_check(checks, "Fail2ban SSH ban duration requirement",
                              "Raspberry Pi", "SSH bantime >= 900 seconds",
                              ban_result.get("output", "NOT RUN"),
                              "NOT RUN", tool="fail2ban-client",
                              version="Pi-installed version",
                              exit_code=ban_result.get("exit_code"),
                              reason="Could not read the active sshd jail bantime.")
                else:
                    ban_seconds = int(ban_match.group(0))
                    meets_requirement = ban_seconds >= 900
                    add_check(checks, "Fail2ban SSH ban duration requirement",
                              "Raspberry Pi", "SSH bantime >= 900 seconds",
                              "{} seconds".format(ban_seconds),
                              "PASS" if meets_requirement else "FAIL",
                              tool="fail2ban-client",
                              version="Pi-installed version",
                              exit_code=0,
                              reason="" if meets_requirement else
                              "The earlier project requirement calls for at least 15 minutes.")
                add_check(checks, "Optional SSH ban and recovery test",
                          "WSL test source -> Pi SSH",
                          "Explicitly authorized separate test source and recovery path",
                          "NOT RUN", "NOT RUN", tool="SSH/Fail2ban",
                          reason="No separate authorized test source and recovery path were configured; no SSH failures were generated.")

                controls = inv.get("source_facts", {})
                for check_name, fact, label in [
                    ("Dashboard password hash source", "password_hash_source_indicator",
                     "Werkzeug hash verification in current source"),
                    ("Dashboard web lockout source", "web_lockout_source_indicator",
                     "Web-specific lockout source indicator"),
                    ("Dashboard WSGI server source", "gunicorn_source_indicator",
                     "Gunicorn WSGI source indicator"),
                    ("Dashboard trusted-proxy source",
                     "trusted_proxy_source_indicator",
                     "Explicit one-hop Nginx ProxyFix source indicator"),
                    ("Anti-framing header source", "anti_framing_source_indicator",
                     "Anti-framing header source indicators"),
                    ("Dedicated dashboard authentication audit log",
                     "dedicated_auth_audit_log_source_indicator",
                     "Dedicated authentication audit log source indicator"),
                ]:
                    value = controls.get(fact)
                    add_check(checks, check_name, "Raspberry Pi project source",
                              label, str(value), "INFORMATIONAL" if value else "NOT IMPLEMENTED",
                              tool="Source inspection", version="SHA-256 recorded",
                              reason="Source indicators are not proof of effective deployed configuration.")

                print("\nPi inventory collected. The trial uses only the hardened logger and GPIO17/GPIO18.")
                print("Do not start another sensor collector while this run is active.")
                start_choice = read_line("Start the new 15-minute instrumented trial? [Y/n]", "Y").lower()
                if start_choice not in ("y", "yes"):
                    trial_not_started_reason = "User declined the trial."
                else:
                    tls = read_line(
                        "Start this dashboard on a non-loopback address with existing TLS cert/key? [y/N]",
                        "N").lower() in ("y", "yes")
                    tls_cert = ""
                    tls_key = ""
                    tls_host = ""
                    if tls:
                        print("The app will bind to 0.0.0.0. Confirm only for an authorized private network.")
                        if read_line("Confirm authorized remote TLS bind? [y/N]", "N").lower() not in ("y", "yes"):
                            tls = False
                        else:
                            tls_cert = read_line("Pi TLS certificate path")
                            tls_key = read_line("Pi TLS private-key path")
                            tls_host = read_line(
                                "HTTPS hostname/IP covered by the certificate", host)
                            if not tls_cert or not tls_key or not tls_host:
                                tls = False
                    dashboard_user, dashboard_password = collect_pir_username_password()
                    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    csv_name = "hardened_sensor_trial_{}_{}.csv".format(
                        stamp, secrets.token_hex(3))
                    start_payload = {
                        "project": project,
                        "username": dashboard_user,
                        "password": dashboard_password,
                        "csv_name": csv_name,
                        "port": 5001,
                        "tls": tls,
                        "tls_cert": tls_cert,
                        "tls_key": tls_key,
                    }
                    try:
                        supervisor, started_event = ssh.start_trial(start_payload)
                    finally:
                        start_payload.pop("password", None)
                    trial_started = True
                    trial_info = {
                        "run_id": started_event.get("run_id"),
                        "csv_path": started_event.get("csv_path"),
                        "logger_log": started_event.get("logger_log"),
                        "dashboard_log": started_event.get("dashboard_log"),
                        "duration_seconds": TRIAL_SECONDS,
                        "end_outcome": "in progress",
                    }
                    pi_packages = started_event.get("runtime_packages") or pi_packages
                    write_json(work / "pi" / "runtime_packages.json", pi_packages)
                    context["trial"] = {
                        key: value for key, value in started_event.items()
                        if key not in ("password", "password_hash")
                    }
                    context["dashboard_scope"] = (
                        "Temporary dashboard started by this collector; "
                        "separately deployed services are not tested."
                    )
                    print("Trial started. Run ID: {}".format(started_event["run_id"]))
                    print("Please create a few PIR motion/no-motion transitions during the trial.")
                    add_check(checks, "Hardened DHT22/PIR trial startup", "Raspberry Pi GPIO17/GPIO18",
                              "15 minutes, 2-second DHT22 interval, unique CSV",
                              json.dumps({
                                  "run_id": started_event.get("run_id"),
                                  "csv_path": started_event.get("csv_path"),
                                  "dashboard_port": started_event.get("dashboard_port"),
                                  "bind_address": started_event.get("bind_address"),
                                  "scheme": started_event.get("scheme"),
                                  "debug_mode": started_event.get("debug_mode"),
                              }),
                              "PASS", tool="combined_logger.py + Gunicorn",
                              version=pi_packages.get("gunicorn", "unknown"),
                              exit_code=0)
                    debug_off = started_event.get("debug_mode") is False
                    add_check(checks, "Dashboard debug mode",
                              "Raspberry Pi runtime",
                              "Flask DEBUG is false",
                              str(started_event.get("debug_mode")),
                              "PASS" if debug_off else "FAIL",
                              tool="Flask app.config", version="Pi runtime",
                              exit_code=0 if debug_off else 1)
                    add_check(checks, "Dashboard bind address and port",
                              "Raspberry Pi runtime",
                              "Record actual bind URL and port",
                              "{}://{}:{}".format(
                                  started_event.get("scheme"),
                                  started_event.get("bind_address"),
                                  started_event.get("dashboard_port")),
                              "INFORMATIONAL", tool="Gunicorn",
                              version=pi_packages.get("gunicorn", "unknown"),
                              exit_code=0)
                    wsgi_pass = bool(pi_packages.get("gunicorn")
                                     and pi_packages.get("gunicorn") != "NOT INSTALLED")
                    add_check(checks, "Dashboard WSGI runtime",
                              "Raspberry Pi runtime",
                              "Dashboard served by Gunicorn",
                              "Gunicorn process remained running at startup",
                              "PASS" if wsgi_pass else "FAIL",
                              tool="Gunicorn", version=pi_packages.get("gunicorn", "unknown"),
                              exit_code=0 if wsgi_pass else 1)
                    route = local_route_report(host, work, checks)
                    local_port = None
                    https_url = None
                    if tls:
                        host_for_url = tls_host
                        if ":" in host_for_url and not host_for_url.startswith("["):
                            host_for_url = "[" + host_for_url + "]"
                        https_url = "https://{}:{}/".format(
                            host_for_url, started_event["dashboard_port"])
                        dashboard_base_url = https_url.rstrip("/")
                    else:
                        try:
                            local_port = select_free_local_port()
                            tunnel = start_tunnel(
                                ssh, local_port, started_event["dashboard_port"])
                            dashboard_base_url = "http://127.0.0.1:{}".format(local_port)
                            add_check(checks, "SSH-tunneled dashboard access", "WSL -> Pi loopback",
                                      "Reach dashboard through encrypted SSH forwarding",
                                      dashboard_base_url, "PASS", tool="OpenSSH local forwarding",
                                      version=tool_version(inventory, "ssh"), exit_code=0,
                                      interface="SSH tunnel")
                        except Exception as exc:
                            add_check(checks, "SSH-tunneled dashboard access", "WSL -> Pi loopback",
                                      "Reach dashboard through encrypted SSH forwarding",
                                      type(exc).__name__, "NOT RUN", tool="OpenSSH",
                                      version=tool_version(inventory, "ssh"),
                                      reason=str(exc))

                    if dashboard_base_url:
                        if tls:
                            route = local_route_report(tls_host, work, checks)
                            auth_interface = route.get("interface")
                        else:
                            auth_interface = "SSH tunnel"
                        api_interface = auth_interface
                        auth, initial_api = auth_matrix(
                            dashboard_base_url, dashboard_user,
                            dashboard_password,
                            checks, work, auth_interface,
                            tool_version(inventory, "curl"))
                        if tls:
                            request_result = auth.get("api_correct_credentials", {})
                            verification_error = request_result.get("error")
                            verified = (
                                request_result.get("status_code") == 200
                                and verification_error is None
                            )
                            add_check(checks, "Remote HTTPS verification",
                                      "WSL -> Pi", "HTTPS request succeeds with certificate validation",
                                      "HTTP {}".format(request_result.get("status_code"))
                                      if verified else verification_error or "No successful response",
                                      "PASS" if verified else "FAIL",
                                      tool="urllib + default SSL context",
                                      version=platform.python_version(),
                                      exit_code=request_result.get("status_code"),
                                      interface=auth_interface,
                                      reason="" if verified else
                                      "Certificate trust/name failure is not bypassed.")
                            if verified:
                                capture_https(
                                    work, checks, dashboard_base_url,
                                    dashboard_user, dashboard_password,
                                    route, started_event["dashboard_port"],
                                    capture_tool_versions)
                            else:
                                add_check(checks, "Wireshark-compatible HTTPS capture", "WSL",
                                          "Capture a successful verified HTTPS request",
                                          "NOT RUN: HTTPS verification/request failed",
                                          "NOT RUN", tool="tshark/tcpdump",
                                          reason="A packet capture is not treated as proof of a successful HTTPS request.")
                        else:
                            add_check(checks, "Remote HTTPS verification", "WSL -> Pi",
                                      "Verify remote HTTPS certificate",
                                      "NOT RUN: local loopback HTTP is carried inside SSH",
                                      "NOT RUN", tool="Python ssl",
                                      reason="No remote TLS bind/certificate was configured.")
                            add_check(checks, "Wireshark-compatible HTTPS capture", "WSL",
                                      "Capture a successful verified HTTPS request",
                                      "NOT RUN: no remote HTTPS endpoint",
                                      "NOT RUN", tool="tshark/tcpdump",
                                      reason="No remote TLS session was configured.")
                        api_comparison = initial_api
                        if initial_api.get("run_id") is None:
                            correlation_status = "NOT RUN"
                            correlation_reason = "No authenticated API response was available."
                        elif initial_api.get("run_id") != started_event.get("run_id"):
                            correlation_status = "FAIL"
                            correlation_reason = "API run ID did not match the newly started CSV run."
                        else:
                            correlation_status = "PASS"
                            correlation_reason = ""
                        if correlation_status != "PASS":
                            add_check(checks, "API run ID correlation", "WSL -> Pi",
                                      started_event.get("run_id"),
                                      str(initial_api.get("run_id")), correlation_status,
                                      reason=correlation_reason)
                        else:
                            add_check(checks, "API run ID correlation", "WSL -> Pi",
                                      started_event.get("run_id"),
                                      str(initial_api.get("run_id")), "PASS")
                    else:
                        add_check(checks, "Dashboard authentication matrix", "WSL -> Pi",
                                  "Test no credentials, incorrect credentials and valid credentials",
                                  "No WSL client route to the dashboard",
                                  "NOT RUN", reason="SSH tunnel or remote HTTPS connection was unavailable.")
                        add_check(checks, "Remote HTTPS verification", "WSL -> Pi",
                                  "Verify remote TLS certificate",
                                  "NOT RUN: no WSL route to the dashboard",
                                  "NOT RUN", tool="Python ssl",
                                  reason="No remote HTTPS request could be made.")
                        add_check(checks, "Wireshark-compatible HTTPS capture", "WSL",
                                  "Capture a successful verified HTTPS request",
                                  "NOT RUN: no successful request",
                                  "NOT RUN", tool="tshark/tcpdump",
                                  reason="Capture must be paired with a successful verified request.")

                    if dashboard_base_url:
                        screenshot_prompted = True
                        try:
                            collect_screenshot(
                                work, checks,
                                live_url=dashboard_base_url.rstrip("/") + "/",
                                run_id=started_event.get("run_id"),
                            )
                        except EOFError:
                            add_check(checks, "Browser screenshot", "WSL/user",
                                      "Capture the live dashboard with the current run ID and metrics",
                                      "No screenshot path was provided",
                                      "NOT RUN",
                                      reason="The dashboard was active, but no screenshot path was entered.")

                    # Preserve early API observations even if the trial later stops unexpectedly.
                    started_at = time.monotonic()
                    last_reported_minute = -1
                    final_remote_status = None
                    listener_snapshots = []
                    listener_marks = set()
                    print("Trial is running. Please do not start other GPIO collectors.")
                    while time.monotonic() - started_at < TRIAL_SECONDS + 120:
                        elapsed = time.monotonic() - started_at
                        minute = int(elapsed // 60)
                        if minute != last_reported_minute:
                            print("Trial elapsed: {} minute(s)".format(minute))
                            last_reported_minute = minute
                        if dashboard_base_url and elapsed >= TRIAL_SECONDS / 2 and not (
                            work / "api" / "midpoint.json"
                        ).exists():
                            snapshot = request_and_record(
                                checks, work, "Mid-trial authenticated API observation",
                                api_result_path(dashboard_base_url), dashboard_user,
                                dashboard_password,
                                expected=200, interface=api_interface)
                            save_response(work, "midpoint.json", snapshot)
                        try:
                            state = ssh.run_code(
                                REMOTE_STATUS,
                                {"csv_path": started_event["csv_path"],
                                 "run_id": started_event["run_id"]},
                                timeout=30)
                            final_remote_status = state
                            if state.get("error"):
                                add_check(checks, "Trial progress polling", "WSL -> Pi",
                                          "Observe CSV counters and concurrent listeners",
                                          state["error"], "NOT RUN",
                                          tool="SSH + Python csv",
                                          reason="The remote CSV could not be read.")
                                break
                            mark = (
                                "start" if elapsed < 60 else
                                "midpoint" if elapsed >= TRIAL_SECONDS / 2 else None
                            )
                            if mark and mark not in listener_marks:
                                listener_marks.add(mark)
                                listener_snapshots.append({
                                    "captured_at_wsl": now_local(),
                                    "captured_at_pi_utc": state.get("captured_at_pi_utc"),
                                    "trial_elapsed_seconds": round(elapsed, 1),
                                    "listeners": state.get("listeners", "NOT RUN"),
                                })
                            if state.get("trial_end"):
                                if "end" not in listener_marks:
                                    listener_marks.add("end")
                                    listener_snapshots.append({
                                        "captured_at_wsl": now_local(),
                                        "captured_at_pi_utc": state.get("captured_at_pi_utc"),
                                        "trial_elapsed_seconds": round(elapsed, 1),
                                        "listeners": state.get("listeners", "NOT RUN"),
                                    })
                                break
                            if supervisor and supervisor.poll() is not None:
                                add_check(checks, "Trial supervisor process", "WSL -> Pi",
                                          "Keep the Pi supervisor connected until trial cleanup",
                                          "Supervisor exited with status {}".format(
                                              supervisor.returncode),
                                          "NOT RUN", tool="SSH",
                                          reason="The supervisor ended before a TRIAL_END record was observed.")
                                break
                        except Exception as exc:
                            add_check(checks, "Trial progress polling", "WSL -> Pi",
                                      "Observe CSV counters and concurrent listeners",
                                      type(exc).__name__, "NOT RUN",
                                      tool="SSH + Python csv", reason=str(exc))
                            break
                        time.sleep(POLL_SECONDS)
                    if listener_snapshots:
                        write_json(work / "pi" / "listeners_during_trial.json",
                                   listener_snapshots)

                    if final_remote_status and "error" not in final_remote_status:
                        configured_duration = final_remote_status.get("duration_seconds")
                        try:
                            configured_duration = float(configured_duration)
                        except (TypeError, ValueError):
                            configured_duration = None
                        actual_elapsed = final_remote_status.get(
                            "actual_elapsed_seconds")
                        try:
                            actual_elapsed = float(actual_elapsed)
                        except (TypeError, ValueError):
                            actual_elapsed = None
                        duration_met = (
                            configured_duration == TRIAL_SECONDS
                            and actual_elapsed is not None
                            and actual_elapsed >= TRIAL_SECONDS
                        )
                        trial_info = {
                            "run_id": started_event.get("run_id"),
                            "csv_path": started_event.get("csv_path"),
                            "logger_log": started_event.get("logger_log"),
                            "dashboard_log": started_event.get("dashboard_log"),
                            "duration_seconds": configured_duration,
                            "actual_elapsed_seconds": actual_elapsed,
                            "end_outcome": (
                                (final_remote_status.get("trial_end") or {}).get("outcome")
                            ),
                            **{key: final_remote_status.get(key) for key in (
                                "attempts", "successes", "failures", "reliability_pct",
                                "pir_transitions", "pir_motion_detected",
                                "pir_motion_stopped")},
                        }
                        trial_completed = trial_info.get("end_outcome") == "completed"
                        completed = trial_completed and duration_met
                        reliability_pass = (
                            completed and trial_info.get("reliability_pct") is not None
                            and trial_info.get("attempts", 0) > 0
                            and trial_info["reliability_pct"] >= 95.0
                        )
                        add_check(checks, "Recorded trial elapsed duration",
                                  "Raspberry Pi CSV",
                                  "Configured duration 900 seconds and recorded elapsed >=900 seconds",
                                  json.dumps({
                                      "configured_duration_seconds": configured_duration,
                                      "actual_elapsed_seconds": actual_elapsed,
                                  }),
                                  "PASS" if duration_met else "FAIL",
                                  tool="combined_logger.py CSV",
                                  exit_code=0 if duration_met else 1,
                                  reason="" if duration_met else
                                  "The end-row elapsed time or configured duration did not meet 900 seconds.")
                        add_check(checks, "15-minute sensor reliability target",
                                  "Raspberry Pi GPIO17/GPIO18",
                                  "Completed 900-second run; DHT22 success >=95%",
                                  json.dumps(trial_info),
                                  "PASS" if reliability_pass else
                                  "FAIL",
                                  tool="combined_logger.py + CSV parser",
                                  version=pi_packages.get("adafruit-circuitpython-dht", "unknown"),
                                  exit_code=0 if reliability_pass else 1,
                                  reason="" if reliability_pass else
                                  "Trial did not complete a recorded 900-second run at or above the 95% target.")
                    else:
                        add_check(checks, "Recorded trial elapsed duration",
                                  "Raspberry Pi CSV",
                                  "Configured duration 900 seconds and recorded elapsed >=900 seconds",
                                  "No final trial status was available", "NOT RUN",
                                  reason="The CSV could not verify the run's actual elapsed time.")
                        add_check(checks, "15-minute sensor reliability target",
                                  "Raspberry Pi GPIO17/GPIO18",
                                  "Completed 900-second run; DHT22 success >=95%",
                                  "No complete TRIAL_END record was observed",
                                  "FAIL", reason="A completed hardware trial was not verified.")

                    if dashboard_base_url and trial_info:
                        if final_remote_status and final_remote_status.get("trial_end"):
                            end_snapshot = request_and_record(
                                checks, work, "Completed-trial API observation",
                                api_result_path(dashboard_base_url), dashboard_user,
                                dashboard_password,
                                expected=200, interface=api_interface)
                            save_response(work, "completed.json", end_snapshot)
                            end_api = inspect_api_body(end_snapshot)
                            api_comparison = end_api
                            same = (
                                end_api.get("run_id") == trial_info.get("run_id")
                                and end_api.get("attempts") == trial_info.get("attempts")
                                and end_api.get("successes") == trial_info.get("successes")
                                and end_api.get("failures") == trial_info.get("failures")
                            )
                            if end_snapshot.get("status_code") is None:
                                correlation_status = "NOT RUN"
                                correlation_reason = "No completed API response was available."
                            else:
                                correlation_status = "PASS" if same else "FAIL"
                                correlation_reason = "" if same else (
                                    "Completed API counters or run ID differ from the final CSV."
                                )
                            add_check(checks, "API/CSV counters correlation",
                                      "WSL API response vs Pi CSV",
                                      "Completed-run ID and counters agree",
                                      "API: {}; CSV: {}".format(
                                          json.dumps(end_api), json.dumps(trial_info)),
                                      correlation_status,
                                      reason=correlation_reason)
                            time.sleep(STALE_SECONDS + 2)
                            stale_snapshot = request_and_record(
                                checks, work, "Post-trial stale/freshness API observation",
                                api_result_path(dashboard_base_url), dashboard_user,
                                dashboard_password,
                                expected=200, interface=api_interface)
                            save_response(work, "post_trial_stale.json", stale_snapshot)
                            freshness = inspect_api_body(stale_snapshot)
                            stale_status = freshness.get("dht_attempt_freshness") == "stale"
                            freshness_check = (
                                "NOT RUN" if stale_snapshot.get("status_code") is None
                                else "PASS" if stale_status else "FAIL"
                            )
                            add_check(checks, "Post-trial freshness status",
                                      "WSL dashboard API",
                                      "DHT attempt becomes stale after collection stops",
                                      json.dumps(freshness),
                                      freshness_check,
                                      reason="" if stale_status else
                                      "No usable response or the attempt was not stale at observation time.")

                    if trial_info:
                        ask_pir_events(work, checks, trial_started)
                    else:
                        write_text(work / "pi" / "pir_user_observations.txt",
                                   "NOT RUN: no completed run statistics were available.\n")

                    add_check(checks, "Web lockout threshold test", "WSL -> Pi",
                              "Do not trigger persistent lockout during reliability trial",
                              "NOT RUN", "NOT RUN",
                              reason="The threshold test could lock out the client; only four auth-failure requests were issued across the two routes.")
                    trial_info = trial_info or {}
                    trial_info["dashboard_port"] = started_event.get("dashboard_port")
                    trial_info["bind_address"] = started_event.get("bind_address")
                    trial_info["debug_mode"] = started_event.get("debug_mode")
                    context["trial"] = trial_info
        if not trial_started:
            add_check(checks, "Hardened DHT22/PIR trial",
                      "Raspberry Pi GPIO17/GPIO18",
                      "Run a new 15-minute trial at a 2-second interval",
                      "No new trial was started", "NOT RUN",
                      reason=trial_not_started_reason)
    except KeyboardInterrupt:
        print("\nInterrupted; preserving collected evidence.")
        add_check(checks, "Collector execution", "WSL",
                  "Complete evidence collection", "User interrupted collection",
                  "NOT RUN", reason="Partial results will be retained.")
    except Exception as exc:
        print("Collection stopped: {}: {}".format(type(exc).__name__, exc))
        add_check(checks, "Collector execution", "WSL",
                  "Complete evidence collection",
                  type(exc).__name__ + ": " + str(exc), "NOT RUN",
                  reason="Any collected partial results will be retained.")
    finally:
        stop_tunnel(tunnel)
        if ssh and supervisor is None:
            supervisor = ssh.last_trial_process
        if ssh and started_event is None:
            started_event = ssh.last_trial_event
        if supervisor and ssh and ssh.active:
            try:
                supervisor_events = ssh.stop_trial(supervisor)
                write_json(work / "pi" / "supervisor_events.json", supervisor_events)
            except Exception as exc:
                add_check(checks, "Pi supervisor cleanup", "WSL -> Pi",
                          "Stop only the collector-owned processes",
                          type(exc).__name__, "NOT RUN", tool="SSH",
                          reason=str(exc))
        if started_event and ssh and ssh.active:
            transfer_pi_files(ssh, started_event, work, checks, trial_info)
        elif started_event and any(started_event.get(key) for key in (
            "csv_path", "logger_log", "dashboard_log"
        )):
            add_check(checks, "Pi evidence transfer", "Raspberry Pi -> WSL",
                      "Copy trial CSV and logger/dashboard output",
                      "SSH connection was unavailable", "NOT RUN",
                      tool="SSH + base64",
                      reason="The Pi-side evidence could not be fetched after the connection ended.")
        if ssh and ssh.active and project:
            try:
                log_data = ssh.run_code(
                    REMOTE_TEST_LOGS,
                    {"ssh_user": username, "source_ip": route.get("source", "")},
                    timeout=60,
                )
                write_json(work / "pi" / "test_logs.json", log_data)
                add_check(checks, "Timestamped SSH/Fail2ban log excerpts",
                          "Raspberry Pi",
                          "Collect matching test-source/user auth entries",
                          json.dumps(log_data), "INFORMATIONAL",
                          tool="journalctl", version="Pi systemd journal",
                          reason="Entries are filtered by the WSL source address and SSH username.")
            except Exception as exc:
                add_check(checks, "Timestamped SSH/Fail2ban log excerpts",
                          "Raspberry Pi",
                          "Collect relevant timestamped log excerpts",
                          type(exc).__name__, "NOT RUN",
                          tool="journalctl", reason=str(exc))
        if trial_started and not (work / "pi" / "pir_user_observations.txt").exists():
            try:
                ask_pir_events(work, checks, trial_started)
            except (EOFError, KeyboardInterrupt):
                write_text(work / "pi" / "pir_user_observations.txt",
                           "NOT RUN: no manual event times were provided.\n")
        if not screenshot_prompted and not list(
            (work / "manual").glob("browser_screenshot.*")
        ):
            try:
                collect_screenshot(work, checks)
            except (EOFError, KeyboardInterrupt):
                add_check(checks, "Browser screenshot", "WSL/user",
                          "Include authentic screenshot or mark manual",
                          "No screenshot path provided", "NOT RUN",
                          reason="No screenshot was fabricated.")
        if not (work / "pi" / "system_inventory.json").exists():
            for name, expected in [
                ("Pi system inventory", "Record Pi model, OS, kernel, network, packages and disk"),
                ("Pi project revision", "Record Git revision/status or source hashes"),
                ("Pi package update status", "Run a read-only package update simulation"),
                ("Hardened project file permissions", "Inspect hardened source path permissions"),
                ("SSH effective authentication settings", "Inspect effective sshd auth settings"),
                ("UFW status collection", "Collect current firewall status and rules"),
                ("UFW active status", "Verify UFW reports active"),
                ("UFW policy validation", "Compare rules with an approved allowlist"),
                ("Fail2ban SSH jail", "Record active SSH jail and effective settings"),
                ("Fail2ban SSH ban duration requirement", "Compare SSH bantime with >=900 seconds"),
                ("Optional SSH ban and recovery test", "Use a separate authorized source/recovery path"),
                ("Timestamped SSH/Fail2ban log excerpts", "Collect relevant timestamped Pi logs"),
            ]:
                if not any(check.get("name") == name for check in checks):
                    add_check(checks, name, "Raspberry Pi",
                              expected, "Pi was not reachable for this check",
                              "NOT RUN", reason="No authenticated SSH session was established.")
        no_run_reason = (
            "Trial or dashboard collection was interrupted before this check."
            if trial_started else trial_not_started_reason
        )
        if not any(check.get("name") == "Recorded trial elapsed duration"
                   for check in checks):
            add_check(checks, "Recorded trial elapsed duration",
                      "Raspberry Pi CSV",
                      "Configured duration 900 seconds and recorded elapsed >=900 seconds",
                      "No final trial status was available", "NOT RUN",
                      reason=no_run_reason)
        if not any(
            check.get("name") == "15-minute sensor reliability target"
            for check in checks
        ):
            add_check(checks, "15-minute sensor reliability target",
                      "Raspberry Pi GPIO17/GPIO18",
                      "Completed 900-second run; DHT22 success >=95%",
                      "No completed 900-second trial was verified",
                      "NOT RUN",
                      reason=no_run_reason)
        missing_dashboard_checks = [
            ("Hardened DHT22/PIR trial startup",
             "Start the 15-minute logger and dashboard without stopping other collectors"),
            ("Dashboard bind address and port",
             "Record actual dashboard bind address and port"),
            ("Dashboard authentication matrix",
             "Test unauthenticated, invalid and valid credentials"),
            ("curl authenticated dashboard API",
             "Verify authenticated dashboard API with curl"),
            ("Anti-framing response headers",
             "Verify anti-framing headers on authenticated response"),
            ("Dashboard debug mode", "Verify Flask DEBUG is false"),
            ("Dashboard WSGI runtime", "Verify Gunicorn is serving the dashboard"),
            ("Remote HTTPS verification", "Verify remote HTTPS certificate"),
            ("Wireshark-compatible HTTPS capture",
             "Capture a verified successful HTTPS request"),
            ("Mid-trial authenticated API observation",
             "Record authenticated dashboard counters during the trial"),
            ("Completed-trial API observation",
             "Record API state after the trial completes"),
            ("Post-trial stale/freshness API observation",
             "Record freshness after the trial ends"),
            ("Post-trial freshness status",
             "Observe freshness after collection ends"),
            ("API run ID correlation",
             "Compare the initial API run ID with the new trial"),
            ("API/CSV counters correlation",
             "Compare final API data with trial CSV"),
            ("Recorded trial elapsed duration",
             "Verify the recorded trial elapsed at least 900 seconds"),
            ("Trial progress polling",
             "Observe CSV counters and concurrent listeners"),
            ("Web lockout threshold test",
             "Observe lockout behavior without risking the trial"),
            ("Deployed HTTPS endpoint",
             "The Pi HTTPS endpoint was not available for a trusted port-443 probe."),
        ]
        for name, expected in missing_dashboard_checks:
            if not any(check.get("name") == name for check in checks):
                add_check(checks, name, "WSL -> Pi", expected,
                          "NOT RUN: no completed dashboard observation",
                          "NOT RUN", reason=no_run_reason)
        for name, reason in (
            ("Deployed Nginx service",
             "The Pi Nginx service was not inspected because SSH inventory did not complete."),
            ("Deployed Nginx reverse-proxy configuration",
             "The enabled Nginx site configuration was not inspected because SSH inventory did not complete."),
            ("Deployed Gunicorn service",
             "The Pi Gunicorn systemd unit was not inspected because SSH inventory did not complete."),
            ("Deployed listener exposure",
             "Pi listener output was not collected because SSH inventory did not complete."),
            ("UFW policy validation",
             "The Pi firewall policy was not collected because SSH inventory did not complete."),
            ("Controlled reboot/recovery test",
             "The collector does not reboot the Pi; attach authorized before/after service and uptime evidence."),
            ("Separately deployed dashboard validation",
             "This run validates only its temporary dashboard instance; test a deployed service separately."),
        ):
            if not any(check.get("name") == name for check in checks):
                add_check(checks, name, "Raspberry Pi",
                          "Verify the control on a separately deployed system",
                          "NOT RUN", "NOT RUN", reason=reason)
        if ssh:
            ssh.close()
        if control_dir:
            shutil.rmtree(control_dir, ignore_errors=True)
        dashboard_password = None
        try:
            add_check(checks, "Nmap comparison with listeners", "WSL/Pi",
                      "Compare authorized scan and listener snapshot",
                      "Listener snapshots may be present; active scan was not run",
                      "NOT RUN", tool="Nmap + ss",
                      version=tool_version(inventory, "nmap"),
                      reason="No automated Nmap scan was run, so a before/after comparison is unavailable.")
        except Exception:
            pass
        write_json(work / "observations.json", {
            "generated_at_local": now_local(),
            "generated_at_utc": now_utc(),
            "context": context,
            "checks": checks,
            "trial": trial_info,
            "api_comparison": api_comparison,
            "manual_evidence_paths": manual_paths,
            "tool_versions": inventory.get("tools", {}),
        })
        if not (work / "pi" / "pir_user_observations.txt").exists():
            write_text(work / "pi" / "pir_user_observations.txt",
                       "NOT RUN: trial/user observation prompt was not reached.\n")
        try:
            finalize_archive(work, output_path, checks, context,
                             trial_info, api_comparison, manual_paths)
            print("\nEvidence ZIP created: {}".format(output_path))
            shutil.rmtree(work)
        except Exception as exc:
            print("\nCould not create final ZIP: {}: {}".format(type(exc).__name__, exc))
            print("Partial evidence is preserved at: {}".format(work))
            print("No existing results file was overwritten.")


if __name__ == "__main__":
    main()
