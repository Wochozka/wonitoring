#!/usr/bin/env python3

import subprocess
import time
import requests
import yaml
import argparse
import csv
import json
import os, sys, subprocess
from datetime import datetime, timedelta

# Configuration constants (can be overridden via CLI)
DEFAULT_CONFIG_FILE = "devices.yaml"
LOG_DIR = "logs"
CSV_LOG_FILE = os.path.join(LOG_DIR, "log.csv")
JSON_LOG_FILE = os.path.join(LOG_DIR, "log.json")

PUSHOVER_USER_KEY = ""
PUSHOVER_API_TOKEN = ""
PING_INTERVAL = 3
FAIL_THRESHOLD = 3

# Notification
def send_pushover_notification(message):
    data = {
        "token": PUSHOVER_API_TOKEN,
        "user": PUSHOVER_USER_KEY,
        "message": message
    }
    try:
        response = requests.post("https://api.pushover.net/1/messages.json", data=data)
        if response.status_code != 200:
            print("Pushover error:", response.text)
    except Exception as e:
        print("Failed to send Pushover notification:", e)

# Ping command
def ping(ip):
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

# Argument parser
def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple network monitoring tool with Pushover notifications."
    )
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_CONFIG_FILE,
        help="Path to the configuration file (YAML or JSON)."
    )
    parser.add_argument(
        "--ping-interval", type=int, default=3,
        help="Seconds between each ping attempt (default: 3)."
    )
    parser.add_argument(
        "--ping-threshold", type=int, default=3,
        help="Number of failed pings before triggering an alert (default: 3)."
    )
    parser.add_argument(
        "--daemon", action="store_true",
        help="Run the monitoring loop in background (as daemon)."
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single network check and print results, then exit. Disables logging unless --nolog is overridden."
    )
    grp_log = parser.add_mutually_exclusive_group(required=False)
    grp_log.add_argument('--nolog', action="store_true",
                     help="Disable logging to files (enabled when --once is used).")
    grp_log.add_argument('--log', action="store_true",
                     help="Enable logging to files (default: enabled unless --once is used).")

    return parser.parse_args()


# Load YAML config
def load_devices(config_path):
    with open(config_path, 'r') as f:
        if config_path.endswith(".json"):
            return json.load(f)
        else:
            return yaml.safe_load(f)


def run_once(config_file, ping_interval, fail_threshold):
    config = load_devices(config_file)
    devices = config.get("devices", [])

    print(f"Running one-time check at {datetime.now().isoformat()}:\n")

    for dev in devices:
        name = dev["name"]
        ip = dev["ip"]
        print(f"Pinging {name} ({ip})...", end=" ", flush=True)
        is_up = ping(ip)
        status = "UP" if is_up else "DOWN"
        print(status)
        if args.log:
            log_event(name, ip, status)


# Logging utilities
def log_event(device_name, ip, status):
    timestamp = datetime.now().isoformat()
    entry = {
        "timestamp": timestamp,
        "device": device_name,
        "ip": ip,
        "status": status
    }

    os.makedirs(LOG_DIR, exist_ok=True)

    # Append to JSON log
    with open(JSON_LOG_FILE, "a") as f_json:
        f_json.write(json.dumps(entry) + "\n")

    # Append to CSV log
    write_header = not os.path.exists(CSV_LOG_FILE)
    with open(CSV_LOG_FILE, "a", newline='') as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=["timestamp", "device", "ip", "status"])
        if write_header:
            writer.writeheader()
        writer.writerow(entry)

def daemonize(nolog):
    # Run a new process with the same arguments but without --daemon
    args = [sys.executable] + [
        arg for arg in sys.argv if arg != "--daemon"
    ]

    log_file = os.path.join(LOG_DIR, "monitor.log")
    os.makedirs(LOG_DIR, exist_ok=True)

    if nolog:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(
                args,
                stdout=devnull,
                stderr=devnull,
                stdin=subprocess.DEVNULL,
                close_fds=True
            )
    else:
        with open(log_file, 'a') as f_out:
            process = subprocess.Popen(
                args,
                stdout=f_out,
                stderr=f_out,
                stdin=subprocess.DEVNULL,
                close_fds=True
            )

    print(f"Started network monitor in background (PID {process.pid}). Logs: {log_file}")


# Monitoring logic
def main(config_file, ping_interval, fail_threshold):
    config = load_devices(config_file)
    devices = config.get("devices", [])
    report_interval = config.get("settings", {}).get("report_interval_minutes", 0)

    failure_counters = {dev['ip']: 0 for dev in devices}
    notified = {dev['ip']: False for dev in devices}
    last_report_time = datetime.now()

    while True:
        for dev in devices:
            name = dev['name']
            ip = dev['ip']
            is_up = ping(ip)

            if is_up:
                if failure_counters[ip] >= fail_threshold:
                    print(f"[{datetime.now()}] {name} ({ip}) RECOVERED.")
                    send_pushover_notification(f"INFO: {name} ({ip}) is back online.")
                    if args.log:
                        log_event(name, ip, "RECOVERED")
                else:
                    print(f"[{datetime.now()}] {name} ({ip}) is UP.")
                failure_counters[ip] = 0
                notified[ip] = False
            else:
                failure_counters[ip] += 1
                print(f"[{datetime.now()}] {name} ({ip}) is DOWN.")
                if failure_counters[ip] == fail_threshold:
                    send_pushover_notification(f"ALERT: {name} ({ip}) is DOWN for {ping_interval * fail_threshold + 1} seconds!")
                    if args.log:
                        log_event(name, ip, "DOWN")
                    notified[ip] = True

        if report_interval > 0 and datetime.now() - last_report_time >= timedelta(minutes=report_interval):
            status_report = []
            for dev in devices:
                ip = dev['ip']
                name = dev['name']
                status = "DOWN" if failure_counters[ip] >= fail_threshold else "UP"
                status_report.append(f"{name} ({ip}): {status}")
            send_pushover_notification("Network Status Report:\n" + "\n".join(status_report))
            last_report_time = datetime.now()

        time.sleep(ping_interval)


# Entry point
if __name__ == "__main__":
    if sys.version_info<(3,5,0):
        sys.stderr.write("You need python 3.5 or later to run this script\n")
        sys.exit(1)

    args = parse_args()

    # Daemonize check
    if args.daemon:
        daemonize(args.nolog)
        sys.exit(0)

    # Determine logging behavior
    if args.once and args.log:
        args.log = True
    elif args.once and not args.log:
        args.log = False
    elif args.nolog:
        args.log = False
    else:
        args.log = True

    if args.once:
        run_once(
            config_file=args.config,
            ping_interval=args.ping_interval,
            fail_threshold=args.ping_threshold
        )
    else:
        main(
            config_file=args.config,
            ping_interval=args.ping_interval,
            fail_threshold=args.ping_threshold
        )
