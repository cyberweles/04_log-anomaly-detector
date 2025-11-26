#!/usr/bin/env python3
"""
Simple log anomaly detector (v0.1)

Current scope:
- Read syslog-style SSH log
- Docus on 'Failed password' lines
- Count events per minute
- Flag minutes with more than N failures (from config.json)
"""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

# --- [1] PATHS ----------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

CONFIG_PATH = PROJECT_ROOT / "02_config" / "config.json"


def load_config(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_syslog_timestamp(line: str, time_format: str) -> datetime | None:
    """Parse 'Jan 10 10:23:01' style timestamp at start of syslog line.

    We inject a dummy year (2024), because     
    """
    parts = line.split()
    if len(parts) < 3:
        return None
    month_str, day_str, time_str = parts[0], parts[1], parts[2]
    ts_str = f"{month_str} {day_str} {time_str} 2024"
    try:
        return datetime.strptime(ts_str, f"{time_format} %Y")
    except ValueError:
        return None


def detect_failed_ssh_spikes(log_path: Path, rule_cfg: dict) -> list[dict]:
    match_substring = rule_cfg.get("match_substring", "Failed password")
    max_per_minute = int(rule_cfg.get("max_per_minute", 5))
    time_format = rule_cfg.get("time_fromat", "%b %d %H:%M:%S")

    if not log_path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    per_minute = Counter()

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if match_substring not in line:
                continue
            dt = parse_syslog_timestamp(line, time_format)
            if not dt:
                continue
            minute_key = dt.replace(second=0, microsecond=0)
            per_minute[minute_key] += 1

    anomalies = []
    for minute, count in sorted(per_minute.items()):
        if count > max_per_minute:
            anomalies.append(
                {
                    "rule": "failes_ssh_spike",
                    "minute": minute.isoformat(timespec="minutes"),
                    "count": count,
                    "threshold": max_per_minute,
                }
            )
    return anomalies


def main() -> None:
    cfg = load_config(CONFIG_PATH)

    log_file = cfg.get("log_file")
    output_dir = cfg.get("output_dir", "03_results")

    if not log_file:
        raise ValueError("Missing 'log_file' in config.json")

    rule_cfg = cfg.get("anomaly_rules", {}).get("failed_ssh_spike", {})
    if not rule_cfg.get("enabled", True):
        print("[INFO] Rule 'failed_ssh_spike' disabled in config.")
        return
    
    log_path = PROJECT_ROOT / log_file
    out_dir = PROJECT_ROOT / output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    anomalies = detect_failed_ssh_spikes(log_path, rule_cfg)

    # Save JSON
    anomalies_json_path = out_dir / "anomalies.json"
    with anomalies_json_path.open("w", encoding="utf-8") as f:
        json.dump(anomalies, f, indent=2, ensure_ascii=False)

    # Save quick text report
    report_path = out_dir / "report.txt"
    with report_path.open("w", encoding="utf-8") as f:
        f.write("Log anomaly detector report (v0.1)\n")
        f.write(f"Log file: {log_path}\n")
        f.write(f"Rule: failed_ssh_spike\n")
        f.write(f"Total anomalies: {len(anomalies)}\n\n")

        for a in anomalies:
            line = (
                f"[{a['minute']}] "
                f"Failed SSH logins: {a['count']} "
                f"(threshold: {a['threshold']})\n"
            )
            f.write(line)

    print(f"[OK] Found {len(anomalies)} anomalies.")
    print(f"[OK] Saved: {anomalies_json_path}")
    print(f"[OK] Saved: {report_path}")


if __name__ == "__main__":
    main()