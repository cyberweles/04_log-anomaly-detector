# Log Anomaly Detector (Project 04)

Simple SOC-style log anomaly detector.

## 📌 Overview

This project implements a lightweight anomaly detection script for syslog-style SSH logs.
It detects **frequency spikes** (failed SSH attempts per minute) based on configurable thresholds.

The script produces:
- `anomalies.json` — structured anomaly data  
- `report.txt` — human‑readable summary  

Fully compatible with standard SSH syslog logs.

---

## 📁 Project Structure

```
04_log-anomaly-detector/
│
├── 00_logs/
│     └── sample_syslog_ssh_big.log
│
├── 01_scripts/
│     └── anomaly_detector.py
│
├── 02_config/
│     └── config.json
│
└── 03_results/
      ├── anomalies.json
      └── report.txt
```

---

## ⚙️ Configuration (`config.json`)

```json
{
  "log_file": "00_logs/sample_syslog_ssh_big.log",
  "output_dir": "03_results",

  "anomaly_rules": {
    "failed_ssh_spike": {
      "enabled": true,
      "match_substring": "Failed password",
      "max_per_minute": 5,
      "time_format": "%b %d %H:%M:%S"
    }
  }
}
```

---

## ▶️ Usage

Run from the project root:

```bash
python 01_scripts/anomaly_detector.py
```

Output appears in `03_results/`.

---

## 🔍 What It Detects (v0.1)

- SSH authentication failure spikes  
- Threshold-based anomaly detection  
- Minute-level aggregation  
- Syslog timestamp parsing  

---

## ✅ Status

Version **0.1** — functional and complete.  
Suitable for THM SOC L1 labs, SOC portfolio, and interview prep.

---

## 👤 Author
**cyberweles**  
GitHub: https://github.com/cyberweles
