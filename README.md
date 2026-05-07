# 🛡️ Threat Detector

A real-time network threat detection system built on **Apache Kafka**, **Apache Spark Structured Streaming**, **Apache Hadoop (HDFS/YARN)**, and **Apache Cassandra**. It ingests firewall/network logs, detects attack patterns in near real-time, and persists results for analysis.

---

## Architecture Overview

```
CSV Logs
   │
   ▼
[Kafka Producer] ──► [Kafka Topic: threat_scan]
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
    [Spark Streaming Consumer]     [Spark Batch: kafka_to_hdfs]
    (real-time detection)          (raw log archival to HDFS)
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
[Brute    [Volume    [Pattern
 Force]    Attack]    Detection]
    │          │          │
    └──────────┴──────────┘
               │
               ▼
         [Cassandra]
    ┌──────────┴──────────┐
    │    threats_counters  │  (per-IP score & alert count)
    │    threats_metadata  │  (last seen, attack types)
    │    threats_now       │  (live alert stream)
    └─────────────────────┘
```

---

## Detection Modules

| Module | Logic | Severity |
|--------|-------|----------|
| **Brute Force** | ≥ 5 login attempts from same source IP within 1 minute | High |
| **Volume Attack** | > 10 MB transferred in 10 seconds from a single IP | High |
| **SQL Injection** | Regex match on request path | Critical |
| **XSS** | Regex match on request path | High |
| **Path Traversal** | Regex match on request path (`../`, encoded variants) | High |
| **Tool-Based Attack** | Known tool signatures in user-agent (`sqlmap`, `nikto`, `gobuster`, etc.) | Medium |

---

## Project Structure

```
threat-detector/
├── producer_stream.py          # Reads CSV and sends logs to Kafka
├── consumer_stream_fixed.py    # Spark Streaming: detects threats in real time
├── detection_functions.py      # Brute force, volume, and pattern detection logic
├── cassandra_write.py          # Writes detected alerts to Cassandra
├── kafka_to_hdfs.py            # Batch job: archives raw Kafka logs to HDFS
├── global_vars.py              # All configuration constants and thresholds
├── requirement.txt             # Python dependencies
├── docker-compose.yml          # Docker Swarm stack (Hadoop + Cassandra)
└── threat_detector_fixed.zip   # Packaged Python files for spark-submit --py-files
```

---

## Prerequisites

- Docker + Docker Swarm
- Apache Kafka (running on `hadoop-master:9092`)
- Python 3.x with pip
- Apache Spark 3.5.x (with YARN)
- A cybersecurity log CSV file (set path in `global_vars.py` → `CYBER_PACKETS`)


