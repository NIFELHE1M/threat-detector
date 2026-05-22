# 🛡️ Threat Detector

A real-time network threat detection system built on **Apache Kafka**, **Apache Spark Structured Streaming**, **Apache Hadoop (HDFS/YARN/HBase)**, **Apache Cassandra**, and a live **web dashboard**. It ingests firewall and network logs, detects attack patterns in near real-time, archives raw data, performs batch analytics, and visualizes everything through an interactive interface.

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
               │                             │
    ┌──────────┼──────────┐                  ▼
    ▼          ▼          ▼           [HBase Loader]
[Brute    [Volume    [Pattern         (batch analytics
 Force]    Attack]    Detection]       → HBase tables)
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
               │
               ▼
    [Dashboard: main.py + dashboard.html]
    (live threat feed, charts, analytics)
```

---

## Detection Modules

| Module | Logic | Severity |
|--------|-------|----------|
| **Brute Force** | ≥ 5 login attempts from same source IP within 1 minute | 🔴 High |
| **Volume Attack** | > 10 MB transferred in 10 seconds from a single IP | 🔴 High |
| **SQL Injection** | Regex match on request path | 🚨 Critical |
| **XSS** | Regex match on request path | 🔴 High |
| **Path Traversal** | Regex match on request path (`../`, encoded variants) | 🔴 High |
| **Tool-Based Attack** | Known signatures in user-agent (`sqlmap`, `nikto`, `gobuster`, etc.) | 🟡 Medium |

---

## Project Structure

```
threat-detector/
│
├── stream/                         # Real-time pipeline
│   ├── producer_stream.py          # Reads CSV logs and publishes to Kafka
│   ├── consumer_stream.py          # Spark Streaming: detects threats in real time
│   ├── detection_functions.py      # Brute force, volume & pattern detection logic
│   ├── cassandra_write.py          # Writes detected alerts to Cassandra
│   ├── kafka_to_hdfs.py            # Archives raw Kafka logs to HDFS
│   └── global_vars.py              # All configuration constants and thresholds
│
├── batch/                          # Batch analytics pipeline
│   ├── analysis1_top_ips.py        # Top attacking IPs by alert count
│   ├── analysis2_threat_volume.py  # Threat volume over time
│   ├── analysis3_attack_patterns.py# Attack type breakdown and trends
│   ├── analysis4_port_scans.py     # Port scan detection and heatmap
│   ├── hbase_loader.py             # Loads batch results into HBase
│   ├── checkpoint_batch.json       # Spark batch job progress checkpoint
│   └── checkpoint_ingest.json      # Kafka ingestion progress checkpoint
│
├── dashboard/                      # Web dashboard
│   ├── main.py                     # FastAPI/Flask server; queries Cassandra & HBase
│   └── dashboard.html              # Single-page dashboard UI (charts, live feed)
│
├── LICENSE
├── README.md
└── requirement.txt                 # Python dependencies
```

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Docker + Docker Swarm** | For the Hadoop + Cassandra stack |
| **Apache Kafka** | Running on `hadoop-master:9092` |
| **Apache Spark 3.5.x** | With YARN resource manager |
| **Apache Hadoop (HDFS + YARN)** | Deployed via Docker Swarm |
| **Apache HBase** | For batch analytics persistence |
| **Apache Cassandra** | For real-time alert storage |
| **Python 3.x** | With pip |
| **Cybersecurity log CSV** | Set path in `stream/global_vars.py` → `CYBER_PACKETS` |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-org/threat-detector.git
cd threat-detector
```

### 2. Install Python dependencies

```bash
pip install -r requirement.txt
```

### 3. Start the infrastructure stack

```bash
docker swarm init
docker stack deploy -c docker-compose.yml hadoop-cassandra
```

Wait for all services to be healthy before proceeding.

### 4. Configure global variables

Edit `stream/global_vars.py` and set your paths and connection details:

```python
CYBER_PACKETS   = "/path/to/your/logs.csv"
KAFKA_BROKER    = "hadoop-master:9092"
KAFKA_TOPIC     = "threat_scan"
CASSANDRA_HOST  = "localhost"
HDFS_OUTPUT     = "hdfs://hadoop-master:9000/threat-detector/raw"
HBASE_HOST      = "localhost"
```

---

## Running the System

### Stream Pipeline

Run each component in a separate terminal (or submit to YARN as needed).

**Step 1 — Start the Kafka producer:**
```bash
python stream/producer_stream.py
```

**Step 2 — Launch the Spark Streaming consumer:**
```bash
spark-submit \
  --master yarn \
  --deploy-mode client \
  --py-files threat_detector.zip \
  stream/consumer_stream.py
```

**Step 3 — Archive raw logs to HDFS:**
```bash
spark-submit \
  --master yarn \
  --deploy-mode client \
  stream/kafka_to_hdfs.py
```

---

### Batch Analytics Pipeline

Run after sufficient data has been archived to HDFS.

```bash
# Top attacking IPs
spark-submit --master yarn batch/analysis1_top_ips.py

# Threat volume over time
spark-submit --master yarn batch/analysis2_threat_volume.py

# Attack pattern breakdown
spark-submit --master yarn batch/analysis3_attack_patterns.py

# Port scan analysis
spark-submit --master yarn batch/analysis4_port_scans.py

# Load results into HBase
python batch/hbase_loader.py
```

Checkpoints are tracked in `checkpoint_batch.json` and `checkpoint_ingest.json` to allow safe restarts without data loss.

---

### Dashboard

```bash
python dashboard/main.py
```

Then open your browser at `http://localhost:8000` (or whichever port is configured in `main.py`).

The dashboard provides:
- **Live threat feed** — alerts streamed from Cassandra in near real-time
- **Top attackers** — ranked by severity score
- **Volume charts** — threats over time
- **Attack pattern breakdown** — chart by type (SQLi, XSS, Brute Force, etc.)
- **Port scan heatmap** — target port distribution

---

## Data Flow Details

### Real-Time Path

1. `producer_stream.py` reads log rows from the CSV and publishes them to the `threat_scan` Kafka topic.
2. `consumer_stream.py` consumes the topic via Spark Structured Streaming, applies detection logic from `detection_functions.py`, and writes alerts to three Cassandra tables via `cassandra_write.py`.

### Batch Path

1. `kafka_to_hdfs.py` archives raw messages from Kafka to HDFS under the configured output path.
2. The four analysis scripts read from HDFS, compute aggregations with Spark, and produce result datasets.
3. `hbase_loader.py` loads those results into HBase for fast dashboard queries.

---

## Cassandra Schema

```
Keyspace: threat_detector
│
├── threats_now       — live alerts (timestamp, source_ip, attack_type, severity, details)
├── threats_counters  — per-IP alert count and cumulative severity score
└── threats_metadata  — per-IP last seen timestamp and list of observed attack types
```

---

## Batch Analytics Descriptions

| Script | Output |
|--------|--------|
| `analysis1_top_ips.py` | Ranked list of source IPs by number of alerts generated |
| `analysis2_threat_volume.py` | Alert counts aggregated by time window (hourly / daily) |
| `analysis3_attack_patterns.py` | Distribution of attack types with trend over time |
| `analysis4_port_scans.py` | Destination port frequency; flags sequential scan behaviour |

---

## Dependencies

```
kafka-python==2.3.1
cassandra-driver==3.30.0
happybase
```

> `happybase` is the Python client for Apache HBase (communicates via the Thrift gateway).
> Spark and Hadoop libraries are managed by the cluster; no local pip install required for those.

---

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
