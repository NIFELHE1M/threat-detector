from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from cassandra.cluster import Cluster
import json
import asyncio

app = FastAPI()

# Allow the HTML page to call this API from the browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Connect to Cassandra ──────────────────────────────────────────
cluster = None
session = None
CASSANDRA_CONTACT_POINTS = ["127.0.0.1"]
CASSANDRA_PORT = 9042
KEYSPACE = "threat_detection"

@app.on_event("startup")
async def startup():
    global cluster, session
    cluster = Cluster(CASSANDRA_CONTACT_POINTS, port=CASSANDRA_PORT)
    session = cluster.connect(KEYSPACE)

@app.on_event("shutdown")
async def shutdown():
    if session is not None:
        session.shutdown()
    if cluster is not None:
        cluster.shutdown()


# ── Endpoint 1: all recent threats ───────────────────────────────
@app.get("/threats")
def get_threats():
    rows = session.execute("SELECT * FROM threats_now")
    result = []
    for row in rows:
        result.append({
            "alert_id":   str(row.alert_id),
            "attack_type": row.attack_type,
            "detected_at": str(row.detected_at),
            "ip_source":   row.ip_source,
            "severity":    row.severity,
        })
    return result


# ── Endpoint 2: threat counters per IP ───────────────────────────
@app.get("/counters")
def get_counters():
    rows = session.execute("SELECT * FROM threats_counters")
    result = []
    for row in rows:
        result.append({
            "ip_source":    row.ip_source,
            "alert_count":  row.alert_count,
            "threat_score": row.threat_score,
        })
    return result


# ── Endpoint 3: metadata per IP ──────────────────────────────────
@app.get("/metadata")
def get_metadata():
    rows = session.execute("SELECT * FROM threats_metadata")
    result = []
    for row in rows:
        result.append({
            "ip_source":    row.ip_source,
            "last_seen":    str(row.last_seen),
            "attack_types": list(row.attack_types) if row.attack_types else [],
        })
    return result


# ── Endpoint 4: SSE streaming (live updates every 5 seconds) ─────
@app.get("/stream")
async def stream_threats():
    async def event_generator():
        while True:
            rows = session.execute("SELECT * FROM threats_now LIMIT 20")
            data = []
            for row in rows:
                data.append({
                    "alert_id":    str(row.alert_id),
                    "attack_type": row.attack_type,
                    "detected_at": str(row.detected_at),
                    "ip_source":   row.ip_source,
                    "severity":    row.severity,
                })
            # SSE format: each message starts with "data: "
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(1)   # refresh every 1 second

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream"
    )
