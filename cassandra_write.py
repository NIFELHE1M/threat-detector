from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
from pyspark.sql import DataFrame
import global_vars as glob
import json
from datetime import datetime
import uuid

statement_threat_by_ip_counters = f"""
    UPDATE {glob.CASSANDRA_TABLE_COUNTERS}
    SET
        threat_score = threat_score + ?,
        alert_count = alert_count + 1
    WHERE ip_source = ?
"""

statement_threat_by_ip_metadata = f"""
    UPDATE {glob.CASSANDRA_TABLE_METADATA}
    SET
        last_seen = ?,
        attack_types = attack_types + ?
    WHERE ip_source = ?
"""

statement_threat_now = f"""
    INSERT INTO {glob.CASSANDRA_TABLE_LIVE_THREAT}
    (alert_id, ip_source, attack_type, severity, detected_at)
    VALUES (?, ?, ?, ?, ?)
"""


def cassandra_w(session, datafragment: DataFrame):
    paquets = datafragment.collect()

    if not paquets:
        return
    
    prepared_statement_counters = session.prepare(statement_threat_by_ip_counters)
    prepared_statement_metadata = session.prepare(statement_threat_by_ip_metadata)
    prepared_statement_now = session.prepare(statement_threat_now)

    for paquet in paquets:
        session.execute(prepared_statement_counters, (
            int(glob.METRICS[paquet['severity']]),
            paquet["source_ip"]
        ))
        
        session.execute(prepared_statement_metadata, (
            datetime.now(),
            {paquet['alert_type']},
            paquet["source_ip"]
        ))
        
        session.execute(prepared_statement_now, (
            uuid.uuid4(),
            paquet["source_ip"],
            paquet['alert_type'],
            paquet['severity'],
            datetime.now()
        ))
