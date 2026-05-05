# consumer_stream_fixed.py
from cassandra.cluster import Cluster
from pyspark.sql import SparkSession
import pyspark.sql.functions as func
from pyspark.sql.types import StructType, StructField, StringType
import time
import global_vars as glob
import detection_functions as detect_func
import cassandra_write as cas_w

# schema for casting stream to json - simplified
log_schema = StructType([
    StructField('timestamp',         StringType()),
    StructField('source_ip',         StringType()),
    StructField('dest_ip',           StringType()),
    StructField('protocol',          StringType()),
    StructField('action',            StringType()),
    StructField('threat_label',      StringType()),
    StructField('log_type',          StringType()),
    StructField('bytes_transferred', StringType()),
    StructField('user_agent',        StringType()),
    StructField('request_path',      StringType()),
])

# opening a cassandra session
cassandra_session = Cluster([glob.CASSANDRA_HOST]).connect(glob.CASSANDRA_KEYSPACE)

# opening spark session
spark_session = (
    SparkSession.builder
    .appName('threat_detector')
    .config("spark.sql.shuffle.partitions", "2")
    .config("spark.ui.enabled",             "false")
    .getOrCreate()
)

spark_session.sparkContext.setLogLevel("ERROR")

# Read from beginning to get all data
raw_data_frame = (
    spark_session.readStream
    .format('kafka')
    .option('kafka.bootstrap.servers', glob.BOOTSTRAP_SERVERS)
    .option('subscribe',               glob.TOPIC)
    .option('startingOffsets',         'earliest')  # Changed from 'latest' to 'earliest'
    .option('maxOffsetsPerTrigger',    '100')
    .option('failOnDataLoss',          'false')
    .load()
)

print("starting the logs filtering......\n")

# Parse JSON and clean data
data_frame = (
    raw_data_frame
    .select(func.col('value').cast('string').alias('log_fragment'))
    .filter(func.col('log_fragment').isNotNull())
    .select(func.from_json(func.col('log_fragment'), log_schema).alias('threat_log'))
    .select('threat_log.*')
    .filter(func.col('timestamp').isNotNull())
    # Clean timestamp - remove any extra characters
    .withColumn('timestamp_clean', 
        func.regexp_replace(func.col('timestamp'), '[^0-9-T:]', ''))
    .withColumn('timestamp', 
        func.to_timestamp(func.col('timestamp_clean'), "yyyy-MM-dd'T'HH:mm:ss"))
    .drop('timestamp_clean')
    .filter(func.col('timestamp').isNotNull())
)

# Show schema for debugging
print("Schema:")
data_frame.printSchema()

# detection names for display
DETECTION_NAMES = [
    'brute_force',
    'volume',
    'pattern',
]

# process each micro-batch
def process_batch(batch_df, batch_id):
    if batch_df.isEmpty():
        print(f"[Batch {batch_id}] No data received.")
        return

    t_batch_start = time.time()
    row_count = batch_df.count()
    
    print(f"\n{'='*60}")
    print(f"  Batch ID        : {batch_id}")
    print(f"  Rows received   : {row_count}")
    print(f"{'='*60}")
    
    # Show sample of received data
    print("\n--- Sample of received data ---")
    batch_df.select('timestamp', 'source_ip', 'action', 'request_path').show(3, truncate=False)
    
    t_detect = time.time()
    all_alerts = [
        detect_func.brute_force_detection(batch_df),
        detect_func.volume_detection(batch_df),
        detect_func.pattern_detection(batch_df),
    ]
    detect_elapsed = time.time() - t_detect
    
    print(f"\n  Detection time  : {detect_elapsed:.4f}s")
    
    t_display = time.time()
    for name, detected in zip(DETECTION_NAMES, all_alerts):
        alert_count = detected.count() if not detected.isEmpty() else 0
        print(f"\n--- {name.upper()} ALERTS --- Found: {alert_count}")
        if not detected.isEmpty():
            detected.show(5, truncate=False)
    display_elapsed = time.time() - t_display
    
    total_elapsed = time.time() - t_batch_start
    print(f"\n  Display time    : {display_elapsed:.4f}s")
    print(f"  Total batch time: {total_elapsed:.4f}s")
    
    t_cas = time.time()
    for detected in all_alerts:
        if not detected.isEmpty():
            cas_w.cassandra_w(cassandra_session, detected)
    cas_elapsed = time.time() - t_cas
    if cas_elapsed > 0:
        print(f"[Cassandra Batch {batch_id}] Write time : {cas_elapsed:.4f}s")
    print(f"{'─'*60}\n")

# start the detection streaming query
query = (
    data_frame.writeStream
    .outputMode('append')
    .foreachBatch(process_batch)
    .trigger(processingTime='5 seconds')
    .option('checkpointLocation', '/tmp/checkpoint_threat_fixed')
    .start()
)

query.awaitTermination()
