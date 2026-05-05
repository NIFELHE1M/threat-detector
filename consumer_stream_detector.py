# consumer_stream_detector.py
from cassandra.cluster import Cluster
from pyspark.sql import SparkSession
import pyspark.sql.functions as func
from pyspark.sql.types import StructType, StructField, StringType
import time
import global_vars as glob
import detection_functions as detect_func
import cassandra_write as cas_w

# schema for casting stream to json
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

raw_data_frame = (
    spark_session.readStream
    .format('kafka')
    .option('kafka.bootstrap.servers', glob.BOOTSTRAP_SERVERS)
    .option('subscribe',               glob.TOPIC)
    .option('startingOffsets',         'latest')
    .option('maxOffsetsPerTrigger',    '100')               # process max 100 msgs/batch
    .load()
)

print("starting the logs filtering......\n")

data_frame = (
    raw_data_frame
    .select(func.col('value').cast('string').alias('log_fragment'))
    .select(func.from_json(func.col('log_fragment'), log_schema).alias('threat_log'))
    .select('threat_log.*')
    .withColumn(
        'timestamp',
        func.to_timestamp(func.col('timestamp'), "yyyy-MM-dd'T'HH:mm:ss")
    )
)

# detection names for display
DETECTION_NAMES = [
    'brute_force',
    'volume',
    'pattern',
]

# process each micro-batch
def process_batch(batch_df, batch_id):
    if batch_df.isEmpty():
        print(f"[Batch {batch_id}] No data.")
        return

    t_batch_start = time.time()                             # ← total batch timer start

    row_count = batch_df.count()

    t_detect = time.time()
    all_alerts = [
        detect_func.brute_force_detection(batch_df),
        detect_func.volume_detection(batch_df),
        detect_func.pattern_detection(batch_df),
    ]
    detect_elapsed = time.time() - t_detect                 # ← detection timer

    print(f"\n{'='*60}")
    print(f"  Batch ID        : {batch_id}")
    print(f"  Rows received   : {row_count}")
    print(f"  Detection time  : {detect_elapsed:.4f}s")
    print(f"{'='*60}")

    t_display = time.time()
    for name, detected in zip(DETECTION_NAMES, all_alerts):
        print(f"\n--- {name.upper()} ALERTS ---")
        detected.show(truncate=False)                       # safe here — batch_df is static
    display_elapsed = time.time() - t_display               # ← display timer

    total_elapsed = time.time() - t_batch_start
    print(f"\n{'─'*60}")
    print(f"  Display time    : {display_elapsed:.4f}s")    # ← how long .show() took
    print(f"{'─'*60}\n")

    t_cas = time.time()                    # ← cassandra timer start
    for detected in all_alerts :
        cas_w.cassandra_w(cassandra_session, detected)
    cas_elapsed = time.time() - t_cas                       # ← cassandra timer stop
    print(f"[Cassandra Batch {batch_id}] Write time : {cas_elapsed:.4f}s")

# start the detection streaming query
query = (
    data_frame.writeStream
    .outputMode('update')
    .foreachBatch(process_batch)                            # detection + display
    .trigger(processingTime='5 seconds')                    # run every 5s
    .option('checkpointLocation', '/tmp/checkpoint_threat')
    .start()
)

query.awaitTermination()
