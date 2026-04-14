from pyspark.sql import DataFrame
import pyspark.sql.functions as func
import global_vars as glob


def brute_force_detection(log: DataFrame) -> DataFrame:
    return (
        log
        .filter(func.col('action') == 'blocked')           # only failed attempts
        .groupBy(
            func.window(func.col('timestamp'), '1 minute'), # 1-min tumbling window
            func.col('source_ip'),
            func.col('dest_ip'),
        )
        .agg(
            func.count('*').alias('attempts'),
            func.first('protocol').alias('protocol'),
        )
        .filter(func.col('attempts') >= glob.BRUTE_FORCE_THRESHOLD)  # apply threshold
        .withColumn('alert_type', func.lit('brute force'))
        .withColumn('severity',   func.lit('high'))
        .withColumn(
            'description',
            func.concat(
                func.lit('brute force detected : '),
                func.col('attempts').cast('string'),
                func.lit(' attempts targeted to '),
                func.col('dest_ip').cast('string'),
            )
        )
        .drop("window")
    )

def volume_detection(log: DataFrame) -> DataFrame:
    return (
        log.groupBy(
            func.window(func.col("timestamp"), "10 seconds"),
            func.col("source_ip"),
        )
        .agg(
            func.sum(func.col("bytes_transferred").cast("long")).alias(
                "volume_transferred"
            )
        )
        .filter(func.col("volume_transferred") >= glob.VOLUME_THRESHOLD)
        .withColumn("alert_type", func.lit("volume_attack"))
        .withColumn("severity", func.lit("high"))
        .withColumn(
            "description",
            func.concat(
                func.lit("volume attack detected : "),
                func.col("volume_transferred").cast("string"),
                func.lit(" bytes transferred"),
            ),
        )
        .drop("window")
    )


def pattern_detection(log: DataFrame) -> DataFrame:
    tools_atk = log.filter(func.col("user_agent").rlike(glob.TOOLS)).withColumn(
        "alert_type", func.lit("tool_based_attack")
    )

    sql_injection = log.filter(
        func.col("request_path").rlike(glob.SQL_INJECTION)
    ).withColumn("alert_type", func.lit("SQL_INJECTION"))

    xss = log.filter(func.col("request_path").rlike(glob.XSS_PATTERNS)).withColumn(
        "alert_type", func.lit("XSS_PATTERNS")
    )
    path_traversal = log.filter(
        func.col("request_path").rlike(glob.PATH_TRAVERSAL)
    ).withColumn("alert_type", func.lit("PATH_TRAVERSAL"))

    return (
        tools_atk.unionByName(sql_injection)
        .unionByName(xss)
        .unionByName(path_traversal)
        .withColumn(
            "severity",
            func.when(func.col("alert_type") == "SQL_INJECTION", func.lit("critical"))
            .when(func.col("alert_type") == "XSS_PATTERNS", func.lit("high"))
            .when(func.col("alert_type") == "PATH_TRAVERSAL", func.lit("high"))
            .when(func.col("alert_type") == "tool_based_attack", func.lit("medium"))
            .otherwise(func.lit("low")),
        )
        .select(
            "source_ip",
            "protocol",
            "user_agent",
            "request_path",
            "alert_type",
            "severity",
        )
    )
