#!/bin/bash

#!/bin/bash

# ================================================================
# Docker Resource Usage Logger with Timed Log Rotation
# ---------------------------------------------------------------
# This script logs system resource usage (CPU, memory, I/O) for
# all running Docker containers at a defined interval.
#
# Features:
#   - Logs docker stats every N seconds
#   - Creates new log files every X hours
#   - Saves full docker logs for each container on rotation
#   - Automatically cleans up logs older than N days
#
# Output:
#   - docker_stats_<timestamp>.log for resource snapshots
#   - <container>_log_<timestamp>.txt for full container logs
# ================================================================



# =========================
# CONFIGURATION
# =========================
INTERVAL=10                         # Seconds between docker stats samples
LOG_DIR="./docker_usage_logs"      # Where to store all logs
RETENTION_DAYS=7                   # How long to keep logs
LOG_INTERVAL_HOURS=4               # Create new stats/log files every 4 hours

# =========================
# SETUP
# =========================
mkdir -p "$LOG_DIR"
LAST_DUMP_TIME=0
CURRENT_STATS_FILE=""

echo "🚀 Docker resource logger started"
echo "Stats interval: $INTERVAL sec, log rotation every $LOG_INTERVAL_HOURS hours"
echo "Log directory: $LOG_DIR"

# =========================
# MAIN LOOP
# =========================
while true; do
    NOW=$(date +%s)

    # Determine if it's time for a new file
    if (( NOW - LAST_DUMP_TIME >= LOG_INTERVAL_HOURS * 3600 )); then
        TIME_TAG=$(date "+%Y-%m-%d_%H-%M")
        CURRENT_STATS_FILE="$LOG_DIR/docker_stats_${TIME_TAG}.log"
        echo "🆕 New stats/log files created: $CURRENT_STATS_FILE"

        # Dump full logs for each container
        for CONTAINER in $(docker ps --format '{{.Names}}'); do
            LOG_FILE="$LOG_DIR/${CONTAINER}_log_${TIME_TAG}.txt"
            docker logs "$CONTAINER" &> "$LOG_FILE"
        done

        LAST_DUMP_TIME=$NOW
    fi

    # Log current docker stats to the active stats file
    {
        echo "=== $(date) ==="
        docker stats --no-stream
        echo ""
    } >> "$CURRENT_STATS_FILE"

    # Clean up old logs
    find "$LOG_DIR" -type f -name "*.log" -mtime +$RETENTION_DAYS -exec rm {} \;

    sleep "$INTERVAL"
done
