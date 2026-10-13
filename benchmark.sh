=#!/bin/bash

# Target server (adjust port if your container runs on something else)
TARGET_URL="http://127.0.0.1:8080/"
CONCURRENCY=100
OUTPUT_FILE=$1 # We will pass the filename as an argument

# Extended up to 50k requests
REQUEST_STEPS=(100 500 1000 5000 10000 15000 25000 50000)

echo "Requests,Throughput,MeanLatency" > $OUTPUT_FILE

for REQS in "${REQUEST_STEPS[@]}"; do
    echo "Firing $REQS requests at $TARGET_URL..."
    
    # Run ab and capture output
    RAW_OUTPUT=$(ab -n $REQS -c $CONCURRENCY $TARGET_URL 2>/dev/null)
    
    # Parse RPS and Latency
    RPS=$(echo "$RAW_OUTPUT" | grep "Requests per second:" | awk '{print $4}')
    LATENCY=$(echo "$RAW_OUTPUT" | grep "Time per request:" | head -n 1 | awk '{print $4}')
    
    echo "$REQS,$RPS,$LATENCY" >> $OUTPUT_FILE
    sleep 2 # Let the CPU breathe and TCP sockets close
done

echo "Saved to $OUTPUT_FILE"

